/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mc-array-private.h"
#include "mc-efc-private.h"
#include "mc-fle-blob-subtype-private.h"
#include "mc-fle2-encryption-placeholder-private.h"
#include "mc-fle2-rfds-private.h"
#include "mc-tokens-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt-traverse-util-private.h"
#include "mongocrypt-util-private.h" // mc_iter_document_as_bson
#include "mongocrypt.h"
#include <bson/bson.h>
#include <stdint.h>

/* _fle2_append_encryptedFieldConfig copies encryptedFieldConfig and applies
 * default state collection names for escCollection, eccCollection, and
 * ecocCollection if required. */
static bool _fle2_append_encryptedFieldConfig(const mongocrypt_ctx_t *ctx,
                                              bson_t *dst,
                                              bson_t *encryptedFieldConfig,
                                              const char *coll_name,
                                              mongocrypt_status_t *status) {
    bson_iter_t iter;
    bool has_escCollection = false;
    bool has_eccCollection = false;
    bool has_ecocCollection = false;

    BSON_ASSERT_PARAM(dst);
    BSON_ASSERT_PARAM(encryptedFieldConfig);
    BSON_ASSERT_PARAM(coll_name);

    if (!bson_iter_init(&iter, encryptedFieldConfig)) {
        CLIENT_ERR("unable to iterate encryptedFieldConfig");
        return false;
    }

    while (bson_iter_next(&iter)) {
        if (strcmp(bson_iter_key(&iter), "escCollection") == 0) {
            has_escCollection = true;
        }
        if (strcmp(bson_iter_key(&iter), "eccCollection") == 0) {
            has_eccCollection = true;
        }
        if (strcmp(bson_iter_key(&iter), "ecocCollection") == 0) {
            has_ecocCollection = true;
        }
        if (!BSON_APPEND_VALUE(dst, bson_iter_key(&iter), bson_iter_value(&iter))) {
            CLIENT_ERR("unable to append field: %s", bson_iter_key(&iter));
            return false;
        }
    }

    if (!has_escCollection) {
        char *default_escCollection = bson_strdup_printf("enxcol_.%s.esc", coll_name);
        if (!BSON_APPEND_UTF8(dst, "escCollection", default_escCollection)) {
            CLIENT_ERR("unable to append escCollection");
            bson_free(default_escCollection);
            return false;
        }
        bson_free(default_escCollection);
    }
    if (!has_eccCollection && !ctx->crypt->opts.use_fle2_v2) {
        char *default_eccCollection = bson_strdup_printf("enxcol_.%s.ecc", coll_name);
        if (!BSON_APPEND_UTF8(dst, "eccCollection", default_eccCollection)) {
            CLIENT_ERR("unable to append eccCollection");
            bson_free(default_eccCollection);
            return false;
        }
        bson_free(default_eccCollection);
    }
    if (!has_ecocCollection) {
        char *default_ecocCollection = bson_strdup_printf("enxcol_.%s.ecoc", coll_name);
        if (!BSON_APPEND_UTF8(dst, "ecocCollection", default_ecocCollection)) {
            CLIENT_ERR("unable to append ecocCollection");
            bson_free(default_ecocCollection);
            return false;
        }
        bson_free(default_ecocCollection);
    }
    return true;
}

static bool _fle2_append_encryptionInformation(const mongocrypt_ctx_t *ctx,
                                               bson_t *dst,
                                               const char *ns,
                                               bson_t *encryptedFieldConfig,
                                               const char *coll_name,
                                               mongocrypt_status_t *status) {
    bson_t encryption_information_bson;
    bson_t schema_bson;
    bson_t encrypted_field_config_bson;

    BSON_ASSERT_PARAM(dst);
    BSON_ASSERT_PARAM(ns);
    BSON_ASSERT_PARAM(encryptedFieldConfig);
    /* deleteTokens may be NULL */
    BSON_ASSERT_PARAM(coll_name);

    if (!BSON_APPEND_DOCUMENT_BEGIN(dst, "encryptionInformation", &encryption_information_bson)) {
        CLIENT_ERR("unable to begin appending 'encryptionInformation'");
        return false;
    }
    if (!BSON_APPEND_INT32(&encryption_information_bson, "type", 1)) {
        CLIENT_ERR("unable to append type to 'encryptionInformation'");
        return false;
    }
    if (!BSON_APPEND_DOCUMENT_BEGIN(&encryption_information_bson, "schema", &schema_bson)) {
        CLIENT_ERR("unable to begin appending 'schema' to 'encryptionInformation'");
        return false;
    }

    if (!BSON_APPEND_DOCUMENT_BEGIN(&schema_bson, ns, &encrypted_field_config_bson)) {
        CLIENT_ERR("unable to begin appending 'encryptedFieldConfig' to "
                   "'encryptionInformation'.'schema'");
        return false;
    }

    if (!_fle2_append_encryptedFieldConfig(ctx,
                                           &encrypted_field_config_bson,
                                           encryptedFieldConfig,
                                           coll_name,
                                           status)) {
        return false;
    }

    if (!bson_append_document_end(&schema_bson, &encrypted_field_config_bson)) {
        CLIENT_ERR("unable to end appending 'encryptedFieldConfig' to "
                   "'encryptionInformation'.'schema'");
        return false;
    }
    if (!bson_append_document_end(&encryption_information_bson, &schema_bson)) {
        CLIENT_ERR("unable to end appending 'schema' to 'encryptionInformation'");
        return false;
    }

    if (!bson_append_document_end(dst, &encryption_information_bson)) {
        CLIENT_ERR("unable to end appending 'encryptionInformation'");
        return false;
    }
    return true;
}

typedef enum { MC_TO_CSFLE, MC_TO_MONGOCRYPTD, MC_TO_MONGOD } mc_cmd_target_t;

/**
 * @brief Add "encryptionInformation" to a command.
 *
 * @param cmd_name The name of the command.
 * @param cmd The command being rewritten. It is an input and output.
 * @param ns The <db>.<collection> namespace for the command.
 * @param encryptedFieldConfig The "encryptedFields" document for the
 * collection.
 * @param deleteTokens Delete tokens to append to "encryptionInformation". May
 * be NULL.
 * @param coll_name The collection name.
 * @param cmd_target The intended destination of the command. csfle,
 * mongocryptd, and mongod have different requirements for the location of
 * "encryptionInformation".
 * @param status Output status.
 * @return true On success
 * @return false Otherwise. Sets a failing status message in this case.
 */
static bool _fle2_insert_encryptionInformation(const mongocrypt_ctx_t *ctx,
                                               const char *cmd_name,
                                               bson_t *cmd /* in and out */,
                                               const char *ns,
                                               bson_t *encryptedFieldConfig,
                                               const char *coll_name,
                                               mc_cmd_target_t cmd_target,
                                               mongocrypt_status_t *status) {
    bson_t out = BSON_INITIALIZER;
    bson_t explain = BSON_INITIALIZER;
    bson_iter_t iter;
    bool ok = false;

    BSON_ASSERT_PARAM(cmd_name);
    BSON_ASSERT_PARAM(cmd);
    BSON_ASSERT_PARAM(ns);
    BSON_ASSERT_PARAM(encryptedFieldConfig);
    /* deleteTokens may be NULL */
    BSON_ASSERT_PARAM(coll_name);

    if (!_fle2_append_encryptionInformation(ctx, cmd, ns, encryptedFieldConfig, coll_name, status)) {
        goto fail;
    }
    bson_destroy(&out);
    goto success;

success:
    ok = true;
fail:
    bson_destroy(&explain);
    if (!ok) {
        bson_destroy(&out);
    }
    return ok;
}

/* Construct the list collections command to send. */
// TODO - dedup?
static bool _mongo_op_collinfo(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t *cmd;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;
    cmd = BCON_NEW("name", BCON_UTF8(ectx->coll_name));
    CRYPT_TRACEF(&ectx->parent.crypt->log, "constructed: %s\n", tmp_json(cmd));
    _mongocrypt_buffer_steal_from_bson(&ectx->list_collections_filter, cmd);
    out->data = ectx->list_collections_filter.data;
    out->len = ectx->list_collections_filter.len;
    return true;
}

static bool _set_schema_from_collinfo(mongocrypt_ctx_t *ctx, bson_t *collinfo) {
    bson_iter_t iter;
    _mongocrypt_ctx_migrate_t *ectx;
    bool found_jsonschema = false;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(collinfo);

    /* Parse out the schema. */
    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    /* Disallow views. */
    if (bson_iter_init_find(&iter, collinfo, "type") && BSON_ITER_HOLDS_UTF8(&iter) && bson_iter_utf8(&iter, NULL)
        && 0 == strcmp("view", bson_iter_utf8(&iter, NULL))) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "cannot auto encrypt a view");
    }

    if (!bson_iter_init(&iter, collinfo)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "BSON malformed");
    }

    if (bson_iter_find_descendant(&iter, "options.encryptedFields", &iter)) {
        if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "options.encryptedFields is not a BSON document");
        }
        if (!_mongocrypt_buffer_copy_from_document_iter(&ectx->encrypted_field_config, &iter)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "unable to copy options.encryptedFields");
        }
        bson_t efc_bson;
        if (!_mongocrypt_buffer_to_bson(&ectx->encrypted_field_config, &efc_bson)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "unable to create BSON from encrypted_field_config");
        }
        if (!mc_EncryptedFieldConfig_parse(&ectx->efc, &efc_bson, ctx->status)) {
            _mongocrypt_ctx_fail(ctx);
            return false;
        }
    }

    BSON_ASSERT(bson_iter_init(&iter, collinfo));

    if (bson_iter_find_descendant(&iter, "options.validator", &iter) && BSON_ITER_HOLDS_DOCUMENT(&iter)) {
        if (!bson_iter_recurse(&iter, &iter)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "BSON malformed");
        }
        while (bson_iter_next(&iter)) {
            const char *key;

            key = bson_iter_key(&iter);
            BSON_ASSERT(key);
            if (0 == strcmp("$jsonSchema", key)) {
                if (found_jsonschema) {
                    return _mongocrypt_ctx_fail_w_msg(ctx, "duplicate $jsonSchema fields found");
                }
                if (!_mongocrypt_buffer_copy_from_document_iter(&ectx->schema, &iter)) {
                    return _mongocrypt_ctx_fail_w_msg(ctx, "malformed $jsonSchema");
                }
                found_jsonschema = true;
            } else {
                ectx->collinfo_has_siblings = true;
            }
        }
    }

    if (!found_jsonschema) {
        bson_t empty = BSON_INITIALIZER;

        _mongocrypt_buffer_steal_from_bson(&ectx->schema, &empty);
    }

    return true;
}

/* context_uses_fle2 returns true if the context uses FLE 2 behavior.
 * If a collection has an encryptedFields document, it uses FLE 2.
 */
static bool context_uses_fle2(mongocrypt_ctx_t *ctx) {
    _mongocrypt_ctx_migrate_t *ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT_PARAM(ctx);

    return !_mongocrypt_buffer_empty(&ectx->encrypted_field_config);
}

static bool _mongo_feed_collinfo(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in) {
    bson_t as_bson;

    _mongocrypt_ctx_migrate_t *ectx;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(in);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;
    if (!bson_init_static(&as_bson, in->data, in->len)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "BSON malformed");
    }

    /* Cache the received collinfo. */
    if (!_mongocrypt_cache_add_copy(&ctx->crypt->cache_collinfo, ectx->ns, &as_bson, ctx->status)) {
        return _mongocrypt_ctx_fail(ctx);
    }

    if (!_set_schema_from_collinfo(ctx, &as_bson)) {
        return false;
    }

    return true;
}

static bool _try_run_csfle_marking(mongocrypt_ctx_t *ctx);

static bool _mongo_done_collinfo(mongocrypt_ctx_t *ctx) {
    _mongocrypt_ctx_migrate_t *ectx;

    BSON_ASSERT_PARAM(ctx);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;
    if (_mongocrypt_buffer_empty(&ectx->schema)) {
        bson_t empty_collinfo = BSON_INITIALIZER;

        /* If no collinfo was fed, cache an empty collinfo. */
        if (!_mongocrypt_cache_add_copy(&ctx->crypt->cache_collinfo, ectx->ns, &empty_collinfo, ctx->status)) {
            bson_destroy(&empty_collinfo);
            return _mongocrypt_ctx_fail(ctx);
        }
        bson_destroy(&empty_collinfo);
    }

    ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
    return _try_run_csfle_marking(ctx);
}

static bool _fle2_mongo_op_markings(mongocrypt_ctx_t *ctx, bson_t *out) {
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t cmd_bson = BSON_INITIALIZER, encrypted_field_config_bson = BSON_INITIALIZER;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT(ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    BSON_ASSERT(context_uses_fle2(ctx));

    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &cmd_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert original_cmd to BSON");
    }

    if (!_mongocrypt_buffer_to_bson(&ectx->encrypted_field_config, &encrypted_field_config_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert encrypted_field_config to BSON");
    }

    return true;
}

/**
 * @brief Create the server-side command that contains information for
 * generating encryption markings via query analysis.
 *
 * @param ctx The encryption context.
 * @param out The destination of the generated BSON document
 * @return true On success
 * @return false Otherwise. Sets a failing status message in this case.
 */
static bool _create_markings_cmd_bson(mongocrypt_ctx_t *ctx, bson_t *out) {
    _mongocrypt_ctx_migrate_t *ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    if (context_uses_fle2(ctx)) {
        // Defer to FLE2 to generate the markings command
        return _fle2_mongo_op_markings(ctx, out);
    }

    // For FLE1:
    // Get the original command document
    bson_t bson_view = BSON_INITIALIZER;
    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &bson_view)) {
        _mongocrypt_ctx_fail_w_msg(ctx, "invalid BSON cmd");
        return false;
    }

    // Copy the command to the output
    // If input command included $db, do not include it in the command to
    // mongocryptd. Drivers are expected to append $db in the RunCommand helper
    // used to send the command.
    bson_init(out);
    bson_copy_to_excluding_noinit(&bson_view, out, "$db", NULL);

    if (!_mongocrypt_buffer_empty(&ectx->schema)) {
        // We have a schema buffer. View it as BSON:
        if (!_mongocrypt_buffer_to_bson(&ectx->schema, &bson_view)) {
            _mongocrypt_ctx_fail_w_msg(ctx, "invalid BSON schema");
            return false;
        }
        // Append the jsonSchema to the output command
        BSON_APPEND_DOCUMENT(out, "jsonSchema", &bson_view);
    } else {
        bson_t empty = BSON_INITIALIZER;
        BSON_APPEND_DOCUMENT(out, "jsonSchema", &empty);
    }

    // if a local schema was not set, set isRemoteSchema=true
    BSON_APPEND_BOOL(out, "isRemoteSchema", !ectx->used_local_schema);
    return true;
}

static bool _mongo_op_markings(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    _mongocrypt_ctx_migrate_t *ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    return true;
}

bool _collect_key_from_marking(void *ctx, _mongocrypt_buffer_t *in, mongocrypt_status_t *status);

static bool _mongo_feed_markings(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in) {
    /* Find keys. */
    bson_t as_bson;
    bson_iter_t iter;
    _mongocrypt_ctx_migrate_t *ectx;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(in);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    _mongocrypt_buffer_copy_from_binary(&ectx->marked_cmd, in);

    if (!_mongocrypt_binary_to_bson(in, &as_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed BSON");
    }

    bson_iter_init(&iter, &as_bson);

    if (!_mongocrypt_traverse_binary_in_bson(_collect_key_from_marking,
                                             (void *)&ctx->kb,
                                             TRAVERSE_MATCH_MARKING,
                                             &iter,
                                             ctx->status)) {
        return _mongocrypt_ctx_fail(ctx);
    }

    return true;
}

static bool _mongo_done_markings(mongocrypt_ctx_t *ctx) {
    _mongocrypt_ctx_migrate_t *ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT_PARAM(ctx);

    (void)_mongocrypt_key_broker_requests_done(&ctx->kb);
    return _mongocrypt_ctx_state_from_key_broker(ctx);
}

/**
 * @brief Append $db to a command being passed to csfle.
 */
static bool _add_dollar_db(const char *cmd_name, bson_t *cmd, const char *db_name, mongocrypt_status_t *status) {
    bson_t out = BSON_INITIALIZER;
    bson_t explain = BSON_INITIALIZER;
    bson_iter_t iter;
    bool ok = false;

    BSON_ASSERT_PARAM(cmd_name);
    BSON_ASSERT_PARAM(cmd);
    BSON_ASSERT_PARAM(db_name);

    if (!bson_iter_init_find(&iter, cmd, "$db")) {
        if (!BSON_APPEND_UTF8(cmd, "$db", db_name)) {
            CLIENT_ERR("failed to append '$db'");
            goto fail;
        }
    }

success:
    ok = true;
fail:
    bson_destroy(&explain);
    if (!ok) {
        bson_destroy(&out);
    }
    return ok;
}

// struct QueryTypeConfig {

//     mongocrypt_query_type_t type;
//     uint64_t contention;
//     // TODO - min
//     // TODO - max
//     uint64_t sparsity;
//     uint64_t precision;
// };

// struct encryptedField {
//     int keyId;
//     char* path;
//     uint8_t bsonType;

//     // QUery - TODO - assume one for now
//     QueryTypeConfig query;
// };

// struct encryptedFieldConfig {
//     char* escCollection;
//     char* ecocCollection;
//     mc_array_t fields;
// };

typedef struct _SinglyLinkedFieldPath {
    const char *field;
    struct _SinglyLinkedFieldPath *predecessor;
} SinglyLinkedFieldPath;

void SinglyLinkedFieldPath_init(SinglyLinkedFieldPath *p) {
    memset(p, 0, sizeof(SinglyLinkedFieldPath));
}

void SinglyLinkedFieldPath_init_field(SinglyLinkedFieldPath *p, const char *field, SinglyLinkedFieldPath *predecessor) {
    p->predecessor = predecessor;
    p->field = field;
}

bool SinglyLinkedFieldPath_getFieldPath(SinglyLinkedFieldPath *p, const char *fieldName, char **field) {
    if (p->predecessor == NULL) {
        if (p->field) {
            *field = bson_strdup(p->field);
            // TODO leak?
            *field = strcat(*field, fieldName);
        } else {
            *field = bson_strdup(fieldName);
        }
    } else {
        char* path = bson_strdup(fieldName);

        const SinglyLinkedFieldPath* head = p->predecessor;

        while (head) {
            if (head->field) {
                char* old_path = path;
                path = bson_strdup_printf("%s.%s", head->field, old_path);
                bson_free(old_path);
            }

            head = head->predecessor;
        }

        *field = path;
    }

    return true;
}

typedef struct _migrate_transform_state {
    int depth;
    mc_EncryptedFieldConfig_t* efc;

    // Client has to remove tokens, update code handles the removal of tokens
    // mc_array_t remove_tokens;

    // No need to add tokens, they are added by server-side
    // mc_array_t add_tokens;
    _mongocrypt_ctx_migrate_t *mctx;
    bool needs_update; // Not all migrations find something to change
} migrate_transform_state;

// decrypt deindex

// encrypt_with_marking index_with_marking

// Note - does not need to add tokens, tokens are added by remote side

mc_fle_blob_subtype_t getExpectedSubType(mc_EncryptedField_t *ef) {
    if (!ef->has_queries) {
        return MC_SUBTYPE_FLE2UnindexedEncryptedValueV2;
    }

    if (ef->query.type == MONGOCRYPT_QUERYCONFIG_TYPE_EQUALITY) {
        return MC_SUBTYPE_FLE2IndexedEqualityEncryptedValueV2;
    }

    if (ef->query.type == MONGOCRYPT_QUERYCONFIG_TYPE_RANGEPREVIEW) {
        return MC_SUBTYPE_FLE2IndexedEqualityEncryptedValueV2;
    }

    BSON_ASSERT(false);
    // pick a default of some sort
    return MC_SUBTYPE_FLE2UnindexedEncryptedValueV2;
}

bool _replace_ciphertext_with_plaintext(void *ctx,
                                        _mongocrypt_buffer_t *in,
                                        bson_value_t *out,
                                        mongocrypt_status_t *status);

bool tryDecryptField(migrate_transform_state *state,
                     bson_iter_t* iter,
                     bson_t *outDoc,
                     mongocrypt_status_t *status) {
    if (!BSON_ITER_HOLDS_BINARY(iter)) {
        bson_append_iter(outDoc, NULL, 0, iter);
        return true;
    }

    _mongocrypt_buffer_t value;

    BSON_ASSERT(_mongocrypt_buffer_from_binary_iter(&value, iter));
    if (value.subtype != BSON_SUBTYPE_ENCRYPTED || value.len == 0) {
        bson_append_iter(outDoc, NULL, 0, iter);
        return false;
    }

    mc_fle_blob_subtype_t actualSubType = value.data[0];

    // TOOD: if actualSubType is not a FLE type, append element as is

    bson_value_t out;
    BSON_ASSERT(_replace_ciphertext_with_plaintext((void *)&(state->mctx->parent.kb), &value, &out, status));
    bson_append_value(outDoc, bson_iter_key(iter), -1, &out);
    return true;
}

void migrateValue(bson_value_t* value, mc_EncryptedField_t *ef, bson_iter_t *iter, bson_t *outDoc, mongocrypt_status_t *status) {

    bson_t holder;
    bson_init(&holder);

    BSON_APPEND_VALUE(&holder, "v", value);

    bson_iter_t holder_iter;
    bson_iter_init(&holder_iter, &holder);
    bson_iter_next(&holder_iter); // position on the first element

    mc_fle_blob_subtype_t expectedSubType = getExpectedSubType(ef);

    // Generate a marking
    mc_FLE2EncryptionPlaceholder_t ep;
    mc_FLE2EncryptionPlaceholder_init(&ep);
    ep.type = MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT;
    ep.v_iter = holder_iter;
    ep.index_key_id = ef->keyId;
    ep.user_key_id = ef->keyId;
    if (expectedSubType == MC_SUBTYPE_FLE2IndexedEqualityEncryptedValueV2) {
        ep.algorithm = MONGOCRYPT_FLE2_ALGORITHM_EQUALITY;
        ep.maxContentionCounter = ef->query.contention;
    } else if (expectedSubType == MC_SUBTYPE_FLE2IndexedRangeEncryptedValueV2) {
        ep.algorithm = MONGOCRYPT_FLE2_ALGORITHM_RANGE;
        ep.maxContentionCounter = ef->query.contention;
        ep.sparsity = ef->query.sparsity;
    } else {
        ep.algorithm = MONGOCRYPT_FLE2_ALGORITHM_UNINDEXED;
    }


    bson_t ep_value;
    bson_init(&ep_value);

    mc_FLE2EncryptionPlaceholder_serialize(&ep, &ep_value, status);


    size_t buffer_len = ep_value.len + 1;
    char* buffer = bson_malloc(buffer_len);
    buffer[0] = MC_SUBTYPE_FLE2EncryptionPlaceholder;
    memcpy( buffer + 1, bson_get_data(&ep_value), ep_value.len);

    bson_append_binary(outDoc, bson_iter_key(iter), strlen(bson_iter_key(iter)), BSON_SUBTYPE_ENCRYPTED, buffer, buffer_len );

}

// TODO - generate marking
// TODO -0 chang return type
bool migrateField(migrate_transform_state *state,
                  mc_EncryptedField_t *ef,
                  bson_iter_t *iter,
                  bson_t *outDoc,
                  mongocrypt_status_t *status) {

    // Ignore non-bindata
    if (!BSON_ITER_HOLDS_BINARY(iter)) {
        migrateValue(bson_iter_value(iter), ef, iter, outDoc, status);
        return true;
    }

    _mongocrypt_buffer_t value;

    BSON_ASSERT(_mongocrypt_buffer_from_binary_iter(&value, iter));

    if (value.subtype != BSON_SUBTYPE_ENCRYPTED) {
        // TODO - handle encryption
        BSON_ASSERT(false);
        return false;
    }

    // Is the encrypted type different?
    if (value.len == 0) {
        return false;
    }

    mc_fle_blob_subtype_t actualSubType = value.data[0];

    mc_fle_blob_subtype_t expectedSubType = getExpectedSubType(ef);

    if (actualSubType == expectedSubType) {
        return false; // No migration done
    }

    // TODO - handle going to CSFLE1
    // Decrypt fields to BSON
    //
    bson_value_t out;
    BSON_ASSERT(_replace_ciphertext_with_plaintext((void *)&(state->mctx->parent.kb), &value, &out, status));

    // Encrypt BSON field to QE
    //
    if(expectedSubType == MC_SUBTYPE_FLE2IndexedEqualityEncryptedValueV2 ||
        expectedSubType == MC_SUBTYPE_FLE2IndexedRangeEncryptedValueV2 ||
        expectedSubType == MC_SUBTYPE_FLE2UnindexedEncryptedValueV2) {
        migrateValue(&out, ef, iter, outDoc, status);
    }

    else {
        // Fail
        BSON_ASSERT(false);
    }
    return true;
}

void transformDocumentInt(bson_iter_t *iter,
                          migrate_transform_state *state,
                          SinglyLinkedFieldPath *p,
                          bson_t *outDoc,
                          mongocrypt_status_t *status) {
    state->depth++;
    if (state->depth > 30) {
        BSON_ASSERT(false); // TODO
    }
    while (bson_iter_next(iter)) {
        printf("Found a field named: %s\n", bson_iter_key(iter));

        if (BSON_ITER_HOLDS_DOCUMENT(iter)) {
            bson_iter_t child_iter;
            bson_iter_recurse(iter, &child_iter);

            bson_t child_doc;
            bson_append_document_begin(outDoc, bson_iter_key(iter), (int)bson_iter_key_len(iter), &child_doc);

            // TODO Get field path
            SinglyLinkedFieldPath child_p;
            SinglyLinkedFieldPath_init_field(&child_p, bson_iter_key(iter), p);

            transformDocumentInt(&child_iter, state, &child_p, &child_doc, status);

            bson_append_document_end(outDoc, &child_doc);

        } else if (BSON_ITER_HOLDS_ARRAY(iter)) {
            bson_iter_t child_iter;
            bson_iter_recurse(iter, &child_iter);

            bson_t child_doc;
            bson_append_array_begin(outDoc, bson_iter_key(iter), (int)bson_iter_key_len(iter), &child_doc);

            // TODO Get field path
            SinglyLinkedFieldPath child_p;
            SinglyLinkedFieldPath_init_field(&child_p, bson_iter_key(iter), p);

            transformDocumentInt(&child_iter, state, &child_p, &child_doc, status);

            bson_append_array_end(outDoc, &child_doc);

        } else {
            // Is this an interesting field - ie. in EFC or BinData 6?
            // BinData 6 is only interesting if we want to decrypt them
            char *fieldName;
            BSON_ASSERT(SinglyLinkedFieldPath_getFieldPath(p, bson_iter_key(iter), &fieldName));
            bool found_match = false;

            for (mc_EncryptedField_t *ef_iter = state->efc->fields; ef_iter != NULL; ef_iter = ef_iter->next) {
                if (strcmp(ef_iter->path, fieldName) == 0) {
                    // TODO - match
                    migrateField(state, ef_iter, iter, outDoc, status);
                    found_match = true;
                }
            }

            if (!found_match) {
                tryDecryptField(state, iter, outDoc, status);
            }
        }
    }

    state->depth--;
}

void transformDocument(_mongocrypt_ctx_migrate_t *mctx,
                       bson_t *doc,
                       mc_EncryptedFieldConfig_t *efc,
                       bson_t *outDoc,
                       mongocrypt_status_t *status) {
    bson_iter_t iter;

    bson_iter_init(&iter, doc);
    bson_init(outDoc);

    SinglyLinkedFieldPath p;
    SinglyLinkedFieldPath_init(&p);

    migrate_transform_state state;
    memset(&state, 0, sizeof(migrate_transform_state));
    //_mc_array_init(state.add_tokens, ) // TODO
    state.mctx = mctx;
    state.efc = efc;

    transformDocumentInt(&iter, &state, &p, outDoc, status);
}

static bool _fle2_finalize(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);

bool _replace_marking_with_ciphertext(void *ctx,
                                      _mongocrypt_buffer_t *in,
                                      bson_value_t *out,
                                      mongocrypt_status_t *status);

static bool __finalize(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    bson_t as_bson, converted;
    bson_iter_t iter;
    _mongocrypt_ctx_migrate_t *ectx;
    bool res;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    if (context_uses_fle2(ctx)) {
        return _fle2_finalize(ctx, out);
    }

    if (ctx->nothing_to_do) {
        _mongocrypt_buffer_to_binary(&ectx->original_cmd, out);
        ctx->state = MONGOCRYPT_CTX_DONE;
        return true;
    }
    if (!_mongocrypt_buffer_to_bson(&ectx->marked_cmd, &as_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson");
    }

    bson_iter_init(&iter, &as_bson);
    bson_init(&converted);
    if (!_mongocrypt_transform_binary_in_bson(_replace_marking_with_ciphertext,
                                              &ctx->kb,
                                              TRAVERSE_MATCH_MARKING,
                                              &iter,
                                              &converted,
                                              ctx->status)) {
        bson_destroy(&converted);
        return _mongocrypt_ctx_fail(ctx);
    }

    bson_t original_cmd_bson;
    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &original_cmd_bson)) {
        bson_destroy(&converted);
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson in original_cmd");
    }

    // If input command has $db, ensure output command has $db.
    if (bson_iter_init_find(&iter, &original_cmd_bson, "$db")) {
        if (!bson_iter_init_find(&iter, &converted, "$db")) {
            BSON_APPEND_UTF8(&converted, "$db", ectx->db_name);
        }
    }

    return true;
}

/**
 * @brief TODO
 *
 * @param ctx A context which has state NEED_MONGO_MARKINGS
 * @return true On success
 * @return false On error.
 */
static bool _try_run_csfle_marking(mongocrypt_ctx_t *ctx) {
    BSON_ASSERT_PARAM(ctx);
    _mongocrypt_ctx_migrate_t *mctx;
    bool okay = false;

    bson_t cmd_bson = BSON_INITIALIZER, marked_bson = BSON_INITIALIZER;
    bson_t encrypted_field_config_bson;

    mctx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT(ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);

    if (!_mongocrypt_buffer_to_bson(&mctx->original_cmd, &cmd_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert original_cmd to BSON");
    }

    if (!_mongocrypt_buffer_to_bson(&mctx->encrypted_field_config, &encrypted_field_config_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert encrypted_field_config to BSON");
    }

    mc_EncryptedFieldConfig_t efc;

    if (!mc_EncryptedFieldConfig_parse(&efc, &encrypted_field_config_bson, ctx->status)) {
        _mongocrypt_ctx_fail(ctx);
        return false;
    }

    // Add markings
    transformDocument(mctx, &cmd_bson, &efc, &marked_bson, ctx->status);

    // Restart key broker since we have more keys to add
    if (!_mongocrypt_key_broker_restart(&ctx->kb)) {
        _mongocrypt_key_broker_status(&ctx->kb, ctx->status);
        goto fail_feed_markings;
    }

    // Copy out the marked document.
    mongocrypt_binary_t *marked = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(&marked_bson), marked_bson.len);
    if (!_mongo_feed_markings(ctx, marked)) {
        // Wrap error with additional information.
        _mongocrypt_set_error(ctx->status,
                              MONGOCRYPT_STATUS_ERROR_CLIENT,
                              MONGOCRYPT_GENERIC_ERROR_CODE,
                              "Consuming the generated csfle markings failed: %s",
                              mongocrypt_status_message(ctx->status, NULL /* len */));
        goto fail_feed_markings;
    }

    okay = _mongo_done_markings(ctx);
    if (!okay) {
        // Wrap error with additional information.
        _mongocrypt_set_error(ctx->status,
                              MONGOCRYPT_STATUS_ERROR_CLIENT,
                              MONGOCRYPT_GENERIC_ERROR_CODE,
                              "Finalizing the generated csfle markings failed: %s",
                              mongocrypt_status_message(ctx->status, NULL /* len */));
    }

fail_feed_markings:
    bson_destroy(&cmd_bson);
    return okay;
}

typedef struct {
    bool must_omit;
    bool ok;
} moe_result;

/**
 * @brief Removes "encryptionInformation" from cmd.
 */
static bool
_fle2_strip_encryptionInformation(const char *cmd_name, bson_t *cmd /* in and out */, mongocrypt_status_t *status) {
    bson_t stripped = BSON_INITIALIZER;
    bool ok = false;

    BSON_ASSERT_PARAM(cmd_name);
    BSON_ASSERT_PARAM(cmd);

    if (0 != strcmp(cmd_name, "explain")) {
        bson_copy_to_excluding_noinit(cmd, &stripped, "encryptionInformation", NULL);
        goto success;
    }

    // The 'explain' command is a special case.
    // 'encryptionInformation' is returned from mongocryptd and csfle nested
    // inside 'explain'. Example:
    // {
    //    "explain": {
    //       "find": "coll"
    //       "encryptionInformation": {}
    //    }
    // }
    bson_iter_t iter;
    bson_t explain;

    BSON_ASSERT(bson_iter_init_find(&iter, cmd, "explain"));
    if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
        CLIENT_ERR("expected 'explain' to be document");
        goto fail;
    }

    {
        bson_t tmp;
        if (!mc_iter_document_as_bson(&iter, &tmp, status)) {
            goto fail;
        }
        bson_init(&explain);
        bson_copy_to_excluding_noinit(&tmp, &explain, "encryptionInformation", NULL);
    }

    if (!BSON_APPEND_DOCUMENT(&stripped, "explain", &explain)) {
        bson_destroy(&explain);
        CLIENT_ERR("unable to append 'explain'");
        goto fail;
    }
    bson_destroy(&explain);
    bson_copy_to_excluding_noinit(cmd, &stripped, "explain", NULL);

success:
    bson_destroy(cmd);
    if (!bson_steal(cmd, &stripped)) {
        CLIENT_ERR("failed to steal BSON without encryptionInformation");
        goto fail;
    }
    ok = true;
fail:
    if (!ok) {
        bson_destroy(&stripped);
    }
    return ok;
}

/* Process a call to mongocrypt_ctx_finalize when an encryptedFieldConfig is
 * associated with the command. */
static bool _fle2_finalize(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    bson_t converted;
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t encrypted_field_config_bson;
    bson_t original_cmd_bson;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT(context_uses_fle2(ctx));
    BSON_ASSERT(ctx->state == MONGOCRYPT_CTX_READY);

    if (!_mongocrypt_buffer_to_bson(&ectx->encrypted_field_config, &encrypted_field_config_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson in encrypted_field_config_bson");
    }

    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &original_cmd_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson in original_cmd");
    }

    /* If marked_cmd buffer is empty, there are no markings to encrypt. */
    if (_mongocrypt_buffer_empty(&ectx->marked_cmd)) {
        /* Append 'encryptionInformation' to the original command. */
        bson_copy_to(&original_cmd_bson, &converted);
    } else {
        bson_t as_bson;
        bson_iter_t iter;

        if (!_mongocrypt_buffer_to_bson(&ectx->marked_cmd, &as_bson)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson");
        }

        bson_iter_init(&iter, &as_bson);
        bson_init(&converted);
        if (!_mongocrypt_transform_binary_in_bson(_replace_marking_with_ciphertext,
                                                  &ctx->kb,
                                                  TRAVERSE_MATCH_MARKING,
                                                  &iter,
                                                  &converted,
                                                  ctx->status)) {
            bson_destroy(&converted);
            return _mongocrypt_ctx_fail(ctx);
        }
    }

    // /* Remove the 'encryptionInformation' field. It is appended in the response
    //  * from mongocryptd or csfle. */
    // if (!_fle2_strip_encryptionInformation(command_name, &converted, ctx->status)) {
    //     bson_destroy(&converted);
    //     return _mongocrypt_ctx_fail(ctx);
    // }

    // moe_result result = must_omit_encryptionInformation(command_name, &converted, ctx->status);
    // if (!result.ok) {
    //     bson_destroy(&converted);
    //     return _mongocrypt_ctx_fail(ctx);
    // }

    // /* Append a new 'encryptionInformation'. */
    // if (!result.must_omit) {
    //     if (!_fle2_insert_encryptionInformation(ctx,
    //                                             command_name,
    //                                             &converted,
    //                                             ectx->ns,
    //                                             &encrypted_field_config_bson,
    //                                             ectx->coll_name,
    //                                             MC_TO_MONGOD,
    //                                             ctx->status)) {
    //         bson_destroy(&converted);
    //         return _mongocrypt_ctx_fail(ctx);
    //     }
    // }

    // If input command has $db, ensure output command has $db.
    bson_iter_t iter;
    if (bson_iter_init_find(&iter, &original_cmd_bson, "$db")) {
        if (!bson_iter_init_find(&iter, &converted, "$db")) {
            BSON_APPEND_UTF8(&converted, "$db", ectx->db_name);
        }
    }

    _mongocrypt_buffer_steal_from_bson(&ectx->encrypted_cmd, &converted);
    _mongocrypt_buffer_to_binary(&ectx->encrypted_cmd, out);
    ctx->state = MONGOCRYPT_CTX_DONE;

    return true;
}

static bool FLE2RangeFindDriverSpec_to_ciphertexts(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    bool ok = false;
    _mongocrypt_ctx_migrate_t *ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    if (!ctx->opts.rangeopts.set) {
        _mongocrypt_ctx_fail_w_msg(ctx, "Expected RangeOpts to be set for Range Find");
        goto fail;
    }
    if (!ctx->opts.contention_factor.set) {
        _mongocrypt_ctx_fail_w_msg(ctx, "Expected Contention Factor to be set for Range Find");
        goto fail;
    }

    bson_t with_placholders = BSON_INITIALIZER;
    bson_t with_ciphertexts = BSON_INITIALIZER;
    bson_t in_bson;
    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &in_bson)) {
        _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert input to BSON");
        goto fail;
    }

    bson_t v_doc;
    // Parse 'v' document from input.
    {
        bson_iter_t v_iter;
        if (!bson_iter_init_find(&v_iter, &in_bson, "v")) {
            _mongocrypt_ctx_fail_w_msg(ctx, "invalid input BSON, must contain 'v'");
            goto fail;
        }
        if (!BSON_ITER_HOLDS_DOCUMENT(&v_iter)) {
            _mongocrypt_ctx_fail_w_msg(ctx, "invalid input BSON, expected 'v' to be document");
            goto fail;
        }
        if (!mc_iter_document_as_bson(&v_iter, &v_doc, ctx->status)) {
            _mongocrypt_ctx_fail(ctx);
            goto fail;
        }
    }

    // Parse FLE2RangeFindDriverSpec.
    {
        mc_FLE2RangeFindDriverSpec_t rfds;

        if (!mc_FLE2RangeFindDriverSpec_parse(&rfds, &v_doc, ctx->status)) {
            _mongocrypt_ctx_fail(ctx);
            goto fail;
        }

        // Convert FLE2RangeFindDriverSpec into a document with placeholders.
        if (!mc_FLE2RangeFindDriverSpec_to_placeholders(
                &rfds,
                &ctx->opts.rangeopts.value,
                ctx->opts.contention_factor.value,
                &ctx->opts.key_id,
                _mongocrypt_buffer_empty(&ctx->opts.index_key_id) ? &ctx->opts.key_id : &ctx->opts.index_key_id,
                mc_getNextPayloadId(),
                &with_placholders,
                ctx->status)) {
            _mongocrypt_ctx_fail(ctx);
            goto fail;
        }
    }

    // Convert document with placeholders into document with ciphertexts.
    {
        bson_iter_t iter;
        if (!bson_iter_init(&iter, &with_placholders)) {
            _mongocrypt_ctx_fail_w_msg(ctx, "unable to iterate into placeholder document");
            goto fail;
        }
        if (!_mongocrypt_transform_binary_in_bson(_replace_marking_with_ciphertext,
                                                  &ctx->kb,
                                                  TRAVERSE_MATCH_MARKING,
                                                  &iter,
                                                  &with_ciphertexts,
                                                  ctx->status)) {
            goto fail;
        }
    }

    // Wrap result in the document: { 'v': <result> }.
    {
        /* v_wrapped is the BSON document { 'v': <v_out> }. */
        bson_t v_wrapped = BSON_INITIALIZER;
        if (!bson_append_document(&v_wrapped, MONGOCRYPT_STR_AND_LEN("v"), &with_ciphertexts)) {
            _mongocrypt_ctx_fail_w_msg(ctx, "unable to append document to 'v'");
            goto fail;
        }
        _mongocrypt_buffer_steal_from_bson(&ectx->encrypted_cmd, &v_wrapped);
        _mongocrypt_buffer_to_binary(&ectx->encrypted_cmd, out);
        ctx->state = MONGOCRYPT_CTX_DONE;
    }

    ok = true;
fail:
    bson_destroy(&with_ciphertexts);
    bson_destroy(&with_placholders);
    return ok;
}

static bool _finalize(mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
    bson_t as_bson, converted;
    bson_iter_t iter;
    _mongocrypt_ctx_migrate_t *ectx;
    bool res;

    BSON_ASSERT_PARAM(ctx);
    BSON_ASSERT_PARAM(out);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    if (context_uses_fle2(ctx)) {
        return _fle2_finalize(ctx, out);
    }

    if (ctx->nothing_to_do) {
        _mongocrypt_buffer_to_binary(&ectx->original_cmd, out);
        ctx->state = MONGOCRYPT_CTX_DONE;
        return true;
    }
    if (!_mongocrypt_buffer_to_bson(&ectx->marked_cmd, &as_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson");
    }

    bson_iter_init(&iter, &as_bson);
    bson_init(&converted);
    if (!_mongocrypt_transform_binary_in_bson(_replace_marking_with_ciphertext,
                                              &ctx->kb,
                                              TRAVERSE_MATCH_MARKING,
                                              &iter,
                                              &converted,
                                              ctx->status)) {
        bson_destroy(&converted);
        return _mongocrypt_ctx_fail(ctx);
    }

    bson_t original_cmd_bson;
    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &original_cmd_bson)) {
        bson_destroy(&converted);
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson in original_cmd");
    }

    // If input command has $db, ensure output command has $db.
    if (bson_iter_init_find(&iter, &original_cmd_bson, "$db")) {
        if (!bson_iter_init_find(&iter, &converted, "$db")) {
            BSON_APPEND_UTF8(&converted, "$db", ectx->db_name);
        }
    }

    _mongocrypt_buffer_steal_from_bson(&ectx->encrypted_cmd, &converted);
    _mongocrypt_buffer_to_binary(&ectx->encrypted_cmd, out);
    ctx->state = MONGOCRYPT_CTX_DONE;

    return true;
}

static void _cleanup(mongocrypt_ctx_t *ctx) {
    _mongocrypt_ctx_migrate_t *ectx;

    if (!ctx) {
        return;
    }

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;
    bson_free(ectx->ns);
    bson_free(ectx->db_name);
    bson_free(ectx->coll_name);
    _mongocrypt_buffer_cleanup(&ectx->list_collections_filter);
    _mongocrypt_buffer_cleanup(&ectx->schema);
    _mongocrypt_buffer_cleanup(&ectx->encrypted_field_config);
    _mongocrypt_buffer_cleanup(&ectx->original_cmd);
    _mongocrypt_buffer_cleanup(&ectx->marked_cmd);
    _mongocrypt_buffer_cleanup(&ectx->encrypted_cmd);
    mc_EncryptedFieldConfig_cleanup(&ectx->efc);
}

static bool _try_schema_from_schema_map(mongocrypt_ctx_t *ctx) {
    mongocrypt_t *crypt;
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t schema_map;
    bson_iter_t iter;

    BSON_ASSERT_PARAM(ctx);

    crypt = ctx->crypt;
    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    if (_mongocrypt_buffer_empty(&crypt->opts.schema_map)) {
        /* No schema map set. */
        return true;
    }

    if (!_mongocrypt_buffer_to_bson(&crypt->opts.schema_map, &schema_map)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed schema map");
    }

    if (bson_iter_init_find(&iter, &schema_map, ectx->ns)) {
        if (!_mongocrypt_buffer_copy_from_document_iter(&ectx->schema, &iter)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "malformed schema map");
        }
        ectx->used_local_schema = true;
        ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
    }

    /* No schema found in map. */
    return true;
}

/* Check if the local encrypted field config map has an entry for this
 * collection.
 * If an encrypted field config is found, the context transitions to
 * MONGOCRYPT_CTX_NEED_MONGO_MARKINGS. */
static bool _fle2_try_encrypted_field_config_from_map(mongocrypt_ctx_t *ctx) {
    mongocrypt_t *crypt;
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t encrypted_field_config_map;
    bson_iter_t iter;

    BSON_ASSERT_PARAM(ctx);

    crypt = ctx->crypt;
    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    if (_mongocrypt_buffer_empty(&crypt->opts.encrypted_field_config_map)) {
        /* No encrypted_field_config_map set. */
        return true;
    }

    if (!_mongocrypt_buffer_to_bson(&crypt->opts.encrypted_field_config_map, &encrypted_field_config_map)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "unable to convert encrypted_field_config_map to BSON");
    }

    if (bson_iter_init_find(&iter, &encrypted_field_config_map, ectx->ns)) {
        if (!_mongocrypt_buffer_copy_from_document_iter(&ectx->encrypted_field_config, &iter)) {
            return _mongocrypt_ctx_fail_w_msg(ctx,
                                              "unable to copy encrypted_field_config from "
                                              "encrypted_field_config_map");
        }
        bson_t efc_bson;
        if (!_mongocrypt_buffer_to_bson(&ectx->encrypted_field_config, &efc_bson)) {
            return _mongocrypt_ctx_fail_w_msg(ctx, "unable to create BSON from encrypted_field_config");
        }
        if (!mc_EncryptedFieldConfig_parse(&ectx->efc, &efc_bson, ctx->status)) {
            _mongocrypt_ctx_fail(ctx);
            return false;
        }
        ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
    }

    /* No encrypted_field_config found in map. */
    return true;
}

static bool _try_schema_from_cache(mongocrypt_ctx_t *ctx) {
    _mongocrypt_ctx_migrate_t *ectx;
    bson_t *collinfo = NULL;

    BSON_ASSERT_PARAM(ctx);

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;

    /* Otherwise, we need a remote schema. Check if we have a response to
     * listCollections cached. */
    if (!_mongocrypt_cache_get(&ctx->crypt->cache_collinfo, ectx->ns /* null terminated */, (void **)&collinfo)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "failed to retrieve from cache");
    }

    if (collinfo) {
        if (!_set_schema_from_collinfo(ctx, collinfo)) {
            return _mongocrypt_ctx_fail(ctx);
        }
        ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
    } else {
        /* we need to get it. */
        ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
    }

    bson_destroy(collinfo);
    return true;
}

// TODO - mcb - dedup
static bool
_permitted_for_encryption(bson_iter_t *iter, mongocrypt_encryption_algorithm_t algo, mongocrypt_status_t *status) {
    bson_type_t bson_type;
    const bson_value_t *bson_value;
    bool ret = false;

    BSON_ASSERT_PARAM(iter);

    bson_value = bson_iter_value(iter);
    if (!bson_value) {
        CLIENT_ERR("Unknown BSON type");
        goto fail;
    }
    bson_type = bson_value->value_type;
    switch (bson_type) {
    case BSON_TYPE_NULL:
    case BSON_TYPE_MINKEY:
    case BSON_TYPE_MAXKEY:
    case BSON_TYPE_UNDEFINED: CLIENT_ERR("BSON type invalid for encryption"); goto fail;
    case BSON_TYPE_BINARY:
        if (bson_value->value.v_binary.subtype == BSON_SUBTYPE_ENCRYPTED) {
            CLIENT_ERR("BSON binary subtype 6 is invalid for encryption");
            goto fail;
        }
        /* ok */
        break;
    case BSON_TYPE_DOUBLE:
    case BSON_TYPE_DOCUMENT:
    case BSON_TYPE_ARRAY:
    case BSON_TYPE_CODEWSCOPE:
    case BSON_TYPE_BOOL:
    case BSON_TYPE_DECIMAL128:
        if (algo == MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC) {
            CLIENT_ERR("BSON type invalid for deterministic encryption");
            goto fail;
        }
        break;
    case BSON_TYPE_UTF8:
    case BSON_TYPE_OID:
    case BSON_TYPE_DATE_TIME:
    case BSON_TYPE_REGEX:
    case BSON_TYPE_DBPOINTER:
    case BSON_TYPE_CODE:
    case BSON_TYPE_SYMBOL:
    case BSON_TYPE_INT32:
    case BSON_TYPE_TIMESTAMP:
    case BSON_TYPE_INT64:
        /* ok */
        break;
    case BSON_TYPE_EOD:
    default: CLIENT_ERR("invalid BSON value type 00"); goto fail;
    }

    ret = true;
fail:
    return ret;
}

// defined in mongocrypt-ctx-decrypt.c
bool _collect_key_from_ciphertext(void *ctx, _mongocrypt_buffer_t *in, mongocrypt_status_t *status);
bool _collect_K_KeyIDs(void *ctx, _mongocrypt_buffer_t *in, mongocrypt_status_t *status);

bool check_if_schema_present(mongocrypt_ctx_t *ctx) {
    BSON_ASSERT_PARAM(ctx);
    _mongocrypt_ctx_migrate_t *mctx;
    mctx = (_mongocrypt_ctx_migrate_t *)ctx;

    /* Check if there is an encrypted field config in encrypted_field_config_map
    //  */
    if (!_fle2_try_encrypted_field_config_from_map(ctx)) {
        return false;
    }

    // TODO - fix schema cache
    if (_mongocrypt_buffer_empty(&mctx->encrypted_field_config)) {
        /* Check if we have a local schema from schema_map */
        if (_mongocrypt_buffer_empty(&mctx->schema)) {
            if (!_try_schema_from_schema_map(ctx)) {
                return false;
            }
        }

        /* If we didn't have a local schema, try the cache. */
        if (_mongocrypt_buffer_empty(&mctx->schema)) {
            if (!_try_schema_from_cache(ctx)) {
                return false;
            }
        }

        /* Otherwise, we need the the driver to fetch the schema. */
        if (_mongocrypt_buffer_empty(&mctx->schema)) {
            ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
        }
    }

    return true;
}

static bool _check_for_K_KeyId(mongocrypt_ctx_t *ctx) {
    BSON_ASSERT_PARAM(ctx);

    if (ctx->kb.state != KB_DONE) {
        return true;
    }

    if (!_mongocrypt_key_broker_restart(&ctx->kb)) {
        _mongocrypt_key_broker_status(&ctx->kb, ctx->status);
        return _mongocrypt_ctx_fail(ctx);
    }

    bson_t as_bson;
    bson_iter_t iter;
    _mongocrypt_ctx_migrate_t *dctx = (_mongocrypt_ctx_migrate_t *)ctx;
    if (!_mongocrypt_buffer_to_bson(&dctx->original_cmd, &as_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "error converting original_cmd to bson");
    }
    bson_iter_init(&iter, &as_bson);

    if (!_mongocrypt_traverse_binary_in_bson(_collect_K_KeyIDs,
                                             &ctx->kb,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             ctx->status)) {
        return _mongocrypt_ctx_fail(ctx);
    }

    if (!_mongocrypt_key_broker_requests_done(&ctx->kb)) {
        _mongocrypt_key_broker_status(&ctx->kb, ctx->status);
        return _mongocrypt_ctx_fail(ctx);
    }
    return true;
}

bool handle_encryption_ready(mongocrypt_ctx_t *ctx) {
    // BSON_ASSERT(ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    // Key broke says we are ready when it gets all the keys
    // but have we done the migration yet?

    if (ctx->state == MONGOCRYPT_CTX_READY) {
        _mongocrypt_ctx_migrate_t *mctx;
        mctx = (_mongocrypt_ctx_migrate_t *)ctx;

        if (mctx->marked_cmd.len == 0) {
            if(!check_if_schema_present(ctx)) {
                return false;
            }

            // If we don't need a schema, lets migrate
            if (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS) {
                // We have all the keys and schema we need, migrate time
                // Remain in MONGOCRYPT_CTX_NEED_MONGO_KEYS as we need more keys after the migration
                return _try_run_csfle_marking(ctx);
            }
        }
    }

    return true;
}

static bool _mongo_done_keys(mongocrypt_ctx_t *ctx) {
    BSON_ASSERT_PARAM(ctx);

    (void)_mongocrypt_key_broker_docs_done(&ctx->kb);
    if (!_check_for_K_KeyId(ctx)) {
        return false;
    }

    if (!_mongocrypt_ctx_state_from_key_broker(ctx)) {
        return false;
    }

    return handle_encryption_ready(ctx);
}

bool mongocrypt_ctx_migrate_init(mongocrypt_ctx_t *ctx,
                                 const char *db,
                                 int32_t db_len,
                                 const char *coll,
                                 int32_t coll_len,
                                 mongocrypt_binary_t *doc) {
    _mongocrypt_ctx_migrate_t *ectx;
    _mongocrypt_ctx_opts_spec_t opts_spec;

    if (!ctx) {
        return false;
    }

    if (!db) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "invalid db");
    }
    if (!coll) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "invalid coll");
    }

    memset(&opts_spec, 0, sizeof(opts_spec));
    opts_spec.schema = OPT_OPTIONAL;
    if (!_mongocrypt_ctx_init(ctx, &opts_spec)) {
        return false;
    }

    ectx = (_mongocrypt_ctx_migrate_t *)ctx;
    ctx->type = _MONGOCRYPT_TYPE_MIGRATE;
    ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
    ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
    ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;
    // ctx->vtable.mongo_op_markings = _mongo_op_markings;
    // ctx->vtable.mongo_feed_markings = _mongo_feed_markings;
    // ctx->vtable.mongo_done_markings = _mongo_done_markings;
    ctx->vtable.mongo_done_keys = _mongo_done_keys;

    ctx->vtable.finalize = _finalize;
    ctx->vtable.cleanup = _cleanup;

    if (!doc || !doc->data) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "invalid document");
    }

    _mongocrypt_buffer_copy_from_binary(&ectx->original_cmd, doc);

    if (!_mongocrypt_validate_and_copy_string(db, db_len, &ectx->db_name) || 0 == strlen(ectx->db_name)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "invalid db");
    }

    if (!_mongocrypt_validate_and_copy_string(coll, coll_len, &ectx->coll_name) || 0 == strlen(ectx->coll_name)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "invalid coll");
    }

    ectx->ns = bson_strdup_printf("%s.%s", ectx->db_name, ectx->coll_name);

    if (ctx->opts.kek.provider.aws.region || ctx->opts.kek.provider.aws.cmk) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "aws masterkey options must not be set");
    }

    if (!_mongocrypt_buffer_empty(&ctx->opts.key_id)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "key_id must not be set for auto encryption");
    }

    if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "algorithm must not be set for auto encryption");
    }

    if (ctx->crypt->log.trace_enabled) {
        char *cmd_val;
        cmd_val = _mongocrypt_new_json_string_from_binary(doc);
        _mongocrypt_log(&ctx->crypt->log,
                        MONGOCRYPT_LOG_LEVEL_TRACE,
                        "%s (%s=\"%s\", %s=%d, %s=\"%s\")",
                        BSON_FUNC,
                        "db",
                        ectx->db_name,
                        "db_len",
                        db_len,
                        "cmd",
                        cmd_val);
        bson_free(cmd_val);
    }

    // Gather all the keys we may need to decrypt data
    //
    bson_t as_bson;
    bson_iter_t iter;

    /* get keys. */
    if (!_mongocrypt_buffer_to_bson(&ectx->original_cmd, &as_bson)) {
        return _mongocrypt_ctx_fail_w_msg(ctx, "malformed bson");
    }

    bson_iter_init(&iter, &as_bson);
    if (!_mongocrypt_traverse_binary_in_bson(_collect_key_from_ciphertext,
                                             &ctx->kb,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             ctx->status)) {
        return _mongocrypt_ctx_fail(ctx);
    }

    (void)_mongocrypt_key_broker_requests_done(&ctx->kb);

    if (!_check_for_K_KeyId(ctx)) {
        return false;
    }

    if (!_mongocrypt_ctx_state_from_key_broker(ctx)) {
        return false;
    }

    return handle_encryption_ready(ctx);
}
