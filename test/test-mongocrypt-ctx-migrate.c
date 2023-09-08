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

#include <mongocrypt-marking-private.h>

#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt-crypto-std-hooks.h"
#include "test-mongocrypt.h"

// Shared implementation for insert and find tests
typedef struct {
    _mongocrypt_buffer_t buf;
    int pos;
} _test_rng_data_source;

static bool _test_rng_source(void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status) {
    _test_rng_data_source *source = (_test_rng_data_source *)ctx;

    if ((source->pos + count) > source->buf.len) {
        TEST_ERROR("Out of random data, wanted: %" PRIu32, count);
        return false;
    }

    memcpy(out->data, source->buf.data + source->pos, count);
    source->pos += count;
    return true;
}

static void _test_encrypt_fle2_encryption_placeholder(_mongocrypt_tester_t *tester,
                                                      const char *data_path,
                                                      _test_rng_data_source *rng_source,
                                                      const char *finalize_failure) {
    mongocrypt_t *crypt;
    char pathbuf[2048];

#define MAKE_PATH(mypath)                                                                                              \
    ASSERT(snprintf(pathbuf, sizeof(pathbuf), "./test/data/%s/%s", data_path, mypath) < sizeof(pathbuf))

    if (!_aes_ctr_is_supported_by_os) {
        printf("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    /* Create crypt with custom hooks. */
    {
        /* localkey_data is the KEK used to encrypt the keyMaterial
         * in ./test/data/keys/ */
        char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
        mongocrypt_binary_t *localkey;

        crypt = mongocrypt_new();

        mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);
        localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hooks(crypt,
                                                 _std_hook_native_crypto_aes_256_cbc_encrypt,
                                                 _std_hook_native_crypto_aes_256_cbc_decrypt,
                                                 _test_rng_source,
                                                 _std_hook_native_hmac_sha512,
                                                 _std_hook_native_hmac_sha256,
                                                 _error_hook_native_sha256,
                                                 rng_source /* ctx */),
                  crypt);

        MAKE_PATH("encrypted-field-map.json");
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE(pathbuf)), crypt);
        mongocrypt_binary_destroy(localkey);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }

    /* Create encryption context. */
    mongocrypt_ctx_t *ctx;
    {
        ctx = mongocrypt_ctx_new(crypt);
        MAKE_PATH("doc.json");
        ASSERT_OK(mongocrypt_ctx_migrate_init(ctx, "db", -1, "test", -1, TEST_FILE(pathbuf)), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        /* Use a FLE2EncryptionPlaceholder obtained from
         * https://gist.github.com/kevinAlbs/cba611fe0d120b3f67c6bee3195d4ce6. */
        MAKE_PATH("mongocryptd-reply.json");
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE(pathbuf)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

#define TEST_KEY_FILE(name) TEST_FILE("./test/data/keys/" name "123498761234123456789012-local-document.json")

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_KEY_FILE("12345678")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_KEY_FILE("ABCDEFAB")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }
#undef TEST_KEY_FILE

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        bool ok = mongocrypt_ctx_finalize(ctx, out);
        if (finalize_failure) {
            ASSERT_FAILS_STATUS(ok, ctx->status, finalize_failure);
        } else {
            ASSERT_OK(ok, ctx);
            MAKE_PATH("encrypted-payload.json");
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE(pathbuf), out);
        }
        mongocrypt_binary_destroy(out);
    }
#undef MAKE_PATH

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* First 16 bytes are IV for 'p' field in FLE2InsertUpdatePayload
 * Second 16 bytes are IV for 'v' field in FLE2InsertUpdatePayload
 */
#define RNG_DATA                                                                                                       \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"

static void _test_migrate_fle2_insert_payload(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;

    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};

    source.pos = 0;
    _test_encrypt_fle2_encryption_placeholder(tester, "fle2-insert", &source, NULL);
}


void _mongocrypt_tester_install_ctx_migrate(_mongocrypt_tester_t *tester) {

    INSTALL_TEST(_test_migrate_fle2_insert_payload);
}
