def decrypt(x):
    pass

def index(x):
    pass

def deindex(x):
    pass

def encrypt(x):
    pass

def index_marking(x):
    pass

def encrypt_marking(x):
    pass

def migrateDocument(OrigDoc, EncryptedFields, DecryptFields):
    tokens_remove = []
    tokens_add = []

    for field in OrigDoc:
        if field.name in EncryptedFields:
            ef = EncryptedFields[field.name]

            # If the field is the expected final state, nothing to do
            if field.encryption == ef.encryption:
                continue

            # Decrypt the value so we can re-encrypt it
            temp_value = None
            if field.indexed:
                (temp_value, tokens) = deindex(field.value)
                tokens_remove.append(tokens)
            elif field.encrypted:
                temp_value = decrypt(field.value)
            else:
                temp_value = field.value


            if ef.indexed:
                (field.value, tokens) = index(temp_value)
                tokens_add.append(tokens)
            elif ef.encrypted:
                field.value = encrypt(field.value)
            else:
                assert False # Cannot not happen

        elif DecryptFields and field.encryption:
            # Only decrypt if specifically asked
            if field.indexed:
                (temp_value, tokens) = deindex(field.value)
                tokens_remove.append(tokens)
            elif field.encrypted:
                temp_value = decrypt(field.value)

    # Fix up __safeContent__
    OrigDoc.__safeContent__.push(tokens_add)
    OrigDoc.__safeContent__.remove(tokens_remove)


def migrateDocumentWithMarkings(OrigDoc, EncryptedFields, DecryptFields):
    for field in OrigDoc:
        if field.name in EncryptedFields:
            ef = EncryptedFields[field.name]

            # If the field is the expected final state, nothing to do
            if field.encryption == ef.encryption:
                continue

            # Decrypt the value so we can re-encrypt it
            temp_value = None
            if field.indexed:
                (temp_value, tokens) = deindex(field.value)
            elif field.encrypted:
                temp_value = decrypt(field.value)
            else:
                temp_value = field.value

            # Encrypt the value
            if ef.indexed:
                (field.value, tokens) = index_marking(temp_value)
            elif ef.encrypted:
                field.value = encrypt_marking(field.value)
            else:
                assert False # Cannot not happen

        elif DecryptFields and field.encryption:
            # Only decrypt if specifically asked
            if field.indexed:
                (temp_value, tokens) = deindex(field.value)
            elif field.encrypted:
                temp_value = decrypt(field.value)

    # Generate update with replace or set


# Test cases
# Change keys on migration
# N x N tests - encrypt as A, migrate to B, verify-type(B), decrypt(B)



# States
# 1. Optional: MONGOCRYPT_CTX_NEED_MONGO_COLLINFO (simliar to encrypt)
# 2. MONGOCRYPT_CTX_NEED_MONGO_KEYS - need keys to decrypt (similar to decrypt)
# 3. MONGOCRYPT_CTX_NEED_MONGO_MARKINGS - migrate document (similar to encrypt), internal
# 4. MONGOCRYPT_CTX_NEED_MONGO_KEYS - need more keys (similar to encrypt)
# 5. MONGOCRYPT_CTX_READY - read to encrypt (similar to encrypt/decrypt)


# LocalKey - 96 bytes - all zero
# Keys - here - test/data/keys/12345678123498761234123456789012-local-document.json
#

# Test generation
# Need to generate documents
# Test Case
# 1. Files
#   a. Input Document
#   b. Input EFC
# 2. Common Key Documents
# 3. Output document
#
# Alternative
# 1. Generate input files
#    a. Input Doc
#    b. Input EFC
# 2. Common Key Documents
# 3. Migration EFC Document
# 4. Output Document

# Schema Tests
# 1. Local Schema
# 2. Remote schema