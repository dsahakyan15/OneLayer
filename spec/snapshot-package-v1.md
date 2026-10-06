# Snapshot Package V1

Status: frozen for Gate E0.

`SnapshotPackageV1` is a deterministic-CBOR envelope for one encrypted registry snapshot. It uses AES-256-GCM with a random 32-byte DEK per snapshot. The DEK is wrapped by a 32-byte recovery KEK using a separate AES-256-GCM domain.

The canonical map contains `formatVersion=1`, `registryId`, `snapshotId` (16 bytes), `snapshotVersion`, `encryptionAlgorithm="AES-256-GCM"`, `chunkSize`, `totalChunks`, ordered `chunks`, `keyWrapAlgorithm="AES-256-GCM"`, `wrappedDek` (32 bytes), `wrappedDekNonce` (12 bytes), `wrappedDekAuthTag` (16 bytes), `keyEncryptionVersion`, `plaintextHash` (32 bytes), and `ciphertextHash` (32 bytes).

Each chunk contains `chunkIndex`, `nonce` (12 bytes), `ciphertext`, and `authTag` (16 bytes). Chunk indexes are exactly `0..totalChunks-1`. All plaintext chunks except the last are exactly `chunkSize` bytes. `chunkSize` and `totalChunks` are positive `u32` values.

```text
chunk_aad = "ONELAYER:SNAPSHOT:CHUNK:V1"
          || u16_be(byte_len(UTF8(NFC(registry_id)))) || UTF8(NFC(registry_id))
          || snapshot_id || u64_be(snapshot_version)
          || u32_be(chunk_size) || u32_be(chunk_index) || u32_be(total_chunks)
          || plaintext_hash

dek_wrap_aad = "ONELAYER:SNAPSHOT:DEKWRAP:V1"
             || u16_be(byte_len(UTF8(NFC(registry_id)))) || UTF8(NFC(registry_id))
             || snapshot_id || u64_be(snapshot_version)
             || u16_be(byte_len(UTF8(NFC(key_encryption_version))))
             || UTF8(NFC(key_encryption_version))
```

The chunk nonce is twelve bytes: eight zero bytes followed by `u32_be(chunk_index)`. This is safe only because every snapshot receives a new CSPRNG-generated DEK. `wrappedDekNonce` is CSPRNG-generated for each wrapping operation.

`ciphertextHash = SHA256(deterministic_cbor(package_without_ciphertextHash))`. Restore verifies this hash before unwrapping the DEK. It then authenticates every chunk and releases no plaintext until all tags and the assembled `plaintextHash` pass.

The recovery KEK is divided 3-of-5. Shares reconstruct only the KEK; snapshot DEKs remain wrapped inside their packages.
