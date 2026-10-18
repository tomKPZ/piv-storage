# Experimental auxiliary blob format v1

This is an experimental composition of standard library primitives, not a
reviewed deniable storage format. It implements one fixed-size record covering
the whole carrier. It intentionally sacrifices incremental update efficiency
to avoid a hidden allocator, multi-record transactions and exposed metadata.

## Keys and byte layout

Both primary and hidden keys are independent supplied 32-byte high-entropy files.
Password handling is out of scope. The hidden key does not derive from the
primary key; reading hidden data does not require the primary key.

Carrier = concatenation of 12-byte IVs in primary logical-sector order. Given C
carrier bytes, payload capacity is C - 64. Reject carriers shorter than 64 bytes.

    carrier = salt[32] || ciphertext[C-48] || Poly1305 tag[16]
    plaintext = encrypted_magic[8] || length_LE64[8] || payload || zero_padding
    encrypted_magic = ASCII PIVBLB01

The plaintext has exactly C - 48 bytes. There is no public magic, length, version,
or constant padding in the carrier. Padding is inside encryption. The 32-byte
salt is uniformly random and regenerated on every pack, including repeated
payloads. The rest is ChaCha20-Poly1305 output from the maintained cryptography
library. No custom cipher, MAC, PRNG, or KDF primitive is implemented.

For a volume UUID encoded as canonical ASCII and primary size V:

    AAD = ASCII("pivstore/blob/v1\0") || UUID || NUL || LE64(V) || LE64(4096)
    subkey = HKDF-SHA256(hidden_key, salt, info=AAD, length=32)
    ciphertext, tag = ChaCha20Poly1305(subkey, nonce=12 zero bytes, plaintext, AAD)

The fixed AEAD nonce is used only with a newly derived subkey. Salt repetition
under a hidden key would repeat that subkey/nonce; require fresh CSPRNG entropy
for every operation and reject unsupported RNG workflows. Random 256-bit salts
make accidental repeats negligible at prototype scale. This does not make
snapshot rollback safe for the primary GCM key.

Binding UUID/size in AAD makes cross-volume transplantation fail authentication
when UUIDs differ. Same-UUID clones remain indistinguishable without trusted
external state; writing independent branches is unsupported. Do not change the
UUID of an image containing a v1 blob and expect extraction to continue working.

## Why the encoding is expected to look random

The salt is random. With a high-entropy hidden key, the derived key is assumed
pseudorandom; ChaCha20 ciphertext is assumed pseudorandom and its one-time
Poly1305 tag is masked by secret per-message material. The fixed plaintext
header and padding therefore do not appear directly in the carrier. This is a
design argument under standard primitive assumptions, not a proof that every
joint carrier distribution or adversarial experiment is indistinguishable.
Ordinary AEAD confidentiality alone would not justify this claim for arbitrary
serialization. Independent cryptographic review remains outstanding.

## Primary nonce policy

Every pack randomizes the entire carrier and rewrites every primary sector.
Generate the entire envelope before primary encryption. Reject envelopes whose
12-byte slots collide with any current IV or with one another, regenerating the
envelope before any primary encryption occurs. The writer also independently
checks this property. Rejection is negligible for the small tested profile.

Only current IV collisions can be checked locally. Historical primary nonce
usage is not reconstructible from the image. Require a known disposable lineage,
no ordinary primary writes, no branching clones, no old-IV restoration into
changed primary data, fresh entropy, and an externally managed conservative
primary-key encryption budget. The CLI is a research tool and does not enforce
that external lifetime budget. Repeating a failed pack starts with new entropy;
never resume by replaying cached IV plans.

## Updates, extraction and limitations

Primary writes are copy-output operations. Authenticate the entire input, build
the envelope, make a private temporary copy, reencrypt every affected primary
sector with exact Linux AAD, authenticate/hash the complete output, fsync it,
and publish with an exclusive hard link followed by directory fsync. Existing
destinations are never replaced. Partial copies are removed on caught errors;
process/power crashes can leave private .partial files. A publication followed
by an fsync error can leave a valid but unacknowledged output; do not auto-retry
onto that destination. This assumes local filesystem hard-link/fsync semantics,
not arbitrary network filesystems or hardware power-failure guarantees.

Extraction authenticates the hidden record and validates its encrypted header,
length and zero padding before publishing plaintext to a private output file.
Wrong keys, uninitialized carriers and corruption are intentionally reported
without claiming which occurred. Same-volume rollback remains possible. A
primary key holder can destroy the payload. No redundancy or incremental update
support exists, and every pack has roughly one full-primary-volume write cost.
