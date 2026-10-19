# Stateless hidden block format v3

One logical 512-byte hidden block uses 576 consecutive carrier bytes, in
logical primary-sector order. Let group=576/IV_bytes: 48 primary sectors for
AES-GCM/ChaCha20-Poly1305 (12-byte IV), or 36 for original AEGIS-128 (16-byte IV).
Hidden block i uses primary sectors group*i through group*i+group-1. There is no header record, allocator, length field or public magic.
Capacity is floor(primary_sectors/group)*512. Incomplete tail primary sectors carry
no hidden block and receive ordinary fresh random IVs on coordinated writes.
Primary sector size is 512 or 4096 bytes; it changes the primary span of one
record (24 KiB or 192 KiB), not its encoding or logical hidden-block size.
AEGIS-128 instead spans 18 KiB or 144 KiB per record. Every byte of its
16-byte IV is a carrier byte; there is no stored padding or discarded IV suffix. The independently keyed hidden AEAD and context are
unchanged; volume identity and geometry bind the records, and the native owner
authenticates primary data under the selected primary cipher before access.

```
carrier[576] = salt[32] || ciphertext[528] || Poly1305_tag[16]
plaintext[528] = "PIVBLK03"[8] || state_LE64[8] || data[512]
context = "pivstore/volume/v3\0" || canonical_UUID_ASCII || NUL
          || LE64(primary_bytes) || LE64(primary_sector_size)
AAD = context || "/block/" || LE64(hidden_block_index)
subkey = HKDF-SHA256(hidden_key, salt, info=AAD, length=32)
ciphertext, tag = ChaCha20Poly1305(subkey, nonce=12 zero bytes, plaintext, AAD)
```

State 0 means valid data. State 1 with zero data is an encrypted invalid marker;
all nonzero states and malformed plaintexts are unavailable to readers. The
kernel emits canonical state 1 only when a decoy write must refresh an absent,
damaged, wrong-key or previously invalid hidden record. No cleartext invalid bit
is stored. Full 512-byte hidden writes replace unavailable records with valid
data; they still authenticate all original primary sectors first.

Every encoding chooses a new uniform 256-bit salt from the seeded kernel CRNG.
The fixed ChaCha nonce is used with a newly derived key. Python cryptography is
the independent decoder/reference encoder; Linux crypto implements the data path.
The whole 576-byte encoding is generated before primary encryption. Slots are
checked against each other and all IVs replaced in that update; a collision
regenerates the encoding up to 16 times. This check cannot reconstruct historical
nonce use or guarantee global primary-key uniqueness. All successful and failed
primary encryption attempts consume the externally managed lifetime budget.

The random salt and assumed pseudorandom derived-key ChaCha ciphertext and
masked Poly1305 tag motivate pseudorandomness of the stored encoding. The magic,
state and invalid-marker zeros are encrypted. This is a composition argument,
not independent cryptographic review or a proof of disk indistinguishability.
Stock journal timing and snapshots can reveal write patterns.

All 512 bytes authenticate together. Partial old/new record assembly fails
except with negligible forgery probability. Old valid whole blocks can still be
replayed, and valid blocks at different addresses can belong to different times.
UUID/address binding rejects transplantation, but same-UUID clones and rollback
have no external freshness anchor. Cross-sector recovery is deliberately absent.
No prior hidden formats are decoded. Changing UUID or primary geometry changes the AAD. Record v3 bytes/context
are unchanged; the validated primary profile determines slot width/group size.
