# Incremental hidden record format

The native paired-block backend uses independently encrypted 32-sector records.
The earlier userspace NBD/FUSE implementation and its commands have been retired;
Git history retains its design and test evidence. See [native usage](native-blocks.md).

Each record consumes 384 carrier bytes (32 persistent 12-byte IVs) and stores
320 payload bytes under the codec in hidden-format.md: salt, HKDF-SHA256 and
ChaCha20-Poly1305, with framing/padding encrypted. Record AAD includes volume
identity, the incremental-v2 domain and logical record index. There is no public
carrier magic. Record 0 stores an authenticated eight-byte hidden length; other
records hold fixed-size payload chunks. Trailing payload padding must be zero.
The native block capacity is the full payload capacity rounded down to 512 bytes.
Remaining primary sectors carry no hidden record.

NativeBootstrap handles only first adoption and unfinished bootstrap recovery.
It preserves the historical encrypted ledger and pending-v2 tuple format,
reserves nonces before encryption, persists the full plan before mutation and
replays exact tuples without encryption. It authenticates originals and never
changes primary plaintext. After native READY, native.log owns all subsequent
history; bootstrap state must not be used to reconstruct missing adopted history.
There is no file-like read/write/truncate service or primary-write frontend in
this component.

The read-only records.decode_image path independently extracts a completed native
volume using only its hidden key. The carrier encoding is unchanged by frontend
retirement. Authentication does not provide independent cross-record freshness
or rollback resistance; recovery depends on surviving external state.
