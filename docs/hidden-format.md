# Hidden block format v3 (removed)

Format v3 (one 512-byte hidden block per 576-byte carrier group: 48 IVs for
AES-GCM/ChaCha20-Poly1305 or 36 for AEGIS-128, with ChaCha20-Poly1305 records
and encrypted invalid markers) was removed on 2026-10-21 together with the
12-byte-IV primary profiles, by user decision. The only hidden format is
[format v4](format-v4.md). The v3 specification, codec and evidence remain in
Git history (for example commit 107f227).
