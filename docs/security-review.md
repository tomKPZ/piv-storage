# Security and threat-model review

Internal source-led review, 2026-10-19, of runtime/format revision 1f4c94f.
This is a bounded engineering assessment, not an independent cryptographic audit
or certification. No new exploitable implementation defect was identified in
the reviewed paths; this is not an assertion that the driver has no defects.
The construction's whole-encoding pseudorandomness still needs external review.

## Assets, assumptions and observers

Assets are primary plaintext integrity, hidden plaintext confidentiality and
per-block authentication, and the proposed concealment of hidden-data existence.
These are separate claims. Assume independently generated high-entropy primary
and 32-byte hidden keys, trusted setup/kernel/crypto implementations, seeded
non-rewound randomness, exclusive coordinated writes and a supported layout.
Key length validation cannot establish entropy or independence. The primary
passphrase protects a LUKS keyslot; the hidden key is direct key material.

| Observer or adversary | Supported reasoning and limits |
| --- | --- |
| Passive reader of current IV slots, without hidden key | The encoding is expected to be pseudorandom under the composition assumptions below. This has not been proved or independently reviewed. |
| Reader of a complete raw disk image | Also sees LUKS configuration, journal and residual storage. A single image can contain write history. No full-image indistinguishability guarantee follows from current-IV randomness. |
| Reader with primary key but no hidden key | Can authenticate/decrypt primary sectors and inspect IVs. Primary-key disclosure alone is not intended to reveal the independent hidden key. No coercion or alternative-opening protocol is implemented. |
| Snapshot, journal-history, known-workload or live-I/O observer | Extra group reencryption is observable; matched controls already demonstrate it. No deniability against these observers is claimed. |
| Active raw-storage attacker without keys | Can destroy data and replay old valid tuples/records. Authentication rejects altered protected content, subject to cipher assumptions; it does not provide availability, freshness or authenticated metadata/journal ordering. |
| Holder of primary key or decoy write access | Can destroy hidden data through uncoordinated writes; cannot be relied upon to preserve it. Correct hidden-key provisioning is required for coordinated preservation. |
| Holder of hidden-device access or hidden key | Receives plaintext or can decrypt/forge hidden records. Filesystem permissions are the access-control boundary. |
| Administrator, compromised kernel or live-memory reader | Outside confidentiality/concealment guarantees: both plaintext views, keys, module names and mappings are present. |

Mounted public block devices expose plaintext. Root-only control ioctls and
mapping identity checks prevent accidental misuse; they do not isolate data
from a hostile administrator. A hidden filesystem's superblocks and access
patterns are concealed only beneath its block interface. There is no forward
secrecy, secure deletion, key erasure guarantee, authenticated boot or protection
against malicious storage firmware. VM shares, keys, snapshots, swap, crash dumps,
Python objects and installed tools are separate operational evidence. Test keys
and deliberately cheap fixture keyslots are unsuitable for real data.

Out of scope by user decision (2026-10-20): multi-snapshot observers, rollback
resistance and coercion-resistant alternative hidden openings. The latter would
only move coercion from one hidden key to the next. Retained single-image
journal history remains in scope (see below).

## Encoding review

The exact bytes are specified in [hidden-format.md](hidden-format.md).
`pn_derive` implements HKDF extract with HMAC-SHA256 keyed by the public salt and
input hidden key, then its single expand block over AAD followed by byte 1.
That matches [RFC 5869 sections 2–3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2).
The Python reference delegates this operation to cryptography's HKDF.

Each encoding uses a fresh 256-bit salt and a derived ChaCha20-Poly1305 key,
with a fixed zero nonce. Uniqueness is needed for each *key/nonce pair*, not
across different keys. [RFC 8439 section 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4)
explains the damage from repeated nonces under one key. Here a repeated salt at
the same context/address repeats the derived key: different plaintexts then
reuse a stream and a Poly1305 one-time key. For r independent salts at one
context/address, salt-collision probability is approximately r(r-1)/2^257;
this is only one failure term, excluding KDF/AEAD advantages and derived-key
collisions. RNG snapshots/clones can make the birthday model inapplicable.
No salt history or deterministic uniqueness enforcement exists.

The intended concealment argument requires the *joint distribution* of salt,
ciphertext and tag to be pseudorandom for repeated/chosen plaintexts, valid and
invalid records and exposed AAD, under many keys derived from one root key.
Ordinary AEAD confidentiality/authenticity alone does not establish that property.
The encrypted magic, state and fixed invalid-marker zeros introduce no public
marker, but are known plaintext for a key guess. Primary IVs come from slices of
this entire encoding; their pseudorandomness is an additional assumption relative
to ordinary independent random IV generation. Local duplicate rejection slightly
conditions the distribution and is not an exact match to the stock sampler.
Statistical summaries in [detectability.md](detectability.md) cannot prove this
composition secure. No primitive or format change is justified by these tests.

AAD binds canonical UUID, primary capacity/sector size and hidden block address.
It does not bind a timestamp, generation, primary key, primary cipher, primary
plaintext or physical disk identity. Correctly transporting an entire record
with the same context/address to a clone remains valid. Cipher conversion with
identical UUID/geometry is not a separate hidden cryptographic domain. Use
independent hidden keys for unrelated volumes; the context is not an anti-cloning
mechanism. Changing UUID/geometry makes existing hidden records unavailable.

Any candidate hidden key can be checked offline using one record's tag and
known plaintext structure. HKDF is not a password-hardening function. Neither
key commitment nor producing convincing alternative valid hidden openings under
other keys is an implemented property. A wrong key looks unavailable to this
interface; it can still destroy correct-key records on a later decoy write.

## Nonce and data budgets

Primary nonce uniqueness is global per primary key across addresses, devices,
clones, stock writes and time. Adding address AAD does not permit nonce reuse.
Assuming pseudorandom IVs, the approximate collision term is q(q-1)/2^97 for
96 bits and q(q-1)/2^129 for 128 bits. At q=2^32 these are about 2^-33 and 2^-65.
They are not complete confidentiality or forgery bounds.

For random-IV AES-GCM, [NIST SP 800-38D section 8.3](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=51288)
limits authenticated-encryption invocations to 2^32 across all instances with
the given key. Sections 8 and Appendix B also discuss IV failure probability,
aggregate data and verification attempts. The prototype's counter is per owner,
starts after earlier stock encryptions, and resets on recreation. It therefore
**does not enforce the GCM key-lifetime requirement**. It is not a safe remaining
write allowance. Failed preparations/retries that reach encryption consume
budget even if no ciphertext is finally installed; applying an exact prepared
tuple or flushing it does not perform another encryption.

A single flat invocation counter is not a full security policy for any supported
cipher. The 2^32 diagnostic cap also applied to ChaCha and original AEGIS-128 is
not a derived cipher-specific bound or approval for that many writes. The
128-bit AEGIS IV lowers the collision term but does not establish stronger
end-to-end security; original AEGIS-128 is not AEGIS-128L, and bounds for the latter
must not be transplanted. Rekey tooling and a reviewed, per-cipher aggregate
policy are still absent. Without trusted external lifetime knowledge, this
stateless image cannot certify that its key is safe to continue using. Do not
add a distinguishable on-disk ledger to solve that under the current scope.

## Integrity, journal and implementation boundaries

Source paths reviewed: `pivstore/{records,format,sector,profile,blocks,kernel_api,
kernel_owner}.py`, `kernel/{piv-native.inc,piv-control.inc,dm-crypt-piv.patch}`,
and the staged pinned dm-crypt AEAD helper in
`vendor/kernel-build/batch-001/dm-crypt.c`. Source/package hashes and fixture
provenance remain in environment/ and the existing development/layout notes.

The primary helper retains Linux sector-address/IV AAD and tag/IV layout.
`piv_load` authenticates before primary modification. PREPARE consumes encryption
invocations; APPLY authenticates the candidate and checks the expected old IV.
Native updates prepare all tuples before applying any, serialize through the
owner mutex and use the lower journal. Hidden reads copy to the caller only
after complete record authentication; larger decoy reads likewise copy only on
success. Expected-IV checks prevent stale local updates, not rollback by an
external writer. Context/size/profile bounds are validated; this was source
inspection, not exhaustive fuzzing, formal verification or a memory-safety audit.

[Linux dm-integrity documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html)
describes journaling sector data with tags and the history visible in an
unencrypted journal. Our selected journal has neither encryption nor a MAC.
Commit IDs detect incomplete sections, not maliciously fabricated history.
Primary AEAD checks do not authenticate all superblock, LUKS configuration or
journal metadata, nor guarantee valid replay ordering. Replaying a valid sector
at its original address can pass primary authentication. Hidden authentication
rejects torn fragments, but an old whole block or different-time valid blocks
can pass. Lower replay can mutate storage before native setup's full scan;
activation is not a promise to reject hostile storage before any modification.

The journal can retain older carrier fragments; enough correctly associated
fragments plus a hidden key may recover older records. This is a reason not to
claim secure deletion or single-image history exclusion. No journal-forensic
reconstruction experiment or active malicious-replay test was performed here.
Multi-sector hidden writes remain non-atomic. EIO may follow a partial mutation;
FUA/flush completion does not create a whole-record transaction or prove physical
hardware durability. A hostile device can always deny service.

Kernel temporary buffers/pages use explicit sensitive frees/wipes in reviewed
paths. Keys also live in crypto transforms and userspace process/subprocess
memory; Python immutable copies are not reliably wiped. Setup reads a privileged
key-containing dm table into memory and sends it through stdin, not argv/logs.
This is not resistance to root, dumps, ptrace or physical memory acquisition.
The private dm-crypt fork also requires ongoing upstream security maintenance;
exact source compatibility does not establish that a pinned kernel is free of
vulnerabilities. Broad deployment is still out of scope.

## Journal history and the decoy-key holder

Added 2026-10-19 from source/layout reasoning; no journal-forensic experiment
was performed. The supported journal retains recent sector writes (ciphertext,
tag, IV and plaintext sector number) until wraparound. The 128 MiB fixtures had
1,848 stock journal sectors (about 0.9 MiB), so at 4096-byte sectors only a few
recent 192 KiB group rewrites can remain. A single raw image therefore carries a
short write history even though multi-snapshot observers are out of scope.

| Observer | What retained journal entries can show |
| --- | --- |
| No keys | Recently rewritten sector numbers and old IVs; contiguous whole-group rewrites. |
| Decoy key holder (coercion case) | Old and new primary plaintext for those sectors: whole carrier groups reencrypted with unchanged plaintext, unusual for ordinary filesystems. |
| Hidden key holder | Potentially older versions of hidden records from correctly associated fragments. |

Every coordinated decoy write also refreshes its full group, so this pattern
indicates use of the prototype rather than proving hidden data exists. In many
coercion settings that distinction offers little protection. Candidate
mitigations, none implemented or tested: formatting with stock
`--integrity-no-journal` (removes on-disk history; torn writes then return
decoy EIO, as for stock users of that option); journal encryption (hides sector
numbers only from keyless observers, and is unverified for LUKS2 AEAD in
cryptsetup); and a record format that re-randomizes only touched IVs, reducing
the group footprint at a capacity cost. These need design review before any claim.

## Disposition and verification

No new kernel/runtime change was made for this review. The important findings
are limitations, now explicit in the claims rather than silently treated as
solved: full-image journal history, unenforced lifetime budgets, offline guessing,
replay acceptance and trusted-host/key-provisioning requirements. External
cryptographic review of the entire encoding is still required before stronger
concealment claims. Active metadata/journal attack fixtures and debug-kernel
memory/lifecycle testing remain separate engineering work.

New host regressions demonstrate that old valid same-address records and mixed
valid block epochs are accepted, while existing tests reject address/context/key
mismatch and every carrier-aligned torn boundary. A deterministic entropy-failure
test demonstrates plaintext-XOR leakage from repeated salt at one address. These
are executable limits of the design, not attacks defeating its stated freshness
or entropy assumptions. Run with the ordinary host suite; no guest execution or
new hardware durability/security evidence is implied by this documentation task.
