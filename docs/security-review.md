# Security and threat-model review

> [!NOTE]
> 2026-10-21: format v3 and the AES-GCM / ChaCha20-Poly1305 profiles were
> removed; 2026-10-22: XTS + HMAC authenc profiles were added beside the default
> AEGIS-128 ([format v4](format-v4.md) needs 16-byte random IVs). Results below that mention them are historical evidence for
> the code at that time; current runs are recorded in commit messages.

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

## Encoding review (format v4)

The exact bytes are specified in [format-v4.md](format-v4.md). Record, keyslot
and directory keys come from HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html))
over the master key (or a keyslot KEK) with the public v4 context as salt and a
`"pivstore/v4/" || label` info string (`pn_hkdf`, cross-checked against the
Python decoder's cryptography HKDF). A keyslot KEK is a 32-byte key file or a
passphrase through Argon2id (default; m = 64 MiB, t = 3, p = 4) or scrypt
(N = 2^17, r = 8, p = 1); the KDF is not recorded, which adds no secrecy.

Each hidden block is a deterministic SIV record: a 16-byte HMAC-SHA256 tag over
context, group, generation and data, and ChaCha20 under `tag[0:12]`. Identical
data at the same address therefore gives an identical record payload; freshness
of the stored bytes comes from the outer encoding, where every 16-byte IV is an
LRW-AES output on (10 fresh random bytes || 6 payload bytes) tweaked by the
primary sector. Per-sector nonce uniqueness rests on those 80 random bits
(n²/2^81 for n rewrites of one sector; see the budget section below).

The concealment argument requires the joint distribution of every stored IV,
for chosen and repeated hidden data, valid and damaged records and the public
context, to be indistinguishable from stock random IVs without the hidden key.
It rests on LRW/AES tweakable-PRP security plus the SIV layer; local collision
rejection slightly conditions the distribution. This is a design argument
without external review. Statistical summaries in [detectability.md](detectability.md)
cannot prove it.

The context binds the canonical UUID, primary capacity, sector size, the A/B
layout and the record group. It does not bind a timestamp, the primary key or
the physical disk: a whole record copied to a clone with the same context stays
valid, and whole-record rollback is accepted (out of scope). Fragments from
different versions fail the tag except with probability 2^-128. Raw stored IVs
of sectors that fail primary authentication feed only this SIV-checked decoding
(keyslots, the directory and hidden reads), never published output.

Keyslots give a fast offline key check: a passphrase KEK is exactly as guessable
as its KDF cost allows, so key files remain the high-entropy option. Neither key
commitment nor convincing alternative openings under other keys is provided. A
wrong key is refused by the wrong-key guard instead of being allowed to destroy
records on a later decoy write. The keyslot directory reveals keyslot outer keys
only to holders of the master key. A hidden write re-encrypts its 90 primary
sectors with unchanged plaintext and remains visible to a decoy-key holder with
journal history.

## Nonce and data budgets (AEGIS-128 lifetime guidance)

Primary nonce uniqueness is global per primary key across addresses, devices,
clones, stock writes and time. Adding address AAD does not permit nonce reuse;
under original AEGIS-128 a repeated (key, nonce) pair leaks plaintext
relations and enables state recovery/forgery, so treat it as a key compromise.

**What consumes nonces.** Every primary encryption draws one 16-byte IV:
stock dm-crypt writes (one per written sector), native decoy writes (exactly
one per written primary sector), hidden writes (90 per 512-byte hidden block,
one record; A/B writes one slot), keyslot/directory updates and initialization
(28 + 90 + 90 × records). Failed preparations that reached encryption count;
exact replays do not.

**Profile matters.** Under original AEGIS-128 a repeated (key, IV) pair leaks
plaintext relations and allows state recovery and forgery. Under the XTS + HMAC
profiles the IV is the XTS tweak and authentication is HMAC over sector, IV and
ciphertext: a repeated IV at the same sector only reveals which 16-byte blocks of
the two plaintexts are equal, and forgery still requires the HMAC key. The same
collision terms apply, but their consequence is much milder for XTS + HMAC.
Serpent/Twofish images are authenticated but not decrypted by the host
diagnostics.

**Two collision terms.**

| Term | Model | Example values |
| --- | --- | --- |
| Whole key, IVs at different sectors | about q²/2^129 (uniform 128-bit IVs) | q = 2^32: 2^-65; 2^40: 2^-49; 2^48: 2^-33 |
| One sector rewritten n times (v4 fragments carry 80 random bits) | about n²/2^81 | n = 2^20: 2^-41; 2^24: 2^-33; 2^32: 2^-17 |

The per-sector term dominates for hot sectors. Sectors outside records (tail) and stock
writes use fully random 128-bit IVs and follow the first row only.

**Guidance (not a proven bound).** Choose a per-key budget for the deployment,
for example at most 2^40 total primary encryptions and at most 2^24 rewrites of
any one sector (both around 2^-33 to 2^-49 collision probability), and rekey
before either is reached by recreating the volume with `pivsetup migrate`
(new LUKS volume key, fresh hidden master key). These numbers come only from
the collision terms above; they are not a reviewed AEGIS-128 security bound
(original AEGIS-128 is not AEGIS-128L, whose analyses must not be transplanted)
and cover neither multi-key nor RNG-failure scenarios. RNG snapshots, cloned
images and VM restores can repeat randomness and void the birthday model.

**Not enforced.** The per-owner 2^32 encryption counter starts after earlier
stock encryptions and resets on recreation; it is a diagnostic cap, not a
remaining allowance. A stateless image cannot know its own lifetime usage, so
the budget must be tracked outside the volume (e.g. by write volume estimates
from the host), and no on-disk ledger is added under the current scope.

## Integrity, journal and implementation boundaries

Source paths reviewed: `kernel/{dm-piv.c,piv-control.inc,piv-native.inc}` (the
standalone target; it reimplements the stock dm-crypt AEAD layout, cross-checked
by host decoding of every kernel-written image), `rust/src/` (pivsetup) and the
independent decoders `pivstore/{records_v4,format,sector,profile}.py`. Parts of
this internal review predate later changes and were not repeated line by line.
Source/package hashes and fixture provenance remain in environment/ and the
development/layout notes.

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
can pass. Lower replay can mutate storage before native setup's scan;
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
The standalone module no longer inherits dm-crypt code or its fixes, but its
own AEAD/integrity path now needs equivalent review; exact header compatibility
does not establish that a pinned kernel is free of vulnerabilities. Broad deployment is still out of scope.

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
mitigations: stock `--integrity-no-journal`, now supported as an opt-in
(removes on-disk history; a crash then tears decoy sectors not only where the
user wrote but also in the carrier of an interrupted hidden write, see
docs/journal-atomicity.md); untested: journal encryption (hides sector
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
