# Security and threat-model review

Internal, source-led engineering assessment of the current standalone module
(`kernel/{dm-piv.c,piv-control.inc,piv-native.inc}`), pivsetup (`rust/src/`) and
the independent decoders (`pivstore/{records_v4,format,sector,profile}.py`). It
is not an independent cryptographic audit or certification. No known
exploitable implementation defect is open; that is not an assertion that none
exist. The whole-encoding pseudorandomness argument still needs external review.

## Assets, assumptions and observers

Assets are primary plaintext integrity, hidden plaintext confidentiality and
per-block authentication, and concealment of hidden-data existence. These are
separate claims. Assume independently generated high-entropy primary and hidden
keys (32-byte key files, or passphrases through the keyslot KDF), trusted
setup/kernel/crypto implementations, seeded non-rewound randomness, exclusive
coordinated writes and a supported layout. Key-length validation cannot
establish entropy or independence. The primary passphrase protects a LUKS
keyslot; the hidden key unlocks a hidden keyslot ([format-v4.md](format-v4.md)).

| Observer or adversary | Supported reasoning and limits |
| --- | --- |
| Passive reader of current IV slots, without hidden key | The encoding is expected to be pseudorandom under the composition assumptions below. This has not been proved or independently reviewed. |
| Reader of a complete raw disk image | Also sees LUKS configuration, the journal and residual storage. A single image can contain write history. No full-image indistinguishability guarantee follows from current-IV randomness. |
| Reader with primary key but no hidden key | Can authenticate/decrypt primary sectors and inspect IVs. Primary-key disclosure alone is not intended to reveal the hidden key. No coercion or alternative-opening protocol is implemented. |
| Snapshot, journal-history, known-workload or live-I/O observer | A hidden write's 90 same-plaintext reencryptions are observable. Decoy writes matched stock closed-snapshot footprints in the AEGIS matched controls, but I/O traces still differ. No deniability against these observers is claimed. |
| Active raw-storage attacker without keys | Can destroy data and replay old valid tuples/records. Authentication rejects altered protected content, subject to cipher assumptions; it does not provide availability, freshness or authenticated metadata/journal ordering. |
| Holder of primary key or decoy write access | Can destroy hidden data through uncoordinated (stock) writes; cannot be relied upon to preserve it. |
| Holder of hidden-device access or hidden key | Receives plaintext or can decrypt/forge hidden records. Filesystem permissions are the access-control boundary. |
| Administrator, compromised kernel or live-memory reader | Outside confidentiality/concealment guarantees: both plaintext views, keys, module names and mappings are present. |

Mounted public block devices expose plaintext. Root-only control ioctls and
mapping identity checks prevent accidental misuse; they do not isolate data
from a hostile administrator. A hidden filesystem's superblocks and access
patterns are concealed only beneath its block interface. There is no forward
secrecy, secure deletion, key erasure guarantee, authenticated boot or protection
against malicious storage firmware. VM shares, keys, snapshots, swap, crash dumps,
Python objects and installed tools are separate operational evidence. Test keys
and fixtures are unsuitable for real data.

Out of scope by user decision: multi-snapshot observers, rollback resistance and
coercion-resistant alternative hidden openings (these would only move coercion
from one hidden key to the next). Retained single-image journal history remains
in scope (see below).

## Encoding review (format v4)

The exact bytes are specified in [format-v4.md](format-v4.md). All hidden keys
come from HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html))
over the master key (or a keyslot KEK) with the public v4 context as salt and
`"pivstore/v4/" ‖ label` as info (`pn_hkdf`, cross-checked against the Python
decoder). A KEK is a 32-byte key file or a passphrase through Argon2id
(m = 64 MiB, t = 3, p = 4, fixed and not recorded).

Each hidden block is a deterministic SIV record: a 16-byte HMAC-SHA256 tag over
context, group, generation and data, and ChaCha20 under `tag[0:12]`. Identical
data at the same address gives an identical record payload; freshness of the
stored bytes comes from the outer encoding, where every 16-byte IV is an LRW-AES
output on (10 fresh random bytes ‖ 6 payload bytes) tweaked by the primary
sector. Per-sector nonce uniqueness rests on those 80 random bits.

The concealment argument requires the joint distribution of every stored IV,
for chosen and repeated hidden data, valid and damaged records and the public
context, to be indistinguishable from stock random IVs without the hidden key.
It rests on LRW/AES tweakable-PRP security plus the SIV layer; local collision
rejection slightly conditions the distribution. There is no public magic: the
keyslots, directory and A/B flag are all inside the PRP input. This
is a design argument without external review. Statistical summaries in
[detectability.md](detectability.md) cannot prove it. The cipher choice itself
(AEGIS-128 or AES-XTS + HMAC-SHA256) is visible in LUKS metadata; compare against ordinary
volumes of the same profile.

The context binds the UUID, primary capacity, sector size, the A/B layout and the
record group. It does not bind a timestamp, the primary key or the physical
disk: a whole record copied to a clone with the same context stays valid, and
whole-record rollback is accepted (out of scope). Fragments from different
versions fail the tag except with probability 2^-128. Raw stored IVs of sectors
that fail primary authentication feed only SIV-checked decoding (keyslots, the
directory and hidden reads), never published output.

Keyslots give a fast offline key check: a passphrase KEK is exactly as guessable
as its KDF cost allows, so key files remain the high-entropy option. Neither key
commitment nor convincing alternative openings under other keys is provided. A
wrong key is refused at setup (`EKEYREJECTED`) instead of being allowed to
destroy records on a later decoy write. The keyslot directory reveals keyslot
outer keys only to holders of the master key.

## Nonce and data budgets

Primary nonce uniqueness is global per primary key across addresses, devices,
clones, stock writes and time. Different sector addresses (AAD or HMAC input) do
not permit nonce reuse.

**What consumes nonces.** Every primary encryption draws one 16-byte IV: stock
dm-crypt writes (one per written sector), native decoy writes (exactly one per
written primary sector), hidden writes (90 per 512-byte block; A/B writes one
slot), keyslot add/remove (28 + 90) and initialization (28 + 90 + 90 × hidden
blocks). Tuples prepared before a failure count; local collision retries before
preparation and exact replays do not.

**Consequence of a repeat, per profile.**

- *Original AEGIS-128* (not AEGIS-128L, whose analyses must not be transplanted):
  a repeated (key, IV) pair leaks plaintext relations and enables state recovery
  and forgery. Treat it as a key compromise.
- *AES-XTS + HMAC-SHA256*: the IV is the XTS tweak and the only
  per-sector input to encryption, so a repeated IV under the same XTS key, at
  the same or another sector, reveals which 16-byte blocks at the same offsets
  of the two plaintexts are equal. Authentication is HMAC over sector, IV and
  ciphertext under a separate key, so forgery still requires the HMAC key. The
  collision terms below are the same; the consequence is much milder.

**Two collision terms.**

| Term | Model | Example values |
| --- | --- | --- |
| Whole key, IVs at different sectors | about q²/2^129 (uniform 128-bit IVs) | q = 2^32: 2^-65; 2^40: 2^-49; 2^48: 2^-33 |
| One sector rewritten n times (v4 fragments carry 80 random bits) | about n²/2^81 | n = 2^20: 2^-41; 2^24: 2^-33; 2^32: 2^-17 |

The per-sector term dominates for hot sectors. Tail sectors, unlisted keyslot
areas and stock writes use fully random 128-bit IVs and follow the first row only.

**Guidance (not a proven bound).** Choose a per-key budget for the deployment,
for example at most 2^40 total primary encryptions and at most 2^24 rewrites of
any one sector (about 2^-49 and 2^-33 collision probability), and rekey before
either is reached with `pivsetup migrate` into a freshly formatted volume (new
LUKS volume key, fresh hidden master key); live rekey is unsupported. These
numbers come only from the collision terms above. They are not a reviewed
AEGIS-128 or XTS bound and cover neither multi-key nor RNG-failure scenarios.
RNG snapshots, cloned images and VM restores can repeat randomness and void the
birthday model. Under XTS + HMAC a deployment may accept a larger budget given
the milder consequence; that is a policy choice, not an analysed bound.

**Not enforced.** The per-owner 2^32 encryption counter starts after earlier
stock encryptions and resets on recreation; it is a diagnostic cap, not a
remaining allowance. A stateless image cannot know its own lifetime usage, so
the budget must be tracked outside the volume, and no on-disk ledger is added
under the current scope.

## Integrity, journal and implementation boundaries

The module reimplements the stock dm-crypt AEAD/authenc sector layout (Linux
AAD/IV/tag offsets), cross-checked by host decoding of kernel-written images:
AEGIS-128 via the pinned SUPERCOP reference and AES-XTS + HMAC-SHA256 via
cryptography. It does not inherit
dm-crypt fixes, so its own crypto/integrity path needs equivalent review; exact
header compatibility does not establish that a pinned kernel is free of
vulnerabilities.

`piv_load` authenticates before primary modification. In-kernel PREPARE
consumes encryption invocations; APPLY authenticates the candidate and checks
the expected old IV. Native updates prepare all tuples before applying any,
serialize through the owner mutex and use the lower journal. Userspace has no
IV/tuple read or apply ioctls. Hidden reads copy to the caller only after
complete record authentication; decoy reads publish a range only after every
sector in it authenticates. Expected-IV checks prevent stale local updates, not
rollback by an external writer. Context, size and profile bounds are validated
and exercised by control-ioctl and dm-table fuzzing and a sanitizer guest
(KASAN/UBSAN/lockdep/kmemleak); this is not exhaustive fuzzing, formal
verification or a memory-safety proof.

The [Linux dm-integrity documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html)
describes journaling sector data with tags. The supported journal has neither
encryption nor a MAC. Commit IDs detect incomplete sections, not maliciously
fabricated history. Primary authentication does not cover all superblock, LUKS
configuration or journal metadata, nor guarantee valid replay ordering.
Replaying a valid sector at its original address passes primary authentication.
Hidden authentication rejects torn fragments, but an old whole block or
different-time valid blocks can pass. Lower replay can mutate storage before
native setup reads it; activation does not reject hostile storage before any
modification.

Multi-sector hidden writes are not atomic ([journal-atomicity.md](journal-atomicity.md)).
EIO may follow a partial mutation; flush completion does not create a
whole-record transaction or prove hardware durability. A hostile device can
always deny service.

Kernel temporary buffers use explicit sensitive frees/wipes in reviewed paths.
Keys also live in crypto transforms and in pivsetup memory (mlocked, zeroized
buffers; never in argv). pivsetup reads the privileged key-containing dm table
into locked memory and passes it to dmsetup only via stdin. This is not
resistance to root, dumps, ptrace or physical memory acquisition. Broad
deployment is out of scope.

## Journal history and the decoy-key holder

From source/layout reasoning; no journal-forensic reconstruction experiment was
performed. The journal retains recent sector writes (ciphertext, tag, IV and
sector number) until wraparound. The 128 MiB fixtures have about 1 MiB of journal
(1,848–2,048 journal sectors depending on profile), so only a few recent hidden
writes (90 primary sectors each, 360 KiB of data at 4096-byte sectors) can
remain. A single raw image therefore carries a short write history even though
multi-snapshot observers are out of scope.

| Observer | What retained journal entries can show |
| --- | --- |
| No keys | Recently rewritten sector numbers and old IVs; runs of 90 contiguous sectors rewritten together. |
| Decoy-key holder (coercion case) | Old and new primary plaintext of those sectors: 90 contiguous sectors reencrypted with unchanged plaintext, unusual for ordinary filesystems. |
| Hidden-key holder | Potentially older versions of hidden records from correctly associated fragments. |

Decoy writes change only the IVs of the sectors written, like stock writes, so
this signature comes from hidden writes (and initialization/keyslot updates).
It indicates hidden-volume activity to a decoy-key holder with journal access.
No supported mitigation removes it: stock `--integrity-no-journal` would remove
on-disk journal history, but pivsetup refuses it because a crash during a
hidden write could then tear decoy sectors of that record's carrier
([journal-atomicity.md](journal-atomicity.md)). Journal encryption is untested
and unverified for LUKS2 integrity profiles in cryptsetup, and would hide sector
numbers only from keyless observers.

## Disposition

The important findings are limitations, stated explicitly rather than treated as
solved: full-image journal history, the hidden-write signature, unenforced
lifetime budgets, offline guessing, replay acceptance and trusted-host/key
requirements. Host regressions (`tests/test_records_v4.py`) reject mixed
fragment versions, wrong keys, swapped A/B slots and the wrong layout; acceptance
of an old whole record or of valid blocks from different times follows from the
design and has no dedicated v4 regression. External cryptographic
review of the entire encoding is still required before stronger concealment
claims. Active metadata/journal attack fixtures remain separate work.
