# Security and threat-model review

Internal, source-led engineering assessment of the current standalone module
(`kernel/{dm-piv.c,piv-control.inc,piv-native.inc,piv-rs.inc}`), pivsetup
(`rust/src/`) and the independent decoders
(`pivstore/{records,rs,format,sector,profile}.py`). It
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
keyslot; the hidden key unlocks a hidden keyslot ([format-v5.md](format-v5.md)).

| Observer or adversary | Supported reasoning and limits |
| --- | --- |
| Passive reader of current IV slots, without hidden key | The encoding is expected to be pseudorandom under the composition assumptions below. This has not been proved or independently reviewed. |
| Reader of a complete raw disk image | Also sees LUKS configuration, the journal and residual storage. A single image can contain write history. No full-image indistinguishability guarantee follows from current-IV randomness. |
| Reader with primary key but no hidden key | Can authenticate/decrypt primary sectors and inspect IVs. Primary-key disclosure alone is not intended to reveal the hidden key. No coercion or alternative-opening protocol is implemented. |
| Snapshot, journal-history, known-workload or live-I/O observer | A hidden write's G (687 + 3p) same-plaintext reencryptions are observable. Decoy writes matched stock closed-snapshot footprints in the AEGIS matched controls, but I/O traces still differ. No deniability against these observers is claimed. |
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

## Encoding review (format v5)

The exact bytes are specified in [format-v5.md](format-v5.md). All hidden keys
come from HKDF-SHA256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html))
over the master key (or a keyslot KEK) with the public v5 context (records: base
plus the whole 32-byte keyslot parameter block) as salt and `"pivstore/v5/" ‖ label` as info
(`pn_hkdf`, cross-checked against the Python decoder). A KEK is a 32-byte key
file or a passphrase through Argon2id at a user-chosen cost tier (1–4; default
tier 3: m = 1 GiB, t = 3, p = 4; the tier is part of the salt and recorded
nowhere). pivsetup computes the four lanes sequentially (the pinned argon2
crate has no parallel mode), so an attacker running them in parallel gains up
to 4× in time over the defender's measured cost, not in memory
([format-v5.md](format-v5.md#passphrase-cost-tiers)).

Each hidden 4096-byte block is a deterministic SIV record: a 16-byte
HMAC-SHA256 tag over context, group, generation and data, and ChaCha20 under
`tag[0:12]`. Optional Reed–Solomon parity fragments are a deterministic
function of that payload, stored inside the same LRW encoding; decoding them
never accepts anything without the SIV tag. Identical
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

The context binds the UUID (canonical form), primary capacity, sector size, the
whole keyslot parameter block (version, A/B flag, block size, parity, reserved
bytes) and the record group. It does not bind a timestamp, the primary key or the physical
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

**Keyslot authority.** Only directory-listed keyslots open a volume (kernel
and Python decoder): a keyslot left authenticating but unlisted by an
interrupted add or remove is rejected like a wrong key, so a removed
passphrase stays removed even after a crash inside the remove. Initialization
overwrites keyslot areas 1–3 and the unused directory group with random IVs
before writing keyslot 0, so re-initialization revokes every earlier
passphrase and directory. Keyslot add/remove (NATIVE_KEYSLOT version 2)
requires the caller's current hidden KEK of a listed keyslot: root with only
the LUKS key and an active owner can neither add a passphrase it knows
(persistent offline access to MK) nor remove the user's keyslots. Root can
still read the plaintext views and the kernel's memory (administrator
observer above).

## Nonce and data budgets

Primary nonce uniqueness is global per primary key across addresses, devices,
clones, stock writes and time. Different sector addresses (AAD or HMAC input) do
not permit nonce reuse.

**What consumes nonces.** Every primary encryption draws one 16-byte IV: stock
dm-crypt writes (one per written sector), native decoy writes (exactly one per
written primary sector), hidden writes (G = 687 + 3p per 4096-byte block; A/B
writes one slot), keyslot add/remove (28 + G), initialization (4 × 28 + 2G +
G × hidden blocks: the revocation of keyslot areas 1–3 and directory group 1,
keyslot 0, the directory and the records; quick initialization 4 × 28 + 2G)
and fill (G per block written; the
check of skipped blocks only reads). Encryptions performed before a failure
count; local collision retries happen before encryption and do not.

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
| One sector rewritten n times (v5 fragments carry 80 random bits) | about n²/2^81 | n = 2^20: 2^-41; 2^24: 2^-33; 2^32: 2^-17 |

The per-sector term dominates for hot sectors. Tail sectors, unlisted keyslot
areas and stock writes use fully random 128-bit IVs and follow the first row only.
Summed over the volume, the fragment-carrying sectors contribute about
Σ_s n_s²/2^81 (n_s: lifetime rewrites of sector s), so a few very hot sectors
dominate. The hottest are typically the keyslot sectors 0–111: they are the
start of the decoy filesystem (an ext4 superblock and group descriptors),
rewritten by every metadata update; at about 2^26 lifetime rewrites one such
sector contributes about 2^-29. This does not change the 10 + 6 split, but a
budget should count rewrites of the filesystem's hottest blocks.

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

**Not enforced.** The per-owner encryption counter (capped at 2^40, raised
from 2^32 so large initializations are not blocked) starts after earlier
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

Every rewrite authenticates the old sectors (`piv_batch_read`) before
modifying them, encrypts all of them before submitting any write, holds a
range lock over every sector it rewrites (concurrent requests touching the same
sectors or hidden record serialize; [concurrency](native-blocks.md#concurrency))
and uses the lower journal
([write path](native-blocks.md#write-path)). The former re-read with an
expected-IV check and the self-decryption of new ciphertext served userspace
PREPARE/APPLY tuples and were dropped with that interface; nothing coordinated
can change a sector between authentication and its write. Userspace has no
IV/tuple read or write ioctls. Hidden reads copy to the caller only after
complete record authentication; decoy reads publish a range only after every
sector in it authenticates. Nothing prevents rollback or races by an external
writer of the lower device. Context, size and profile bounds are validated
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
writes (687 primary sectors each without parity, 2.7 MiB of data at 4096-byte
sectors) can remain; at 4096-byte sectors the journal holds less than one
record write. A single raw image therefore carries a short write history even though
multi-snapshot observers are out of scope.

| Observer | What retained journal entries can show |
| --- | --- |
| No keys | Recently rewritten sector numbers and old IVs; runs of contiguous record sectors rewritten together. |
| Decoy-key holder (coercion case) | Old and new primary plaintext of those sectors: contiguous record sectors reencrypted with unchanged plaintext, unusual for ordinary filesystems. |
| Hidden-key holder | Potentially older versions of hidden records from correctly associated fragments. |

Decoy writes change only the IVs of the sectors written, like stock writes, so
this signature comes from hidden writes (and initialization, fill and keyslot
updates). A quick initialization rewrites only the keyslot and directory
sectors; never-written record carriers keep their previous IVs (stock random
IVs or LRW outputs under an earlier master key), which a single image cannot
tell apart from records without the master key. Its later hidden writes are
then the per-record signature above, as after a full initialization.
It indicates hidden-volume activity to a decoy-key holder with journal access.
A removed keyslot's (or, after re-initialization, a revoked keyslot's) old
IVs can likewise remain in the journal until it wraps, so its passphrase stays
testable offline from one raw image during that window; write more than a
journal's worth of decoy data after a removal to push them out.
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
requirements. Host regressions (`tests/test_records.py`) reject mixed
fragment versions, wrong keys, swapped A/B slots, the wrong layout and
miscorrected RS output; acceptance of an old whole record or of valid blocks
from different times follows from the design and has no dedicated v5
regression. External cryptographic
review of the entire encoding is still required before stronger concealment
claims. Active metadata/journal attack fixtures remain separate work.
