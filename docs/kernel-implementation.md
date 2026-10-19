# Kernel implementation guide

kernel/dm-crypt-piv.patch adds the opt-in piv_control feature, integrates the
native AEAD helpers and registers piv-view. kernel/piv-control.inc handles
privileged generation-bound control, authenticated primary load/preparation/
application, suspend/controller gates and lifetime references. Public private-owner
bios are blocked once a native context is active.

kernel/piv-native.inc owns stateless hidden records, both views and the ordered
NOIO workqueue. It has no filesystem persistence path. See native-blocks.md for
ABI 3, the write sequence and error behavior. The independently implemented
Python codec in pivstore/records.py must agree with kernel output. Tests must
verify complete primary data with both stock Linux and the independent decoder.

Exact-current-tuple application is idempotent and does not encrypt again. The
checkpoint helper similarly submits the existing authenticated tuple to make
ordinary journal shutdown clean, consuming no nonce. Fresh preparation counts an
AES-GCM invocation even if later application fails. Current counters are volatile
and cannot establish lifetime nonce usage. Raw control primitives remain privileged
research interfaces, not a complete nonce-policy service.

Hidden unavailability uses the positive internal PN_UNAVAILABLE sentinel, not a
Linux errno. In particular BLK_STS_MEDIUM maps to -ENODATA: treating that errno
as a hidden-record error would incorrectly spare a physical medium failure from
shared fail-stop. Only authenticated-record decode failures produce the sentinel;
all ordinary negative storage/authentication errors retain failure semantics.
