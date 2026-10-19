# Kernel architecture

The selected approach extends the pinned dm-crypt implementation and registers
paired piv-view device-mapper targets in the same experimental module. This
reuses dm-crypt's exact primary AEAD/AAD handling and dm-integrity's ordinary
journal, avoiding an independent primary encryption implementation or modified
on-disk metadata format.

See [native blocks](native-blocks.md) for the implemented control/data path and
[format](hidden-format.md) for hidden crypto. The former userspace recovery/WAL
architecture is removed; previous investigations remain in Git, not as current
instructions. Source/profile provenance remains in environment/kernel-sources.json,
kernel/README.md and observed-layout.md.
