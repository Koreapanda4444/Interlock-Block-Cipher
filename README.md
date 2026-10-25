# Interlock-128

[한국어](README_KR.md)

An experimental, single-design block cipher research project: 128-bit blocks,
256-bit keys, and 28 rounds. The implementation target is portable C11.
Security strength and novelty are **not established**; do not use it to protect
real secrets. This repository is a primitive, not a file-encryption application.

The [normative specification](docs/spec_ko.md) fixes byte order, sequential
updates, the PRESENT S-box and the SHAKE256 schedule. The
[research record](docs/security_ko.md) separates proofs, observations and open
questions. Earlier designs belong in Git history, not parallel source trees.

Implementation and reproducible checks are being introduced as separate,
validated commits. No implementation or CI success is claimed by this initial
specification commit.
