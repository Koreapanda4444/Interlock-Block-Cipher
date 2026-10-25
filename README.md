# Interlock-128

An experimental block cipher research project: 128-bit blocks, 256-bit keys,
and 28 rounds. Security strength and novelty are not established. Do not use
this research primitive to protect real secrets.

The project maintains one current C11 implementation and one bit-level
specification. Modes, padding, authentication, file encryption, GUI and servers
are outside its scope. Earlier designs belong in Git history.

Research distinguishes forward-only PRP queries, strong-PRP forward/inverse
queries, related-key queries with explicit key relations, and internal-state
observations. Recovering an exposed round subkey is not evidence of recovering
the master key through the external block oracle.

Implementation, independent known-answer checks, early structural analysis and
CI will be introduced as validated logical commits. Task IDs are research
checklist items, not a count of commits or evidence of security.

한국어 명세와 연구 근거는 구현 커밋부터 함께 제공한다.
