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

The current checkpoint includes encryption/decryption, a fixed 28-round public
API, key erasure, independent intermediate-state KATs, and bounded structural,
differential, rotational and integral analysis through eight-round prefixes.
Python is used only for independent tests/research; the library has
no runtime dependencies beyond C11. Reduced-round entry points are test-only.

## Build and verify

On Linux, use a C11 compiler, Make, and Python 3.10+ (standard library for the default checks).

```sh
make all             # build/libinterlock.a
make check           # C KAT/negative checks plus independent Python comparison
make research        # 19 full experiments; build/summary.json and individual reports
make sanitize        # C KAT and deterministic API fuzzing with ASan/UBSan
```

Clean before changing compiler/flags. `make sanitize` cleans automatically;
clean again before loading the ordinary Python test bridge. Instrumented C
tests run as executables, without loading ASan into Python.

Optional exact SMT research uses the pinned Z3 package:

```sh
python3 -m pip install -r research/requirements-smt.txt
make smt-check smt-research
```

The seven-experiment SMT bundle checks model consistency, projected counts,
external one-round FM subkey inference and known-key feasibility through 28
rounds. Inverse-output preprocessing recovered all first-round subkeys in three tested
keys, with held-out blocks and uniqueness checks. This remains a one-round
attack; six 12/20/28-round low-weight queries remain unresolved.
See the [attack models](docs/attacks_ko.md) and
[phase/task checkpoint](docs/research_status_ko.md) for scope and open work.
SMT JSON and formulas are retained in CI artifacts for seven days.

Optional implementation checks and measurement:

```sh
make fuzz-check       # 8,192 deterministic API cases, ordinary C11 compiler
make fuzz CC=clang    # 50,000 libFuzzer mutations, ASan/UBSan
make ct-check         # Valgrind + headers; deliberate branch/address leak controls
make measure          # 7 repeats, key setup/block costs, object size/stack/disassembly
```

CI also executes the C KAT/buffer checks on ARM32 little-endian and s390x
big-endian under QEMU. GCC/Clang `-O2` secret-taint audits cover sampled key
expansion, encryption/decryption and erasure paths. This is not a constant-time
proof. Measurement reports include compiler/options, code fingerprints and
library-object disassembly for independent inspection.

## API

Include `interlock.h` and link `build/libinterlock.a`. Zero-initialize an
`interlock_ctx`, call `interlock_init(&ctx, key, 32)`, then
`interlock_encrypt_block(&ctx, out, out_capacity, in, 16)` or the corresponding
decrypt function. Return values are `INTERLOCK_OK`, `INTERLOCK_ERR_ARGUMENT`,
and `INTERLOCK_ERR_STATE`. Finish with `interlock_clear(&ctx)`.

Output capacity must be at least 16; only those 16 bytes are written. Block
errors leave output unchanged. Input/output may overlap; output/context may
not. Invalid init arguments erase a non-NULL context. Callers guarantee valid
object extents and must not race context mutation against block operations.

The research record includes one-to-three-round differential distinguishers,
a proven all-key nontrivial one/two-round boomerang distinguisher, observed
complete first-round subkey recovery, and a strong local FM bias. These are
reduced-round results, not attacks against the public 28-round API.

The ordinary evidence bundle contains 19 full experiments and 10,550,568
block-oracle evaluations; component evaluations and the optional SMT bundle
are separate. `make research` rejects mixed source/binary identities, smoke
reports and inconsistent query ledgers. CI retains reports for seven days.

Full-round attack complexity, security margin, novelty, timing behavior across
platforms and external independent cryptanalysis remain unverified. The
[current research status](docs/research_status_ko.md) states the remaining work.
