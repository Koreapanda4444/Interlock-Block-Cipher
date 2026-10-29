"""Measure the current C primitive; no cross-cipher security/performance claim."""

import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/measure"
cc = shlex.split(os.environ.get("BENCH_CC", "cc"))
summary = ROOT / "build/benchmark.json"
summary.unlink(missing_ok=True)
result = subprocess.run([str(BUILD / "benchmark")], check=True, cwd=ROOT,
                        capture_output=True, text=True, timeout=60)
raw = json.loads(result.stdout)
for row in raw["rows"]:
    samples = row["samples_ns"]
    if len(samples) != 7 or any(not math.isfinite(v) or v <= 0 for v in samples):
        raise AssertionError("incomplete/invalid measurement samples")
    row.update({"median_ns": statistics.median(samples), "mean_ns": statistics.mean(samples),
                "stdev_ns": statistics.stdev(samples), "min_ns": min(samples)})
    if row["operation"] != "key_init":
        row["serial_MiB_per_second"] = 16*1e9/(statistics.median(samples)*2**20)
frames = []
for path in sorted(BUILD.glob("*.su")):
    for line in path.read_text().splitlines():
        name, size, qualifier = line.rsplit("\t",2)
        frames.append({"function_location": name,"bytes": int(size),"qualifier": qualifier})
if not frames:
    raise AssertionError("compiler produced no stack-usage records")
size_tool = shlex.split(os.environ.get("BENCH_SIZE", "size"))
size_output = subprocess.check_output([*size_tool,str(BUILD / "libinterlock.a")],text=True)
objects = []
for line in size_output.splitlines()[1:]:
    fields = line.split()
    if len(fields) < 6:
        raise AssertionError("unexpected size output")
    objects.append({"object": " ".join(fields[5:]),"text_and_rodata_bytes": int(fields[0]),
                    "data_bytes": int(fields[1]),"bss_bytes": int(fields[2])})
source_paths = [*ROOT.glob("src/*.[ch]"),*ROOT.glob("include/*.h"),
                ROOT / "research/benchmark.c", ROOT / "research/benchmark.py", ROOT / "Makefile"]
cpu = platform.processor()
info = Path("/proc/cpuinfo")
if info.exists():
    cpu = next((line.split(":",1)[1].strip() for line in info.read_text().splitlines()
                if line.startswith("model name")),cpu)
document = {"compiler_command": cc,"compiler_version": subprocess.check_output([*cc,"--version"],text=True).splitlines()[0],
    "cflags": os.environ.get("BENCH_CFLAGS", ""),"cppflags": os.environ.get("BENCH_CPPFLAGS", ""),
    "ldflags": os.environ.get("BENCH_LDFLAGS", ""),"platform": platform.platform(),"cpu": cpu,
    "git_head": subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
    "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths},
    "binary_sha256": hashlib.sha256((BUILD / "benchmark").read_bytes()).hexdigest(),
    "archive_sha256": hashlib.sha256((BUILD / "libinterlock.a").read_bytes()).hexdigest(),
    "measurements": raw,"object_sizes": objects,"stack_frames": frames,
    "max_reported_function_frame_bytes": max(row["bytes"] for row in frames),
    "limits": "serial dependent-block API timings with 128 warmups and 7 repeats; process scheduling/frequency uncontrolled; compiler frames are not total call-chain stack; no security-normalized AES comparison"}
summary.write_text(json.dumps(document,indent=2)+"\n")
for row in raw["rows"]:
    print(f"{row['operation']}: median={row['median_ns']:.1f} ns, stdev={row['stdev_ns']:.1f} ns")
print(f"Object sizes and compiler frame records -> {summary.relative_to(ROOT)}")
