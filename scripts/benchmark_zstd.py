#!/usr/bin/env python3
"""Reproducible offline benchmark for peer-observer Zstandard archives.

The measured region contains exactly one Zstandard compressor process.  Input
archives are checked and decompressed once before any warmup or measured run.
No peer-observer protobuf is decoded or re-encoded.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


MIN_ZSTD_LEVEL = 1
MAX_ZSTD_LEVEL = 22
MIB = 1024 * 1024
REPORT_FILENAMES = (
    "benchmark-results.csv",
    "benchmark-results.json",
    "benchmark-summary.md",
)

LIMITATIONS = (
    "Measures the Zstandard compressor over real archive bytes.",
    "Isolates the effect of the Zstandard compression level.",
    "Peak RSS covers the standalone zstd CLI child, not the full archiver process.",
    "The archiver flushes after ArchiveHeader; whole-stream CLI compression does not "
    "reproduce that flush boundary, so compressed frames need not be byte-identical.",
    "Does not measure NATS.",
    "Does not measure archiver backlog.",
    "Does not reproduce temporal pacing.",
    "Does not decode or re-encode protobuf messages.",
)

CSV_FIELDS = (
    "sample",
    "sample_description",
    "level",
    "baseline",
    "run",
    "order_position",
    "actual_order",
    "wall_time_seconds",
    "cpu_user_seconds",
    "cpu_system_seconds",
    "cpu_total_seconds",
    "cpu_utilization_percent",
    "peak_rss_raw",
    "peak_rss_raw_unit",
    "peak_rss_bytes",
    "peak_rss_conversion",
    "input_bytes",
    "compressed_bytes",
    "compression_ratio",
    "throughput_mib_per_second",
    "input_throughput_mib_per_second",
    "zstd_version",
    "command",
    "zstd_command",
    "exit_status",
    "raw_wait_status",
    "valid",
    "interrupted",
    "integrity_test_exit_status",
    "validation_decompress_exit_status",
    "validation_bytes",
    "validation_sha256",
    "validation_error",
)


class BenchmarkError(RuntimeError):
    """A user-facing benchmark setup or execution error."""


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark arbitrary Zstandard levels using identical decompressed "
            "peer-observer archive bytes."
        )
    )
    parser.add_argument(
        "--levels",
        type=int,
        nargs="+",
        required=True,
        metavar="LEVEL",
        help="compression levels to compare (1 through 22)",
    )
    parser.add_argument(
        "--baseline",
        type=int,
        required=True,
        metavar="LEVEL",
        help="level used as the comparison baseline",
    )
    parser.add_argument(
        "--runs",
        type=int,
        required=True,
        metavar="N",
        help="number of measured runs per sample and level",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        metavar="PATH",
        help="explicit directory for temporary files and reports",
    )
    parser.add_argument(
        "--sample-description",
        action="append",
        default=[],
        metavar="SAMPLE_ID=TEXT",
        help=(
            "optional general, non-sensitive workload description; sample IDs "
            "are assigned by argument order (sample-001, sample-002, ...)"
        ),
    )
    parser.add_argument(
        "archives",
        type=Path,
        nargs="+",
        metavar="ARCHIVE.bin.zst",
        help="one or more private peer-observer .bin.zst archives",
    )
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse and validate CLI arguments; accepts argv for unit tests."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if not args.levels:
        parser.error("--levels must contain at least one level")
    if len(set(args.levels)) != len(args.levels):
        parser.error("--levels must not contain duplicates")
    for level in args.levels:
        if level == 0:
            parser.error(
                "compression level 0 is not valid here; in the peer-observer "
                "archiver, 0 means uncompressed output"
            )
        if not MIN_ZSTD_LEVEL <= level <= MAX_ZSTD_LEVEL:
            parser.error(
                "compression levels must be between {} and {} (got {})".format(
                    MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL, level
                )
            )
    if args.baseline not in args.levels:
        parser.error("--baseline must also be present in --levels")
    for archive in args.archives:
        if not str(archive).endswith(".bin.zst"):
            parser.error("archive must end in .bin.zst: {}".format(archive))

    descriptions: Dict[str, str] = {}
    valid_sample_ids = {
        "sample-{:03d}".format(index)
        for index in range(1, len(args.archives) + 1)
    }
    for value in args.sample_description:
        sample_id, separator, description = value.partition("=")
        sample_id = sample_id.strip()
        description = description.strip()
        if not separator or not sample_id or not description:
            parser.error(
                "--sample-description must use SAMPLE_ID=TEXT, for example "
                "sample-001=full-data"
            )
        if sample_id not in valid_sample_ids:
            parser.error(
                "unknown sample ID in --sample-description: {}; expected one of {}".format(
                    sample_id, ", ".join(sorted(valid_sample_ids))
                )
            )
        if sample_id in descriptions:
            parser.error("duplicate description for {}".format(sample_id))
        if "\n" in description or "\r" in description:
            parser.error("sample descriptions must be a single line")
        descriptions[sample_id] = description
    args.sample_descriptions = descriptions
    return args


def build_level_order(levels: Sequence[int], run_index: int) -> List[int]:
    """Return a deterministic balanced order for a zero-based measured run.

    Two levels alternate exactly (A,B then B,A).  Larger sets use adjacent
    forward/reverse pairs, rotating the starting level after each pair.
    """
    if run_index < 0:
        raise ValueError("run_index must be non-negative")
    order = list(levels)
    if not order:
        raise ValueError("levels must not be empty")
    if len(order) == 1:
        return order
    if len(order) == 2:
        return order if run_index % 2 == 0 else list(reversed(order))

    rotation = (run_index // 2) % len(order)
    rotated = order[rotation:] + order[:rotation]
    return rotated if run_index % 2 == 0 else list(reversed(rotated))


def normalize_rss(
    raw_value: float, platform_name: Optional[str] = None
) -> Dict[str, Any]:
    """Normalize wait4().ru_maxrss to bytes and document the conversion."""
    name = (platform_name or sys.platform).lower()
    if name.startswith("darwin"):
        raw_unit = "bytes"
        factor = 1
        conversion = "ru_maxrss is bytes on macOS; peak_rss_bytes = raw value"
    elif name.startswith("linux"):
        raw_unit = "KiB"
        factor = 1024
        conversion = "ru_maxrss is KiB on Linux; peak_rss_bytes = raw value * 1024"
    else:
        raw_unit = "KiB (platform assumption)"
        factor = 1024
        conversion = (
            "platform is neither macOS nor Linux; assumed ru_maxrss is KiB and "
            "multiplied by 1024"
        )
    return {
        "raw": raw_value,
        "raw_unit": raw_unit,
        "bytes": int(raw_value * factor),
        "conversion": conversion,
    }


def sha256_file(path: Path, chunk_size: int = MIB) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _command_display(
    command: Sequence[str], stdin_path: Optional[Path] = None, stdout_path: Optional[Path] = None
) -> str:
    display = shlex.join([str(part) for part in command])
    if stdin_path is not None:
        display += " < " + shlex.quote(str(stdin_path))
    if stdout_path is not None:
        display += " > " + shlex.quote(str(stdout_path))
    return display


def _record_command(
    history: List[Dict[str, Any]],
    stage: str,
    command: Sequence[str],
    exit_status: int,
    sample: Optional[str] = None,
    run: Optional[int] = None,
    level: Optional[int] = None,
    stdin_path: Optional[Path] = None,
    stdout_path: Optional[Path] = None,
) -> None:
    history.append(
        {
            "stage": stage,
            "sample": sample,
            "run": run,
            "level": level,
            "command": [str(part) for part in command],
            "command_display": _command_display(command, stdin_path, stdout_path),
            "exit_status": exit_status,
        }
    )


def run_checked_command(
    command: Sequence[str],
    history: List[Dict[str, Any]],
    stage: str,
    sample: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [str(part) for part in command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    _record_command(history, stage, command, completed.returncode, sample=sample)
    return completed


def run_redirected_command(
    command: Sequence[str],
    output_path: Path,
    history: List[Dict[str, Any]],
    stage: str,
    sample: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    """Run an unmeasured command and atomically create its redirected output."""
    try:
        with output_path.open("xb") as output:
            completed = subprocess.run(
                [str(part) for part in command],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise
    _record_command(
        history,
        stage,
        command,
        completed.returncode,
        sample=sample,
        stdout_path=output_path,
    )
    return completed


def build_compression_command(zstd_path: str, level: int) -> List[str]:
    command = [
        zstd_path,
        "--quiet",
        "--single-thread",
        "--no-asyncio",
        "--no-check",
    ]
    if level >= 20:
        command.append("--ultra")
    # Spell out stdin as '-' so the recorded command is unambiguous and does
    # not accidentally acquire a positional filename in future edits.
    command.extend(["-{}".format(level), "--stdout", "-"])
    return command


def _wait4_retry_eintr(pid: int) -> Tuple[int, int, Any]:
    """Wait for one exact child while retrying ordinary interrupted syscalls."""
    while True:
        try:
            return os.wait4(pid, 0)
        except InterruptedError:
            continue


def _terminate_and_wait4(pid: int) -> Tuple[int, int, Any]:
    """Terminate and reap a measured child without letting Popen reap it first."""
    termination_signal = signal.SIGTERM
    while True:
        try:
            os.kill(pid, termination_signal)
        except ProcessLookupError:
            # A dead-but-unreaped child can already be absent from kill(2) while
            # its wait4 resource record is still available to the parent.
            pass
        try:
            return _wait4_retry_eintr(pid)
        except KeyboardInterrupt:
            # A second interrupt escalates termination, but resource collection
            # still remains owned exclusively by wait4.
            termination_signal = signal.SIGKILL


def _kill_and_reap_after_error(pid: int) -> None:
    """Best-effort cleanup that never calls Popen.poll()/wait() after wait4 use."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            _wait4_retry_eintr(pid)
            return
        except KeyboardInterrupt:
            continue
        except ChildProcessError:
            return


def run_measured_compression(
    command: Sequence[str],
    input_path: Path,
    output_path: Path,
    stderr_path: Path,
) -> Dict[str, Any]:
    """Run one compressor and obtain exact child usage from os.wait4()."""
    if not hasattr(os, "wait4"):
        raise BenchmarkError("this benchmark requires os.wait4 (macOS or Linux)")

    interrupted = False
    process: Optional[subprocess.Popen[bytes]] = None
    started_ns: Optional[int] = None
    finished_ns: Optional[int] = None
    try:
        with input_path.open("rb") as source, output_path.open("xb") as output, stderr_path.open(
            "xb"
        ) as error_output:
            started_ns = time.perf_counter_ns()
            process = subprocess.Popen(
                [str(part) for part in command],
                stdin=source,
                stdout=output,
                stderr=error_output,
                close_fds=True,
            )
            try:
                _, wait_status, usage = _wait4_retry_eintr(process.pid)
            except KeyboardInterrupt:
                interrupted = True
                _, wait_status, usage = _terminate_and_wait4(process.pid)
            process.returncode = os.waitstatus_to_exitcode(wait_status)
            finished_ns = time.perf_counter_ns()
    except BaseException:
        if process is not None and process.returncode is None:
            _kill_and_reap_after_error(process.pid)
        output_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        raise

    if started_ns is None or finished_ns is None:
        raise BenchmarkError("compressor timing boundaries were not captured")
    wall_seconds = (finished_ns - started_ns) / 1_000_000_000
    cpu_user = float(usage.ru_utime)
    cpu_system = float(usage.ru_stime)
    cpu_total = cpu_user + cpu_system
    rss = normalize_rss(usage.ru_maxrss)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace").strip()
    return {
        "wall_time_seconds": wall_seconds,
        "cpu_user_seconds": cpu_user,
        "cpu_system_seconds": cpu_system,
        "cpu_total_seconds": cpu_total,
        "cpu_utilization_percent": (cpu_total / wall_seconds * 100.0)
        if wall_seconds > 0
        else None,
        "peak_rss_raw": rss["raw"],
        "peak_rss_raw_unit": rss["raw_unit"],
        "peak_rss_bytes": rss["bytes"],
        "peak_rss_conversion": rss["conversion"],
        "exit_status": process.returncode,
        "raw_wait_status": wait_status,
        "interrupted": interrupted,
        "stderr": stderr_text,
    }


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def prepare_work_dir(work_dir: Path, repository_root: Path) -> Path:
    """Create/validate an explicit workspace without risking repository data."""
    resolved = work_dir.expanduser().resolve()
    if resolved == Path(resolved.anchor):
        raise BenchmarkError("--work-dir must not be a filesystem root")
    if _is_within(resolved, repository_root.resolve()):
        raise BenchmarkError(
            "--work-dir must be outside the repository so private archive bytes "
            "cannot be copied into Git"
        )
    resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise BenchmarkError("--work-dir is not a directory: {}".format(resolved))
    return resolved


def safe_cleanup_run_dir(run_dir: Path, work_dir: Path) -> None:
    """Remove only the unique temporary directory created by this invocation."""
    run_resolved = run_dir.resolve()
    work_resolved = work_dir.resolve()
    if run_resolved.parent != work_resolved or not run_resolved.name.startswith(
        ".benchmark-zstd-"
    ):
        raise BenchmarkError("refusing unsafe cleanup outside the owned run directory")
    if run_resolved.exists():
        shutil.rmtree(run_resolved)


def _zstd_test_command(zstd_path: str, path: Path) -> List[str]:
    return [zstd_path, "--quiet", "--test", "--", str(path)]


def _zstd_decompress_command(zstd_path: str, path: Path) -> List[str]:
    return [zstd_path, "--quiet", "--decompress", "--stdout", "--", str(path)]


def prepare_sample(
    archive: Path,
    sample_id: str,
    description: str,
    run_dir: Path,
    zstd_path: str,
    zstd_version: str,
    history: List[Dict[str, Any]],
) -> Dict[str, Any]:
    source = archive.expanduser().resolve()
    if not source.exists():
        raise BenchmarkError("archive does not exist: {}".format(source))
    if not source.is_file():
        raise BenchmarkError("archive is not a regular file: {}".format(source))

    stat_before = source.stat()
    source_identity_before = (
        stat_before.st_dev,
        stat_before.st_ino,
        stat_before.st_size,
        stat_before.st_mtime_ns,
    )

    tested = run_checked_command(
        _zstd_test_command(zstd_path, source), history, "original-integrity-test", sample_id
    )
    if tested.returncode != 0:
        detail = tested.stderr.strip() or "zstd returned no diagnostic"
        raise BenchmarkError(
            "original archive failed zstd --test for {}: {}".format(sample_id, detail)
        )

    compressed_sha256 = sha256_file(source)
    compressed_bytes = stat_before.st_size
    decompressed_path = run_dir / "{}.bin".format(sample_id)
    decompressed = run_redirected_command(
        _zstd_decompress_command(zstd_path, source),
        decompressed_path,
        history,
        "original-decompression",
        sample_id,
    )
    if decompressed.returncode != 0:
        detail = decompressed.stderr.strip() or "zstd returned no diagnostic"
        raise BenchmarkError(
            "could not decompress original archive for {}: {}".format(sample_id, detail)
        )

    stat_after = source.stat()
    source_identity_after = (
        stat_after.st_dev,
        stat_after.st_ino,
        stat_after.st_size,
        stat_after.st_mtime_ns,
    )
    if source_identity_after != source_identity_before:
        raise BenchmarkError(
            "archive changed while preparing {}; refusing to benchmark mixed bytes".format(
                sample_id
            )
        )

    return {
        "sample": sample_id,
        "description": description,
        "source_path": str(source),
        "compressed_sha256": compressed_sha256,
        "compressed_bytes": compressed_bytes,
        "zstd_version": zstd_version,
        "decompressed_sha256": sha256_file(decompressed_path),
        "decompressed_bytes": decompressed_path.stat().st_size,
        "_decompressed_path": decompressed_path,
    }


def validate_measured_output(
    output_path: Path,
    expected_sha256: str,
    expected_bytes: int,
    validation_path: Path,
    zstd_path: str,
    history: List[Dict[str, Any]],
    sample: str,
    run: int,
    level: int,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": False,
        "integrity_test_exit_status": None,
        "validation_decompress_exit_status": None,
        "validation_bytes": None,
        "validation_sha256": None,
        "validation_error": None,
    }
    tested = run_checked_command(
        _zstd_test_command(zstd_path, output_path),
        history,
        "measured-integrity-test",
        sample,
    )
    history[-1].update({"run": run, "level": level})
    result["integrity_test_exit_status"] = tested.returncode
    if tested.returncode != 0:
        result["validation_error"] = "zstd --test failed: {}".format(
            tested.stderr.strip() or "no diagnostic"
        )
        return result

    decompressed = run_redirected_command(
        _zstd_decompress_command(zstd_path, output_path),
        validation_path,
        history,
        "measured-validation-decompression",
        sample,
    )
    history[-1].update({"run": run, "level": level})
    result["validation_decompress_exit_status"] = decompressed.returncode
    if decompressed.returncode != 0:
        result["validation_error"] = "validation decompression failed: {}".format(
            decompressed.stderr.strip() or "no diagnostic"
        )
        return result

    validation_bytes = validation_path.stat().st_size
    validation_sha256 = sha256_file(validation_path)
    result["validation_bytes"] = validation_bytes
    result["validation_sha256"] = validation_sha256
    if validation_bytes != expected_bytes:
        result["validation_error"] = (
            "decompressed byte-count mismatch (expected {}, got {})".format(
                expected_bytes, validation_bytes
            )
        )
        return result
    if validation_sha256 != expected_sha256:
        result["validation_error"] = (
            "decompressed SHA-256 mismatch (expected {}, got {})".format(
                expected_sha256, validation_sha256
            )
        )
        return result
    result["valid"] = True
    return result


def valid_results(results: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Return only completed, validated rows used by all statistics."""
    return [row for row in results if row.get("valid") is True and not row.get("interrupted")]


AGGREGATE_METRICS = (
    "compressed_bytes",
    "wall_time_seconds",
    "cpu_total_seconds",
    "peak_rss_bytes",
    "compression_ratio",
    "input_throughput_mib_per_second",
    "cpu_utilization_percent",
)


def _summary(values: Sequence[float]) -> Dict[str, float]:
    return {
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def _relative_delta(value: float, baseline: float) -> Optional[float]:
    return (value - baseline) / baseline if baseline != 0 else None


def _ratio(numerator: float, denominator: float) -> Optional[float]:
    return numerator / denominator if denominator != 0 else None


def aggregate_results(
    results: Sequence[Mapping[str, Any]], baseline: int
) -> List[Dict[str, Any]]:
    """Aggregate valid rows and compare medians with each sample's baseline."""
    grouped_valid: Dict[Tuple[str, int], List[Mapping[str, Any]]] = {}
    grouped_all: Dict[Tuple[str, int], List[Mapping[str, Any]]] = {}
    for row in results:
        key = (str(row["sample"]), int(row["level"]))
        grouped_all.setdefault(key, []).append(row)
    for row in valid_results(results):
        key = (str(row["sample"]), int(row["level"]))
        grouped_valid.setdefault(key, []).append(row)

    aggregates: List[Dict[str, Any]] = []
    by_key: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for key in sorted(grouped_all):
        rows = grouped_valid.get(key, [])
        first = grouped_all[key][0]
        metrics: Dict[str, Dict[str, float]] = {}
        for metric in AGGREGATE_METRICS:
            values = [float(row[metric]) for row in rows if row.get(metric) is not None]
            if values:
                metrics[metric] = _summary(values)
        aggregate = {
            "sample": key[0],
            "sample_description": first.get("sample_description", "unspecified"),
            "level": key[1],
            "baseline": baseline,
            "valid_runs": len(rows),
            "invalid_runs": len(grouped_all[key]) - len(rows),
            "metrics": metrics,
            "comparison_to_baseline": {
                "storage_delta": None,
                "speedup": None,
                "cpu_delta": None,
                "memory_delta": None,
            },
        }
        # Flat median fields keep the machine-readable summary convenient for
        # CSV-like consumers while ``metrics`` retains min/median/max.
        for metric, summary in metrics.items():
            aggregate[metric + "_median"] = summary["median"]
        aggregates.append(aggregate)
        by_key[key] = aggregate

    for aggregate in aggregates:
        base = by_key.get((aggregate["sample"], baseline))
        metrics = aggregate["metrics"]
        if base is None or not base["metrics"]:
            continue
        base_metrics = base["metrics"]
        required = (
            "compressed_bytes",
            "wall_time_seconds",
            "cpu_total_seconds",
            "peak_rss_bytes",
        )
        if any(metric not in metrics or metric not in base_metrics for metric in required):
            continue
        aggregate["comparison_to_baseline"] = {
            "storage_delta": _relative_delta(
                metrics["compressed_bytes"]["median"],
                base_metrics["compressed_bytes"]["median"],
            ),
            "speedup": _ratio(
                base_metrics["wall_time_seconds"]["median"],
                metrics["wall_time_seconds"]["median"],
            ),
            "cpu_delta": _relative_delta(
                metrics["cpu_total_seconds"]["median"],
                base_metrics["cpu_total_seconds"]["median"],
            ),
            "memory_delta": _relative_delta(
                metrics["peak_rss_bytes"]["median"],
                base_metrics["peak_rss_bytes"]["median"],
            ),
        }
        aggregate.update(aggregate["comparison_to_baseline"])
    for aggregate in aggregates:
        # Groups without a usable baseline still expose the same stable shape.
        for name, value in aggregate["comparison_to_baseline"].items():
            aggregate.setdefault(name, value)
    return aggregates


def _extract_cargo_versions(lock_path: Path) -> Dict[str, Optional[str]]:
    versions: Dict[str, Optional[str]] = {
        "zstd_crate": None,
        "zstd_safe_crate": None,
        "zstd_sys_crate": None,
        "libzstd": None,
    }
    if not lock_path.exists():
        return versions
    text = lock_path.read_text(encoding="utf-8")
    for package_name, key in (
        ("zstd", "zstd_crate"),
        ("zstd-safe", "zstd_safe_crate"),
        ("zstd-sys", "zstd_sys_crate"),
    ):
        match = re.search(
            r'\[\[package\]\]\s+name = "{}"\s+version = "([^"]+)"'.format(
                re.escape(package_name)
            ),
            text,
        )
        if match:
            versions[key] = match.group(1)
    sys_version = versions["zstd_sys_crate"]
    if sys_version:
        lib_match = re.search(r"\+zstd\.(\d+\.\d+\.\d+)", sys_version)
        if lib_match:
            versions["libzstd"] = lib_match.group(1)
    return versions


def _parse_zstd_cli_version(version_output: str) -> Optional[str]:
    match = re.search(r"\bv?(\d+\.\d+\.\d+)\b", version_output)
    return match.group(1) if match else None


def _help_supports_flag(help_output: str, flag: str) -> bool:
    """Recognize both literal flags and zstd's --[no-]OPTION notation."""
    if flag in help_output:
        return True
    if flag.startswith("--no-"):
        bracketed = "--[no-]" + flag[len("--no-") :]
        return bracketed in help_output
    return False


def _git_commit(repository_root: Path) -> Optional[str]:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _read_first_matching(path: Path, prefix: str) -> Optional[str]:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(prefix):
                return line.split(":", 1)[-1].strip()
    except OSError:
        return None
    return None


def _sysctl_value(name: str) -> Optional[str]:
    completed = subprocess.run(
        ["sysctl", "-n", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def collect_hardware_metadata() -> Dict[str, Any]:
    system = platform.system()
    cpu_model: Optional[str] = None
    physical_cores: Optional[int] = None
    total_memory_bytes: Optional[int] = None
    hardware_model: Optional[str] = None

    if system == "Darwin":
        cpu_model = _sysctl_value("machdep.cpu.brand_string") or _sysctl_value(
            "hw.model"
        )
        hardware_model = _sysctl_value("hw.model")
        physical = _sysctl_value("hw.physicalcpu")
        memory = _sysctl_value("hw.memsize")
        physical_cores = int(physical) if physical and physical.isdigit() else None
        total_memory_bytes = int(memory) if memory and memory.isdigit() else None
    elif system == "Linux":
        cpu_model = _read_first_matching(Path("/proc/cpuinfo"), "model name")
        memory_kib = _read_first_matching(Path("/proc/meminfo"), "MemTotal")
        if memory_kib:
            match = re.match(r"(\d+)\s+kB", memory_kib)
            if match:
                total_memory_bytes = int(match.group(1)) * 1024

    return {
        "hardware_model": hardware_model,
        "cpu_model": cpu_model or platform.processor() or None,
        "logical_cpu_count": os.cpu_count(),
        "physical_cpu_count": physical_cores,
        "total_memory_bytes": total_memory_bytes,
    }


def collect_metadata(
    repository_root: Path,
    zstd_path: str,
    zstd_version_output: str,
    zstd_help_output: str,
) -> Dict[str, Any]:
    cargo = _extract_cargo_versions(repository_root / "Cargo.lock")
    cli_libzstd = _parse_zstd_cli_version(zstd_version_output)
    archive_source = repository_root / "tools/archive/src/archiver/mod.rs"
    archive_text = (
        archive_source.read_text(encoding="utf-8", errors="replace")
        if archive_source.exists()
        else ""
    )
    constructor_present = bool(
        re.search(r"zstd::Encoder::new\s*\(\s*tracker\s*,", archive_text)
        and re.search(r"use\s+shared::zstd\s*;", archive_text)
    )
    option_markers = {
        "multithread": r"\.multithread\s*\(",
        "checksum": r"\.include_checksum\s*\(",
        "content_size": r"\.include_contentsize\s*\(",
        "window_log": r"\.window_log\s*\(",
        "long_distance_matching": r"\.long_distance_matching\s*\(",
        "dictionary": r"(?:with_|set_)?(?:prepared_)?dictionary",
        "pledged_source_size": r"\.set_pledged_src_size\s*\(",
        "raw_parameter": r"\.set_parameter\s*\(",
    }
    special_options = [
        name
        for name, marker in option_markers.items()
        if re.search(marker, archive_text)
    ]
    required_flags = ("--single-thread", "--no-asyncio", "--no-check", "--ultra")
    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hardware": collect_hardware_metadata(),
        "operating_system": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "platform": platform.platform(),
        },
        "architecture": platform.machine(),
        "peer_observer_commit": _git_commit(repository_root),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "zstd_cli_version": cli_libzstd,
        "zstd_crate_version": cargo["zstd_crate"],
        "repo_libzstd_version": cargo["libzstd"],
        "zstd_cli": {
            "executable": zstd_path,
            "version_output": zstd_version_output.strip(),
            "libzstd_version": cli_libzstd,
        },
        "cargo_versions": cargo,
        "repo_libzstd_version_source": (
            "Cargo.lock zstd-sys version suffix; a build-time "
            "ZSTD_SYS_USE_PKG_CONFIG override cannot be reconstructed after the build"
        ),
        "zstd_sys_use_pkg_config_environment": os.environ.get(
            "ZSTD_SYS_USE_PKG_CONFIG"
        ),
        "archiver_compatibility": {
            "source": "tools/archive/src/archiver/mod.rs",
            "uses_shared_zstd_encoder_new": constructor_present,
            "single_thread": "multithread" not in special_options,
            "special_options": special_options,
            "supported_compression_level_range": {
                "minimum": MIN_ZSTD_LEVEL,
                "maximum": MAX_ZSTD_LEVEL,
            },
            "zero_means_uncompressed": True,
            "cli_flags": list(required_flags),
            "cli_supports_required_flags": all(
                _help_supports_flag(zstd_help_output, flag) for flag in required_flags
            ),
            "repo_libzstd_version": cargo["libzstd"],
            "cli_and_repo_libzstd_match": bool(
                cli_libzstd
                and cargo["libzstd"]
                and cli_libzstd == cargo["libzstd"]
            ),
            "assessment": (
                "The archiver constructs shared::zstd::Encoder with only a level. "
                "The CLI reads stdin as an unknown-size stream; --single-thread "
                "avoids worker threads, --no-asyncio avoids CLI I/O workers, and "
                "--no-check matches the streaming encoder checksum default."
                " The production ArchiveHeader flush boundary is intentionally not "
                "reproduced by this protobuf-agnostic whole-stream benchmark."
            ),
        },
        "rss_normalization": normalize_rss(1),
    }


def ensure_archiver_compatibility(metadata: Mapping[str, Any]) -> None:
    """Reject a run when the local CLI cannot represent the repo encoder."""
    compatibility = metadata["archiver_compatibility"]
    problems = []
    if not compatibility["uses_shared_zstd_encoder_new"]:
        problems.append("shared::zstd::Encoder::new(writer, level) was not detected")
    if not compatibility["single_thread"]:
        problems.append("the archiver enables Zstd worker threads")
    if compatibility["special_options"]:
        problems.append(
            "the archiver sets special encoder options: {}".format(
                ", ".join(compatibility["special_options"])
            )
        )
    if not compatibility["cli_supports_required_flags"]:
        problems.append("the zstd CLI does not advertise every required flag")
    repo_version = compatibility["repo_libzstd_version"]
    cli_version = metadata["zstd_cli"]["libzstd_version"]
    if not repo_version or not cli_version:
        problems.append("the repo or CLI libzstd version could not be determined")
    elif repo_version != cli_version:
        problems.append(
            "CLI libzstd {} differs from repo libzstd {}".format(
                cli_version, repo_version
            )
        )
    if problems:
        raise BenchmarkError(
            "zstd CLI cannot be verified as archiver-compatible; a "
            "shared::zstd helper would be required: {}".format("; ".join(problems))
        )


def _format_bytes(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return "{:.2f} MiB".format(value / MIB)


def _format_seconds(value: Optional[float]) -> str:
    return "n/a" if value is None else "{:.3f}s".format(value)


def _format_percent(value: Optional[float], baseline: bool = False) -> str:
    if baseline:
        return "base"
    return "n/a" if value is None else "{:+.2%}".format(value)


def _format_ratio(value: Optional[float]) -> str:
    return "n/a" if value is None else "{:.2f}x".format(value)


def _metric_range(metrics: Mapping[str, Any], name: str, formatter: Any) -> str:
    metric = metrics.get(name)
    if not metric:
        return "n/a"
    return "{} [{}–{}]".format(
        formatter(metric["median"]), formatter(metric["min"]), formatter(metric["max"])
    )


def render_markdown(payload: Mapping[str, Any]) -> str:
    """Render a path-free public summary using anonymized sample IDs only."""
    metadata = payload["metadata"]
    config = payload["configuration"]
    samples = metadata["samples"]
    aggregates = payload["aggregates"]
    lines = [
        "# Zstandard level benchmark",
        "",
        "This public summary intentionally omits archive paths and filenames. "
        "Samples use anonymized IDs; private source paths remain only in the JSON artifact.",
        "",
        "## Configuration",
        "",
        "- Levels: {}".format(", ".join(str(level) for level in config["levels"])),
        "- Baseline: {}".format(config["baseline"]),
        "- Measured runs per level: {}".format(config["runs"]),
        "- Zstandard: {}".format(metadata["zstd_cli"]["version_output"]),
        "- peer-observer commit: `{}`".format(metadata["peer_observer_commit"] or "unknown"),
        "",
        "## Corpus",
        "",
        "| Sample | General workload | Original SHA-256 | Original size | Decompressed SHA-256 | Input size |",
        "|---|---|---|---:|---|---:|",
    ]
    for sample in samples:
        lines.append(
            "| {} | {} | `{}` | {} | `{}` | {} |".format(
                sample["sample"],
                str(sample["description"]).replace("|", "\\|"),
                sample["compressed_sha256"],
                _format_bytes(sample["compressed_bytes"]),
                sample["decompressed_sha256"],
                _format_bytes(sample["decompressed_bytes"]),
            )
        )

    lines.extend(
        [
            "",
            "## Results",
            "",
            "Statistics use validated runs only. Values are median [minimum–maximum]; "
            "baseline comparisons use the corresponding medians.",
            "",
            "| Sample | Workload | Level | Valid | Size | Storage delta | Wall | Speedup | CPU | CPU delta | Peak RSS | Memory delta | Input throughput | Compression ratio | CPU utilization |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for aggregate in aggregates:
        metrics = aggregate["metrics"]
        comparison = aggregate["comparison_to_baseline"]
        is_baseline = aggregate["level"] == config["baseline"]
        lines.append(
            "| {} | {} | {} | {}/{} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                aggregate["sample"],
                str(aggregate["sample_description"]).replace("|", "\\|"),
                aggregate["level"],
                aggregate["valid_runs"],
                aggregate["valid_runs"] + aggregate["invalid_runs"],
                _metric_range(metrics, "compressed_bytes", _format_bytes),
                _format_percent(comparison["storage_delta"], is_baseline),
                _metric_range(metrics, "wall_time_seconds", _format_seconds),
                _format_ratio(comparison["speedup"]),
                _metric_range(metrics, "cpu_total_seconds", _format_seconds),
                _format_percent(comparison["cpu_delta"], is_baseline),
                _metric_range(metrics, "peak_rss_bytes", _format_bytes),
                _format_percent(comparison["memory_delta"], is_baseline),
                _metric_range(
                    metrics,
                    "input_throughput_mib_per_second",
                    lambda value: "{:.2f} MiB/s".format(value),
                ),
                _metric_range(
                    metrics,
                    "compression_ratio",
                    lambda value: "{:.3f}x".format(value),
                ),
                _metric_range(
                    metrics,
                    "cpu_utilization_percent",
                    lambda value: "{:.1f}%".format(value),
                ),
            )
        )

    lines.extend(
        [
            "",
            "## Actual measured order",
            "",
            "| Sample | Run | Level order |",
            "|---|---:|---|",
        ]
    )
    seen_orders = set()
    for row in payload["raw_results"]:
        key = (row["sample"], row["run"])
        if key in seen_orders:
            continue
        seen_orders.add(key)
        lines.append(
            "| {} | {} | {} |".format(
                row["sample"], row["run"], " → ".join(str(x) for x in row["actual_order"])
            )
        )

    compatibility = metadata["archiver_compatibility"]
    rss = metadata["rss_normalization"]
    lines.extend(
        [
            "",
            "## Method and compatibility",
            "",
            "Each original frame is tested, decompressed once outside the measured region, "
            "and reused byte-for-byte. Each level gets one unreported warmup. Compressors "
            "run sequentially. Every measured output is tested, decompressed, and checked "
            "against the input SHA-256.",
            "",
            "The archiver inspection found `shared::zstd::Encoder::new` with only the writer "
            "and level, so it is single-threaded and has no special encoder options. The CLI "
            "uses stdin plus `--single-thread --no-asyncio --no-check`; levels 20–22 also use "
            "`--ultra`.",
            "",
            "Peak RSS is the compressor child's peak, not the complete archiver's. Also, the "
            "production archiver flushes immediately after `ArchiveHeader`; this whole-stream "
            "benchmark deliberately preserves bytes rather than parsing protobufs, so it does "
            "not recreate that flush boundary and frames need not be byte-identical.",
            "",
            "- Repo libzstd: {}".format(compatibility["repo_libzstd_version"] or "unknown"),
            "- CLI/repo libzstd match: {}".format(
                "yes" if compatibility["cli_and_repo_libzstd_match"] else "no"
            ),
            "- RSS source unit: {}".format(rss["raw_unit"]),
            "- RSS conversion: {}".format(rss["conversion"]),
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend("- " + limitation for limitation in payload["limitations"])
    lines.extend(
        [
            "",
            "This report supports a storage-versus-CPU/memory/time decision; it does not "
            "change the archiver default. An end-to-end NATS benchmark is only warranted if "
            "these offline results are inconclusive or level 22 may not keep up with live load.",
            "",
        ]
    )
    return "\n".join(lines)


def _csv_value(row: Mapping[str, Any], field: str) -> Any:
    value = row.get(field)
    if field == "actual_order" and isinstance(value, list):
        return " ".join(str(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else value


def _atomic_replace_text(destination: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + destination.name + ".", suffix=".tmp", dir=str(destination.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_reports(work_dir: Path, payload: Mapping[str, Any]) -> Dict[str, Path]:
    """Write the three required artifacts atomically into the explicit work dir."""
    work_dir = Path(work_dir)
    csv_destination = work_dir / REPORT_FILENAMES[0]
    json_destination = work_dir / REPORT_FILENAMES[1]
    markdown_destination = work_dir / REPORT_FILENAMES[2]

    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in payload["raw_results"]:
        writer.writerow({field: _csv_value(row, field) for field in CSV_FIELDS})
    _atomic_replace_text(csv_destination, csv_buffer.getvalue())
    _atomic_replace_text(
        json_destination,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n",
    )
    _atomic_replace_text(markdown_destination, render_markdown(payload))
    return {
        "csv": csv_destination,
        "json": json_destination,
        "markdown": markdown_destination,
    }


def _public_sample_metadata(sample: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in sample.items() if not key.startswith("_")}


def run_benchmark(args: argparse.Namespace) -> Tuple[Dict[str, Any], Dict[str, Path], bool]:
    repository_root = Path(__file__).resolve().parents[1]
    work_dir = prepare_work_dir(args.work_dir, repository_root)
    zstd_path = shutil.which("zstd")
    if zstd_path is None:
        raise BenchmarkError("zstd CLI was not found on PATH")
    if not hasattr(os, "wait4"):
        raise BenchmarkError("os.wait4 is unavailable; this script requires macOS or Linux")

    # Resolve archive errors before interrogating zstd so bad inputs always
    # receive the most relevant diagnostic.
    for archive in args.archives:
        resolved_archive = archive.expanduser().resolve()
        if not resolved_archive.exists():
            raise BenchmarkError("archive does not exist: {}".format(resolved_archive))
        if not resolved_archive.is_file():
            raise BenchmarkError("archive is not a regular file: {}".format(resolved_archive))

    commands: List[Dict[str, Any]] = []
    version = run_checked_command([zstd_path, "--version"], commands, "zstd-version")
    if version.returncode != 0:
        raise BenchmarkError("could not query zstd version: {}".format(version.stderr.strip()))
    zstd_version_output = (version.stdout or version.stderr).strip()
    help_result = run_checked_command([zstd_path, "--help"], commands, "zstd-help")
    zstd_help_output = (help_result.stdout or "") + (help_result.stderr or "")
    if help_result.returncode != 0:
        raise BenchmarkError("could not query zstd --help: {}".format(help_result.stderr.strip()))
    metadata = collect_metadata(
        repository_root, zstd_path, zstd_version_output, zstd_help_output
    )
    ensure_archiver_compatibility(metadata)

    run_dir = Path(tempfile.mkdtemp(prefix=".benchmark-zstd-", dir=str(work_dir)))
    raw_results: List[Dict[str, Any]] = []
    samples: List[Dict[str, Any]] = []
    interrupted = False
    try:
        seen_sources = set()
        for index, archive in enumerate(args.archives, start=1):
            resolved = archive.expanduser().resolve()
            if resolved in seen_sources:
                raise BenchmarkError("the same archive was supplied more than once: {}".format(resolved))
            seen_sources.add(resolved)
            sample_id = "sample-{:03d}".format(index)
            try:
                samples.append(
                    prepare_sample(
                        archive=archive,
                        sample_id=sample_id,
                        description=args.sample_descriptions.get(sample_id, "unspecified"),
                        run_dir=run_dir,
                        zstd_path=zstd_path,
                        zstd_version=zstd_version_output,
                        history=commands,
                    )
                )
            except KeyboardInterrupt:
                interrupted = True
                break

        for sample in samples:
            if interrupted:
                break
            input_path = sample["_decompressed_path"]
            # One unreported warmup for every sample/level, in deterministic order.
            for position, level in enumerate(build_level_order(args.levels, 0), start=1):
                output_path = run_dir / "{}-warmup-level-{}.zst".format(sample["sample"], level)
                stderr_path = run_dir / "{}-warmup-level-{}.stderr".format(sample["sample"], level)
                command = build_compression_command(zstd_path, level)
                metrics = run_measured_compression(command, input_path, output_path, stderr_path)
                _record_command(
                    commands,
                    "warmup",
                    command,
                    metrics["exit_status"],
                    sample=sample["sample"],
                    level=level,
                    stdin_path=input_path,
                    stdout_path=output_path,
                )
                output_path.unlink(missing_ok=True)
                stderr_path.unlink(missing_ok=True)
                if metrics["interrupted"]:
                    interrupted = True
                    break
                if metrics["exit_status"] != 0:
                    raise BenchmarkError(
                        "warmup failed for {} at level {}: {}".format(
                            sample["sample"], level, metrics["stderr"] or "no diagnostic"
                        )
                    )
            if interrupted:
                break

            for run_index in range(args.runs):
                order = build_level_order(args.levels, run_index)
                for position, level in enumerate(order, start=1):
                    run_number = run_index + 1
                    stem = "{}-run-{:03d}-pos-{:03d}-level-{}".format(
                        sample["sample"], run_number, position, level
                    )
                    output_path = run_dir / (stem + ".zst")
                    stderr_path = run_dir / (stem + ".stderr")
                    validation_path = run_dir / (stem + ".validated.bin")
                    command = build_compression_command(zstd_path, level)
                    metrics = run_measured_compression(
                        command, input_path, output_path, stderr_path
                    )
                    _record_command(
                        commands,
                        "measured-compression",
                        command,
                        metrics["exit_status"],
                        sample=sample["sample"],
                        run=run_number,
                        level=level,
                        stdin_path=input_path,
                        stdout_path=output_path,
                    )
                    compressed_bytes = output_path.stat().st_size if output_path.exists() else None
                    wall = metrics["wall_time_seconds"]
                    row: Dict[str, Any] = {
                        "sample": sample["sample"],
                        "sample_description": sample["description"],
                        "level": level,
                        "baseline": args.baseline,
                        "run": run_number,
                        "order_position": position,
                        "actual_order": list(order),
                        **{key: value for key, value in metrics.items() if key != "stderr"},
                        "input_bytes": sample["decompressed_bytes"],
                        "compressed_bytes": compressed_bytes,
                        "compression_ratio": (
                            sample["decompressed_bytes"] / compressed_bytes
                            if compressed_bytes
                            else None
                        ),
                        "input_throughput_mib_per_second": (
                            sample["decompressed_bytes"] / MIB / wall if wall > 0 else None
                        ),
                        "zstd_version": zstd_version_output,
                        "zstd_command": _command_display(command, input_path, output_path),
                        "valid": False,
                        "integrity_test_exit_status": None,
                        "validation_decompress_exit_status": None,
                        "validation_bytes": None,
                        "validation_sha256": None,
                        "validation_error": None,
                    }
                    row["throughput_mib_per_second"] = row[
                        "input_throughput_mib_per_second"
                    ]
                    row["command"] = row["zstd_command"]
                    if metrics["interrupted"]:
                        row["validation_error"] = "compressor interrupted"
                        interrupted = True
                    elif metrics["exit_status"] != 0:
                        row["validation_error"] = "compressor failed: {}".format(
                            metrics["stderr"] or "no diagnostic"
                        )
                    else:
                        try:
                            row.update(
                                validate_measured_output(
                                    output_path=output_path,
                                    expected_sha256=sample["decompressed_sha256"],
                                    expected_bytes=sample["decompressed_bytes"],
                                    validation_path=validation_path,
                                    zstd_path=zstd_path,
                                    history=commands,
                                    sample=sample["sample"],
                                    run=run_number,
                                    level=level,
                                )
                            )
                        except KeyboardInterrupt:
                            row["interrupted"] = True
                            row["validation_error"] = "validation interrupted"
                            interrupted = True
                        except OSError as error:
                            row["validation_error"] = "validation operating-system error: {}".format(
                                error
                            )
                    raw_results.append(row)
                    validation_path.unlink(missing_ok=True)
                    output_path.unlink(missing_ok=True)
                    stderr_path.unlink(missing_ok=True)
                    if interrupted:
                        break
                if interrupted:
                    break
            if interrupted:
                break

        metadata["samples"] = [_public_sample_metadata(sample) for sample in samples]
        payload: Dict[str, Any] = {
            "schema_version": 1,
            "configuration": {
                "levels": list(args.levels),
                "baseline": args.baseline,
                "runs": args.runs,
                "work_dir": str(work_dir),
                "schedule": (
                    "two levels alternate; three or more levels rotate after each "
                    "forward/reverse pair"
                ),
                "warmups_per_sample_and_level": 1,
            },
            "metadata": metadata,
            "raw_results": raw_results,
            "aggregates": aggregate_results(raw_results, args.baseline),
            "commands_executed": commands,
            "limitations": list(LIMITATIONS),
            "interrupted": interrupted,
        }
        paths = write_reports(work_dir, payload)
        return payload, paths, interrupted
    finally:
        safe_cleanup_run_dir(run_dir, work_dir)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parse_args(argv)
        payload, paths, interrupted = run_benchmark(args)
    except BenchmarkError as error:
        print("benchmark_zstd.py: error: {}".format(error), file=sys.stderr)
        return 2
    except OSError as error:
        print("benchmark_zstd.py: operating-system error: {}".format(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("benchmark_zstd.py: interrupted", file=sys.stderr)
        return 130

    valid_count = len(valid_results(payload["raw_results"]))
    invalid_count = len(payload["raw_results"]) - valid_count
    print("Validated measured runs: {}; invalid: {}".format(valid_count, invalid_count))
    for name in ("csv", "json", "markdown"):
        print("{}: {}".format(name, paths[name]))
    if interrupted:
        return 130
    if invalid_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
