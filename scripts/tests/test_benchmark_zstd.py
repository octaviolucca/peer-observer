#!/usr/bin/env python3
"""Black-box and unit tests for scripts/benchmark_zstd.py."""

from __future__ import annotations

import csv
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts" / "benchmark_zstd.py"
MAGIC = b"FAKEZSTD"


FAKE_ZSTD = r'''
import json
import os
from pathlib import Path
import re
import struct
import sys

MAGIC = b"FAKEZSTD"
args = sys.argv[1:]

log_path = os.environ.get("FAKE_ZSTD_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(args) + "\n")

if "--version" in args or "-V" in args:
    print("*** Zstandard CLI (64-bit) v1.5.7, by Fake ***")
    raise SystemExit(0)

if "--help" in args or "-h" in args:
    print(
        "fake zstd supports levels 1 through 22: "
        "--single-thread --no-asyncio --no-check --ultra"
    )
    raise SystemExit(0)

def output_path():
    for index, arg in enumerate(args):
        if arg in ("-o", "--output") and index + 1 < len(args):
            return Path(args[index + 1])
        if arg.startswith("--output="):
            return Path(arg.split("=", 1)[1])
    return None

def input_path(output, *, required):
    skipped = False
    candidates = []
    for index, arg in enumerate(args):
        if skipped:
            skipped = False
            continue
        if arg in ("-o", "--output"):
            skipped = True
            continue
        if arg == "-":
            continue
        if arg.startswith("-") or (output is not None and Path(arg) == output):
            continue
        candidate = Path(arg)
        if candidate.is_file():
            candidates.append(candidate)
    if not candidates and required:
        print("fake zstd: missing input", file=sys.stderr)
        raise SystemExit(2)
    return candidates[-1] if candidates else None

def decode(path):
    encoded = path.read_bytes()
    if not encoded.startswith(MAGIC) or len(encoded) < len(MAGIC) + 8:
        raise ValueError("invalid fake zstd stream")
    size = struct.unpack(">Q", encoded[len(MAGIC):len(MAGIC) + 8])[0]
    start = len(MAGIC) + 8
    if len(encoded) < start + size:
        raise ValueError("truncated fake zstd stream")
    return encoded[start:start + size]

out = output_path()
testing = "--test" in args or "-t" in args
decompressing = "--decompress" in args or "-d" in args
source = input_path(out, required=testing or decompressing)

if testing:
    try:
        decode(source)
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0)

to_stdout = "--stdout" in args or "-c" in args
if decompressing:
    try:
        result = decode(source)
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
else:
    level = 3
    for arg in args:
        match = re.fullmatch(r"-(-?\d+)", arg)
        if match:
            level = int(match.group(1))
        elif arg.startswith("--compression-level="):
            level = int(arg.split("=", 1)[1])
    payload = source.read_bytes() if source is not None else sys.stdin.buffer.read()
    padding = b"P" * max(0, 24 - level)
    result = MAGIC + struct.pack(">Q", len(payload)) + payload + padding
    corrupt_level = os.environ.get("FAKE_ZSTD_CORRUPT_LEVEL")
    if corrupt_level is not None and int(corrupt_level) == level:
        result = b"CORRUPT" + result

if to_stdout:
    sys.stdout.buffer.write(result)
elif out is not None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(result)
else:
    print("fake zstd: missing output", file=sys.stderr)
    raise SystemExit(2)
'''


def encode_fake_zstd(payload: bytes, *, padding: int = 0) -> bytes:
    return MAGIC + struct.pack(">Q", len(payload)) + payload + (b"P" * padding)


def load_benchmark_module():
    spec = importlib.util.spec_from_file_location("benchmark_zstd_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BenchmarkHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = load_benchmark_module()

    def test_two_level_order_is_balanced_and_deterministic(self) -> None:
        order = self.benchmark.build_level_order
        self.assertEqual(order([19, 22], 0), [19, 22])
        self.assertEqual(order([19, 22], 1), [22, 19])
        self.assertEqual(order([19, 22], 2), [19, 22])
        self.assertEqual(order([19, 22], 3), [22, 19])
        self.assertEqual(order([19, 22], 3), order([19, 22], 3))

    def test_multi_level_order_rotates_and_reverses_deterministically(self) -> None:
        levels = [3, 18, 19, 20, 21, 22]
        orders = [
            self.benchmark.build_level_order(levels, run_index)
            for run_index in range(len(levels) * 2)
        ]
        for generated in orders:
            self.assertEqual(sorted(generated), sorted(levels))
        self.assertEqual(
            orders,
            [
                self.benchmark.build_level_order(levels, run_index)
                for run_index in range(len(levels) * 2)
            ],
        )
        self.assertGreaterEqual(len({tuple(item) for item in orders}), len(levels))
        self.assertTrue(any(item == list(reversed(levels)) for item in orders))

    def test_normalize_rss_handles_macos_and_linux_units(self) -> None:
        macos = self.benchmark.normalize_rss(4096, "darwin")
        self.assertEqual(macos["raw"], 4096)
        self.assertEqual(macos["raw_unit"], "bytes")
        self.assertEqual(macos["bytes"], 4096)
        self.assertIn("byte", macos["conversion"].lower())

        linux = self.benchmark.normalize_rss(4096, "linux")
        self.assertEqual(linux["raw"], 4096)
        self.assertIn(linux["raw_unit"].lower(), {"kib", "kb", "kilobytes"})
        self.assertEqual(linux["bytes"], 4096 * 1024)
        self.assertIn("1024", linux["conversion"])

    def test_compatibility_requires_matching_libzstd_and_encoder_settings(self) -> None:
        metadata = {
            "zstd_cli": {"libzstd_version": "1.5.7"},
            "archiver_compatibility": {
                "uses_shared_zstd_encoder_new": True,
                "single_thread": True,
                "special_options": [],
                "cli_supports_required_flags": True,
                "repo_libzstd_version": "1.5.7",
            },
        }
        self.benchmark.ensure_archiver_compatibility(metadata)

        metadata["zstd_cli"]["libzstd_version"] = "1.5.8"
        with self.assertRaisesRegex(self.benchmark.BenchmarkError, "differs"):
            self.benchmark.ensure_archiver_compatibility(metadata)

        metadata["zstd_cli"]["libzstd_version"] = "1.5.7"
        metadata["archiver_compatibility"]["special_options"] = ["checksum"]
        with self.assertRaisesRegex(self.benchmark.BenchmarkError, "special"):
            self.benchmark.ensure_archiver_compatibility(metadata)

    def test_interrupted_child_escalates_without_popen_polling(self) -> None:
        usage = object()
        expected = (1234, 15, usage)
        with mock.patch.object(self.benchmark.os, "kill") as kill, mock.patch.object(
            self.benchmark,
            "_wait4_retry_eintr",
            side_effect=[KeyboardInterrupt(), expected],
        ):
            actual = self.benchmark._terminate_and_wait4(1234)

        self.assertEqual(actual, expected)
        self.assertEqual(
            kill.call_args_list,
            [
                mock.call(1234, self.benchmark.signal.SIGTERM),
                mock.call(1234, self.benchmark.signal.SIGKILL),
            ],
        )

    def test_invalid_runs_are_excluded_before_aggregation(self) -> None:
        rows = [
            {
                "sample": "tiny",
                "level": 19,
                "baseline": 22,
                "run": 1,
                "valid": True,
                "compressed_bytes": 110,
                "wall_time_seconds": 2.0,
                "cpu_total_seconds": 1.5,
                "peak_rss_bytes": 1100,
            },
            {
                "sample": "tiny",
                "level": 19,
                "baseline": 22,
                "run": 2,
                "valid": False,
                "compressed_bytes": 1,
                "wall_time_seconds": 0.01,
                "cpu_total_seconds": 0.01,
                "peak_rss_bytes": 1,
                "validation_error": "hash mismatch",
            },
            {
                "sample": "tiny",
                "level": 22,
                "baseline": 22,
                "run": 1,
                "valid": True,
                "compressed_bytes": 100,
                "wall_time_seconds": 3.0,
                "cpu_total_seconds": 2.0,
                "peak_rss_bytes": 1000,
            },
        ]
        filtered = self.benchmark.valid_results(rows)
        self.assertEqual(len(filtered), 2)
        self.assertNotIn(rows[1], filtered)

        aggregates = self.benchmark.aggregate_results(rows, 22)
        level_19 = next(item for item in aggregates if item["level"] == 19)
        self.assertEqual(level_19["valid_runs"], 1)
        self.assertEqual(level_19["metrics"]["compressed_bytes"]["median"], 110)
        comparison = level_19["comparison_to_baseline"]
        self.assertAlmostEqual(comparison["storage_delta"], 0.10)
        self.assertAlmostEqual(comparison["speedup"], 1.5)


class BenchmarkCliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.fake_zstd = self.bin_dir / "zstd"
        self.fake_zstd.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent(FAKE_ZSTD),
            encoding="utf-8",
        )
        self.fake_zstd.chmod(
            self.fake_zstd.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
        self.work_dir = self.root / "work"
        self.archive = self.root / "tiny.bin.zst"
        self.payload = (b"peer-observer-test-data\x00" * 8) + bytes(range(64))
        self.archive.write_bytes(encode_fake_zstd(self.payload, padding=4))
        self.log_path = self.root / "zstd-commands.jsonl"

    def run_benchmark(
        self,
        arguments: list[str],
        *,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(self.bin_dir), environment.get("PATH", "")]
        )
        environment["FAKE_ZSTD_LOG"] = str(self.log_path)
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=REPOSITORY,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def common_arguments(
        self,
        *,
        levels: tuple[int, ...] = (1, 2),
        baseline: int = 2,
        runs: int = 1,
        archive: Path | None = None,
        work_dir: Path | None = None,
    ) -> list[str]:
        return [
            "--levels",
            *(str(level) for level in levels),
            "--baseline",
            str(baseline),
            "--runs",
            str(runs),
            "--work-dir",
            str(work_dir or self.work_dir),
            str(archive or self.archive),
        ]

    def assert_cli_error(self, arguments: list[str], pattern: str) -> None:
        completed = self.run_benchmark(arguments)
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertRegex(completed.stdout + completed.stderr, pattern)

    def test_rejects_baseline_missing_from_levels(self) -> None:
        self.assert_cli_error(
            self.common_arguments(levels=(1, 2), baseline=3),
            r"(?is)baseline.*levels",
        )

    def test_rejects_zero_and_non_integer_levels(self) -> None:
        self.assert_cli_error(
            self.common_arguments(levels=(0, 2), baseline=2),
            r"(?is)level.*0|0.*level",
        )
        arguments = self.common_arguments()
        level_index = arguments.index("1")
        arguments[level_index] = "fast"
        self.assert_cli_error(arguments, r"(?is)invalid.*int|level")

        self.assert_cli_error(
            self.common_arguments(levels=(2, 23), baseline=2),
            r"(?is)levels?.*(between|22)|23.*(invalid|level)",
        )
        self.assert_cli_error(
            self.common_arguments(levels=(2, 2), baseline=2),
            r"(?is)levels?.*duplicate|duplicate.*levels?",
        )

    def test_rejects_non_positive_run_count(self) -> None:
        self.assert_cli_error(
            self.common_arguments(runs=0),
            r"(?is)runs.*positive|runs.*greater|runs.*[1-9]",
        )

    def test_rejects_missing_or_misnamed_archive(self) -> None:
        self.assert_cli_error(
            self.common_arguments(archive=self.root / "missing.bin.zst"),
            r"(?is)archive.*(exist|file)|does not exist|not found",
        )
        misnamed = self.root / "tiny.zst"
        misnamed.write_bytes(self.archive.read_bytes())
        self.assert_cli_error(
            self.common_arguments(archive=misnamed),
            r"(?is)archive.*bin\.zst|\.bin\.zst",
        )
        corrupt = self.root / "corrupt.bin.zst"
        corrupt.write_bytes(b"not a compressed stream")
        self.assert_cli_error(
            self.common_arguments(archive=corrupt),
            r"(?is)(archive.*failed|failed.*archive).*zstd|zstd.*test",
        )

    def test_tiny_archive_end_to_end_writes_complete_reports(self) -> None:
        completed = self.run_benchmark(
            self.common_arguments(levels=(1, 2), baseline=2, runs=2)
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"stdout:\n{completed.stdout}\n\nstderr:\n{completed.stderr}",
        )

        csv_path = self.work_dir / "benchmark-results.csv"
        json_path = self.work_dir / "benchmark-results.json"
        markdown_path = self.work_dir / "benchmark-summary.md"
        for report in (csv_path, json_path, markdown_path):
            self.assertTrue(report.is_file(), f"missing report: {report}")
            self.assertGreater(report.stat().st_size, 0)

        with csv_path.open(newline="", encoding="utf-8") as stream:
            csv_rows = list(csv.DictReader(stream))
        self.assertEqual(len(csv_rows), 4)
        required_columns = {
            "sample",
            "level",
            "baseline",
            "run",
            "order_position",
            "wall_time_seconds",
            "cpu_user_seconds",
            "cpu_system_seconds",
            "cpu_total_seconds",
            "cpu_utilization_percent",
            "peak_rss_raw",
            "peak_rss_raw_unit",
            "peak_rss_bytes",
            "input_bytes",
            "compressed_bytes",
            "compression_ratio",
            "input_throughput_mib_per_second",
            "zstd_version",
            "zstd_command",
            "exit_status",
            "valid",
            "validation_error",
        }
        self.assertTrue(required_columns.issubset(csv_rows[0]))
        self.assertTrue(all(row["valid"].lower() == "true" for row in csv_rows))
        self.assertEqual({int(row["level"]) for row in csv_rows}, {1, 2})

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertTrue(
            {"raw_results", "aggregates", "metadata", "commands_executed"}.issubset(
                payload
            )
        )
        self.assertEqual(len(payload["raw_results"]), 4)
        self.assertTrue(all(row["valid"] for row in payload["raw_results"]))
        self.assertEqual(len(payload["aggregates"]), 2)

        results_by_run: dict[int, list[dict[str, object]]] = {}
        for result in payload["raw_results"]:
            results_by_run.setdefault(int(result["run"]), []).append(result)
        actual_orders = []
        for run in sorted(results_by_run):
            ordered = sorted(
                results_by_run[run], key=lambda result: int(result["order_position"])
            )
            actual_orders.append([int(result["level"]) for result in ordered])
        self.assertEqual(actual_orders, [[1, 2], [2, 1]])

        serialized_metadata = json.dumps(payload["metadata"], sort_keys=True)
        self.assertIn(hashlib.sha256(self.archive.read_bytes()).hexdigest(), serialized_metadata)
        self.assertIn(hashlib.sha256(self.payload).hexdigest(), serialized_metadata)
        for expected_metadata in (
            "hardware",
            "operating_system",
            "architecture",
            "peer_observer_commit",
            "python_version",
            "zstd_cli",
            "cargo_versions",
            "archiver_compatibility",
            "rss_normalization",
            "samples",
        ):
            self.assertIn(expected_metadata, payload["metadata"])
        self.assertIn("zstd_crate", payload["metadata"]["cargo_versions"])
        self.assertIn(
            "repo_libzstd_version",
            payload["metadata"]["archiver_compatibility"],
        )

        markdown = markdown_path.read_text(encoding="utf-8")
        self.assertIn("sample-001", markdown)
        self.assertRegex(markdown, r"(?i)baseline|base")
        for limitation in ("NATS", "backlog", "pacing", "protobuf"):
            self.assertIn(limitation, markdown)

        logged_commands = [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]
        compression_commands = [
            command
            for command in logged_commands
            if "--single-thread" in command
            and "--decompress" not in command
            and "-d" not in command
            and "--test" not in command
            and "-t" not in command
        ]
        self.assertGreaterEqual(len(compression_commands), 6)
        self.assertTrue(
            all(str(self.archive) not in command for command in compression_commands)
        )
        original_decompressions = [
            command
            for command in logged_commands
            if str(self.archive.resolve()) in command
            and ("--decompress" in command or "-d" in command)
        ]
        self.assertEqual(len(original_decompressions), 1)

    def test_invalid_measured_output_is_reported_but_not_aggregated(self) -> None:
        completed = self.run_benchmark(
            self.common_arguments(levels=(1, 2), baseline=2, runs=2),
            extra_environment={"FAKE_ZSTD_CORRUPT_LEVEL": "1"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(
            completed.stdout + completed.stderr,
            r"(?is)invalid.*2|2.*invalid",
        )

        csv_path = self.work_dir / "benchmark-results.csv"
        json_path = self.work_dir / "benchmark-results.json"
        markdown_path = self.work_dir / "benchmark-summary.md"
        for report in (csv_path, json_path, markdown_path):
            self.assertTrue(report.is_file(), f"missing report after invalid run: {report}")

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        raw_level_1 = [
            row for row in payload["raw_results"] if int(row["level"]) == 1
        ]
        self.assertEqual(len(raw_level_1), 2)
        self.assertTrue(all(row["valid"] is False for row in raw_level_1))
        self.assertTrue(all(row["validation_error"] for row in raw_level_1))
        self.assertTrue(
            all(row["integrity_test_exit_status"] != 0 for row in raw_level_1)
        )

        aggregate = next(
            item for item in payload["aggregates"] if int(item["level"]) == 1
        )
        self.assertEqual(aggregate["valid_runs"], 0)
        self.assertEqual(aggregate["invalid_runs"], 2)
        self.assertEqual(aggregate["metrics"], {})
        self.assertTrue(
            all(
                value is None
                for value in aggregate["comparison_to_baseline"].values()
            )
        )

        with csv_path.open(newline="", encoding="utf-8") as stream:
            csv_rows = list(csv.DictReader(stream))
        invalid_csv_rows = [row for row in csv_rows if row["level"] == "1"]
        self.assertEqual(len(invalid_csv_rows), 2)
        self.assertTrue(all(row["valid"] == "false" for row in invalid_csv_rows))

        markdown = markdown_path.read_text(encoding="utf-8")
        self.assertRegex(markdown, r"(?m)^\| sample-001 \| .* \| 1 \| 0/2 \|")


if __name__ == "__main__":
    unittest.main()
