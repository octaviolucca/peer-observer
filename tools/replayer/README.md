# `replayer`

Reads peer-observer archive files and prints decoded events to stdout.

Supports:
- `.bin`
- `.bin.zst`

## Usage

```bash
cargo run -p replayer -- archive/test.0.bin
cargo run -p replayer -- archive/test.0.bin.zst
cargo run -p replayer -- archive/test.0.bin archive/test.1.bin.zst
```

## Example output

```text
header: version=1 git=abcd1234
[1] ts=1234567890 ebpf: ...
[2] ts=1234567891 ebpf: ...
total: 2 events
```

## Help

```
Read and display peer-observer archive files

Usage: replayer <file.bin[.zst]> [file2.bin[.zst] ...]
```
