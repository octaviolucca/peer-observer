# `replayer`

Reads peer-observer archive files (`.bin` or `.bin.zst`) and prints decoded
events to stdout.

## Usage

```bash
# print decoded events
cargo run -p replayer -- archive.0.bin.zst

# multiple files
cargo run -p replayer -- archive.0.bin.zst archive.1.bin.zst

# list peers sorted by message count
cargo run -p replayer -- archive.0.bin.zst --list-peers

# generate a mermaid sequence diagram
cargo run -p replayer -- archive.0.bin.zst --sequence-diagram

# filter diagram to specific peers
cargo run -p replayer -- archive.0.bin.zst --sequence-diagram --peer 1 --peer 3

# write diagram as self-contained HTML
cargo run -p replayer -- archive.0.bin.zst --sequence-diagram --html diagram.html

# write P2P events as CSV
cargo run -p replayer -- archive.0.bin.zst --csv events.csv

# filter events by timestamp (milliseconds)
cargo run -p replayer -- archive.0.bin.zst --from 1703001600000 --to 1703001700000
```

Note: `--sequence-diagram`, `--html`, and `--csv` only work with a single archive file.
