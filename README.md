# apikeyfinder

Scans Common Crawl WARC archives for leaked API keys with trufflehog, then
browses the results in a terminal UI.

## Pipeline

1. **Plan** — query the Common Crawl CDX index (`[targets]`) for the
   configured URL patterns, probe sizes, and pick WARC files until
   `target_bytes` is reached. The plan is saved in the checkpoint.
2. **Download** — fetch WARC files through a bounded network queue
   (`[download]`) with retries, exponential backoff, and HEAD-probe guards.
3. **Split** — awk splits each WARC into 256-record chunks while applying the
   record filter (`[filter.records]`: response records only, text/json
   payloads, size bounds, WARC/1.0 + Content-Length validation).
4. **Scan** — trufflehog (`[scan]`, `only_verified = true`) runs on each
   chunk. Verified findings are enriched with the host/website, a code
   snippet around the secret, and the enclosing source WARC record, which is
   extracted to `results/artifacts/` for the finding's `artifact` field.
5. **Assemble** — findings live in an in-memory cache (spilling to
   `results/spill/` past `mem_limit_bytes`), are written per WARC to
   `results/partials/`, and are assembled into `results/findings.jsonl`.

Every stage is resumable: `results/checkpoint.json` holds the plan plus
per-WARC completion, so a re-run skips finished WARCs without re-querying the
index. Startup purges stale downloads; SIGINT/SIGTERM/SIGHUP clean up
`work/` and the spill dir and keep the resume state. `results/`
(partials, artifacts, findings) is never touched by cleanup.

Set `targets.unlimited = true` to keep scanning past the end of the plan:
once a batch drains, the pipeline queries the index again for the next
`target_bytes` worth of *unseen* WARCs, appends them to the checkpointed
plan, and continues until you Ctrl-C. If the index has nothing new left, or
an entire batch fails, it finishes cleanly instead of looping.

## Quick start

```sh
cargo build --release
./target/release/apikeyfinder                 # uses ./config.toml
./target/release/apikeyfinder other/config.toml
```

Ctrl-C once: graceful stop, cleanup, resume state preserved. To force a fresh
plan, delete `results/checkpoint.json` (delete `results/partials/` too if you
also want to discard the findings from the old plan).

## Configuration

`config.toml` is commented inline; the knobs you will touch most:

| section | key | meaning |
|---|---|---|
| `targets` | `index_collection` | Common Crawl collection to query |
| `targets` | `url_patterns`, `per_pattern_limit` | breadth of the CDX sampling |
| `targets` | `target_bytes` | total compressed WARC bytes for one run (batch size if `unlimited`) |
| `targets` | `unlimited` | plan another batch after each drain, until Ctrl-C |
| `filter.records` | mime / status / size rules | which records reach trufflehog |
| `download` | `parallel_fetches` | concurrent WARC downloads |
| `scan` | `only_verified` | keep only trufflehog-verified findings |
| `scan` | `workers`, `trufflehog_concurrency` | scan parallelism |
| `scan` | `artifact_max_bytes` | cap on an extracted source record (0 = no cap) |
| `cache` | `mem_limit_bytes`, `final_output` | RAM→spill threshold; output path |
| `paths` | `artifacts_dir`, `partials_dir` | durable outputs (never purged) |

## Findings viewer

```sh
./target/release/findings_viewer                 # TUI (stats report when piped)
./target/release/findings_viewer stats           # plain-text overalls + reports
./target/release/findings_viewer search QUERY    # --regex, --full, --describe
./target/release/findings_viewer dupes           # repeated secrets first
./target/release/findings_viewer -f other.jsonl  # alternate input (repeatable)
```

Findings fall into two buckets: **bad** (worth acting on — JWT, cloud,
unknown detectors) and **trivial** (designed to be public — Algolia
browse/search-only keys, New Relic browser keys, browser-shipping tokens).

### TUI keys

```
j/k, arrows    move                Enter/Space   open / close (or select)
g/G            first / last        Tab           filter: all → bad → trivial
PgUp/PgDn      move by 10          e             export selection to results/exports/
m              toggle mouse capture (click a details line to copy it)
q / Esc        quit                Ctrl+C        quit
```

The details pane shows detector, category, full value, website, source WARC,
code snippet, and (for findings from new scans) the extracted source-record
artifact path. With mouse capture on, the wheel scrolls the pane under the
cursor and a click copies a details line (the value row copies the complete
secret).

## Development

```sh
cargo test                    # unit tests (pipeline + viewer + TUI)
cargo clippy --all-targets
cargo build --release
```
