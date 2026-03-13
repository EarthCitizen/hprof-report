# hprof-report

Standalone Python CLI for analyzing JVM `.hprof` heap dumps and reporting what is using RAM that cannot be garbage collected.

It does this by:
- parsing HPROF heap data into an object graph
- finding objects reachable from GC roots (non-collectable at snapshot time)
- ranking top classes by shallow bytes
- estimating per-object retained bytes with a dominator-tree calculation

## Requirements

- Python 3.11+

## Install

```bash
pip install -e .
```

## Usage

Use the wrapper script to run analysis. It bootstraps local `.venv`, installs requirements, and executes the CLI:

```bash
./run_hprof_report.sh /path/to/heapdump.hprof
```

`run_hprof_report.sh` defaults to `--engine disk` and `--workers 4` (override with CLI flags, `HPROF_ENGINE`, or `HPROF_WORKERS`).
By default, the script places cache and disk-engine temp files under `./.hprof-cache/`:
- results cache: `./.hprof-cache/results`
- disk temp/work files: `./.hprof-cache/tmp`

Optional flags:

```bash
./run_hprof_report.sh /path/to/heapdump.hprof --top 30
./run_hprof_report.sh /path/to/heapdump.hprof --format json
./run_hprof_report.sh /path/to/heapdump.hprof --engine disk --work-dir /tmp/hprof-work
./run_hprof_report.sh /path/to/heapdump.hprof --workers 8
./run_hprof_report.sh /path/to/heapdump.hprof --no-dominator
./run_hprof_report.sh /path/to/heapdump.hprof --include-unreachable-roots
./run_hprof_report.sh /path/to/heapdump.hprof --cache-dir ./.hprof-cache/results
./run_hprof_report.sh /path/to/heapdump.hprof --no-cache
./run_hprof_report.sh /path/to/heapdump.hprof --max-memory-gb 24
./run_hprof_report.sh /path/to/heapdump.hprof --verbose
```

`--verbose` prints periodic progress and phase timing to stderr so you can tell it is still working on large dumps, including `worker=<n>` tags for parallel phases.

## Example Output (text)

```text
File: /tmp/heap.hprof
Objects parsed: 8,391,223
GC roots: 31,102
Total shallow heap: 3.12 GiB
Non-collectable shallow heap: 2.44 GiB (6,812,904 objects reachable from GC roots)

Top classes by non-collectable shallow size:
   #    Objects     Shallow  Type
   1  1,942,511   824.12 MiB  byte[]
   2    581,223   401.90 MiB  java.lang.String
   3    211,888   271.73 MiB  com.myapp.CacheEntry

Top object retainers (approximate retained size):
   #    Retained     Shallow           Object ID  Type
   1  1.14 GiB      56 B              0x7f8c99a8  com.myapp.BigCache
      held_by: GC_ROOT
      chain: GC_ROOT -> 0x7f8c99a8(com.myapp.BigCache)
   2  0.63 GiB      80 B              0x7f2d11c0  java.util.HashMap
      held_by: 0x7f8c99a8 com.myapp.BigCache
      chain: GC_ROOT -> 0x7f8c99a8(com.myapp.BigCache) -> 0x7f2d11c0(java.util.HashMap)
```

## Notes and limitations

- Reported sizes are based on payload bytes present in HPROF records:
  - instances: `INSTANCE_DUMP` payload length
  - object arrays: `length * id_size`
  - primitive arrays: `length * primitive_size`
- Object-header and alignment overhead are not reconstructed, so values are best for relative ranking.
- Dominator retained sizes are approximate and can be expensive on very large dumps; use `--no-dominator` for faster class-only output.
- `--engine disk` stores dominator adjacency in memory-mapped CSR temp files instead of Python list-of-lists.
- `--work-dir` controls where `--engine disk` temp files are created.
- `--workers` controls parallel parser/analysis phases (class summary, deferred-instance resolution, and disk successor materialization).
- `--cache` / `--no-cache` controls result caching keyed by heap file hash + analysis options.
- `--cache-dir` controls where cached analysis results are stored.
- `--max-memory-gb` sets a soft budget for dominator edge indexing (defaults to 45% of detected system RAM).
- If dominator edge indexing runs out of memory, analysis now falls back to class-only output instead of aborting.
- For very large dumps, use `--verbose` to monitor parser/analysis progress and timings.
- Parser supports standard HPROF records used by HotSpot/OpenJDK heap dumps (`STRING`, `LOAD_CLASS`, `HEAP_DUMP`, `HEAP_DUMP_SEGMENT` and core heap sub-records).

## Development

Run tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
