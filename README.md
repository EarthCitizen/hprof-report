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

```bash
hprof-report /path/to/heapdump.hprof
```

Run without installing (from repository root):

```bash
python3 -m hprof_report.cli /path/to/heapdump.hprof
```

Optional flags:

```bash
hprof-report /path/to/heapdump.hprof --top 30
hprof-report /path/to/heapdump.hprof --format json
hprof-report /path/to/heapdump.hprof --no-dominator
hprof-report /path/to/heapdump.hprof --include-unreachable-roots
hprof-report /path/to/heapdump.hprof --verbose
```

`--verbose` prints periodic progress and phase timing to stderr so you can tell it is still working on large dumps.

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
   2  0.63 GiB      80 B              0x7f2d11c0  java.util.HashMap
```

## Notes and limitations

- Reported sizes are based on payload bytes present in HPROF records:
  - instances: `INSTANCE_DUMP` payload length
  - object arrays: `length * id_size`
  - primitive arrays: `length * primitive_size`
- Object-header and alignment overhead are not reconstructed, so values are best for relative ranking.
- Dominator retained sizes are approximate and can be expensive on very large dumps; use `--no-dominator` for faster class-only output.
- For very large dumps, use `--verbose` to monitor parser/analysis progress and timings.
- Parser supports standard HPROF records used by HotSpot/OpenJDK heap dumps (`STRING`, `LOAD_CLASS`, `HEAP_DUMP`, `HEAP_DUMP_SEGMENT` and core heap sub-records).

## Development

Run tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
