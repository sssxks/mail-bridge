# Live memory baseline

Measured on a Linux host on 2026-10-19.
Thirty samples at one-second intervals, normal background operation with no
injected requests, service restart, configuration changes or memory dumping.
Service remained active with NRestarts=0. This is not a maximum-load benchmark
or a long-term leak test.

| Metric | Observed |
| --- | --- |
| smaps RSS | 8,368 KiB (8.17 MiB), unchanged across samples |
| smaps PSS | 6,505 KiB (6.35 MiB), unchanged |
| Private clean + dirty (USS) | 6,272 KiB (6.13 MiB) |
| Anonymous resident pages | 2,008 KiB (1.96 MiB) |
| cgroup memory.current | 7,487,488–7,520,256 bytes (7.14–7.17 MiB) |
| status VmHWM | 10,332 KiB (10.09 MiB), lifetime historical high |
| status VmSize | 149,176 KiB (145.68 MiB), virtual address space |
| Swap / threads / open descriptors | 0 / 1 / 13 |

`status` reported RSS 8,296 KiB; the page-table-based `smaps` result above is
preferred. The small difference is consistent with asynchronous RSS counters.

## RSS composition

Mutually exclusive mapping categories, denominator 8,368 KiB:

| Mapping category | RSS KiB | Share |
| --- | ---: | ---: |
| Main executable, including code, constants and writable data | 4,888 | 58.41% |
| Shared libraries | 2,152 | 25.72% |
| Named heap | 1,128 | 13.48% |
| Other anonymous mappings | 136 | 1.63% |
| Main stack | 60 | 0.72% |
| Kernel special mappings | 4 | 0.05% |

Another partition of the same RSS is private clean 4,264 KiB, private dirty
2,008 KiB, shared clean 2,096 KiB. Do not add these to the mapping categories.
The executable contains 628 KiB anonymous pages; shared libraries contain 56 KiB.
This explains why total anonymous memory exceeds named heap plus anonymous mappings.
Anonymous pages include allocator capacity and mutable data, not just live objects.

First-sample cgroup accounting: anon 2,056,192 bytes, file 5,156,864 bytes,
kernel 278,528 bytes (27.45%, 68.83%, 3.72% respectively). These counters are
not an alternative partition of RSS. File cache and kernel charges are included,
and shared pages are charged differently. Do not sum nested memory.stat counters
such as file_mapped into file, or slab into kernel.

## Optimization priorities

1. For lower idle RSS, inspect executable code/constant pages first. They account
   for 58% of RSS. The release already uses opt-level=z, thin LTO, one codegen unit,
   stripping and panic=abort. Compare fat LTO and dependency feature changes in
   isolated release builds with the same workload. A smaller binary is not proof
   of lower RSS: only touched pages count. Preserve Chinese charset decoding,
   HTML conversion, TLS and event functionality unless a change is intentional.
2. For load peaks, profile full MIME parsing in `crates/mail/src/mime.rs::parse_mail`. It
   obtains an owned body before clipping to 20,000 characters, while the full
   message is still available. Borrowing a decoded text body until clipping may
   avoid one large transient copy. MIME decoding and HTML processing still need
   independent measurement with synthetic near-limit messages and four concurrent
   requests; the 2 MiB input limit is not a 2 MiB allocation limit.
3. `RealBackend::connect` rebuilds the root store and TLS configuration for each
   IMAP connection. Shared configuration may reduce allocation churn and parallel
   duplication, but can retain more memory at idle. Measure before adopting.
4. SQLite cache_size=-1024 is a budget, not a measured 1 MiB allocation. The named
   heap is only 1.10 MiB in total here, including other allocations. Attribute
   SQLite usage with sqlite3_db_status or an isolated heap profile before shrinking
   its cache. This is unlikely to yield multi-MiB idle savings.
5. Keep the current single-thread Tokio runtime. Neither shrinking stack address
   reservations nor changing allocator arena limits has demonstrated RSS value
   in this one-thread sample. Do not tune solely from VmSize.

No production optimization was applied. Repeat idle and post-load sampling,
compare several identical runs, and reject changes without a repeatable gain
or with regressions in latency, Chinese decoding or mailbox/event behavior.
The configured 160 MiB ceiling should not be reduced from this idle measurement.

## Repeat

Run [the sampler](../scripts/measure-memory.py) on the Linux host with permission
to read the service's smaps and cgroup. It reads accounting only, never process
memory, environment, mailbox data or credentials:

```bash
sudo python3 scripts/measure-memory.py --samples 30 --interval 1
```

Local raw output is excluded under `.research/memory/`. The final script was also
run successfully for one additional live sample after fixing rollup-header parsing.

References: [Linux proc accounting](https://docs.kernel.org/filesystems/proc.html),
[cgroup v2 memory accounting](https://docs.kernel.org/admin-guide/cgroup-v2.html).
