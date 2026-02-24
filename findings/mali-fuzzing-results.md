# Mali r7p0 Fuzzing Results

**Target:** Samsung SM-T377A (Galaxy Tab A), Mali T720 (r7p0-03rel0), kernel 3.10.9  
**Fuzzer:** `mali_fuzz_full.c` — full-coverage ioctl fuzzer  
**Date:** 2026-02-23

## Summary

| Metric | Value |
|--------|-------|
| Total iterations | 5,100 (100 smoke + 5,000 stress) |
| Total ioctl operations | 29,744 |
| Unique function IDs exercised | 24 of ~50 dispatchable |
| Use-after-free attempts | 396 |
| Double-free attempts | 152 |
| Kernel crashes | **0** |
| Kernel BUG()/oops | **0** |
| Userspace signal recoveries | 0 |

## Op Distribution (5K run, seed=0xcafebabe)

| Operation | Count | Notes |
|-----------|-------|-------|
| MEM_ALLOC | 4,160 | With flag mutation, boundary pages, over-commit |
| PROFILING_CTRL | 4,069 | GET/SET_PROFILING_CONTROLS |
| MEM_QUERY | 3,943 | All 3 query types + fuzzed addrs |
| RAW_FUZZ | 2,997 | Random func_id + random size + random payload |
| MEM_FREE | 2,400 | Including freed-VA and fuzzed-addr variants |
| MEM_FLAGS_CHANGE | 1,857 | Wild flag/mask combinations on live allocs |
| MEM_COMMIT | 1,294 | Over-commit, zero-commit tested |
| TLSTREAM_ACQUIRE | 809 | Not supported (returns "unknown ioctl") |
| HWCNT_SETUP | 777 | Security-gated (EFAULT expected) |
| JOB_SUBMIT | 745 | No valid job atoms (uk_ret=3 expected) |
| MEM_ALLOC_CAP | 726 | Skipped due to memory cap |
| DESTROY_SURFACE | 719 | Samsung vendor dispatch |
| SYNC | 657 | Type 0-3 tested; type 3 rejected as "unknown msync op" |
| KEEP_GPU_POWERED | 649 | Deprecated on this build |
| FIND_CPU_OFFSET | 619 | No valid mappings found (uk_ret=3) |
| STREAM_CREATE | 597 | fd returned and closed |
| MEM_QUERY_UAF | 396 | Use-after-free: query on freed VA |
| SET/UNSET_MIN_LOCK | 720 | Samsung DVFS lock (not compiled in) |
| MEM_FREE_DOUBLE | 152 | Double-free attempts |

## Findings from dmesg

No kernel panics, BUGs, or oopses. Driver error log:

1. **`unknown ioctl 544`** — TLSTREAM_ACQUIRE not available (disabled in build config)
2. **`unknown ioctl 555`** — UNSET_MIN_LOCK not dispatched (Samsung-specific `#ifdef` not enabled)
3. **`KEEP_GPU_POWERED: function is deprecated and disabled`** — known deprecation
4. **`Unknown msync op 3`** — SYNC type values 0-2 valid; 3 rejected
5. **`Wrong syscall size (N) for XXXXX`** — RAW_FUZZ sends intentionally wrong sizes; driver rejects cleanly
6. **`Can't find CPU mapping`** — FIND_CPU_OFFSET with invalid mapping; expected failure
7. **`kbase_mem_alloc called with bad flags`** — Intentional flag mutation; driver checks flags
8. **`stop latency exceeded`** — GPU PM timing; unrelated to fuzzing

## Mutation Strategy

### Memory allocation mutations
- Flag bit-flipping (1-2 random bits in lower 32)
- Boundary page counts: 0, 1, 2, 15, 16, 17, 32, 64, 128, 256, 1024
- commit_pages > va_pages (over-commit)
- va_pages = 0 (zero-page alloc)
- va_pages = 0xFFFFFFFF (huge VA)
- All flags set (0xFFFFFFFFFFFFFFFF)
- Zero flags (known-bad)
- Non-zero va_alignment
- Non-zero extent

### Memory lifecycle mutations
- Use-after-free: MEM_QUERY on freed VA (20% of freed allocs retained in table)
- Double-free: MEM_FREE on already-freed VA
- Address fuzzing: XOR low bits of valid gpu_va
- Cross-query: COMMIT_SIZE, VA_SIZE, FLAGS, and invalid query types
- MEM_FLAGS_CHANGE: Wild mask/flag combos on live allocs
- MEM_COMMIT: Over-commit, zero-commit on live allocs

### Context lifecycle
- Periodic fd close + reopen + re-handshake (~every 500 iterations)
- Tests kernel context cleanup paths

### Raw chaos
- Random func_id from full ID space (including unknown 999)
- Random payload size (8 to CALL_MAX_SIZE)
- Random payload bytes
- Tests `copy_from_user` error paths and `bad_size` dispatch

## Conclusions

The Mali T720 r7p0 kbase driver on this Samsung kernel (3.10.9, SPL 2017-07-01) is **robust against
userspace ioctl fuzzing from an unprivileged shell context**:

1. **Size validation** is strict — `sizeof(expected) != args_size → reject`
2. **Flag validation** rejects invalid combinations before allocation
3. **Address validation** catches stale/invalid gpu_va before use
4. **Double-free** returns uk_ret=3 (FUNCTION_FAILED), no kernel corruption
5. **Use-after-free queries** return uk_ret=3, no info leak from freed objects
6. **Security-gated functions** (HWCNT_SETUP, HWCNT_DUMP) deny unprivileged access
7. **Context cleanup** on fd close appears to free all allocations properly
8. **copy_from_user failures** return -EFAULT without kernel state corruption

### Attack surface notes
- The driver **does not validate** that `commit_pages <= va_pages` at the ioctl level — it returns success but may handle internally
- `MEM_FLAGS_CHANGE` reaches deep into the driver before failing on invalid masks — a complex code path worth deeper review
- `SYNC` with user-supplied addresses could be interesting with valid mmap'd regions
- The Samsung vendor dispatch (`gpu_vendor_dispatch`) is a separate attack surface with less-tested code paths
- `STREAM_CREATE` returns a real fd — potential for fd exhaustion DoS
