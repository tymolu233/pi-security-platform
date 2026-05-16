# IDA Multi-MCP Usage Guide (RE agents only)

> **Audience**: `re-triage`, `re-static`, `re-dynamic`, `re-symbolic`, `pwn-exploit`. Other agents do not have access.
>
> **Source**: <https://github.com/MeroZemory/ida-multi-mcp>

## Why IDA via MCP

`ida-multi-mcp` exposes IDA Pro to subagents as MCP tools. It is **the ONLY binary-related toolchain that runs locally (not in the sandbox)** — IDA Pro is installed on the host. Use it when sandbox r2/ghidra output is insufficient.

### When to use IDA vs sandbox r2

| Situation | Tool |
|---|---|
| **Any static analysis task (default)** | **IDA** (Hex-Rays decompile is primary) |
| Quick `strings` / `file` / `rabin2` during triage | sandbox (faster, no IDA overhead) |
| IDA doesn't support the arch (exotic custom ISA) | sandbox r2 |
| Batch scripting across 100+ functions (r2pipe) | sandbox r2 |
| `idalib_open` fails (license/Python issue) | sandbox r2 as fallback |
| Need to RUN the binary (debug/trace/hook) | sandbox (gdb/frida/ltrace) — but plan with IDA first |

**Rule: IDA is the default for static analysis. r2 is the fallback, not the other way around.**

## Instance lifecycle

Every IDA tool call requires an `instance_id`. There are two ways to get one:

### A. Headless (preferred for subagents)

```
mcp__ida-multi-mcp__idalib_open({
  input_path: "F:/agent/distorted",   // absolute host path
  timeout: 300,                        // seconds for auto-analysis
  unsafe: false
})
→ returns: { instance_id: "k7m2", ... }
```

Auto-spawns a headless IDA via `idalib`. **Requires full IDA Pro license** (not Home/Free).

**Always pair with close** when done to free the license:

```
mcp__ida-multi-mcp__idalib_close({ instance_id: "k7m2" })
```

If a subagent's time budget is about to expire, still call `idalib_close` before returning.

### B. GUI mode

If the user has IDA Pro open manually with the binary loaded, the plugin auto-registers the instance. List existing instances:

```
mcp__ida-multi-mcp__list_instances()
→ returns: [{ id: "px3a", type: "gui", binary: "..." }, ...]
```

Prefer headless unless the user explicitly opened IDA themselves.

### Instance ID can expire

If the user opens a different binary in the same IDA instance, the old `instance_id` is invalidated. The error message includes the replacement ID — use it.

## Tool categories

All tools are namespaced `mcp__ida-multi-mcp__<name>`. Every call needs `instance_id`.

### Triage (one-shot overview)
- `survey_binary` — metadata + segments + top strings + top functions + imports + call graph in one call. Use first when entering IDA on a new binary.

### Navigation
- `list_funcs` — function inventory (paginate via cache if large)
- `lookup_funcs` — find by name pattern
- `imports`, `list_globals`
- `find`, `find_bytes`, `find_regex` — content search
- `search_structs`

### Analysis
- `analyze_function` — full analysis of one function (CFG, calls, types)
- `decompile` — Hex-Rays C-like decompile of a function
- `disasm` — assembly listing
- `basic_blocks` — CFG primitives
- `decompile_to_file` — bulk decompile to disk (for large funcs)
- `analyze_component` — high-level component grouping

### Cross-references
- `xrefs_to`, `xrefs_to_field`
- `callees`, `callgraph`
- `trace_data_flow` — taint-style trace from a source

### Types & data
- `infer_types` — bulk type recovery
- `set_type`, `declare_type`, `declare_stack`, `delete_stack`, `stack_frame`
- `read_struct` — interpret bytes as a struct
- `get_int`, `put_int`, `get_string`, `get_bytes`
- `int_convert`

### Annotation (persistent on the idb)
- `rename` — name functions/vars
- `set_comments`, `append_comments`

### Patching
- `patch` — byte patch
- `patch_asm` — assembly patch
- `define_code`, `define_func`, `undefine`
- `diff_before_after` — show diff of recent edits
- `compare_binaries` — cross-binary diff

### Misc / power tools
- `py_eval` — execute Python in IDA context. **Powerful — use only when no dedicated tool fits.** Prefer the typed tools above.
- `get_global_value`, `export_funcs`
- `refresh_caches`, `refresh_tools`

### Output paging
- `get_cached_output(cache_id, offset, size)` — large outputs return a `cache_id`; use this to paginate. Don't keep re-running the producer call.
- `list_cached_outputs` — list available caches

## Standard workflow inside an RE subagent

```
1. Read triage cache: /workspace/cache/<basename>.triage.json
   → decide analysis approach

2. Open IDA (keep open throughout the session):
   idalib_open(input_path=<absolute host path>)
   → save instance_id

3. survey_binary({instance_id})
   → overall map

4. Static + Dynamic interleave (for re-dynamic):
   IDA: decompile({instance_id, function_name: "check"})
     → identify breakpoint addresses, understand logic
   sandbox: gdb -batch -ex "b *0x401234" -ex "run" -ex "x/s $rsi"
     → capture runtime values
   IDA: set_comments({instance_id, addr: 0x401234, comment: "runtime: rsi='secret'"})
     → annotate findings back into IDA

5. Save key findings to /workspace/cache/<basename>.ida.md
   (decompiled functions, recovered types, annotations applied,
    runtime values captured via gdb)

6. idalib_close({instance_id})
   → ALWAYS call before returning, even on error or timeout
```

**Key principle**: IDA stays open for the entire analysis session. Don't open/close between each operation — that wastes time on re-analysis. One `idalib_open` at the start, one `idalib_close` at the end.

## Gotchas

- **Host paths, not sandbox paths**: `idalib_open` runs on the host. Use `F:/agent/distorted`, not `/workspace/targets/distorted`. The sandbox `/workspace` mount is irrelevant to IDA.
- **Python version matching**: if `idalib_open` fails to initialize, the package was installed against the wrong Python. Not a runtime concern — flag it to the user and fall back to sandbox r2.
- **Heartbeats**: instances silent for 2+ minutes get evicted. Long-running operations (`trace_data_flow` over a huge graph) may need to be sliced.
- **Localhost only**: no remote IDA.
- **License**: headless mode consumes an IDA Pro seat. Don't leave instances open across subagent boundaries.
- **Don't dispatch IDA as part of sandbox_exec**. IDA tools are MCP-direct, sandbox is for everything else.

## Cross-agent handoff

`instance_id` is **process-local to your subagent**. You CANNOT pass it to another subagent — they'd need to `idalib_open` themselves. What you CAN pass via `/workspace/cache/<bin>.ida.md`:

- Function addresses you've identified (e.g., `0x401234 = check_flag`)
- Decompiled snippets
- Types you've recovered (the next agent can re-declare with `declare_type`)
- Annotations you applied (persist on the idb file itself if it was saved)

The next agent does its own `idalib_open` and uses the cached intel to skip rediscovery.
