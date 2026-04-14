# Infrastructure

The wirewatch runtime is fully containerized. See the top-level `README.md`
for the user-facing flow.

## Layout

- `cuttlefish/` — Dockerfile and entrypoint for the cuttlefish container
- `agent/` — Dockerfile for the agent container
- `bench/` — bash sources for `bench` subcommands
- `arm/` — pinned arm64 AOSP image artifacts (gitignored; populated by `bench fetch`)
- `x86/` — pinned x86_64 AOSP image artifacts (for optional x86 host)
- `versions.txt` — pinned AOSP build numbers and sha256s
