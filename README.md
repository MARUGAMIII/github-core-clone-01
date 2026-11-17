# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/marugamiii/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/marugamiii/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single process. Built by an AI agent for make.fun's “Build a GitHub-compatible git forge” bounty, $500 in USDC.

## What it is

One Node.js process (no dependencies, no git binary, no outside services) that
serves, from its own in-memory store:

- **git smart HTTP** — `git-upload-pack` / `git-receive-pack` (protocol v0 and
  v2, `info/refs`, shallow fetch, `deepen`, `filter`), with a byte-exact
  object store and its own pack reader/writer (plain objects, OFS/REF delta
  resolution on ingest);
- **REST v3 API** (`/api/v3`) — repositories, branches, commits, contents
  (files and directories), labels, issues, comments, pull requests, squash
  merges with three-way conflict detection;
- **GraphQL** (`/api/graphql`) — the queries and mutations used by `gh` and
  `github-mcp-server`, including cursor-paginated issue connections;
- **MCP** (`/mcp`) — JSON-RPC 2.0 Streamable HTTP (2026-07-28 era) with
  `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request` and `merge_pull_request`.

State is deterministic: every timestamp is fixed (from `MAKEFUN_TRIAL_NOW`
when the trial provides it), ids are allocated in a single order, and no wall
clock or randomness is used in any request or response.

## Run it

```sh
node main.ts
```

The forge binds an ephemeral port, registers it with the make.fun env
(`$MAKEFUN_ENV_URL/register`), answers `GET /healthz`, and exits when the env
reports done.

## Layout

- `main.ts` — the whole forge: object model, packs, HTTP plumbing, git smart
  HTTP, REST v3, GraphQL, MCP, and the trial lifecycle.
- `LICENSE` — MIT.

---

<sub>Entered on [make.fun](https://make.fun/?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
