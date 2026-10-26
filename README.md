# rotcheck

A zero-dependency scanner that goes through `node_modules` and finds packages that are **deprecated, abandoned, sabotaged, or vulnerable**, then tells you what to replace them with or how to work around them.

It complements Dependabot: Dependabot tells you about published CVEs; rotcheck also catches packages that have **no CVE but no future** (deprecated, archived repos, years without a release), explains *why* a transitive package is in your tree, and points at the real root cause to fix.

It's a single file with no dependencies, on purpose: a security tool shouldn't add to your supply chain.

## Install

You need Node.js 18 or newer.

**Download the file** (macOS / Linux), check it against the published checksum, and run it:

```bash
curl -fsSLO https://github.com/tonagalata/rotcheck-cli/releases/latest/download/rotcheck.mjs
curl -fsSLO https://github.com/tonagalata/rotcheck-cli/releases/latest/download/rotcheck.mjs.sha256
shasum -a 256 -c rotcheck.mjs.sha256      # should print "rotcheck.mjs: OK"
node rotcheck.mjs --help
```

On Windows (PowerShell):

```powershell
Invoke-WebRequest https://github.com/tonagalata/rotcheck-cli/releases/latest/download/rotcheck.mjs -OutFile rotcheck.mjs
(Get-FileHash rotcheck.mjs -Algorithm SHA256).Hash   # compare with rotcheck.mjs.sha256 on the releases page
node rotcheck.mjs --help
```

**Or install it as a `rotcheck` command** straight from this repo (pin a version tag):

```bash
npm install -g github:tonagalata/rotcheck-cli#v1.0.0
rotcheck --help
```

Every version, with its checksum, is on the [releases page](https://github.com/tonagalata/rotcheck-cli/releases).

## Run it

From your project root, after `npm install` / `yarn` / `pnpm install`:

```bash
node path/to/rotcheck.mjs                # or just `rotcheck` if you installed the command
```

You get a terminal summary and `rotcheck-report.html` in the project folder. Open the HTML for the full, filterable report.

```bash
node rotcheck.mjs --prod                 # only what ships to production
node rotcheck.mjs --direct-only          # only your own dependencies
node rotcheck.mjs --stale-months 36      # be more lenient about old releases
node rotcheck.mjs --json report.json     # machine-readable output
node rotcheck.mjs --fail-on high         # exit 1 for CI if anything is high or critical
GITHUB_TOKEN=ghp_xxx node rotcheck.mjs   # check every package's repo for "archived"
```

Run `node rotcheck.mjs --help` for all options. Results are cached for 24h in `node_modules/.cache/rotcheck` (skip with `--no-cache`).

## Dashboard

Prefer a browser? Start the web dashboard:

```bash
node rotcheck.mjs --ui
```

It opens `http://127.0.0.1:4477`. If you start it inside a project, it scans that project right away; otherwise pick a folder (type a path or use **Browse…**) and press **Scan project**. The results open with a verdict at the top (critical issues, high issues, or all clear), followed by the same filterable findings as the HTML report. From there you can rescan, download the report as HTML or JSON, or open a saved JSON report.

The dashboard is still zero-dependency, and it only listens on your own machine (127.0.0.1). Use `--port <n>` to pick a port and `--no-open` to skip opening the browser.

## What it checks

| Source | What it tells us |
|---|---|
| npm registry | Deprecation of the latest *and* your installed version, last publish date, maintainer count, source repo, unpublished packages |
| npm downloads API | Weekly downloads — separates "finished" tiny utilities from abandoned ones |
| OSV.dev | Known vulnerabilities (same GitHub advisories Dependabot uses) **and** known-malicious packages (`MAL-*` entries) |
| GitHub API | Archived or deleted repositories, last commit |
| Built-in list | ~70 packages with a known story: deprecated/abandoned (request, node-sass, vm2, crypto-js…), sabotaged (colors, faker, event-stream, node-ipc), maintenance mode (moment), or replaceable by built-ins (node-fetch, mkdirp, bluebird…), each with recommended alternatives |
| Your install | Packages that run `preinstall`/`install`/`postinstall` scripts (a common malware vector) |

rotcheck only sends package names and versions to these public APIs. It never uploads your code.

## How it judges "unmaintained"

Old isn't automatically bad — lots of tiny packages are simply finished. The scoring tries to tell the difference:

- **Critical** — known malicious, or has known vulnerabilities *and* is deprecated/abandoned (a fix will likely never ship).
- **High** — deprecated by its author, archived repo, known sabotage history, high-severity CVE, or no release in 2× the stale threshold (4 years by default) with no sign anyone maintained still relies on it.
- **Medium** — no release in 2+ years, your installed version is deprecated (but newer isn't), moderate CVE, or maintenance-mode packages.
- **Low** — stale but clearly fine: very widely used (1M+/week and tiny), or an actively maintained parent still depends on it; also "replaceable by a built-in" and major-version lag.
- **Info** — install scripts, private packages.

**Root-cause collapsing:** if a package is only in your tree because of something already deprecated (e.g. everything under `request`, or under `eslint@8`), it's downgraded and the advice points at the one thing to fix — "replace request" — instead of 20 separate alarms.

## What the recommendations look like

- **Direct dependency** → named replacements (curated, plus the author's own suggestion parsed from the deprecation message) or the exact upgrade command.
- **Transitive dependency** → the full path (`express → body-parser → qs`), advice to upgrade the direct dependency first, and a ready-to-paste `overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides` snippet pinned to the fixed version when one exists.
- **No fix available** → replace, or limit exposure (no untrusted input, keep build-only tools out of production).
- **Malicious** → remove, reinstall clean, rotate secrets.

## CI

[`rotcheck.yml`](rotcheck.yml) is a GitHub Actions workflow that runs weekly and on lockfile changes, fails on critical findings, and uploads the HTML report as a build artifact. Save it as `.github/workflows/rotcheck.yml` in your project. It downloads a pinned rotcheck release and checks its SHA-256 before running it.

## Limits

- Works from what's installed, so run it after an install. Supports npm, yarn classic and pnpm layouts; Yarn Plug'n'Play (no `node_modules`) isn't supported.
- Dependency paths are reconstructed from `package.json` files; with heavy hoisting the path shown is the shortest one, not necessarily the only one. `npm ls <name>` shows all of them.
- Without `GITHUB_TOKEN`, GitHub checks are limited to direct and already-flagged packages (60 requests/hour anonymous limit).
- The curated list reflects known history as of late 2026; registry and OSV data is always live.

## License

[MIT](LICENSE)
