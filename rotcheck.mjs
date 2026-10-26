#!/usr/bin/env node
/**
 * rotcheck — a zero-dependency package health & vulnerability scanner for node_modules.
 *
 * What it does
 *   1. Walks node_modules (npm, yarn classic, pnpm) and inventories every installed package.
 *   2. For each package, checks:
 *        - npm registry: deprecation (latest + installed version), last publish date,
 *          maintainers, repository, unpublished status
 *        - npm downloads API: weekly downloads (popularity / "finished vs abandoned" judgment)
 *        - OSV.dev: known vulnerabilities AND known-malicious packages (MAL-*)
 *        - GitHub API: archived / deleted source repos, last push (set GITHUB_TOKEN for full coverage)
 *        - a curated list of packages known to be deprecated, abandoned, sabotaged or
 *          replaceable by built-ins, with recommended alternatives
 *   3. Scores each package, traces how transitive packages got into your tree, and gives
 *      concrete fixes: replacement packages, upgrade targets, and npm/yarn/pnpm override snippets.
 *   4. Prints a terminal summary and writes an interactive HTML report (and optional JSON).
 *
 * It has no dependencies on purpose: a security tool shouldn't add to your supply chain.
 * Requires Node.js 18+.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = '1.0.0';
if (Number(process.versions.node.split('.')[0]) < 18) {
  console.error('rotcheck needs Node.js 18 or newer (it uses the built-in fetch).');
  process.exit(2);
}

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEV_NAME = ['info', 'low', 'medium', 'high', 'critical'];

// ---------------------------------------------------------------------------
// Curated knowledge: packages with a known story. Registry signals catch most
// deprecations automatically; this list adds context, alternatives, and the
// cases the registry doesn't flag (maintenance mode, sabotage, native replacements).
// status: compromised | deprecated | abandoned | maintenance | native
// ---------------------------------------------------------------------------
const FETCH_ALTS = ['native fetch (Node 18+)', 'undici', 'ky', 'axios'];
const KNOWN = {
  'request': { status: 'deprecated', alts: FETCH_ALTS, note: 'Fully deprecated since Feb 2020 and receives no security fixes. It also drags in other deprecated packages (har-validator, old uuid, old tough-cookie).' },
  'request-promise': { status: 'deprecated', alts: FETCH_ALTS, note: 'Wrapper around the deprecated `request`; deprecated with it.' },
  'request-promise-native': { status: 'deprecated', alts: FETCH_ALTS, note: 'Wrapper around the deprecated `request`; deprecated with it.' },
  'har-validator': { status: 'deprecated', alts: [], note: 'Only used by `request`. Removing `request` removes this.' },
  'moment': { status: 'maintenance', alts: ['dayjs (near-identical API)', 'date-fns', 'luxon', 'Temporal (native, where supported)'], note: 'Its maintainers declared it a legacy project in maintenance mode. It still gets critical fixes but no new development; it is large and mutable.' },
  'moment-timezone': { status: 'maintenance', alts: ['luxon', 'date-fns-tz', 'dayjs + timezone plugin', 'Intl.DateTimeFormat'], note: 'Tied to moment, which is in maintenance mode.' },
  'node-uuid': { status: 'deprecated', alts: ['uuid', 'crypto.randomUUID() (native)'], note: 'Renamed to `uuid` long ago.' },
  'shortid': { status: 'deprecated', alts: ['nanoid'], note: 'Deprecated by its author, who recommends nanoid.' },
  'node-sass': { status: 'deprecated', alts: ['sass (Dart Sass)'], note: 'LibSass and node-sass are deprecated; they need a native build and pull in old dependencies.' },
  'tslint': { status: 'deprecated', alts: ['eslint + typescript-eslint'], note: 'Deprecated in favor of typescript-eslint.' },
  'babel-eslint': { status: 'deprecated', alts: ['@babel/eslint-parser'], note: 'Renamed and moved under the @babel scope.' },
  'eslint-plugin-node': { status: 'abandoned', alts: ['eslint-plugin-n'], note: 'Unmaintained; eslint-plugin-n is the maintained fork.' },
  'uglify-es': { status: 'abandoned', alts: ['terser'], note: 'Abandoned; terser is the maintained fork.' },
  'rollup-plugin-terser': { status: 'deprecated', alts: ['@rollup/plugin-terser'], note: 'Moved to the official @rollup scope.' },
  'sourcemap-codec': { status: 'deprecated', alts: ['@jridgewell/sourcemap-codec'], note: 'Replaced by the @jridgewell version.' },
  'istanbul': { status: 'deprecated', alts: ['c8', 'nyc'], note: 'Old Istanbul CLI is deprecated.' },
  'colors': { status: 'compromised', alts: ['picocolors', 'chalk', 'util.styleText (Node 20.12+)'], note: 'Its author published sabotaged releases in Jan 2022 (infinite loop). If you must keep it, pin exactly 1.4.0.' },
  'faker': { status: 'compromised', alts: ['@faker-js/faker'], note: 'Wiped by its author in Jan 2022. The community fork is @faker-js/faker.' },
  'event-stream': { status: 'compromised', alts: ['node:stream utilities', 'through2'], note: 'v3.3.6 was hijacked in 2018 to steal cryptocurrency wallets (via flatmap-stream).' },
  'flatmap-stream': { status: 'compromised', critical: true, alts: [], note: 'Malicious package from the event-stream incident. Remove immediately.' },
  'node-ipc': { status: 'compromised', alts: ['node:net / node:child_process IPC'], note: 'Versions 10.1.1–10.1.3 shipped protestware that overwrote files (2022). Avoid, or pin a verified version.' },
  'vm2': { status: 'abandoned', alts: ['isolated-vm', 'run untrusted code in a separate process or container'], note: 'Discontinued in 2023 because of sandbox escapes that could not be fixed. Do not use it as a security boundary.' },
  'crypto-js': { status: 'abandoned', alts: ['node:crypto', 'Web Crypto API (crypto.subtle)'], note: 'Development discontinued in 2023. Native crypto is faster and better audited.' },
  'xmldom': { status: 'abandoned', alts: ['@xmldom/xmldom'], note: 'Moved to the @xmldom scope; the unscoped package is unmaintained and has known issues.' },
  'phantomjs': { status: 'abandoned', alts: ['playwright', 'puppeteer'], note: 'PhantomJS development was suspended in 2018.' },
  'phantomjs-prebuilt': { status: 'abandoned', alts: ['playwright', 'puppeteer'], note: 'PhantomJS development was suspended in 2018.' },
  'html-pdf': { status: 'abandoned', alts: ['playwright / puppeteer (page.pdf())', 'pdf-lib'], note: 'Built on the abandoned PhantomJS.' },
  'csurf': { status: 'deprecated', alts: ['csrf-csrf', 'csrf-sync'], note: 'Deprecated by the Express team.' },
  'popper.js': { status: 'deprecated', alts: ['@floating-ui/dom', '@popperjs/core'], note: 'Popper v1; superseded by @popperjs/core and Floating UI.' },
  '@hapi/joi': { status: 'deprecated', alts: ['joi', 'zod'], note: 'Moved back to the unscoped `joi` package.' },
  'react-scripts': { status: 'deprecated', alts: ['vite', 'Next.js', 'React Router (framework mode)'], note: 'Create React App was officially deprecated in Feb 2025.' },
  'enzyme': { status: 'abandoned', alts: ['@testing-library/react'], note: 'No official adapter for React 18+.' },
  'protractor': { status: 'deprecated', alts: ['playwright', 'cypress', 'webdriverio'], note: 'Deprecated by the Angular team.' },
  'karma': { status: 'deprecated', alts: ['vitest (browser mode)', 'jest', '@web/test-runner'], note: 'Deprecated by its maintainers in 2023.' },
  'gulp-util': { status: 'deprecated', alts: ['plugin-error', 'fancy-log', 'ansi-colors', 'vinyl'], note: 'Split into individual modules.' },
  'node-pre-gyp': { status: 'deprecated', alts: ['@mapbox/node-pre-gyp'], note: 'Moved to the @mapbox scope.' },
  'inflight': { status: 'deprecated', alts: ['lru-cache'], note: 'Leaks memory. Usually pulled in by glob < 9 or rimraf < 4 — upgrading those removes it.' },
  'npmlog': { status: 'deprecated', alts: [], note: 'Usually pulled in by older node-gyp / node-pre-gyp; upgrading those removes it.' },
  'gauge': { status: 'deprecated', alts: [], note: 'Usually pulled in by older npmlog / node-gyp; upgrading those removes it.' },
  'are-we-there-yet': { status: 'deprecated', alts: [], note: 'Usually pulled in by older npmlog / node-gyp; upgrading those removes it.' },
  '@npmcli/move-file': { status: 'deprecated', alts: ['@npmcli/fs'], note: 'Functionality moved into @npmcli/fs.' },
  '@humanwhocodes/config-array': { status: 'deprecated', alts: ['@eslint/config-array'], note: 'Comes from ESLint 8. Upgrading to ESLint 9 removes it.' },
  '@humanwhocodes/object-schema': { status: 'deprecated', alts: ['@eslint/object-schema'], note: 'Comes from ESLint 8. Upgrading to ESLint 9 removes it.' },
  'abab': { status: 'deprecated', alts: ['native atob() / btoa()'], note: 'Platform has native base64 helpers.' },
  'domexception': { status: 'deprecated', alts: ['native DOMException'], note: 'Native in modern Node.' },
  'node-domexception': { status: 'deprecated', alts: ['native DOMException'], note: 'Native in modern Node.' },
  'w3c-hr-time': { status: 'deprecated', alts: ['native performance.now()'], note: 'Native in modern Node.' },
  'stable': { status: 'deprecated', alts: ['Array.prototype.sort (stable since ES2019)'], note: 'Built-in sort is stable now.' },
  'querystring': { status: 'deprecated', alts: ['URLSearchParams'], note: 'The npm package is deprecated; use the web-standard URLSearchParams.' },
  'left-pad': { status: 'deprecated', alts: ['String.prototype.padStart'], note: 'Native since ES2017.' },
  'babel-polyfill': { status: 'deprecated', alts: ['core-js@3'], note: 'Deprecated in favor of importing core-js directly.' },
  '@babel/polyfill': { status: 'deprecated', alts: ['core-js@3'], note: 'Deprecated in favor of importing core-js directly.' },
  'fstream': { status: 'deprecated', alts: ['tar', 'node:fs streams'], note: 'Unmaintained; has had path-traversal advisories.' },
  'levelup': { status: 'deprecated', alts: ['level', 'abstract-level'], note: 'Superseded by abstract-level.' },
  'source-map-resolve': { status: 'deprecated', alts: [], note: 'Usually pulled in by old snapdragon/micromatch@3 chains (e.g. chokidar@2). Upgrading the parent tool removes it.' },
  'source-map-url': { status: 'deprecated', alts: [], note: 'Usually pulled in by old snapdragon chains. Upgrading the parent tool removes it.' },
  'resolve-url': { status: 'deprecated', alts: [], note: 'Usually pulled in by old snapdragon chains. Upgrading the parent tool removes it.' },
  'urix': { status: 'deprecated', alts: [], note: 'Usually pulled in by old snapdragon chains. Upgrading the parent tool removes it.' },
  'es6-promise': { status: 'native', alts: ['native Promise'], note: 'Promise is built in everywhere you run today.' },
  'q': { status: 'native', alts: ['native Promise / async-await'], note: 'Native promises cover this.' },
  'bluebird': { status: 'native', alts: ['native Promise / async-await'], note: 'Its own maintainers recommend native promises for new code.' },
  'mkdirp': { status: 'native', alts: ['fs.mkdir(p, { recursive: true })'], note: 'Native since Node 10.12.' },
  'object-assign': { status: 'native', alts: ['Object.assign / spread'], note: 'Native since ES2015.' },
  'node-fetch': { status: 'native', alts: ['native fetch (Node 18+)'], note: 'Node has fetch built in. v2 only gets critical fixes; v3 is ESM-only.' },
  'isomorphic-fetch': { status: 'native', alts: ['native fetch'], note: 'Fetch is built into Node 18+ and all browsers.' },
  'cross-fetch': { status: 'native', alts: ['native fetch'], note: 'Fetch is built into Node 18+ and all browsers.' },
  'intl': { status: 'native', alts: ['built-in Intl'], note: 'Intl is built into Node and browsers.' },
};
const LODASH_SPLIT = { status: 'native', alts: ['lodash (full, ^4.17.21)', 'lodash-es', 'native JS equivalent'], note: 'Per-method lodash.* packages are not updated in step with lodash, so security fixes may never reach them (e.g. lodash.template).' };
const KNOWN_OVERRIDES = {
  'lodash.template': { status: 'abandoned', alts: ['lodash@^4.17.21 (_.template)'], note: 'Standalone package was never patched for the command-injection CVE fixed in lodash 4.17.21.' },
  'lodash.get': { status: 'native', alts: ['optional chaining (a?.b?.c)'], note: 'Optional chaining replaces it.' },
  'lodash.isequal': { status: 'deprecated', alts: ['util.isDeepStrictEqual (node:util)'], note: 'Deprecated in favor of the native check.' },
};
function knownFor(name) {
  return KNOWN_OVERRIDES[name] || KNOWN[name] || (name.startsWith('lodash.') && !name.startsWith('lodash._') ? LODASH_SPLIT : null);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function printHelp() {
  console.log(`rotcheck ${VERSION} — find unmaintained, deprecated and vulnerable packages in node_modules

Usage: node rotcheck.mjs [options]
       node rotcheck.mjs --ui      Open the web dashboard instead

Options:
  -p, --path <dir>        Project directory (default: current directory)
  --ui                    Start the local web dashboard (scans --path on open if it's a project)
  --port <n>              Dashboard port (default: 4477, or the next free one)
  --no-open               Don't open the dashboard in a browser automatically
  --stale-months <n>      Months without a release before a package counts as stale (default: 24)
  --html <file>           HTML report path (default: rotcheck-report.html in the project)
  --no-html               Don't write an HTML report
  --json <file>           Also write the findings as JSON
  --prod                  Only packages reachable from production dependencies
  --direct-only           Only your direct dependencies
  --min <severity>        Lowest severity printed in the terminal: low|medium|high|critical (default: medium)
  --fail-on <severity>    Exit with code 1 if anything at or above this severity is found (for CI)
  --no-osv                Skip the OSV.dev vulnerability lookup
  --no-github             Skip GitHub repository checks
  --no-cache              Ignore the 24h cache in node_modules/.cache/rotcheck
  --concurrency <n>       Parallel registry requests (default: 8)
  -h, --help              Show this help

Environment:
  GITHUB_TOKEN / GH_TOKEN Enables GitHub checks for every package (otherwise only flagged
                          packages are checked, to stay under the 60 requests/hour anonymous limit)`);
}

function parseArgs(argv) {
  const o = { path: process.cwd(), staleMonths: 24, html: undefined, json: null, prodOnly: false, directOnly: false,
    min: 'medium', failOn: null, osv: true, github: true, cacheHours: 24, concurrency: 8, ui: false, port: 4477, open: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) fail(`${a} needs a value`); return v; };
    switch (a) {
      case '-p': case '--path': o.path = path.resolve(next()); break;
      case '--stale-months': o.staleMonths = Number(next()); break;
      case '--html': o.html = next(); break;
      case '--no-html': o.html = null; break;
      case '--json': o.json = next(); break;
      case '--prod': o.prodOnly = true; break;
      case '--direct-only': o.directOnly = true; break;
      case '--min': o.min = next(); break;
      case '--fail-on': o.failOn = next(); break;
      case '--no-osv': o.osv = false; break;
      case '--no-github': o.github = false; break;
      case '--no-cache': o.cacheHours = 0; break;
      case '--concurrency': o.concurrency = Math.max(1, Number(next())); break;
      case '--ui': o.ui = true; break;
      case '--port': o.port = Number(next()); break;
      case '--no-open': o.open = false; break;
      case '-h': case '--help': printHelp(); process.exit(0);
      default: fail(`Unknown option: ${a} (see --help)`);
    }
  }
  for (const k of ['min', 'failOn']) if (o[k] && !(o[k] in SEV)) fail(`--${k === 'failOn' ? 'fail-on' : k} must be one of: low, medium, high, critical`);
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) fail('--port must be a number between 0 and 65535');
  if (o.html === undefined) o.html = path.join(o.path, 'rotcheck-report.html');
  return o;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const C = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const col = { red: C('31'), yellow: C('33'), blue: C('34'), magenta: C('35'), gray: C('90'), bold: C('1'), green: C('32'), bgRed: C('41;97') };
const sevColor = [col.gray, col.blue, col.yellow, col.magenta, col.bgRed];

// User-facing errors are thrown (not exited on) so the dashboard can show them; main() prints them.
class UserError extends Error {}
function fail(msg) { throw new UserError(msg); }
// The dashboard sets this to stream progress to the browser instead of the terminal.
let progressHook = null;
function progress(msg) { if (progressHook) progressHook(msg); else if (process.stderr.isTTY) process.stderr.write(`\r\x1b[K${col.gray(msg)}`); }
function progressDone() { if (!progressHook && process.stderr.isTTY) process.stderr.write('\r\x1b[K'); }
function note(msg) { if (progressHook) progressHook(msg); else console.error(col.gray(msg)); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const chunk = (arr, n) => { const out = []; for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n)); return out; };
const trimStr = (s, n = 220) => { s = String(s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const monthsSince = (iso) => (Date.now() - new Date(iso).getTime()) / (30.44 * 864e5);
const fmtN = (n) => (n == null ? '?' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n));
const years = (m) => (m / 12).toFixed(1);
function readJSONSync(f) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } }
async function safeReaddir(d) { try { return await fsp.readdir(d); } catch { return []; } }

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  }));
  return out;
}

async function getJSON(url, init = {}, retries = 2) {
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(url, { ...init, signal: AbortSignal.timeout(30000) });
      if (r.status === 404) return { __status: 404 };
      if ((r.status === 429 || r.status >= 500) && attempt < retries) { await sleep(1000 * (attempt + 1)); continue; }
      if (!r.ok) return { __status: r.status };
      return await r.json();
    } catch (e) {
      if (attempt < retries) { await sleep(500 * (attempt + 1)); continue; }
      throw e;
    }
  }
}

function parseV(v) { const m = String(v).match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?/); return m ? [+m[1], +m[2], +m[3], m[4] || ''] : null; }
function cmpV(a, b) {
  const A = parseV(a), B = parseV(b); if (!A || !B) return 0;
  for (let i = 0; i < 3; i++) if (A[i] !== B[i]) return A[i] - B[i];
  if (A[3] === B[3]) return 0; if (!A[3]) return 1; if (!B[3]) return -1; return A[3] < B[3] ? -1 : 1;
}

function normRepo(r) {
  if (!r) return null;
  let u = typeof r === 'string' ? r : r.url;
  if (!u || typeof u !== 'string') return null;
  u = u.trim();
  if (/^[\w.-]+\/[\w.-]+$/.test(u)) u = 'https://github.com/' + u;
  u = u.replace(/^github:/, 'https://github.com/').replace(/^gitlab:/, 'https://gitlab.com/').replace(/^bitbucket:/, 'https://bitbucket.org/')
    .replace(/^git\+/, '').replace(/^git:\/\//, 'https://').replace(/^ssh:\/\/git@/, 'https://').replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/^http:\/\//, 'https://').replace(/#.*$/, '').replace(/\.git$/, '').replace(/\/$/, '');
  return u;
}
function githubSlug(u) {
  const m = u && u.match(/github\.com\/([^/]+)\/([^/#?]+)/i);
  return m ? `${m[1]}/${m[2].replace(/\.git$/, '')}`.toLowerCase() : null;
}

// ---------------------------------------------------------------------------
// Cache (node_modules/.cache/rotcheck/cache.json)
// ---------------------------------------------------------------------------
function openCache(root, hours, dir) {
  const file = path.join(dir || path.join(root, 'node_modules', '.cache', 'rotcheck'), 'cache.json');
  const data = (hours > 0 && readJSONSync(file)) || { v: 1, e: {} };
  const ttl = hours * 3600e3;
  return {
    get(k) { const x = data.e[k]; return x && Date.now() - x.t < ttl ? x.v : undefined; },
    set(k, v) { data.e[k] = { t: Date.now(), v }; },
    save() {
      try {
        for (const [k, x] of Object.entries(data.e)) if (Date.now() - x.t > 7 * 864e5) delete data.e[k];
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, JSON.stringify(data));
      } catch { /* cache is best-effort */ }
    },
  };
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------
async function collectInstalled(root) {
  const nm = path.join(root, 'node_modules');
  if (!fs.existsSync(nm)) fail(`No node_modules in ${root}. Run your package manager's install first.`);
  const pkgs = new Map();
  const seenDirs = new Set();
  const seenPkgs = new Set();

  async function walk(dir) {
    let real; try { real = await fsp.realpath(dir); } catch { return; }
    if (seenDirs.has(real)) return; seenDirs.add(real);
    for (const name of await safeReaddir(dir)) {
      const full = path.join(dir, name);
      if (name === '.pnpm') { for (const id of await safeReaddir(full)) await walk(path.join(full, id, 'node_modules')); continue; }
      if (name.startsWith('.')) continue;
      if (name.startsWith('@')) { for (const s of await safeReaddir(full)) await readPkg(path.join(full, s)); continue; }
      await readPkg(full);
    }
  }
  async function readPkg(dir) {
    let real; try { real = await fsp.realpath(dir); } catch { return; }
    if (seenPkgs.has(real)) return; seenPkgs.add(real);
    let pj; try { pj = JSON.parse(await fsp.readFile(path.join(real, 'package.json'), 'utf8')); } catch { return; }
    if (pj.name && pj.version && !pj.private) {
      const key = `${pj.name}@${pj.version}`;
      let p = pkgs.get(key);
      if (!p) {
        const scripts = {};
        for (const s of ['preinstall', 'install', 'postinstall']) if (pj.scripts?.[s]) scripts[s] = pj.scripts[s];
        p = { name: pj.name, version: pj.version, deps: Object.keys({ ...pj.dependencies, ...pj.optionalDependencies }),
          installScripts: Object.keys(scripts).length ? scripts : null, license: typeof pj.license === 'string' ? pj.license : pj.license?.type || null,
          locations: [] };
        pkgs.set(key, p);
      }
      p.locations.push(path.relative(root, dir));
    }
    await walk(path.join(real, 'node_modules'));
  }
  await walk(nm);
  return pkgs;
}

function collectDirect(root, rootPkg) {
  const direct = new Map(); // name -> 'prod' | 'dev'
  const addFrom = (pj) => {
    for (const n of Object.keys(pj.devDependencies || {})) if (!direct.has(n)) direct.set(n, 'dev');
    for (const n of Object.keys({ ...pj.dependencies, ...pj.optionalDependencies, ...pj.peerDependencies })) direct.set(n, 'prod');
  };
  addFrom(rootPkg);
  // Workspaces (npm/yarn "workspaces" array or object, simple globs like packages/*)
  const ws = Array.isArray(rootPkg.workspaces) ? rootPkg.workspaces : rootPkg.workspaces?.packages || [];
  const wsNames = new Set();
  for (const pattern of ws) {
    const dirs = pattern.endsWith('/*')
      ? (() => { const base = path.join(root, pattern.slice(0, -2)); try { return fs.readdirSync(base).map((d) => path.join(base, d)); } catch { return []; } })()
      : [path.join(root, pattern)];
    for (const d of dirs) { const pj = readJSONSync(path.join(d, 'package.json')); if (pj) { addFrom(pj); if (pj.name) wsNames.add(pj.name); } }
  }
  for (const n of wsNames) direct.delete(n);
  return { direct, wsNames };
}

function buildGraph(installed) {
  const forward = new Map(); const reverse = new Map();
  for (const p of installed.values()) {
    if (!forward.has(p.name)) forward.set(p.name, new Set());
    for (const d of p.deps) {
      forward.get(p.name).add(d);
      if (!reverse.has(d)) reverse.set(d, new Set());
      reverse.get(d).add(p.name);
    }
  }
  return { forward, reverse };
}
function reachableFrom(starts, forward) {
  const seen = new Set(starts); const q = [...starts];
  while (q.length) { const n = q.shift(); for (const d of forward.get(n) || []) if (!seen.has(d)) { seen.add(d); q.push(d); } }
  return seen;
}
function makeChainFinder(reverse, direct) {
  const memo = new Map();
  return (name) => {
    if (memo.has(name)) return memo.get(name);
    if (direct.has(name)) { memo.set(name, [name]); return [name]; }
    const prev = new Map([[name, null]]); const q = [name]; let hit = null;
    while (q.length && !hit) {
      const n = q.shift();
      for (const parent of reverse.get(n) || []) {
        if (prev.has(parent)) continue;
        prev.set(parent, n);
        if (direct.has(parent)) { hit = parent; break; }
        q.push(parent);
      }
    }
    const chain = [];
    if (hit) { for (let n = hit; n; n = prev.get(n)) chain.push(n); }
    memo.set(name, chain.length ? chain : [name]);
    return memo.get(name);
  };
}

// ---------------------------------------------------------------------------
// Remote data
// ---------------------------------------------------------------------------
function summarizeDoc(doc) {
  const latest = doc['dist-tags']?.latest;
  const versions = doc.versions || {};
  const lv = versions[latest] || {};
  const times = doc.time || {};
  let lastPublish = null;
  for (const [k, t] of Object.entries(times)) { if (k === 'created' || k === 'modified' || k === 'unpublished') continue; if (!lastPublish || t > lastPublish) lastPublish = t; }
  const deprecatedVersions = {};
  for (const [v, m] of Object.entries(versions)) if (m.deprecated) deprecatedVersions[v] = trimStr(m.deprecated, 400);
  return {
    latest: latest || null,
    latestPublished: (latest && times[latest]) || null,
    deprecatedLatest: lv.deprecated ? trimStr(lv.deprecated, 400) : null,
    deprecatedVersions,
    repository: normRepo(lv.repository || doc.repository),
    homepage: lv.homepage || doc.homepage || null,
    description: trimStr(lv.description || doc.description || '', 200),
    keywords: (lv.keywords || doc.keywords || []).slice(0, 5),
    maintainers: (doc.maintainers || []).length,
    lastPublish,
    created: times.created || null,
    unpublished: !!times.unpublished && !latest,
  };
}

async function fetchRegistry(names, cache, opt) {
  const out = new Map(); let done = 0; let errors = 0;
  await pool(names, opt.concurrency, async (name) => {
    let v = cache.get('reg:' + name);
    if (v === undefined) {
      try {
        const doc = await getJSON(`https://registry.npmjs.org/${name.replace('/', '%2F')}`);
        v = doc.__status === 404 ? { notFound: true } : doc.__status ? undefined : summarizeDoc(doc);
        if (v) cache.set('reg:' + name, v); else errors++;
      } catch { errors++; }
    }
    if (v) out.set(name, v);
    progress(`npm registry ${++done}/${names.length}`);
  });
  progressDone();
  return { map: out, errors };
}

async function fetchDownloads(names, cache) {
  const out = new Map(); const todo = [];
  for (const n of names) { const c = cache.get('dl:' + n); if (c !== undefined) out.set(n, c); else todo.push(n); }
  const set = (n, v) => { out.set(n, v); cache.set('dl:' + n, v); };
  const unscoped = todo.filter((n) => !n.startsWith('@')); const scoped = todo.filter((n) => n.startsWith('@'));
  await pool(chunk(unscoped, 128), 4, async (ch) => {
    try {
      const r = await getJSON(`https://api.npmjs.org/downloads/point/last-week/${ch.join(',')}`);
      if (r.__status) return;
      if (ch.length === 1) set(ch[0], r.downloads ?? null); else for (const n of ch) set(n, r[n]?.downloads ?? null);
    } catch { /* optional data */ }
  });
  let done = 0;
  await pool(scoped, 6, async (n) => {
    try { const r = await getJSON(`https://api.npmjs.org/downloads/point/last-week/${n}`); if (!r.__status) set(n, r.downloads ?? null); } catch { /* optional */ }
    progress(`download stats ${++done}/${scoped.length}`);
  });
  progressDone();
  return out;
}

async function fetchOsv(list) {
  const byKey = new Map(); const ids = new Set();
  try {
    for (const ch of chunk(list, 500)) {
      const r = await getJSON('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: ch.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) }),
      });
      if (r.__status) return { error: `OSV.dev returned HTTP ${r.__status}` };
      r.results.forEach((res, i) => {
        const v = (res.vulns || []).map((x) => x.id);
        if (v.length) { byKey.set(`${ch[i].name}@${ch[i].version}`, v); v.forEach((id) => ids.add(id)); }
      });
    }
    const details = new Map(); let done = 0;
    await pool([...ids], 8, async (id) => {
      try { const d = await getJSON(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`); if (!d.__status) details.set(id, d); } catch { /* skip */ }
      progress(`vulnerability details ${++done}/${ids.size}`);
    });
    progressDone();
    return { byKey, details };
  } catch (e) {
    return { error: `Could not reach OSV.dev (${e.cause?.code || e.message})` };
  }
}

async function fetchGithub(slugs, cache) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'rotcheck' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const out = new Map(); let limited = false; let done = 0;
  await pool(slugs, 4, async (slug) => {
    const c = cache.get('gh:' + slug);
    if (c !== undefined) { out.set(slug, c); return; }
    if (limited) return;
    try {
      const r = await fetch(`https://api.github.com/repos/${slug}`, { headers, signal: AbortSignal.timeout(20000) });
      if (r.status === 403 || r.status === 429) { limited = true; return; }
      let v;
      if (r.status === 404) v = { missing: true };
      else if (r.ok) { const j = await r.json(); v = { archived: !!j.archived, disabled: !!j.disabled, pushedAt: j.pushed_at, stars: j.stargazers_count, openIssues: j.open_issues_count }; }
      if (v) { out.set(slug, v); cache.set('gh:' + slug, v); }
    } catch { /* optional */ }
    progress(`GitHub repos ${++done}/${slugs.length}`);
  });
  progressDone();
  return { map: out, limited, token: !!token };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function vulnInfo(d, name) {
  const s = String(d.database_specific?.severity || '').toUpperCase();
  const malicious = d.id.startsWith('MAL-');
  const severity = malicious ? SEV.critical : ({ CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 }[s] ?? 2);
  const fixed = new Set();
  for (const a of d.affected || []) {
    if (a.package?.name !== name) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
  }
  return {
    id: d.id, cve: (d.aliases || []).find((a) => a.startsWith('CVE-')) || null, malicious, severity,
    summary: trimStr(d.summary || d.details || 'No summary provided', 200), fixed: [...fixed],
    url: d.id.startsWith('GHSA-') ? `https://github.com/advisories/${d.id}` : `https://osv.dev/vulnerability/${d.id}`,
  };
}

function suggestedFromDeprecation(msg, self) {
  if (!msg) return [];
  const out = new Set();
  const re = /\b(?:use|switch to|replaced by|moved to|migrate to|superseded by|in favou?r of|renamed to|see)\s+(?:the\s+)?[`'"]?(@?[a-z0-9][\w.-]*(?:\/[\w.-]+)?)/gi;
  let m;
  for (const u of msg.matchAll(/(?:npmjs\.com|socket\.dev\/npm)\/package\/(@[\w.-]+\/[\w.-]+|[\w.-]+)/gi)) if (u[1] !== self) out.add(u[1]);
  while ((m = re.exec(msg))) {
    const cand = m[1].replace(/[.,;)]+$/, '');
    if (cand && cand !== self && /[a-z]/i.test(cand) && !/^(it|this|that|a|an|the|version|v\d|https?|instead|native|node|your|our|latest|newer|upgrade)$/i.test(cand)) out.add(cand);
  }
  return [...out].slice(0, 3);
}

function overrideSnippet(name, version) {
  return `// package.json — force a safe version of a transitive dependency
// npm 8.3+
"overrides": { "${name}": "${version}" }
// yarn
"resolutions": { "${name}": "${version}" }
// pnpm
"pnpm": { "overrides": { "${name}": "${version}" } }`;
}

function analyze(p, ctx) {
  const m = ctx.meta.get(p.name) || {};
  const reasons = []; const recs = []; const cats = new Set();
  let sev = -1;
  const add = (s, cat, msg) => { reasons.push({ sev: s, msg }); cats.add(cat); if (s > sev) sev = s; };

  const isDirect = ctx.direct.has(p.name);
  // Prefer the exact parent when the package is nested (node_modules/A/node_modules/B => A).
  let chain = ctx.chain(p.name);
  const nested = !isDirect && p.locations.map((l) => l.split(path.sep)).find((s) => s.length > 2 && !s.includes('.pnpm'));
  if (nested) {
    const idx = nested.lastIndexOf('node_modules', nested.length - 2);
    let parent = nested[idx - 1];
    if (parent?.startsWith('@')) parent = null;
    else if (idx >= 2 && nested[idx - 2]?.startsWith('@')) parent = `${nested[idx - 2]}/${parent}`;
    if (parent && parent !== p.name) chain = [...ctx.chain(parent), p.name];
  }
  const devOnly = !ctx.prod.has(p.name);
  const known = knownFor(p.name);
  const dl = ctx.downloads.get(p.name);
  const slug = githubSlug(m.repository);
  const gh = slug ? ctx.gh.get(slug) : null;
  const ageM = m.lastPublish ? monthsSince(m.lastPublish) : null;
  const installedDep = m.deprecatedVersions?.[p.version] || null;
  let unmaintained = false;

  if (m.notFound) add(SEV.info, 'registry', 'Not on the public npm registry (private, local or removed package) — not checked.');
  if (m.unpublished) { add(SEV.high, 'unmaintained', 'All versions have been unpublished from npm.'); unmaintained = true; }

  if (m.deprecatedLatest) {
    const ancestor = chain.slice(0, -1).find((n) => ctx.isBadRoot(n));
    add(ancestor ? SEV.medium : SEV.high, 'deprecated', `Deprecated by its author: "${m.deprecatedLatest}"${ancestor ? ` — it is only here because of ${ancestor}, which is ${ctx.isOldRoot(ancestor) ? 'itself on a deprecated version' : 'also deprecated'}.` : ''}`);
    unmaintained = true;
  }
  else if (installedDep) add(SEV.medium, 'outdated', `Installed version ${p.version} is deprecated ("${installedDep}"). The latest version (${m.latest}) is not.`);

  if (gh?.archived) { add(SEV.high, 'unmaintained', 'Source repository is archived on GitHub (read-only — no more fixes).'); unmaintained = true; }
  else if (gh?.missing) add(SEV.medium, 'unmaintained', 'Its GitHub repository no longer exists (404).');

  if (known) {
    const k = known;
    if (k.status === 'compromised') add(k.critical ? SEV.critical : SEV.high, 'known-issue', `Known supply-chain incident: ${k.note}`);
    else if (k.status === 'deprecated' || k.status === 'abandoned') { if (!m.deprecatedLatest) add(SEV.high, 'known-issue', `Known ${k.status}: ${k.note}`); else reasons.push({ sev: SEV.info, msg: k.note }); }
    else if (k.status === 'maintenance') add(SEV.medium, 'known-issue', `Maintenance mode: ${k.note}`);
    else if (k.status === 'native') add(SEV.low, 'replaceable', `Replaceable: ${k.note}`);
    if (k.status !== 'native' && k.status !== 'maintenance') unmaintained = true;
  }

  // A transitive package that only exists because an ancestor is itself deprecated/abandoned:
  // the fix is to replace the ancestor, so don't report it as a separate problem.
  const badAncestor = chain.slice(0, -1).find((n) => ctx.isBadRoot(n)) || null;
  const parents = [...(ctx.reverse.get(p.name) || [])];
  const freshParent = !isDirect ? parents.find((n) => ctx.isFresh(n) && !ctx.isBadRoot(n)) : null;

  if (ageM != null && ageM >= ctx.opt.staleMonths && !m.deprecatedLatest) {
    const stable = (dl ?? 0) >= 1_000_000 && p.deps.length <= 2 && !gh?.archived;
    if (badAncestor && !gh?.archived) {
      add(SEV.low, 'stale', `No release in ${years(ageM)} years — only installed because of ${badAncestor}, which is itself deprecated/abandoned. Replacing ${badAncestor} removes it.`);
    } else if (stable) {
      add(SEV.low, 'stale', `No release in ${years(ageM)} years, but it is small and very widely used (${fmtN(dl)} downloads/week) — likely "finished" rather than abandoned.`);
    } else if (freshParent && !gh?.archived && m.maintainers !== 0) {
      add(SEV.low, 'stale', `No release in ${years(ageM)} years, but ${freshParent} (actively maintained) still depends on it — most likely small and finished rather than abandoned.`);
    } else {
      const s = ageM >= ctx.opt.staleMonths * 2 && p.deps.length > 0 ? SEV.high : SEV.medium;
      const extras = [];
      if (m.maintainers === 1) extras.push('single maintainer');
      if (!m.repository) extras.push('no source repository listed');
      if (gh?.pushedAt && monthsSince(gh.pushedAt) >= ctx.opt.staleMonths) extras.push(`no commits in ${years(monthsSince(gh.pushedAt))} years`);
      if (dl != null && dl < 1000) extras.push(`only ${fmtN(dl)} downloads/week`);
      add(s, 'stale', `No release in ${years(ageM)} years${extras.length ? ` (${extras.join(', ')})` : ''}.`);
      if (s >= SEV.high) unmaintained = true;
    }
  }

  const vulns = (ctx.vulns?.byKey?.get(`${p.name}@${p.version}`) || [])
    .map((id) => ctx.vulns.details.get(id)).filter(Boolean).map((d) => vulnInfo(d, p.name))
    .sort((a, b) => b.severity - a.severity);
  for (const v of vulns) {
    add(v.severity, v.malicious ? 'malicious' : 'vulnerable', `${v.malicious ? 'KNOWN MALICIOUS PACKAGE' : `${SEV_NAME[v.severity]} vulnerability`} ${v.cve || v.id}: ${v.summary}`);
  }
  if (vulns.length && unmaintained && !vulns.some((v) => v.malicious)) {
    add(SEV.critical, 'vulnerable', 'Has known vulnerabilities AND appears unmaintained — a fix may never ship. Replace it.');
  }

  if (isDirect && m.latest) {
    const a = parseV(p.version), b = parseV(m.latest);
    if (a && b && b[0] > a[0]) add(SEV.low, 'outdated', `${b[0] - a[0]} major version${b[0] - a[0] > 1 ? 's' : ''} behind (latest is ${m.latest}).`);
  }

  if (p.installScripts) add(SEV.info, 'install-script', `Runs code at install time — ${Object.entries(p.installScripts).map(([k, v]) => `${k}: ${trimStr(v, 80)}`).join('; ')}`);

  if (sev < 0) return null;

  // ---- Recommendations ----
  const via = chain.length > 1 ? chain[0] : null;
  if (badAncestor) {
    const upgrade = ctx.isOldRoot(badAncestor);
    recs.push({ text: `Fix the root cause: ${upgrade ? 'upgrade' : 'replace'} ${badAncestor}${badAncestor === chain[0] ? ' (your direct dependency)' : ` (pulled in by ${chain.slice(0, chain.indexOf(badAncestor) + 1).join(' → ')})`}${upgrade ? ' — the version you have is deprecated' : ''}. This package should disappear with it.` });
  }
  const malicious = vulns.some((v) => v.malicious) || known?.critical;
  if (malicious) {
    recs.push({ text: `Remove this package now${via ? ` (it comes in via ${chain.join(' → ')})` : ''}, delete node_modules and your lockfile entry for it, reinstall, and rotate any secrets (npm, GitHub, cloud, .env) that were present on machines where it was installed.` });
  }
  const alts = new Set(known?.alts || []);
  for (const s of suggestedFromDeprecation(m.deprecatedLatest || installedDep, p.name)) if (![...alts].some((a) => a.startsWith(s))) alts.add(`${s} (suggested by the author)`);

  if (alts.size && (unmaintained || known || m.deprecatedLatest)) {
    recs.push({ text: `${isDirect ? 'Replace with' : 'Better alternatives (for whoever depends on it)'}: ${[...alts].join(', ')}` });
  }

  const fix = vulns.flatMap((v) => v.fixed).filter((f) => cmpV(f, p.version) > 0).sort(cmpV).at(-1);
  if (vulns.length && !malicious) {
    if (fix) {
      if (isDirect) recs.push({ text: `Upgrade to ${fix} or newer to clear the known vulnerabilities.`, code: `npm install ${p.name}@^${fix}` });
      else recs.push({ text: `First try upgrading ${via} (run \`npm ls ${p.name}\` to see every path). If ${via}'s latest still pins a vulnerable ${p.name}, force the fixed version with an override, then run your tests — overrides can break the parent if the major version changes.`, code: overrideSnippet(p.name, `^${fix}`) });
    } else {
      recs.push({ text: 'No fixed version is published. Replace the package, or limit exposure: do not pass it untrusted input, and keep it out of production builds if it is only needed at build time.' });
    }
  }

  if (installedDep && !m.deprecatedLatest) {
    if (isDirect) recs.push({ text: `Upgrade to the non-deprecated latest version.`, code: `npm install ${p.name}@${m.latest}` });
    else recs.push({ text: `This old version is pulled in by ${chain.join(' → ')}. Upgrading ${via} usually fixes it; if not, an override to ${p.name}@${m.latest} is an option (test it — major versions may differ).` });
  }

  if ((unmaintained || cats.has('stale')) && sev >= SEV.medium && !badAncestor && !alts.size && !malicious && !cats.has('vulnerable')) {
    const kw = m.keywords?.[0] || p.name;
    recs.push({ text: isDirect
      ? `No curated replacement. Look for an actively maintained alternative (search npm for "${kw}"), or vendor the code if it is small and stable.`
      : `This comes in via ${chain.join(' → ')}. Check whether a newer ${via} has dropped it; if not, consider opening an issue with ${via}'s maintainers.`, link: `https://www.npmjs.com/search?q=${encodeURIComponent('keywords:' + kw)}` });
  }

  if (cats.has('install-script') && sev <= SEV.low) {
    recs.push({ text: 'Install scripts are a common malware vector. If this package works without them, install with --ignore-scripts, or set ignore-scripts=true in .npmrc and allow-list the packages that need them.' });
  }

  if (cats.has('outdated') && isDirect && !installedDep && !vulns.length && !known) {
    recs.push({ text: `Plan an upgrade to ${m.latest} — staying several majors behind means you won't get security fixes that only land on the current line.` });
  }

  reasons.sort((a, b) => b.sev - a.sev);
  return {
    name: p.name, version: p.version, latest: m.latest || null, severity: sev, categories: [...cats],
    direct: isDirect, devOnly, chain, reasons, recommendations: recs, vulns,
    meta: {
      lastPublish: m.lastPublish || null, ageMonths: ageM != null ? Math.round(ageM) : null, maintainers: m.maintainers ?? null,
      weeklyDownloads: dl ?? null, repository: m.repository || null, archived: gh?.archived || false, stars: gh?.stars ?? null,
      license: p.license, installScripts: p.installScripts, description: m.description || '',
      npm: `https://www.npmjs.com/package/${p.name}/v/${p.version}`, locations: p.locations.slice(0, 5),
    },
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
function printTerminal(report, opt) {
  const { summary, findings } = report;
  const minSev = SEV[opt.min];
  console.log('');
  console.log(col.bold(`rotcheck — ${report.project.name || path.basename(report.project.path)}`));
  console.log(col.gray(`${summary.scanned} installed packages scanned (${summary.direct} direct)`));
  console.log('');
  const line = [4, 3, 2, 1].map((s) => sevColor[s](` ${SEV_NAME[s].toUpperCase()} ${summary.bySeverity[SEV_NAME[s]]} `)).join(' ');
  console.log(line);
  console.log(col.gray(`${summary.vulnerable} with known vulnerabilities · ${summary.unmaintained} deprecated/unmaintained · ${summary.installScripts} with install scripts`));
  for (const w of report.warnings) console.log(col.yellow('! ') + w);
  console.log('');

  const shown = findings.filter((f) => f.severity >= minSev);
  const limit = 40;
  for (const f of shown.slice(0, limit)) {
    const tag = sevColor[f.severity](` ${SEV_NAME[f.severity].toUpperCase().padEnd(8)}`);
    const where = f.direct ? 'direct' : `via ${f.chain.slice(0, -1).join(' → ') || '?'}`;
    console.log(`${tag} ${col.bold(`${f.name}@${f.version}`)} ${col.gray(`${where}${f.devOnly ? ' · dev' : ''}`)}`);
    for (const r of f.reasons.filter((r) => r.sev > 0).slice(0, 3)) console.log(`           ${col.gray('•')} ${trimStr(r.msg, 160)}`);
    if (f.recommendations[0]) console.log(`           ${col.green('→')} ${trimStr(f.recommendations[0].text, 160)}`);
  }
  if (shown.length > limit) console.log(col.gray(`\n… and ${shown.length - limit} more in the HTML report.`));
  if (!shown.length) console.log(col.green(`Nothing at ${opt.min} severity or above. 🎉`));
}

// The static HTML report and the dashboard share the same styles, markup and rendering code.
const REPORT_CSS = String.raw`
:root{color-scheme:light;--bg:#f6f6f3;--card:#fff;--text:#1d1d1b;--muted:#6b6b66;--border:#e3e2dc;--code:#f0efea;--crit:#b42318;--high:#c2410c;--med:#a16207;--low:#2563eb;--info:#78776f;--ok:#15803d;--chipt:#fff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 2px;letter-spacing:-.01em}.sub{color:var(--muted);margin:0 0 20px}
.verdict{display:flex;gap:14px;align-items:center;background:var(--card);border:1px solid var(--border);border-left:4px solid var(--vc);border-radius:12px;padding:14px 18px;margin-bottom:14px}
.verdict .ic{flex:none;width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:var(--vc);color:var(--chipt);font-weight:800;font-size:17px}
.verdict b{display:block;font-size:16px;letter-spacing:-.01em}.verdict span{color:var(--muted);font-size:13px}
.v-ok{--vc:var(--ok)}.v-warn{--vc:var(--high)}.v-bad{--vc:var(--crit)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;cursor:pointer;text-align:left;font:inherit;color:inherit;border-top:3px solid var(--sevc,var(--border))}
.card:hover{border-color:var(--muted)}.card .n{font-size:24px;font-weight:650;line-height:1.1}.card .l{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.warn{background:var(--card);border:1px dashed var(--border);border-radius:8px;padding:8px 12px;color:var(--muted);margin-bottom:10px;font-size:13px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2}
input[type=search],select{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:7px 10px;font:inherit}
input[type=search]{flex:1;min-width:180px}label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px;white-space:nowrap}
.count{color:var(--muted);font-size:13px;margin-bottom:8px}
.f{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--sevc);border-radius:10px;margin-bottom:8px}
.f summary{list-style:none;cursor:pointer;padding:11px 14px;display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center}
.f summary::-webkit-details-marker{display:none}
.chip{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--chipt);background:var(--sevc);border-radius:5px;padding:2px 7px}
.name{font-weight:650;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px;word-break:break-all}
.badge{font-size:11.5px;border:1px solid var(--border);border-radius:999px;padding:0 8px;color:var(--muted)}
.why{color:var(--muted);flex-basis:100%;font-size:13px}
.body{padding:2px 16px 14px;border-top:1px solid var(--border)}
.body h4{margin:14px 0 6px;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.body ul{margin:0;padding-left:18px}.body li{margin:3px 0}
pre,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--code);padding:10px 12px;border-radius:8px;overflow:auto;margin:6px 0}code{background:var(--code);padding:1px 5px;border-radius:4px}
.path{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-word}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;padding:5px 8px 5px 0;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted);font-weight:600}
a{color:var(--low)}.meta{display:flex;flex-wrap:wrap;gap:4px 18px;color:var(--muted);font-size:12.5px;margin-top:14px}
.empty{color:var(--muted);padding:40px;text-align:center}
.tips{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:4px 20px 14px;margin-top:28px}.tips li{margin:6px 0}
.s-critical{--sevc:var(--crit)}.s-high{--sevc:var(--high)}.s-medium{--sevc:var(--med)}.s-low{--sevc:var(--low)}.s-info{--sevc:var(--info)}
`;

const REPORT_MARKUP = String.raw`
<h1 id="title">Package Health Report</h1><p class="sub" id="sub"></p>
<div id="verdict"></div><div id="warnings"></div><div class="cards" id="cards"></div>
<div class="controls">
<input type="search" id="q" placeholder="Filter by package, reason or advisory…">
<select id="min"><option value="1">Low and above</option><option value="2">Medium and above</option><option value="3">High and above</option><option value="4">Critical only</option><option value="0">Everything (incl. info)</option></select>
<select id="cat"><option value="">All issue types</option><option value="vulnerable">Vulnerable</option><option value="malicious">Malicious</option><option value="deprecated">Deprecated</option><option value="unmaintained">Unmaintained / archived</option><option value="stale">Stale</option><option value="known-issue">Known incident / abandoned</option><option value="outdated">Outdated</option><option value="replaceable">Replaceable by built-in</option><option value="install-script">Install scripts</option></select>
<label class="chk"><input type="checkbox" id="direct"> Direct only</label>
<label class="chk"><input type="checkbox" id="prod"> Hide dev-only</label>
</div>
<div class="count" id="count"></div><div id="list"></div>
<div class="tips"><h3>General hardening (works alongside Dependabot)</h3><ul>
<li><b>Commit your lockfile and install with <code>npm ci</code></b> in CI so builds use exactly the versions you reviewed.</li>
<li><b>Verify registry signatures:</b> <code>npm audit signatures</code> checks that installed packages were signed by the registry and reports provenance attestations.</li>
<li><b>Block install scripts by default:</b> add <code>ignore-scripts=true</code> to <code>.npmrc</code> and explicitly run the few that are needed. Most supply-chain malware runs from postinstall.</li>
<li><b>Force fixes into transitive deps</b> with <code>overrides</code> (npm), <code>resolutions</code> (yarn) or <code>pnpm.overrides</code> — then remove the override once the parent catches up.</li>
<li><b>Turn on Dependabot <i>version</i> updates</b> (not just security alerts) with grouping, so you stay close to current and upgrades stay small.</li>
<li><b>Don't install brand-new releases immediately:</b> pnpm's <code>minimumReleaseAge</code> setting delays them, which avoids most hijacked-release incidents that are caught within hours or days.</li>
<li><b>Prefer built-ins</b> (fetch, crypto.randomUUID, structuredClone, URLSearchParams, fs.rm) over tiny single-purpose packages — every package is another maintainer account that can be compromised.</li>
</ul></div>
<p class="sub" style="margin-top:20px" id="foot"></p>
`;

// Defines show(report); the static report calls it with inlined data, the dashboard after each scan.
const REPORT_JS = String.raw`
var D,SEVN=['info','low','medium','high','critical'],st,cards=[];
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function fmtN(n){if(n==null)return '?';return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':String(n);}
function link(u,t){return u?'<a href="'+esc(u)+'" target="_blank" rel="noopener noreferrer">'+esc(t||u)+'</a>':'';}
function plural(n,one,many){return n+' '+(n===1?one:many);}
function show(data){
D=data;var s=D.summary.bySeverity;
$('title').textContent='Package Health — '+(D.project.name||D.project.path);
$('sub').textContent=D.summary.scanned+' installed packages scanned ('+D.summary.direct+' direct) · '+new Date(D.generatedAt).toLocaleString();
$('foot').textContent='Generated by '+D.tool.name+' '+D.tool.version+' · stale threshold '+D.options.staleMonths+' months · data from the npm registry, OSV.dev and GitHub.';
$('warnings').innerHTML=D.warnings.map(function(w){return '<div class="warn">'+esc(w)+'</div>';}).join('');
var rest=s.medium+s.low;
var v=s.critical?['v-bad','!',plural(s.critical,'critical issue needs','critical issues need')+' attention','Fix these first. Open each one to see why it was flagged and what to do.']
:s.high?['v-warn','!','No critical issues','But '+plural(s.high,'high-severity issue is','high-severity issues are')+' worth fixing soon.']
:['v-ok','✓','No critical or high-severity issues',rest?plural(rest,'lower-severity item','lower-severity items')+' below, for when you have time.':'Your dependency tree looks healthy.'];
$('verdict').innerHTML='<div class="verdict '+v[0]+'"><div class="ic">'+v[1]+'</div><div><b>'+esc(v[2])+'</b><span>'+esc(v[3])+'</span></div></div>';
cards=[['critical',s.critical,'s-critical',{min:4}],['high',s.high,'s-high',{min:3}],['medium',s.medium,'s-medium',{min:2}],['low',s.low,'s-low',{min:1}],['vulnerable',D.summary.vulnerable,'',{cat:'vulnerable',min:0}],['unmaintained',D.summary.unmaintained,'',{cat:'',min:3}],['install scripts',D.summary.installScripts,'',{cat:'install-script',min:0}]];
$('cards').innerHTML=cards.map(function(c,i){return '<button class="card '+c[2]+'" data-i="'+i+'"><div class="n">'+c[1]+'</div><div class="l">'+c[0]+'</div></button>';}).join('');
st={q:'',min:2,cat:'',direct:false,prod:false};$('q').value='';$('direct').checked=false;$('prod').checked=false;
sync();render();}
$('cards').addEventListener('click',function(e){var b=e.target.closest('.card');if(!b)return;var c=cards[+b.dataset.i][3];st.min=c.min;st.cat=c.cat||'';sync();render();});
function sync(){$('min').value=String(st.min);$('cat').value=st.cat;}
['q','min','cat','direct','prod'].forEach(function(id){$(id).addEventListener('input',function(){st.q=$('q').value.toLowerCase();st.min=+$('min').value;st.cat=$('cat').value;st.direct=$('direct').checked;st.prod=$('prod').checked;render();});});
function card(f){
var s=SEVN[f.severity];var top=f.reasons.filter(function(r){return r.sev>0;})[0]||f.reasons[0];
var h='<details class="f s-'+s+'"><summary><span class="chip">'+s+'</span><span class="name">'+esc(f.name)+'@'+esc(f.version)+'</span>';
if(f.latest&&f.latest!==f.version)h+='<span class="badge">latest '+esc(f.latest)+'</span>';
h+='<span class="badge">'+(f.direct?'direct':'transitive')+'</span>';if(f.devOnly)h+='<span class="badge">dev only</span>';
if(f.vulns.length)h+='<span class="badge">'+f.vulns.length+' advisor'+(f.vulns.length>1?'ies':'y')+'</span>';
if(f.meta.ageMonths!=null)h+='<span class="badge">last release '+(f.meta.ageMonths<12?f.meta.ageMonths+' mo':(f.meta.ageMonths/12).toFixed(1)+' yr')+' ago</span>';
h+='<span class="why">'+esc(top?top.msg:'')+'</span></summary><div class="body">';
h+='<h4>Why it was flagged</h4><ul>'+f.reasons.map(function(r){return '<li>'+esc(r.msg)+'</li>';}).join('')+'</ul>';
if(f.recommendations.length){h+='<h4>What to do</h4><ul>'+f.recommendations.map(function(r){return '<li>'+esc(r.text)+(r.link?' '+link(r.link,'Search npm'):'')+(r.code?'<pre>'+esc(r.code)+'</pre>':'')+'</li>';}).join('')+'</ul>';}
if(f.vulns.length){h+='<h4>Advisories</h4><table><tr><th>ID</th><th>Severity</th><th>Summary</th><th>Fixed in</th></tr>'+f.vulns.map(function(v){return '<tr><td>'+link(v.url,v.cve||v.id)+'</td><td>'+(v.malicious?'MALICIOUS':SEVN[v.severity])+'</td><td>'+esc(v.summary)+'</td><td>'+esc(v.fixed.join(', ')||'—')+'</td></tr>';}).join('')+'</table>';}
if(!f.direct&&f.chain.length>1)h+='<h4>How it got here</h4><div class="path">'+f.chain.map(esc).join(' → ')+'</div>';
var m=f.meta;h+='<div class="meta">';
if(m.description)h+='<span>'+esc(m.description)+'</span>';
h+='<span>'+fmtN(m.weeklyDownloads)+' downloads/week</span>';if(m.maintainers!=null)h+='<span>'+m.maintainers+' maintainer'+(m.maintainers===1?'':'s')+'</span>';
if(m.license)h+='<span>'+esc(m.license)+'</span>';if(m.stars!=null)h+='<span>★ '+fmtN(m.stars)+'</span>';
h+='<span>'+link(m.npm,'npm')+'</span>';if(m.repository)h+='<span>'+link(m.repository,'source')+'</span>';
h+='</div></div></details>';return h;}
function render(){
var list=D.findings.filter(function(f){
if(f.severity<st.min)return false;if(st.cat&&f.categories.indexOf(st.cat)<0)return false;if(st.direct&&!f.direct)return false;if(st.prod&&f.devOnly)return false;
if(st.q){var hay=(f.name+' '+f.reasons.map(function(r){return r.msg;}).join(' ')+' '+f.vulns.map(function(v){return v.id+' '+(v.cve||'');}).join(' ')).toLowerCase();if(hay.indexOf(st.q)<0)return false;}
return true;});
$('count').textContent=list.length+' of '+D.findings.length+' flagged packages shown';
$('list').innerHTML=list.length?list.map(card).join(''):'<div class="empty">Nothing matches these filters.</div>';}
`;

const HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>rotcheck report</title>
<style>${REPORT_CSS}</style></head><body><div class="wrap">${REPORT_MARKUP}</div>
<script>${REPORT_JS}
show(__DATA__);
</script></body></html>`;

function reportHtml(report) {
  const json = JSON.stringify(report).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  return HTML.replace('__DATA__', () => json);
}
function writeHtml(report, file) { fs.writeFileSync(file, reportHtml(report)); }

// ---------------------------------------------------------------------------
// Web dashboard (--ui): a local page to pick a project, scan it, and browse results
// ---------------------------------------------------------------------------
const UI_CSS = String.raw`
[hidden]{display:none!important}
.top{border-bottom:1px solid var(--border);background:var(--card)}
.top-in{max-width:1100px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:8px;font-weight:750;font-size:15px;color:var(--text);text-decoration:none;letter-spacing:-.01em}
.brand svg{color:var(--ok)}.ver{color:var(--muted);font-size:12px}.sp{flex:1}
nav{display:flex;gap:6px;flex-wrap:wrap}
.btn{font:inherit;font-weight:600;font-size:13px;border-radius:8px;padding:7px 12px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;white-space:nowrap;text-decoration:none;display:inline-block}
.btn:hover{border-color:var(--muted)}.btn:disabled{opacity:.5;cursor:default}
.btn.ghost{background:transparent}
.btn.primary{background:var(--text);color:var(--bg);border-color:var(--text)}.btn.primary:hover{opacity:.88}
.btn.big{width:100%;padding:12px;font-size:15px;margin-top:18px}
.hero{max-width:640px;margin:0 auto;padding:56px 16px 64px}
.hero h2{font-size:30px;letter-spacing:-.025em;line-height:1.15;margin:0 0 10px}
.lead{color:var(--muted);font-size:15px;margin:0 0 26px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 8px 28px rgba(0,0,0,.05)}
.lbl{display:block;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600;margin-bottom:6px}
.row{display:flex;gap:8px}
.inp{flex:1;min-width:0;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 11px;font:inherit}
.inp:focus{outline:2px solid var(--low);outline-offset:-1px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.num{flex:none;width:64px;padding:4px 6px}
.hint{font-size:12.5px;margin-top:7px;min-height:19px;color:var(--muted)}.hint.ok{color:var(--ok)}.hint.bad{color:var(--high)}
.opts{margin-top:14px;border-top:1px solid var(--border);padding-top:12px}
.opts summary{cursor:pointer;color:var(--muted);font-size:13px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px 16px;margin-top:10px}
.grid label.chk{white-space:normal}
.err{margin-top:14px;padding:10px 12px;border-radius:8px;border:1px solid var(--crit);color:var(--crit);font-size:13px}
.alt{text-align:center;color:var(--muted);font-size:13px;margin-top:12px}
.linkish{color:var(--low);cursor:pointer;text-decoration:underline;text-underline-offset:2px}
.recent{margin-top:26px}
.pill{display:block;width:100%;text-align:left;background:transparent;border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin-bottom:6px;color:var(--text);cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill:hover{background:var(--card);border-color:var(--muted)}
.scanning{text-align:center;padding:36px 24px}.scanning h3{margin:0 0 4px;font-size:18px}
.muted{color:var(--muted)}.small{font-size:12.5px}
.spin{width:34px;height:34px;border-radius:50%;border:3px solid var(--border);border-top-color:var(--text);margin:0 auto 16px;animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.steps{list-style:none;padding:0;margin:22px auto 18px;text-align:left;max-width:280px}
.steps li{display:flex;gap:10px;align-items:center;padding:3px 0;color:var(--muted);font-size:13.5px}
.steps li::before{content:'';width:8px;height:8px;border-radius:50%;border:1.5px solid var(--border);flex:none}
.steps li.act{color:var(--text);font-weight:600}.steps li.act::before{background:var(--low);border-color:var(--low)}
.steps li.done::before{background:var(--ok);border-color:var(--ok)}
.bar{height:4px;background:var(--border);border-radius:4px;overflow:hidden;margin-bottom:8px}
.bar i{display:block;height:100%;width:0;background:var(--text);transition:width .2s}
.bar.ind i{width:30%;animation:ind 1.3s ease-in-out infinite}@keyframes ind{from{transform:translateX(-100%)}to{transform:translateX(340%)}}
dialog{width:min(560px,calc(100vw - 32px));border:1px solid var(--border);border-radius:14px;padding:0;background:var(--card);color:var(--text)}
dialog::backdrop{background:rgba(0,0,0,.4)}
.dlg-h,.dlg-f{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px}
.dlg-f{border-top:1px solid var(--border)}
.x{background:none;border:0;font-size:22px;line-height:1;color:var(--muted);cursor:pointer}
.crumbs{padding:8px 16px;background:var(--code);word-break:break-all;font-size:12.5px}
.dirs{list-style:none;margin:0;padding:6px;max-height:50vh;overflow:auto}
.dirs button{width:100%;text-align:left;background:none;border:0;color:var(--text);font:inherit;padding:7px 10px;border-radius:7px;cursor:pointer;display:flex;gap:8px;align-items:center}
.dirs button:hover{background:var(--code)}.dirs svg{flex:none;color:var(--muted)}
.dirs .tag{margin-left:auto;font-size:11px;color:var(--ok);font-weight:600}
@media (max-width:520px){.hero{padding-top:32px}.hero h2{font-size:24px}.row{flex-direction:column}}
@media (prefers-reduced-motion:reduce){.spin,.bar.ind i{animation-duration:4s}}
`;

const UI_JS = String.raw`
var CFG=__CONFIG__;
var cur=null,lastOpts=null,RKEY='rotcheck.recent';
var FOLDER='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>';
var STEPS=[['Reading node_modules',/node_modules|Found/],['npm registry',/registry/],['Download stats',/download/],['Vulnerabilities',/OSV|vulnerab/],['GitHub repos',/GitHub/],['Scoring findings',/Scoring/]];
function recent(){try{return JSON.parse(localStorage.getItem(RKEY))||[];}catch(e){return [];}}
function addRecent(p){try{var r=recent().filter(function(x){return x!==p;});r.unshift(p);localStorage.setItem(RKEY,JSON.stringify(r.slice(0,5)));}catch(e){}}
function drawRecent(){var r=recent();$('recent').innerHTML=r.length?'<span class="lbl">Recent projects</span>'+r.map(function(p){return '<button type="button" class="pill mono" data-p="'+esc(p)+'" title="'+esc(p)+'">'+esc(p)+'</button>';}).join(''):'';}
function view(v){['start','scan','results'].forEach(function(k){$('v-'+k).hidden=k!==v;});$('actions').hidden=v!=='results';window.scrollTo(0,0);}
function showErr(m){$('err').textContent=m;$('err').hidden=!m;}
function opts(){return{path:$('path').value.trim()||CFG.path,prodOnly:$('o-prod').checked,directOnly:$('o-direct').checked,osv:$('o-osv').checked,github:$('o-gh').checked,useCache:$('o-cache').checked,staleMonths:+$('o-stale').value||24};}

var hintT;
function checkPath(){clearTimeout(hintT);hintT=setTimeout(function(){var p=$('path').value.trim();if(!p){$('pathhint').textContent='';return;}
fetch('/api/dirs?path='+encodeURIComponent(p)).then(function(r){return r.json();}).then(function(r){var h=$('pathhint');
if(r.error){h.className='hint bad';h.textContent=r.error;}
else if(r.project&&r.installed){h.className='hint ok';h.textContent='✓ Node project with installed dependencies';}
else if(r.project){h.className='hint bad';h.textContent='Has a package.json but no node_modules. Run npm install (or yarn / pnpm) there first.';}
else{h.className='hint bad';h.textContent='No package.json in this folder.';}}).catch(function(){});},250);}

function step(msg){var i=-1;STEPS.forEach(function(s,k){if(s[1].test(msg))i=k;});
if(i>=0)Array.prototype.forEach.call($('steps').children,function(li,k){li.className=k<i?'done':k===i?'act':'';});
var m=/(\d+)\/(\d+)/.exec(msg);$('bar').parentNode.className=m?'bar':'bar ind';$('bar').style.width=m?Math.round(100*m[1]/m[2])+'%':'';
$('stepmsg').textContent=msg;}

async function run(o){
lastOpts=o;showErr('');view('scan');$('scan-path').textContent=o.path;
$('steps').innerHTML=STEPS.map(function(s){return '<li>'+s[0]+'</li>';}).join('');step('Reading node_modules…');
try{
var res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});
if(!res.ok){var j=await res.json().catch(function(){return {};});throw new Error(j.error||'The server answered '+res.status+'.');}
var rd=res.body.getReader(),dec=new TextDecoder(),buf='',done=false;
while(!done){var c=await rd.read();if(c.done)break;buf+=dec.decode(c.value,{stream:true});var lines=buf.split('\n');buf=lines.pop();
for(var i=0;i<lines.length;i++){if(!lines[i])continue;var m=JSON.parse(lines[i]);
if(m.type==='progress')step(m.msg);
else if(m.type==='error')throw new Error(m.msg);
else if(m.type==='done'){done=true;cur=m.report;addRecent(o.path);show(cur);view('results');}}}
if(!done)throw new Error('The scan stopped unexpectedly. Check the terminal running rotcheck.');
}catch(e){view('start');drawRecent();showErr(e.message==='Failed to fetch'?'Lost connection to rotcheck. Is it still running in your terminal?':e.message);}}

function save(name,type,text){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:type}));a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},0);}
function slug(){return (cur.project.name||'project').replace(/[^\w.-]+/g,'-')+'-health';}
$('dljson').onclick=function(){save(slug()+'.json','application/json',JSON.stringify(cur,null,2));};
$('dlhtml').onclick=async function(){var t=await (await fetch('/api/report-template')).text();
var j=JSON.stringify(cur).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
save(slug()+'.html','text/html',t.replace('__DATA__',function(){return j;}));};
$('rescan').onclick=function(){run(lastOpts||Object.assign(opts(),{path:cur.project.path}));};
$('newscan').onclick=function(){drawRecent();view('start');};

$('form').addEventListener('submit',function(e){e.preventDefault();run(opts());});
$('path').addEventListener('input',checkPath);
$('recent').addEventListener('click',function(e){var b=e.target.closest('.pill');if(b){$('path').value=b.dataset.p;checkPath();}});
$('file').addEventListener('change',function(){var f=this.files[0];this.value='';if(!f)return;
f.text().then(function(t){var r=JSON.parse(t);if(!r||!r.findings||!r.summary)throw new Error('That file is not a rotcheck JSON report.');cur=r;lastOpts=null;show(r);view('results');})
.catch(function(e){showErr(e instanceof SyntaxError?'Could not read that file as JSON.':e.message);});});

var dlgPath=null;
function openDir(p){fetch('/api/dirs?path='+encodeURIComponent(p)).then(function(r){return r.json();}).then(function(r){
if(r.error&&dlgPath){$('dlg-note').textContent=r.error;return;}
dlgPath=r.path;$('dlg-path').textContent=r.path;
var h=r.parent?'<li><button data-p="'+esc(r.parent)+'">'+FOLDER+'<span>..</span></button></li>':'';
h+=r.dirs.map(function(d){return '<li><button data-p="'+esc(d.path)+'">'+FOLDER+'<span>'+esc(d.name)+'</span>'+(d.project?'<span class="tag">'+(d.installed?'project':'project · not installed')+'</span>':'')+'</button></li>';}).join('');
$('dlg-list').innerHTML=h||'<li class="muted small" style="padding:10px">No subfolders</li>';
$('dlg-note').textContent=r.error||(r.project?(r.installed?'This folder is a project.':'Project found, but run npm install first.'):'');});}
$('browse').onclick=function(){dlgPath=null;openDir($('path').value.trim()||CFG.path);$('dlg').showModal();};
$('dlg-list').addEventListener('click',function(e){var b=e.target.closest('button');if(b)openDir(b.dataset.p);});
$('dlg-x').onclick=function(){$('dlg').close();};
$('dlg-ok').onclick=function(){if(dlgPath){$('path').value=dlgPath;checkPath();}$('dlg').close();};

$('ver').textContent='v'+CFG.version;$('path').value=CFG.path;$('o-stale').value=CFG.staleMonths;
if(!CFG.token)$('gh-lbl').title='Without GITHUB_TOKEN set, only flagged and direct packages are checked.';
drawRecent();checkPath();
var auto=false;try{auto=CFG.autoScan&&!sessionStorage.getItem('rotcheck.auto');sessionStorage.setItem('rotcheck.auto','1');}catch(e){}
if(auto)run(opts());
`;

const UI_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>rotcheck</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M3 12h4l3-8 4 16 3-8h4' fill='none' stroke='%2315803d' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>${REPORT_CSS}${UI_CSS}</style></head><body>
<header class="top"><div class="top-in">
<a class="brand" href="/"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>rotcheck</a>
<span class="ver" id="ver"></span><div class="sp"></div>
<nav id="actions" hidden><button class="btn ghost" id="rescan">Rescan</button><button class="btn ghost" id="dlhtml">Download HTML</button><button class="btn ghost" id="dljson">Download JSON</button><button class="btn primary" id="newscan">New scan</button></nav>
</div></header>
<main>
<section id="v-start" class="hero">
<h2>How healthy are your dependencies?</h2>
<p class="lead">Pick a project folder. rotcheck checks every installed package for known vulnerabilities, deprecation, abandonment and supply-chain incidents, and tells you what to do about each one.</p>
<form id="form" class="panel">
<label class="lbl" for="path">Project folder</label>
<div class="row"><input id="path" class="inp mono" autocomplete="off" spellcheck="false"><button type="button" class="btn" id="browse">Browse…</button></div>
<div id="pathhint" class="hint"></div>
<details class="opts"><summary>Options</summary><div class="grid">
<label class="chk"><input type="checkbox" id="o-prod"> Production dependencies only</label>
<label class="chk"><input type="checkbox" id="o-direct"> Direct dependencies only</label>
<label class="chk"><input type="checkbox" id="o-osv" checked> Check OSV.dev for vulnerabilities</label>
<label class="chk" id="gh-lbl"><input type="checkbox" id="o-gh" checked> Check GitHub for archived repos</label>
<label class="chk"><input type="checkbox" id="o-cache" checked> Reuse results from the last 24h</label>
<label class="chk">Stale after <input type="number" id="o-stale" class="inp num" min="1" max="240"> months</label>
</div></details>
<div id="err" class="err" role="alert" hidden></div>
<button class="btn primary big" type="submit">Scan project</button>
<div class="alt">or <label class="linkish">open a saved JSON report<input type="file" id="file" accept=".json,application/json" hidden></label></div>
</form>
<div id="recent" class="recent"></div>
</section>
<section id="v-scan" class="hero" hidden><div class="panel scanning" aria-live="polite">
<div class="spin"></div><h3>Scanning…</h3><div class="mono muted small" id="scan-path"></div>
<ol class="steps" id="steps"></ol>
<div class="bar"><i id="bar"></i></div><div class="muted small" id="stepmsg"></div>
</div></section>
<section id="v-results" hidden><div class="wrap">${REPORT_MARKUP}</div></section>
</main>
<dialog id="dlg">
<div class="dlg-h"><b>Choose a project folder</b><button class="x" id="dlg-x" aria-label="Close">×</button></div>
<div class="mono crumbs" id="dlg-path"></div>
<ul class="dirs" id="dlg-list"></ul>
<div class="dlg-f"><span class="muted small" id="dlg-note"></span><button class="btn primary" id="dlg-ok">Use this folder</button></div>
</dialog>
<script>${REPORT_JS}${UI_JS}</script>
</body></html>`;

function dirInfo(p) {
  const dir = path.resolve(String(p));
  const has = (d, f) => fs.existsSync(path.join(d, f));
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return { path: dir, error: `Can't open ${dir}`, dirs: [] }; }
  const parent = path.dirname(dir);
  const dirs = entries.filter((e) => e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules')
    .map((e) => e.name).sort((a, b) => a.localeCompare(b)).slice(0, 400)
    .map((name) => { const full = path.join(dir, name); return { name, path: full, project: has(full, 'package.json'), installed: has(full, 'node_modules') }; });
  return { path: dir, parent: parent === dir ? null : parent, project: has(dir, 'package.json'), installed: has(dir, 'node_modules'), dirs };
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const parts = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new UserError('Request too large')); req.destroy(); } else parts.push(c); });
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    req.on('error', reject);
  });
}

async function serve(opt) {
  const http = await import('node:http');
  const start = dirInfo(opt.path);
  const config = { path: opt.path, version: VERSION, staleMonths: opt.staleMonths, autoScan: !!(start.project && start.installed),
    token: !!(process.env.GITHUB_TOKEN || process.env.GH_TOKEN) };
  const page = UI_HTML.replace('__CONFIG__', () => JSON.stringify(config).replace(/</g, '\\u003c'));
  let busy = false;

  const send = (res, status, type, body) => { res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(body); };
  const sendJSON = (res, status, obj) => send(res, status, 'application/json; charset=utf-8', JSON.stringify(obj));

  async function handleScan(req, res) {
    // Requiring JSON forces a CORS preflight, so other websites can't trigger scans.
    if (!/^application\/json/.test(req.headers['content-type'] || '')) return sendJSON(res, 415, { error: 'Expected JSON' });
    if (busy) return sendJSON(res, 409, { error: 'A scan is already running. Wait for it to finish.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid request' }); }
    const stale = Number(body.staleMonths);
    const o = { ...opt, path: path.resolve(String(body.path || opt.path)), prodOnly: !!body.prodOnly, directOnly: !!body.directOnly,
      osv: body.osv !== false, github: body.github !== false, cacheHours: body.useCache === false ? 0 : 24,
      staleMonths: stale >= 1 && stale <= 240 ? stale : 24 };

    res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store' });
    const out = (m) => res.write(JSON.stringify(m) + '\n');
    busy = true;
    progressHook = (msg) => out({ type: 'progress', msg });
    console.log(col.gray(`Scanning ${o.path}…`));
    try {
      const report = await scan(o);
      const s = report.summary.bySeverity;
      console.log(`Scanned ${report.summary.scanned} packages: ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low.`);
      out({ type: 'done', report });
    } catch (e) {
      const msg = e instanceof UserError ? e.message : `Scan failed: ${e.message}`;
      if (!(e instanceof UserError)) console.error(col.red('Scan failed: ') + (e.stack || e));
      out({ type: 'error', msg });
    } finally {
      busy = false; progressHook = null; res.end();
    }
  }

  const server = http.createServer(async (req, res) => {
    // Only answer requests addressed to this machine by name (blocks DNS-rebinding attacks).
    const host = req.headers.host || '';
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host)) return send(res, 403, 'text/plain', 'Forbidden');
    if (req.headers.origin && req.headers.origin !== `http://${host}`) return send(res, 403, 'text/plain', 'Forbidden');
    const url = new URL(req.url, `http://${host}`);
    try {
      if (req.method === 'GET' && url.pathname === '/') return send(res, 200, 'text/html; charset=utf-8', page);
      if (req.method === 'GET' && url.pathname === '/api/dirs') return sendJSON(res, 200, dirInfo(url.searchParams.get('path') || opt.path));
      if (req.method === 'GET' && url.pathname === '/api/report-template') return send(res, 200, 'text/plain; charset=utf-8', HTML);
      if (req.method === 'POST' && url.pathname === '/api/scan') return await handleScan(req, res);
      send(res, 404, 'text/plain', 'Not found');
    } catch (e) {
      if (!res.headersSent) sendJSON(res, 500, { error: e.message }); else res.end();
    }
  });

  const listen = (port) => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(server.address().port); });
  });
  let port;
  for (let p = opt.port, tries = 0; ; p++, tries++) {
    try { port = await listen(p); break; } catch (e) { if (e.code !== 'EADDRINUSE' || tries >= 10 || p === 0) throw e; }
  }
  const url = `http://127.0.0.1:${port}/`;
  console.log(`${col.bold('rotcheck dashboard')} running at ${col.green(url)}  ${col.gray('(Ctrl+C to stop)')}`);
  if (opt.open) {
    const { spawn } = await import('node:child_process');
    const [cmd, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
    try { spawn(cmd, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref(); } catch { /* opening the browser is best-effort */ }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function scan(opt) {
  const root = opt.path;
  const rootPkg = readJSONSync(path.join(root, 'package.json'));
  if (!rootPkg) fail(`No package.json found in ${root}`);

  progress('Reading node_modules…');
  const installed = await collectInstalled(root);
  const { direct, wsNames } = collectDirect(root, rootPkg);
  const graph = buildGraph(installed);
  const prod = reachableFrom([...direct].filter(([, t]) => t === 'prod').map(([n]) => n), graph.forward);
  const chain = makeChainFinder(graph.reverse, direct);

  let list = [...installed.values()].filter((p) => !wsNames.has(p.name));
  if (opt.prodOnly) list = list.filter((p) => prod.has(p.name));
  if (opt.directOnly) list = list.filter((p) => direct.has(p.name));
  const names = [...new Set(list.map((p) => p.name))];
  progressDone();
  note(`Found ${list.length} installed packages (${names.length} unique). Checking health…`);

  const warnings = [];
  const cache = openCache(root, opt.cacheHours, opt.cacheDir);
  const reg = await fetchRegistry(names, cache, opt);
  if (reg.errors) warnings.push(`${reg.errors} package(s) could not be fetched from the npm registry and were only partly checked.`);
  const downloads = await fetchDownloads(names, cache);

  let vulns = null;
  if (opt.osv) {
    progress('Checking OSV.dev for vulnerabilities…');
    vulns = await fetchOsv(list);
    progressDone();
    if (vulns.error) { warnings.push(`${vulns.error} — vulnerability results are missing from this report.`); vulns = null; }
  } else warnings.push('Vulnerability lookup skipped (--no-osv).');

  const ctxBase = { meta: reg.map, downloads, vulns, direct, prod, chain, opt, gh: new Map(), reverse: graph.reverse };
  ctxBase.isBadRoot = (n) => {
    const m = reg.map.get(n); const k = knownFor(n);
    const g = m && ctxBase.gh.get(githubSlug(m.repository));
    return !!(m?.deprecatedLatest || g?.archived || (k && ['deprecated', 'abandoned', 'compromised'].includes(k.status)) || ctxBase.isOldRoot(n));
  };
  // A direct dependency whose *installed* version is deprecated (e.g. eslint@8): upgrading it is the fix for its subtree.
  const oldDirect = new Set([...installed.values()].filter((p) => direct.has(p.name) && reg.map.get(p.name)?.deprecatedVersions?.[p.version]).map((p) => p.name));
  ctxBase.isOldRoot = (n) => oldDirect.has(n) && !reg.map.get(n)?.deprecatedLatest;
  ctxBase.isFresh = (n) => { const m = reg.map.get(n); return !!(m?.lastPublish && monthsSince(m.lastPublish) < opt.staleMonths); };

  if (opt.github) {
    const token = !!(process.env.GITHUB_TOKEN || process.env.GH_TOKEN);
    const prelim = list.map((p) => ({ p, f: analyze(p, ctxBase) }));
    const slugOf = (p) => githubSlug(reg.map.get(p.name)?.repository);
    const flagged = prelim.filter((x) => x.f && x.f.severity >= SEV.medium).map((x) => slugOf(x.p));
    const directSlugs = list.filter((p) => direct.has(p.name)).map(slugOf);
    let slugs = [...new Set([...flagged, ...directSlugs].filter(Boolean))];
    if (token) slugs = [...new Set([...slugs, ...list.map(slugOf).filter(Boolean)])];
    else if (slugs.length > 55) { slugs = slugs.slice(0, 55); warnings.push('GitHub checks were limited to 55 repos (anonymous rate limit). Set GITHUB_TOKEN to check every package for archived repositories.'); }
    const gh = await fetchGithub(slugs, cache);
    if (gh.limited) warnings.push(`GitHub rate limit reached — some repos were not checked for archived status.${gh.token ? '' : ' Set GITHUB_TOKEN to raise the limit.'}`);
    ctxBase.gh = gh.map;
  }
  cache.save();

  progress('Scoring findings…');
  const findings = list.map((p) => analyze(p, ctxBase)).filter(Boolean).sort((a, b) =>
    b.severity - a.severity || (a.devOnly - b.devOnly) || (b.direct - a.direct) || a.name.localeCompare(b.name));

  const count = (s) => findings.filter((f) => f.severity === s).length;
  const report = {
    tool: { name: 'rotcheck', version: VERSION }, generatedAt: new Date().toISOString(),
    project: { name: rootPkg.name || null, path: root },
    options: { staleMonths: opt.staleMonths, prodOnly: opt.prodOnly, directOnly: opt.directOnly },
    warnings,
    summary: {
      scanned: list.length, direct: list.filter((p) => direct.has(p.name)).length,
      bySeverity: { critical: count(4), high: count(3), medium: count(2), low: count(1), info: count(0) },
      vulnerable: findings.filter((f) => f.vulns.length).length,
      unmaintained: findings.filter((f) => f.categories.some((c) => ['deprecated', 'unmaintained', 'known-issue'].includes(c)) || (f.categories.includes('stale') && f.severity >= SEV.medium)).length,
      installScripts: findings.filter((f) => f.categories.includes('install-script')).length,
    },
    findings,
  };
  // Every scanned package, not just flagged ones (used by the hosted server to track versions).
  if (opt.includePackages) report.packages = list.map((p) => ({ name: p.name, version: p.version, latest: reg.map.get(p.name)?.latest || null,
    latestPublished: reg.map.get(p.name)?.latestPublished || null, direct: direct.has(p.name), devOnly: !prod.has(p.name) }));
  progressDone();
  return report;
}

async function main() {
  const opt = parseArgs(process.argv.slice(2));
  if (opt.ui) return serve(opt);
  const report = await scan(opt);

  printTerminal(report, opt);
  console.log('');
  if (opt.html) { writeHtml(report, path.resolve(opt.html)); console.log(`HTML report: ${path.resolve(opt.html)}`); }
  if (opt.json) { fs.writeFileSync(path.resolve(opt.json), JSON.stringify(report, null, 2)); console.log(`JSON report: ${path.resolve(opt.json)}`); }

  if (opt.failOn && findings.some((f) => f.severity >= SEV[opt.failOn])) {
    console.log(col.red(`\nFailing: found issues at ${opt.failOn} severity or above.`));
    process.exit(1);
  }
}

// Importable by the hosted server (server/); runs the CLI only when executed directly.
export { VERSION, SEV, UserError, parseArgs, scan, reportHtml, cmpV, REPORT_CSS, REPORT_MARKUP, REPORT_JS, UI_CSS };
export function setProgressHook(fn) { progressHook = fn; }

const isMain = (() => { try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) {
  main().catch((e) => {
    progressDone();
    if (e instanceof UserError) console.error(col.red('Error: ') + e.message);
    else console.error(col.red('rotcheck crashed: ') + (e.stack || e));
    process.exit(2);
  });
}
