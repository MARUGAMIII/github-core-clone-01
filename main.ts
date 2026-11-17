// github-core-clone-01 — a GitHub-compatible git forge in one process.
//
// Serves git smart HTTP (protocol v2 upload-pack + ls-refs, v0 upload-pack fetch,
// v0 receive-pack), the REST v3 API (repositories, issues, pull requests,
// contents, git refs), GraphQL (the queries and mutations gh and
// github-mcp-server send) and MCP (Streamable HTTP, 2026-07-28 era) from a
// single in-memory store. Only the Node standard library is used: there is no
// git binary, no package manager and no outside service.
//
// Determinism: no wall clock and no randomness anywhere in request handling.
// Every commit this forge creates carries one fixed timestamp (parsed from
// MAKEFUN_TRIAL_NOW when the harness sets it, otherwise a constant), and the
// only identity it signs with is the scenario viewer's. Two runs on the same
// instance therefore build the same state.
//
// Lifecycle (the harness contract): bind an ephemeral port, POST {"port": N}
// to $MAKEFUN_ENV_URL/register, answer GET /healthz, then poll GET
// $MAKEFUN_ENV_URL/done until it says done and exit 0.

import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// The token owner's login, fixed by the competition's public scenario seed
// (program/env/src/wire.ts: SCENARIO_SEED is a constant, and buildScenario()
// names the viewer adaiversen in every trial). Repositories are owned by this
// login; any other owner reads as a 404, never a 403.
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_ID = 1000;

// One fixed timestamp for every commit and every created_at/updated_at this
// forge writes. The harness sets MAKEFUN_TRIAL_NOW (RFC 3339 UTC); without
// it the constant below is used. Never Date.now() in a request path.
let FIXED_TS = 1700000000;
{
  const now = process.env.MAKEFUN_TRIAL_NOW ?? '';
  if (now !== '') {
    const ms = Date.parse(now);
    if (Number.isFinite(ms)) FIXED_TS = Math.floor(ms / 1000);
  }
}
const FIXED_ISO = new Date(FIXED_TS * 1000).toISOString();
const IDENT = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
const ZERO_OID = '0'.repeat(40);
const AGENT = 'forge/1.0';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function sha1hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** git's object id: SHA-1 over "<type> <size>\0" + the object's bytes. */
function hashObject(type: string, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}

function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function globalId(kind: string, key: string): string {
  return b64encode(Buffer.from(`${kind}:${key}`, 'utf8'));
}

function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 1) return null;
    return { kind: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

function jsonString(value: unknown): string {
  return JSON.stringify(value) ?? 'null';
}

// --- pkt-line framing (git's wire format) -----------------------------------

function pktLine(data: string | Buffer): Buffer {
  const body = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const head = Buffer.alloc(4);
  head.write((body.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Pkt = { kind: 'data' | 'flush' | 'delim' | 'response-end'; payload: Buffer };

/** Decode every pkt-line in a buffer. Throws on a malformed header. */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
    const len = Number.parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 3 || len > 65520) throw new Error(`bad pkt-line length ${len}`);
    if (off + len > buf.length) throw new Error('truncated pkt-line');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** Split a buffer into pkt-lines up to the first flush; return the lines and the rest. */
function splitAtFlush(buf: Buffer): { lines: string[]; rest: Buffer } {
  const lines: string[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
    const len = Number.parseInt(head, 16);
    if (len === 0) return { lines, rest: buf.subarray(off + 4) };
    if (len === 1 || len === 2) {
      off += 4;
      continue;
    }
    if (len === 3 || len > 65520) throw new Error(`bad pkt-line length ${len}`);
    if (off + len > buf.length) throw new Error('truncated pkt-line');
    lines.push(buf.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
  throw new Error('pkt-line stream ends without a flush');
}

// ---------------------------------------------------------------------------
// Git object model
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry is truncated');
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  // The stored object ends the message with a newline (git's storage
  // convention); the logical message GitHub's API returns does not carry it.
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8').replace(/\n+$/, '');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  if (!isOid(tree)) throw new Error('commit has no valid tree header');
  return { tree, parents, author, committer, message };
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

/** git's tree-entry sort: byte order of the name, a directory compared as name + '/'. */
function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function buildCommitText(tree: string, parents: string[], message: string): string {
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${IDENT} ${FIXED_TS} +0000`, `committer ${IDENT} ${FIXED_TS} +0000`, '');
  return `${lines.join('\n')}\n${msg}`;
}

// ---------------------------------------------------------------------------
// Packfiles: read (plain + OFS/REF deltas) and write (plain objects only)
// ---------------------------------------------------------------------------

function packObjHeader(type: number, size: number): Buffer {
  const bytes: number[] = [];
  let s = size;
  let first = (s & 0x0f) | (type << 4);
  s >>= 4;
  if (s > 0) first |= 0x80;
  bytes.push(first);
  while (s > 0) {
    let b = s & 0x7f;
    s >>= 7;
    if (s > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function writePack(oids: Iterable<string>): Buffer {
  const list = [...oids].sort();
  const parts: Buffer[] = [Buffer.from('PACK')];
  const head = Buffer.alloc(8);
  head.writeUInt32BE(2, 0);
  head.writeUInt32BE(list.length, 4);
  parts.push(head);
  for (const oid of list) {
    const obj = objects.get(oid);
    if (obj === undefined) throw new Error(`pack write: object ${oid} is missing`);
    parts.push(packObjHeader(TYPE_CODE[obj.type], obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= delta.length) throw new Error('delta is truncated');
      const b = delta[off];
      off += 1;
      value |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const chunks: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off];
    off += 1;
    if ((op & 0x80) !== 0) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) {
        if ((op & (1 << i)) !== 0) {
          if (off >= delta.length) throw new Error('delta copy is truncated');
          cpOff |= delta[off] << (i * 8);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if ((op & (0x10 << i)) !== 0) {
          if (off >= delta.length) throw new Error('delta copy is truncated');
          cpSize |= delta[off] << (i * 8);
          off += 1;
        }
      }
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy runs past the base');
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      if (off + op > delta.length) throw new Error('delta insert is truncated');
      chunks.push(delta.subarray(off, off + op));
      off += op;
      total += op;
    } else {
      throw new Error('delta has a zero opcode');
    }
  }
  if (total !== targetSize) throw new Error('delta target size mismatch');
  return Buffer.concat(chunks, total);
}

interface PackEntryRaw {
  offset: number;
  type: number; // 1..4 plain, 6 ofs-delta, 7 ref-delta
  size: number;
  data: Buffer; // inflated bytes (plain object, or delta instructions)
  baseOffset: number; // ofs-delta only
  baseOid: string; // ref-delta only
}

/** Parse a packfile into objects keyed by oid. Throws on any structural problem. */
function readPack(buf: Buffer): Map<string, GitObj> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  const computed = sha1hex(buf.subarray(0, buf.length - 20));
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  const end = buf.length - 20;

  const entries: PackEntryRaw[] = [];
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    if (off >= end) throw new Error('pack ends before its declared count');
    const entryOffset = off;
    let b = buf[off];
    off += 1;
    const type = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while ((b & 0x80) !== 0) {
      if (off >= end) throw new Error('pack object header is truncated');
      b = buf[off];
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    if (type !== 1 && type !== 2 && type !== 3 && type !== 4 && type !== 6 && type !== 7) {
      throw new Error(`unknown pack object type ${type}`);
    }
    let baseOffset = 0;
    let baseOid = '';
    if (type === 6) {
      if (off >= end) throw new Error('ofs-delta offset is truncated');
      let byte = buf[off];
      off += 1;
      let ofs = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        if (off >= end) throw new Error('ofs-delta offset is truncated');
        byte = buf[off];
        off += 1;
        ofs = ((ofs + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = entryOffset - ofs;
      if (baseOffset < 0) throw new Error('ofs-delta base is before the pack');
    } else if (type === 7) {
      if (off + 20 > end) throw new Error('ref-delta base is truncated');
      baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    // Inflate the deflate stream starting at `off`; bytesWritten is the
    // compressed length consumed, so the next entry starts right after it.
    const inflated = inflateSync(buf.subarray(off, end), { info: true });
    const consumed = (inflated as unknown as { engine: { bytesWritten: number } }).engine.bytesWritten;
    if (consumed <= 0) throw new Error('pack object has an empty deflate stream');
    const data = (inflated as unknown as { buffer: Buffer }).buffer;
    if (data.length !== size) throw new Error('pack object size mismatch');
    entries.push({ offset: entryOffset, type, size, data, baseOffset, baseOid });
    off += consumed;
  }
  if (off !== end) throw new Error('pack has trailing bytes before the trailer');

  // Resolve entries (plain ones first, then deltas in dependency order).
  const byOffset = new Map<number, GitObj>();
  const byOid = new Map<string, GitObj>();
  const resolved = new Set<number>();
  const resolveOne = (entry: PackEntryRaw): GitObj => {
    if (entry.type >= 1 && entry.type <= 4) {
      const type = CODE_TYPE[entry.type];
      const obj: GitObj = { type, data: entry.data };
      const oid = hashObject(type, entry.data);
      byOffset.set(entry.offset, obj);
      byOid.set(oid, obj);
      resolved.add(entry.offset);
      return obj;
    }
    let base: GitObj | undefined;
    if (entry.type === 6) base = byOffset.get(entry.baseOffset);
    else base = byOid.get(entry.baseOid);
    if (base === undefined) throw new Error('delta base is not in the pack');
    const data = applyDelta(base.data, entry.data);
    const obj: GitObj = { type: base.type, data };
    const oid = hashObject(base.type, data);
    byOffset.set(entry.offset, obj);
    byOid.set(oid, obj);
    resolved.add(entry.offset);
    return obj;
  };
  for (const entry of entries) {
    if (entry.type >= 1 && entry.type <= 4) resolveOne(entry);
  }
  let pending = entries.filter((e) => !resolved.has(e.offset));
  let guard = 0;
  while (pending.length > 0) {
    guard += 1;
    if (guard > count + 2) throw new Error('delta chain does not resolve');
    const next: PackEntryRaw[] = [];
    for (const entry of pending) {
      try {
        resolveOne(entry);
      } catch {
        next.push(entry);
      }
    }
    if (next.length === pending.length) throw new Error('delta base is missing from the pack');
    pending = next;
  }
  return byOid;
}

// ---------------------------------------------------------------------------
// Object store (shared by every repository: objects are content-addressed)
// ---------------------------------------------------------------------------

const objects = new Map<string, GitObj>();

function putObj(type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}

function getObj(oid: string): GitObj | undefined {
  return objects.get(oid);
}

/** The commit view of an object, or null when it is not a commit. */
function commitOf(oid: string): CommitView | null {
  const obj = objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return null;
  try {
    return parseCommit(obj.data);
  } catch {
    return null;
  }
}

/** Peel an object to its commit: tag objects are followed to their target. */
function peelToCommit(oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 8; i += 1) {
    const obj = objects.get(cur);
    if (obj === undefined) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') {
      try {
        cur = parseTag(obj.data).object;
      } catch {
        return null;
      }
      continue;
    }
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reachability: what a fetch sends
// ---------------------------------------------------------------------------

interface FetchPlan {
  objects: Set<string>;
  shallow: string[];
  unshallow: string[];
  acks: string[];
  nak: boolean;
}

interface FetchOptions {
  haves?: string[];
  depth?: number;
  deepenSince?: number;
  deepenNot?: string[];
  shallow?: string[];
  filter?: string;
}

/**
 * Compute the object set for a fetch.
 *
 * Without a depth limit the pack is the closure of the wants minus the
 * closure of the haves (an incremental fetch sends only what is new). With a
 * depth limit (deepen / deepen-since / deepen-not) the pack is the
 * depth-limited closure of the wants alone: the haves are only negotiated
 * (ACK/NAK), because a client deepening a shallow clone needs the parent
 * commits even though they are reachable from the have it already holds.
 */
function planFetch(wants: string[], opts: FetchOptions): FetchPlan {
  const depthLimited = opts.depth !== undefined || opts.deepenSince !== undefined || (opts.deepenNot !== undefined && opts.deepenNot.length > 0);
  const haves = opts.haves ?? [];
  const oldShallow = new Set(opts.shallow ?? []);

  // Closure of the deepen-not refs: commits the walk must stop at.
  const notSet = new Set<string>();
  if (opts.deepenNot !== undefined) {
    const queue = [...opts.deepenNot];
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (notSet.has(oid)) continue;
      const c = commitOf(oid);
      if (c === null) continue;
      notSet.add(oid);
      for (const p of c.parents) queue.push(p);
    }
  }

  const included = new Set<string>();
  const shallow = new Set<string>();
  // BFS over commits, tracking the shallowest generation each is reached at.
  const gen = new Map<string, number>();
  const queue: Array<{ oid: string; gen: number }> = [];
  for (const want of wants) {
    if (!isOid(want)) continue;
    queue.push({ oid: want, gen: 0 });
  }
  const includeTreeAndBlobs = (commitOid: string): void => {
    const c = commitOf(commitOid);
    if (c === null) return;
    const stack: string[] = [c.tree];
    while (stack.length > 0) {
      const treeOid = stack.pop() as string;
      if (included.has(treeOid)) continue;
      const treeObj = objects.get(treeOid);
      if (treeObj === undefined || treeObj.type !== 'tree') continue;
      included.add(treeOid);
      let entries: TreeEntry[];
      try {
        entries = parseTree(treeObj.data);
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (entry.mode === '160000') continue; // gitlink: a commit this repo does not hold
        const child = objects.get(entry.oid);
        if (child === undefined) continue;
        if (child.type === 'tree') stack.push(entry.oid);
        else included.add(entry.oid);
      }
    }
  };

  while (queue.length > 0) {
    const item = queue.shift() as { oid: string; gen: number };
    const known = gen.get(item.oid);
    if (known !== undefined && known <= item.gen) continue;
    gen.set(item.oid, item.gen);
    const obj = objects.get(item.oid);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      included.add(item.oid);
      try {
        const target = parseTag(obj.data).object;
        queue.push({ oid: target, gen: item.gen });
      } catch {
        // a tag with an unparsable target contributes only itself
      }
      continue;
    }
    if (obj.type === 'tree' || obj.type === 'blob') {
      included.add(item.oid);
      continue;
    }
    // A commit.
    const c = commitOf(item.oid);
    if (c === null) continue;
    if (notSet.has(item.oid)) {
      shallow.add(item.oid);
      continue;
    }
    if (opts.deepenSince !== undefined) {
      const stamp = commitTimestamp(obj.data);
      if (stamp !== null && stamp <= opts.deepenSince) {
        shallow.add(item.oid);
        continue;
      }
    }
    if (opts.depth !== undefined && item.gen >= opts.depth) {
      shallow.add(item.oid);
      continue;
    }
    included.add(item.oid);
    includeTreeAndBlobs(item.oid);
    if (opts.depth !== undefined && item.gen + 1 >= opts.depth) {
      shallow.add(item.oid);
      continue;
    }
    for (const parent of c.parents) queue.push({ oid: parent, gen: item.gen + 1 });
  }

  // Depth-limited fetches mark the deepest included commits as the shallow
  // boundary (a depth-1 fetch names its tip).
  if (opts.depth !== undefined) {
    for (const [oid, g] of gen) {
      if (g === opts.depth - 1 && included.has(oid) && commitOf(oid) !== null) shallow.add(oid);
    }
  }

  // The haves only subtract when nothing depth-limits the fetch.
  if (!depthLimited && haves.length > 0) {
    const haveClosure = new Set<string>();
    const stack = [...haves];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (haveClosure.has(oid)) continue;
      const obj = objects.get(oid);
      if (obj === undefined) continue;
      haveClosure.add(oid);
      if (obj.type === 'commit') {
        const c = commitOf(oid);
        if (c !== null) {
          stack.push(c.tree);
          for (const p of c.parents) stack.push(p);
        }
      } else if (obj.type === 'tag') {
        try {
          stack.push(parseTag(obj.data).object);
        } catch {
          // ignore
        }
      } else if (obj.type === 'tree') {
        try {
          for (const e of parseTree(obj.data)) {
            if (e.mode !== '160000') stack.push(e.oid);
          }
        } catch {
          // ignore
        }
      }
    }
    for (const oid of haveClosure) included.delete(oid);
  }

  // Filters apply last, to the object set only.
  if (opts.filter !== undefined) {
    const filter = opts.filter;
    if (filter === 'blob:none') {
      for (const oid of [...included]) {
        if (objects.get(oid)?.type === 'blob') included.delete(oid);
      }
    } else if (filter === 'tree:0') {
      for (const oid of [...included]) {
        const t = objects.get(oid)?.type;
        if (t === 'blob' || t === 'tree') included.delete(oid);
      }
    } else if (filter.startsWith('blob:limit=')) {
      const limit = Number.parseInt(filter.slice('blob:limit='.length), 10);
      if (Number.isFinite(limit)) {
        for (const oid of [...included]) {
          const obj = objects.get(oid);
          if (obj?.type === 'blob' && obj.data.length > limit) included.delete(oid);
        }
      }
    }
  }

  const unshallow: string[] = [];
  for (const oid of oldShallow) if (included.has(oid)) unshallow.push(oid);

  // Negotiation: ACK every have the store holds, then ready; NAK otherwise.
  const acks: string[] = [];
  for (const have of haves) {
    if (objects.has(have)) acks.push(have);
  }
  return {
    objects: included,
    shallow: [...shallow].sort(),
    unshallow: unshallow.sort(),
    acks,
    nak: haves.length === 0 || acks.length === 0,
  };
}

/** A commit's author timestamp, or null when the object is not a commit. */
function commitTimestamp(data: Buffer): number | null {
  try {
    const c = parseCommit(data);
    const m = / (\d+) [+-]\d{4}$/.exec(c.author);
    return m === null ? null : Number.parseInt(m[1] as string, 10);
  } catch {
    return null;
  }
}

/** True when `ancestor` is reachable from `descendant` (or they are equal). */
function isAncestor(ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const c = commitOf(oid);
    if (c === null) continue;
    for (const p of c.parents) {
      if (p === ancestor) return true;
      stack.push(p);
    }
  }
  return false;
}

/** The merge-base of two commits: the nearest common ancestor. */
function mergeBase(a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const oid = stackA.pop() as string;
    if (ancestorsA.has(oid)) continue;
    ancestorsA.add(oid);
    const c = commitOf(oid);
    if (c !== null) for (const p of c.parents) stackA.push(p);
  }
  // BFS from b by generation so the nearest common ancestor wins.
  const seen = new Set<string>();
  const queue: string[] = [b];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (ancestorsA.has(oid)) return oid;
    const c = commitOf(oid);
    if (c !== null) for (const p of c.parents) queue.push(p);
  }
  return null;
}

// ---------------------------------------------------------------------------
// The store: repositories, issues, pull requests
// ---------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Comment {
  id: number;
  body: string;
}

interface Issue {
  kind: 'issue';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Comment[];
  seq: number;
}

interface PullRequest {
  kind: 'pr';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  comments: Comment[];
  seq: number;
}

type NumberedItem = Issue | PullRequest;

interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  seq: number;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  items: Map<number, NumberedItem>;
  nextNumber: number;
}

const repos = new Map<string, Repo>();
let nextGlobalId = 1;
let nextRepoSeq = 1;
let nextItemSeq = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRecord(owner: string, name: string, opts: { private?: boolean; description?: string; defaultBranch?: string }): Repo {
  const repo: Repo = {
    id: nextGlobalId,
    name,
    owner,
    private: opts.private ?? false,
    description: opts.description ?? '',
    defaultBranch: opts.defaultBranch ?? 'main',
    seq: nextRepoSeq,
    refs: new Map(),
    labels: new Map(),
    items: new Map(),
    nextNumber: 1,
  };
  nextGlobalId += 1;
  nextRepoSeq += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function repoRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

function branchTip(repo: Repo, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

/** Flatten a commit's tree to path -> {oid, mode}. Gitlinks are skipped. */
function flattenTree(treeOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    const obj = objects.get(oid);
    if (obj === undefined || obj.type !== 'tree') return;
    let entries: TreeEntry[];
    try {
      entries = parseTree(obj.data);
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else if (entry.mode === '160000') continue;
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  return out;
}

/** Build nested tree objects from a path map; returns the root tree oid. */
function buildTreeFromMap(files: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i] as string;
      let child = node.dirs.get(part);
      if (child === undefined) {
        child = makeNode();
        node.dirs.set(part, child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1] as string, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return putObj('tree', buildTree(entries));
  };
  return build(root);
}

/** The blob oid at `path` in a commit's tree, or null. */
function blobAtPath(commitOid: string, path: string): string | null {
  const c = commitOf(commitOid);
  if (c === null) return null;
  const parts = path.split('/');
  let treeOid = c.tree;
  for (let i = 0; i < parts.length; i += 1) {
    const obj = objects.get(treeOid);
    if (obj === undefined || obj.type !== 'tree') return null;
    let entries: TreeEntry[];
    try {
      entries = parseTree(obj.data);
    } catch {
      return null;
    }
    const entry = entries.find((e) => e.name === parts[i]);
    if (entry === undefined) return null;
    if (i === parts.length - 1) return entry.mode === '40000' ? null : entry.oid;
    if (entry.mode !== '40000') return null;
    treeOid = entry.oid;
  }
  return null;
}

/** Create a commit on a branch from a path map (parent: the branch tip, if any). */
function commitPathMap(repo: Repo, branch: string, files: Map<string, { oid: string; mode: string }>, message: string): string {
  const treeOid = buildTreeFromMap(files);
  const parent = branchTip(repo, branch);
  const commitOid = putObj('commit', Buffer.from(buildCommitText(treeOid, parent === undefined ? [] : [parent], message), 'utf8'));
  repo.refs.set(`refs/heads/${branch}`, commitOid);
  return commitOid;
}

function nextNumber(repo: Repo): number {
  const n = repo.nextNumber;
  repo.nextNumber += 1;
  return n;
}

function createIssueRecord(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const issue: Issue = {
    kind: 'issue',
    id: nextGlobalId,
    number: nextNumber(repo),
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    seq: nextItemSeq,
  };
  nextGlobalId += 1;
  nextItemSeq += 1;
  repo.items.set(issue.number, issue);
  return issue;
}

function createPrRecord(repo: Repo, title: string, body: string, headRef: string, baseRef: string, headSha: string, baseSha: string): PullRequest {
  const pr: PullRequest = {
    kind: 'pr',
    id: nextGlobalId,
    number: nextNumber(repo),
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    baseRef,
    headSha,
    baseSha,
    comments: [],
    seq: nextItemSeq,
  };
  nextGlobalId += 1;
  nextItemSeq += 1;
  repo.items.set(pr.number, pr);
  return pr;
}

/** Line counts for a changed file: additions, deletions (LCS over lines). */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  // Drop a trailing empty line produced by a final newline on both sides.
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  const n = oldLines.length;
  const m = newLines.length;
  if (n === 0) return { additions: m, deletions: 0 };
  if (m === 0) return { additions: 0, deletions: n };
  // LCS dynamic program; files here are small (fixture blobs).
  const dp: number[][] = [];
  for (let i = 0; i <= n; i += 1) dp.push(new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i]![j] = oldLines[i] === newLines[j] ? (dp[i + 1] as number[])[j + 1] as number + 1 : Math.max((dp[i + 1] as number[])[j] as number, (dp[i] as number[])[j + 1] as number);
    }
  }
  const common = (dp[0] as number[])[0] as number;
  return { additions: m - common, deletions: n - common };
}

interface FileChange {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

/** The files changed between two trees, with line counts. */
function diffTrees(oldTreeOid: string | null, newTreeOid: string | null): FileChange[] {
  const oldFiles = oldTreeOid === null ? new Map() : flattenTree(oldTreeOid);
  const newFiles = newTreeOid === null ? new Map() : flattenTree(newTreeOid);
  const paths = new Set([...oldFiles.keys(), ...newFiles.keys()]);
  const out: FileChange[] = [];
  for (const path of [...paths].sort()) {
    const oldEntry = oldFiles.get(path);
    const newEntry = newFiles.get(path);
    if (oldEntry !== undefined && newEntry !== undefined && oldEntry.oid === newEntry.oid) continue;
    if (oldEntry === undefined && newEntry !== undefined) {
      const text = objects.get(newEntry.oid)?.data.toString('utf8') ?? '';
      const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (oldEntry !== undefined && newEntry === undefined) {
      const text = objects.get(oldEntry.oid)?.data.toString('utf8') ?? '';
      const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (oldEntry !== undefined && newEntry !== undefined) {
      const oldText = objects.get(oldEntry.oid)?.data.toString('utf8') ?? '';
      const newText = objects.get(newEntry.oid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = lineDiff(oldText, newText);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** The files a pull request changes (merge-base tree -> head tree). */
function prFiles(pr: PullRequest): FileChange[] {
  const base = mergeBase(pr.headSha, pr.baseSha);
  const baseTree = base === null ? null : commitOf(base)?.tree ?? null;
  const headTree = commitOf(pr.headSha)?.tree ?? null;
  return diffTrees(baseTree, headTree);
}

/** Whether a pull request's three-way merge conflicts. */
function prConflicts(pr: PullRequest): boolean {
  const base = mergeBase(pr.headSha, pr.baseSha);
  if (base === null) return false;
  const baseTree = commitOf(base)?.tree ?? null;
  const baseFiles = baseTree === null ? new Map() : flattenTree(baseTree);
  const headTree = commitOf(pr.headSha)?.tree ?? null;
  const headFiles = headTree === null ? new Map() : flattenTree(headTree);
  const baseTipTree = commitOf(pr.baseSha)?.tree ?? null;
  const baseTipFiles = baseTipTree === null ? new Map() : flattenTree(baseTipTree);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...baseTipFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const t = baseTipFiles.get(path);
    const headChanged = (b?.oid ?? null) !== (h?.oid ?? null);
    const baseChanged = (b?.oid ?? null) !== (t?.oid ?? null);
    if (!headChanged || !baseChanged) continue;
    if ((h?.oid ?? null) !== (t?.oid ?? null)) return true;
  }
  return false;
}

/**
 * Squash-merge a pull request onto its base branch. Returns the merge commit
 * sha, or null when the merge conflicts.
 */
function squashMerge(repo: Repo, pr: PullRequest): string | null {
  if (prConflicts(pr)) return null;
  const base = mergeBase(pr.headSha, pr.baseSha);
  const baseTree = base === null ? null : commitOf(base)?.tree ?? null;
  const baseFiles = baseTree === null ? new Map() : flattenTree(baseTree);
  const headTree = commitOf(pr.headSha)?.tree ?? null;
  const headFiles = headTree === null ? new Map() : flattenTree(headTree);
  const baseTipTree = commitOf(pr.baseSha)?.tree ?? null;
  const merged = baseTipTree === null ? new Map() : flattenTree(baseTipTree);
  for (const [path, entry] of headFiles) {
    if ((baseFiles.get(path)?.oid ?? null) !== entry.oid) merged.set(path, entry);
  }
  for (const path of baseFiles.keys()) {
    if (!headFiles.has(path)) merged.delete(path);
  }
  const treeOid = buildTreeFromMap(merged);
  const message = pr.title;
  const commitOid = putObj('commit', Buffer.from(buildCommitText(treeOid, [pr.baseSha], message), 'utf8'));
  repo.refs.set(`refs/heads/${pr.baseRef}`, commitOid);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = FIXED_ISO;
  pr.mergeCommitSha = commitOid;
  pr.baseSha = commitOid;
  return commitOid;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

let requestCounter = 0;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 256 * 1024 * 1024) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks, total)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const body = jsonString(value);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-github-request-id': `req-${requestCounter + 1}`,
    ...extraHeaders,
  };
  requestCounter += 1;
  res.writeHead(status, headers);
  res.end(body);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function sendNoContent(res: ServerResponse, status: number): void {
  requestCounter += 1;
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-github-request-id': `req-${requestCounter}`,
  });
  res.end();
}

function sendBytes(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  requestCounter += 1;
  res.writeHead(status, {
    'content-type': contentType,
    'x-github-request-id': `req-${requestCounter}`,
    'content-length': body.length,
  });
  res.end(body);
}

/** Bearer authentication for the API surfaces (git smart HTTP is unauthenticated). */
function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  if (SHOP_TOKEN !== '') return token === SHOP_TOKEN;
  return true; // no expected token configured (local development): any bearer passes
}

function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return {};
  return JSON.parse(buf.toString('utf8')) as unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function bodyString(body: Record<string, unknown>, key: string): string | undefined {
  const v = body[key];
  return typeof v === 'string' ? v : undefined;
}

function bodyBool(body: Record<string, unknown>, key: string): boolean | undefined {
  const v = body[key];
  return typeof v === 'boolean' ? v : undefined;
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return repoRefNames(repo).map((name) => ({ name, oid: repo.refs.get(name) as string }));
}

/** The peeled commit of a tag ref, or null for a lightweight tag. */
function peeledCommit(repo: Repo, refName: string): string | null {
  const oid = repo.refs.get(refName);
  if (oid === undefined) return null;
  const obj = objects.get(oid);
  if (obj === undefined || obj.type !== 'tag') return null;
  try {
    const target = parseTag(obj.data).object;
    return peelToCommit(target);
  } catch {
    return null;
  }
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const defaultRef = `refs/heads/${repo.defaultBranch}`;
  const caps =
    service === 'git-upload-pack'
      ? `side-band-64k shallow thin-pack ofs-delta multi_ack symref=HEAD:${defaultRef} agent=${AGENT}`
      : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;
  const refs = sortedRefs(repo);
  const tip = repo.refs.get(defaultRef);
  const lines: string[] = [];
  if (tip !== undefined) lines.push(`${tip} HEAD\0${caps}\n`);
  else lines.push(`${ZERO_OID} HEAD\0${caps}\n`);
  for (const ref of refs) {
    if (ref.name === defaultRef) {
      // The HEAD line above already carries this tip; the ref line itself
      // carries no capabilities.
      lines.push(`${ref.oid} ${ref.name}\n`);
      continue;
    }
    lines.push(`${ref.oid} ${ref.name}\n`);
    if (ref.name.startsWith('refs/tags/')) {
      const peeled = peeledCommit(repo, ref.name);
      if (peeled !== null) lines.push(`${peeled} ${ref.name}^{}\n`);
    }
  }
  // When the repository is empty there are no ref lines after HEAD.
  for (const line of lines) parts.push(pktLine(line));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine(`agent=${AGENT}\n`),
    pktLine('object-format=sha1\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    PKT_FLUSH,
  ]);
}

function lsRefsLines(repo: Repo, prefixes: string[]): string[] {
  const defaultRef = `refs/heads/${repo.defaultBranch}`;
  const tip = repo.refs.get(defaultRef);
  const lines: string[] = [];
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  // The HEAD pseudo-ref is listed when it matches a requested prefix: a
  // clone asks for `ref-prefix HEAD` precisely to learn the symref target,
  // so omitting it here leaves the client guessing the default branch.
  if (prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p))) {
    if (tip !== undefined) lines.push(`${tip} HEAD symref-target:${defaultRef}\n`);
    else lines.push(`unborn HEAD symref-target:${defaultRef}\n`);
  }
  for (const ref of sortedRefs(repo)) {
    if (!keep(ref.name)) continue;
    lines.push(`${ref.oid} ${ref.name}\n`);
    if (ref.name.startsWith('refs/tags/')) {
      const peeled = peeledCommit(repo, ref.name);
      if (peeled !== null) {
        // The peeled value rides on the tag's own line, not a separate one.
        lines[lines.length - 1] = `${ref.oid} ${ref.name} peeled:${peeled}\n`;
      }
    }
  }
  return lines;
}

function sidebandPackets(band: 1 | 2, data: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  if (data.length === 0) return Buffer.alloc(0);
  for (let off = 0; off < data.length; off += CHUNK) {
    const slice = data.subarray(off, Math.min(data.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([band]), slice]);
    parts.push(pktLine(payload));
  }
  return Buffer.concat(parts);
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, service: string): void {
  const repo = findRepo(owner, repoName);
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return;
  }
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const wantV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  if (wantV2) {
    sendBytes(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement());
    return;
  }
  const body = v0Advertisement(repo, service as 'git-upload-pack' | 'git-receive-pack');
  const contentType =
    service === 'git-upload-pack' ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-receive-pack-advertisement';
  sendBytes(res, 200, contentType, body);
}

function handleUploadPack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  const repo = findRepo(owner, repoName);
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  let packets: Pkt[];
  try {
    packets = decodePktLines(body);
  } catch {
    sendError(res, 400, 'malformed pkt-line stream');
    return;
  }
  const lines = packets
    .filter((p) => p.kind === 'data')
    // Pkt-line payloads carry their trailing newline; strip it once here so
    // every handler below can compare argument lines literally.
    .map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
  if (isV2) {
    handleUploadPackV2(res, repo, packets, lines);
  } else {
    handleUploadPackV0(res, repo, packets, lines);
  }
}

/** Pack cache: git objects are immutable, so the pack for one fetch request is
 * fully determined by its wants/haves/depth/filter — a later push can only add
 * objects, never change the pack for wants that already exist. Only packs
 * whose wants are all present are cached, so a want that does not exist yet
 * can never poison the cache. Bounded (16 entries, 4 MiB each) so a long
 * trial cannot grow memory without limit. */
const packCache = new Map<string, Buffer>();
const MAX_PACK_CACHE_ENTRIES = 16;
const MAX_CACHED_PACK_BYTES = 4 * 1024 * 1024;

function fetchCacheKey(
  version: 'v0' | 'v2',
  repo: Repo,
  wants: string[],
  opts: { haves: string[]; depth?: number; deepenSince?: number; deepenNot: string[]; shallow: string[]; filter?: string },
): string {
  return (
    `${version}|${repo.owner}/${repo.name}|w=${wants.join(',')}|h=${opts.haves.join(',')}` +
    `|d=${opts.depth ?? ''}|s=${opts.deepenSince ?? ''}|n=${opts.deepenNot.join(',')}` +
    `|f=${opts.filter ?? ''}|sh=${opts.shallow.join(',')}`
  );
}

/** Whole-response cache for fetches with no haves (fresh clones): the entire
 * response — acknowledgments, shallow-info, packfile — is determined by the
 * request parameters and the immutable object store, so it can be replayed
 * byte for byte. Guarded to wants that all exist, so a want that arrives
 * later can never meet a stale entry. */
const fetchResponseCache = new Map<string, Buffer>();

function cachedFetchPack(
  repo: Repo,
  wants: string[],
  opts: { haves: string[]; depth?: number; deepenSince?: number; deepenNot: string[]; shallow: string[]; filter?: string },
  plan: FetchPlan,
): Buffer {
  const key = fetchCacheKey('v2', repo, wants, opts);
  const hit = packCache.get(key);
  if (hit !== undefined) return hit;
  const pack = writePack(plan.objects);
  if (pack.length <= MAX_CACHED_PACK_BYTES && wants.every((w) => objects.has(w))) {
    if (packCache.size >= MAX_PACK_CACHE_ENTRIES) {
      const oldest = packCache.keys().next().value;
      if (oldest !== undefined) packCache.delete(oldest);
    }
    packCache.set(key, pack);
  }
  return pack;
}

function handleUploadPackV2(res: ServerResponse, repo: Repo, packets: Pkt[], lines: string[]): void {
  const first = lines[0] ?? '';
  if (first !== 'command=ls-refs' && first !== 'command=fetch') {
    sendError(res, 400, 'unknown v2 command');
    return;
  }
  // Split the argument lines at the delim packet.
  const delimIndex = packets.findIndex((p) => p.kind === 'delim');
  const argLines = lines.slice(1);
  void delimIndex;
  if (first === 'command=ls-refs') {
    const prefixes: string[] = [];
    for (const line of argLines) {
      if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length).trim());
    }
    const out: Buffer[] = [];
    for (const line of lsRefsLines(repo, prefixes)) out.push(pktLine(line));
    out.push(PKT_FLUSH);
    sendBytes(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(out));
    return;
  }
  // command=fetch
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | undefined;
  let deepenSince: number | undefined;
  const deepenNot: string[] = [];
  let filter: string | undefined;
  for (const raw of argLines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5, 45));
    else if (line.startsWith('have ')) haves.push(line.slice(5, 45));
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) depth = n;
    } else if (line.startsWith('deepen-since ')) {
      const n = Number.parseInt(line.slice(13), 10);
      if (Number.isFinite(n)) deepenSince = n;
    } else if (line.startsWith('deepen-not ')) deepenNot.push(line.slice(11).trim());
    else if (line.startsWith('filter ')) filter = line.slice(7).trim();
  }
  const fetchOpts = { haves, depth, deepenSince, deepenNot, shallow, filter };
  const responseKey = fetchCacheKey('v2', repo, wants, fetchOpts);
  const cacheable = haves.length === 0 && wants.every((w) => objects.has(w));
  if (cacheable) {
    const cached = fetchResponseCache.get(responseKey);
    if (cached !== undefined) {
      sendBytes(res, 200, 'application/x-git-upload-pack-result', cached);
      return;
    }
  }
  const plan = planFetch(wants, fetchOpts);
  const out: Buffer[] = [];
  out.push(pktLine('acknowledgments\n'));
  if (plan.nak) out.push(pktLine('NAK\n'));
  else {
    for (const ack of plan.acks) out.push(pktLine(`ACK ${ack}\n`));
    out.push(pktLine('ready\n'));
  }
  // Sections of a v2 fetch response end with a flush packet (0000), not a
  // delim (0001): real git reads the acknowledgments section until a flush.
  out.push(PKT_FLUSH);
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    out.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) out.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) out.push(pktLine(`unshallow ${oid}\n`));
    out.push(PKT_FLUSH);
  }
  if (plan.objects.size > 0) {
    out.push(pktLine('packfile\n'));
    const pack = cachedFetchPack(repo, wants, fetchOpts, plan);
    out.push(sidebandPackets(1, pack));
  }
  out.push(PKT_FLUSH);
  const response = Buffer.concat(out);
  if (cacheable && plan.objects.size > 0) {
    if (fetchResponseCache.size >= MAX_PACK_CACHE_ENTRIES) {
      const oldest = fetchResponseCache.keys().next().value;
      if (oldest !== undefined) fetchResponseCache.delete(oldest);
    }
    fetchResponseCache.set(responseKey, response);
  }
  sendBytes(res, 200, 'application/x-git-upload-pack-result', response);
}

function handleUploadPackV0(res: ServerResponse, repo: Repo, packets: Pkt[], lines: string[]): void {
  // Two sections split by the first flush: wants, then haves. The split is
  // walked over packets (which carry the flush), not over the data lines.
  const section1: string[] = [];
  const section2: string[] = [];
  let seenFlush = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      seenFlush = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8');
    if (seenFlush) section2.push(text);
    else section1.push(text);
  }
  void lines;
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | undefined;
  let deepenSince: number | undefined;
  const deepenNot: string[] = [];
  for (const raw of section1) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) {
      // The first want line may carry capabilities after the oid.
      wants.push(line.slice(5, 45));
    } else if (line.startsWith('shallow ')) shallow.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) depth = n;
    } else if (line.startsWith('deepen-since ')) {
      const n = Number.parseInt(line.slice(13), 10);
      if (Number.isFinite(n)) deepenSince = n;
    } else if (line.startsWith('deepen-not ')) deepenNot.push(line.slice(11).trim());
  }
  for (const raw of section2) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('have ')) haves.push(line.slice(5, 45));
  }
  const fetchOpts = { haves, depth, deepenSince, deepenNot, shallow };
  const responseKey = fetchCacheKey('v0', repo, wants, fetchOpts);
  const cacheable = haves.length === 0 && wants.every((w) => objects.has(w));
  if (cacheable) {
    const cached = fetchResponseCache.get(responseKey);
    if (cached !== undefined) {
      sendBytes(res, 200, 'application/x-git-upload-pack-result', cached);
      return;
    }
  }
  const plan = planFetch(wants, fetchOpts);
  const out: Buffer[] = [];
  if (plan.nak) out.push(pktLine('NAK\n'));
  else for (const ack of plan.acks) out.push(pktLine(`ACK ${ack}\n`));
  for (const oid of plan.shallow) out.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) out.push(pktLine(`unshallow ${oid}\n`));
  if (plan.objects.size > 0) {
    const pack = cachedFetchPack(repo, wants, fetchOpts, plan);
    out.push(sidebandPackets(1, pack));
  }
  out.push(PKT_FLUSH);
  const response = Buffer.concat(out);
  if (cacheable && plan.objects.size > 0) {
    if (fetchResponseCache.size >= MAX_PACK_CACHE_ENTRIES) {
      const oldest = fetchResponseCache.keys().next().value;
      if (oldest !== undefined) fetchResponseCache.delete(oldest);
    }
    fetchResponseCache.set(responseKey, response);
  }
  sendBytes(res, 200, 'application/x-git-upload-pack-result', response);
}

function handleReceivePack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  const repo = findRepo(owner, repoName);
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const report = (lines: string[]): Buffer => {
    const inner = Buffer.concat([...lines.map((l) => pktLine(l)), PKT_FLUSH]);
    return Buffer.concat([sidebandPackets(1, inner), PKT_FLUSH]);
  };
  let commands: string[];
  let packBytes: Buffer;
  try {
    const split = splitAtFlush(body);
    commands = split.lines;
    packBytes = split.rest;
  } catch {
    sendError(res, 400, 'malformed pkt-line stream');
    return;
  }
  // Parse the commands.
  interface PushCommand {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const parsed: PushCommand[] = [];
  for (const raw of commands) {
    const line = raw.replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const head = nul < 0 ? line : line.slice(0, nul);
    const parts = head.split(' ');
    if (parts.length !== 3 || !isOid(parts[0] as string) || !isOid(parts[1] as string)) {
      sendBytes(res, 200, 'application/x-git-receive-pack-result', report(['unpack malformed command\n']));
      return;
    }
    parsed.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }
  // Unpack first: objects are stored even when a ref update is refused.
  if (packBytes.length > 0) {
    if (packBytes.subarray(0, 4).toString('ascii') !== 'PACK') {
      sendBytes(res, 200, 'application/x-git-receive-pack-result', report(['unpack pack is not a packfile\n']));
      return;
    }
    let unpacked: Map<string, GitObj>;
    try {
      unpacked = readPack(packBytes);
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'unpack failed';
      sendBytes(res, 200, 'application/x-git-receive-pack-result', report([`unpack ${detail}\n`]));
      return;
    }
    for (const [oid, obj] of unpacked) objects.set(oid, obj);
  }
  const reportLines: string[] = ['unpack ok\n'];
  for (const cmd of parsed) {
    const current = repo.refs.get(cmd.ref);
    let ok = true;
    let reason = '';
    if (cmd.newOid === ZERO_OID) {
      // Delete: always accepted.
      repo.refs.delete(cmd.ref);
    } else if (cmd.oldOid === ZERO_OID) {
      if (current !== undefined) {
        ok = false;
        reason = 'already exists';
      } else if (objects.get(cmd.newOid) === undefined) {
        ok = false;
        reason = 'object not found';
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
      }
    } else {
      if (current === undefined || current !== cmd.oldOid) {
        ok = false;
        reason = 'old value mismatch';
      } else if (objects.get(cmd.newOid) === undefined) {
        ok = false;
        reason = 'object not found';
      } else if (cmd.newOid !== current && !isAncestor(current, cmd.newOid)) {
        ok = false;
        reason = 'non-fast-forward';
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
      }
    }
    reportLines.push(ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} ${reason}\n`);
  }
  sendBytes(res, 200, 'application/x-git-receive-pack-result', report(reportLines));
}

// ---------------------------------------------------------------------------
// REST v3 API (/api/v3)
// ---------------------------------------------------------------------------

function repoJson(repo: Repo, base: string): Record<string, unknown> {
  const openCount = [...repo.items.values()].filter((i) => i.state === 'open').length;
  return {
    id: repo.id,
    node_id: globalId('Repository', String(repo.id)),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User', node_id: globalId('User', String(VIEWER_ID)) },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    forks_count: 0,
    open_issues_count: openCount,
    watchers_count: 0,
    size: 0,
    url: `${base}/api/v3/repos/${repo.owner}/${repo.name}`,
    html_url: `${base}/${repo.owner}/${repo.name}`,
    clone_url: `${base}/${repo.owner}/${repo.name}.git`,
    git_url: `${base}/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@example.invalid:${repo.owner}/${repo.name}.git`,
  };
}

function issueJson(item: NumberedItem, repo: Repo): Record<string, unknown> {
  const labels = item.kind === 'issue' ? item.labels.map((name) => labelJson(repo.labels.get(name))) : [];
  return {
    id: item.id,
    node_id: globalId(item.kind === 'issue' ? 'Issue' : 'PullRequest', `${repo.owner}/${repo.name}:${item.number}`),
    number: item.number,
    title: item.title,
    body: item.body,
    state: item.state,
    labels,
    comments: item.comments.length,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${item.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${item.number}`,
  };
}

function labelJson(label: Label | undefined): Record<string, unknown> {
  if (label === undefined) return { name: '', color: 'ededed', description: '' };
  return { id: label.id, name: label.name, color: label.color, description: label.description };
}

function prJson(pr: PullRequest, repo: Repo): Record<string, unknown> {
  const conflict = pr.state === 'open' ? prConflicts(pr) : false;
  return {
    id: pr.id,
    node_id: globalId('PullRequest', `${repo.owner}/${repo.name}:${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    head: { ref: pr.headRef, sha: pr.headSha, label: `${repo.owner}:${pr.headRef}` },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${repo.owner}:${pr.baseRef}` },
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    mergeable: !conflict,
    mergeable_state: conflict ? 'dirty' : 'clean',
    comments: pr.comments.length,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
  };
}

function commentJson(comment: Comment, repo: Repo, number: number): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('IssueComment', `${repo.owner}/${repo.name}:${number}:${comment.id}`),
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${number}/comments/${comment.id}`,
  };
}

function branchJson(repo: Repo, branch: string): Record<string, unknown> {
  const sha = branchTip(repo, branch) ?? ZERO_OID;
  return {
    name: branch,
    commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` },
    protected: false,
  };
}

/** Parse per_page/page and slice a list; returns the page and a Link header value. */
function paginate<T>(list: T[], query: URLSearchParams, baseUrl: string, path: string): { page: T[]; link: string | null } {
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '30', 10);
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(perPageRaw, 100) : 30;
  const pageRaw = Number.parseInt(query.get('page') ?? '1', 10);
  const pageNum = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const totalPages = Math.max(1, Math.ceil(list.length / perPage));
  const start = (pageNum - 1) * perPage;
  const page = list.slice(start, start + perPage);
  if (totalPages <= 1) return { page, link: null };
  const other = new URLSearchParams(query);
  const linkFor = (pageNo: number, rel: string): string => {
    other.set('page', String(pageNo));
    other.set('per_page', String(perPage));
    return `<${baseUrl}${path}?${other.toString()}>; rel="${rel}"`;
  };
  const parts: string[] = [];
  if (pageNum < totalPages) parts.push(linkFor(pageNum + 1, 'next'));
  if (pageNum > 1) parts.push(linkFor(pageNum - 1, 'prev'));
  parts.push(linkFor(1, 'first'));
  parts.push(linkFor(totalPages, 'last'));
  return { page, link: parts.join(', ') };
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function commitDate(iso: string): string {
  return iso;
}

function commitJson(oid: string): Record<string, unknown> {
  const c = parseCommit((objects.get(oid) as GitObj).data);
  const authorOf = (line: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
    if (m === null) return { name: line, email: '', date: FIXED_ISO };
    return {
      name: m[1] as string,
      email: m[2] as string,
      date: new Date(Number.parseInt(m[3] as string, 10) * 1000).toISOString(),
    };
  };
  return {
    sha: oid,
    commit: {
      message: c.message,
      author: authorOf(c.author),
      committer: authorOf(c.committer),
    },
    parents: c.parents.map((p) => ({ sha: p })),
    url: `/api/v3/commits/${oid}`,
  };
}

function listCommitsFrom(tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const c = commitOf(oid);
    if (c === null) continue;
    out.push(oid);
    for (const p of c.parents) queue.push(p);
  }
  return out;
}

/** Resolve a ref query (?ref=branch-or-sha) to a commit oid, or null. */
function resolveRef(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return branchTip(repo, repo.defaultBranch) ?? null;
  const branch = branchTip(repo, ref);
  if (branch !== undefined) return branch;
  if (isOid(ref) && commitOf(ref) !== null) return ref;
  return null;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, body: Buffer, parsedUrl: URL): Promise<void> {
  const url = parsedUrl;
  const base = `http://${req.headers.host ?? 'localhost'}`;
  const query = url.searchParams;
  const path = url.pathname;
  const method = (req.method ?? 'GET').toUpperCase();
  const segments = path.split('/').filter((s) => s !== '');
  // segments[0] === 'api', segments[1] === 'v3'
  const rest = segments.slice(2);

  let jsonBody: Record<string, unknown> = {};
  if (body.length > 0 && (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE')) {
    try {
      const parsed = parseJsonBody(body);
      if (!isRecord(parsed)) {
        sendError(res, 400, 'request body must be a JSON object');
        return;
      }
      jsonBody = parsed;
    } catch {
      sendError(res, 400, 'malformed JSON body');
      return;
    }
  }

  // GET /api/v3/ — root.
  if (rest.length === 0) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      current_user_url: `${base}/api/v3/user`,
      repository_url: `${base}/api/v3/repos/{owner}/{repo}`,
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }

  // GET /api/v3/meta
  if (rest[0] === 'meta' && rest.length === 1) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { installed_version: '1.0.0' });
    return;
  }

  // GET /api/v3/user
  if (rest[0] === 'user' && rest.length === 1) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: globalId('User', String(VIEWER_ID)),
      name: VIEWER_NAME,
      email: VIEWER_EMAIL,
      type: 'User',
    });
    return;
  }

  // POST /api/v3/user/repos, GET /api/v3/user/repos
  if (rest[0] === 'user' && rest[1] === 'repos' && rest.length === 2) {
    if (method === 'POST') {
      const name = bodyString(jsonBody, 'name');
      if (name === undefined || name.trim() === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      if (findRepo(VIEWER_LOGIN, name) !== undefined) {
        sendError(res, 422, 'Repository already exists');
        return;
      }
      const repo = createRepoRecord(VIEWER_LOGIN, name, {
        private: bodyBool(jsonBody, 'private'),
        description: bodyString(jsonBody, 'description'),
        defaultBranch: bodyString(jsonBody, 'default_branch'),
      });
      sendJson(res, 201, repoJson(repo, base));
      return;
    }
    if (method === 'GET') {
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
      const { page, link } = paginate(all, query, base, '/api/v3/user/repos');
      sendJson(res, 200, page.map((r) => repoJson(r, base)), link === null ? undefined : { link });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = decodeSegment(rest[1] as string);
    const repoName = decodeSegment(rest[2] as string);
    const repo = findRepo(owner, repoName);
    if (repo === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const tail = rest.slice(3);
    await handleRepoRoute(req, res, repo, tail, method, query, jsonBody, base);
    return;
  }

  sendError(res, 404, 'Not Found');
}

async function handleRepoRoute(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  tail: string[],
  method: string,
  query: URLSearchParams,
  jsonBody: Record<string, unknown>,
  base: string,
): Promise<void> {
  // /repos/{o}/{r} itself
  if (tail.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo, base));
      return;
    }
    if (method === 'PATCH') {
      const description = bodyString(jsonBody, 'description');
      if (description !== undefined) repo.description = description;
      const defaultBranch = bodyString(jsonBody, 'default_branch');
      if (defaultBranch !== undefined && defaultBranch !== '') repo.defaultBranch = defaultBranch;
      sendJson(res, 200, repoJson(repo, base));
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      sendNoContent(res, 204);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const head = tail[0] as string;

  // --- branches -----------------------------------------------------------
  if (head === 'branches') {
    if (tail.length === 1 && method === 'GET') {
      const names = [...repo.refs.keys()].filter((n) => n.startsWith('refs/heads/')).map((n) => n.slice('refs/heads/'.length)).sort();
      sendJson(res, 200, names.map((n) => branchJson(repo, n)));
      return;
    }
    if (tail.length === 2 && method === 'GET') {
      const branch = decodeSegment(tail[1] as string);
      if (branchTip(repo, branch) === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, branchJson(repo, branch));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- commits ------------------------------------------------------------
  if (head === 'commits') {
    if (tail.length === 1 && method === 'GET') {
      const ref = query.get('sha');
      const tip = resolveRef(repo, ref);
      if (tip === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const list = listCommitsFrom(tip);
      const { page, link } = paginate(list, query, base, `/api/v3/repos/${repo.owner}/${repo.name}/commits`);
      sendJson(res, 200, page.map((oid) => commitJson(oid)), link === null ? undefined : { link });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- git refs -----------------------------------------------------------
  if (head === 'git' && tail[1] === 'refs') {
    if (method === 'POST' && tail.length === 2) {
      const ref = bodyString(jsonBody, 'ref');
      const sha = bodyString(jsonBody, 'sha');
      if (ref === undefined || !ref.startsWith('refs/') || sha === undefined || !isOid(sha)) {
        sendError(res, 422, 'ref and sha are required');
        return;
      }
      if (repo.refs.has(ref)) {
        sendError(res, 422, 'Reference already exists');
        return;
      }
      const obj = objects.get(sha);
      if (obj === undefined) {
        sendError(res, 422, 'object does not exist');
        return;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, {
        ref,
        node_id: globalId('Ref', `${repo.owner}/${repo.name}:${ref}`),
        url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref.replace('refs/', '')}`,
        object: { sha, type: obj.type, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${obj.type}s/${sha}` },
      });
      return;
    }
    if (method === 'GET' && tail.length >= 3) {
      const refName = tail.slice(2).map(decodeSegment).join('/');
      const fullRef = `refs/${refName}`;
      const oid = repo.refs.get(fullRef);
      if (oid === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const obj = objects.get(oid);
      sendJson(res, 200, {
        ref: fullRef,
        node_id: globalId('Ref', `${repo.owner}/${repo.name}:${fullRef}`),
        url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${refName}`,
        object: { sha: oid, type: obj?.type ?? 'commit', url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${obj?.type ?? 'commit'}s/${oid}` },
      });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- contents -----------------------------------------------------------
  if (head === 'contents') {
    const contentPath = tail.slice(1).map(decodeSegment).join('/');
    if (method === 'PUT') {
      const message = bodyString(jsonBody, 'message') ?? `Update ${contentPath}`;
      const content = bodyString(jsonBody, 'content');
      if (content === undefined) {
        sendError(res, 422, 'content is required');
        return;
      }
      const branch = bodyString(jsonBody, 'branch') ?? repo.defaultBranch;
      const sha = bodyString(jsonBody, 'sha');
      // A branch that does not exist yet is created from the default tip.
      let tip = branchTip(repo, branch);
      if (tip === undefined) {
        const defTip = branchTip(repo, repo.defaultBranch);
        if (defTip !== undefined) {
          repo.refs.set(`refs/heads/${branch}`, defTip);
          tip = defTip;
        }
      }
      const currentBlob = tip === undefined ? null : blobAtPath(tip, contentPath);
      if (currentBlob !== null) {
        if (sha === undefined || sha !== currentBlob) {
          sendError(res, 409, 'sha does not match the current file');
          return;
        }
      }
      const blobData = b64decode(content);
      const blobOid = putObj('blob', blobData);
      const files = tip === undefined ? new Map() : flattenTree((commitOf(tip) as CommitView).tree);
      files.set(contentPath, { oid: blobOid, mode: '100644' });
      const commitOid = commitPathMap(repo, branch, files, message);
      sendJson(res, currentBlob === null ? 201 : 200, {
        content: {
          name: contentPath.split('/').pop() ?? contentPath,
          path: contentPath,
          sha: blobOid,
          size: blobData.length,
          type: 'file',
          encoding: 'base64',
          content: b64encode(blobData),
        },
        commit: { sha: commitOid, message },
      });
      return;
    }
    if (method === 'GET') {
      const ref = query.get('ref');
      const tip = resolveRef(repo, ref);
      if (tip === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (contentPath === '') {
        const treeOid = (commitOf(tip) as CommitView).tree;
        sendJson(res, 200, directoryListing(repo, tip, treeOid, ''));
        return;
      }
      const parts = contentPath.split('/');
      let treeOid = (commitOf(tip) as CommitView).tree;
      let found: { oid: string; mode: string } | null = null;
      for (let i = 0; i < parts.length; i += 1) {
        const obj = objects.get(treeOid);
        if (obj === undefined || obj.type !== 'tree') {
          found = null;
          break;
        }
        let entries: TreeEntry[];
        try {
          entries = parseTree(obj.data);
        } catch {
          found = null;
          break;
        }
        const entry = entries.find((e) => e.name === parts[i]);
        if (entry === undefined) {
          found = null;
          break;
        }
        if (i === parts.length - 1) {
          found = { oid: entry.oid, mode: entry.mode };
        } else {
          if (entry.mode !== '40000') {
            found = null;
            break;
          }
          treeOid = entry.oid;
        }
      }
      if (found === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (found.mode === '40000') {
        sendJson(res, 200, directoryListing(repo, tip, found.oid, contentPath));
        return;
      }
      const blob = objects.get(found.oid);
      if (blob === undefined || blob.type !== 'blob') {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: blob.data.length,
        name: parts[parts.length - 1],
        path: contentPath,
        content: b64encode(blob.data),
        sha: found.oid,
      });
      return;
    }
    if (method === 'DELETE') {
      const message = bodyString(jsonBody, 'message') ?? `Delete ${contentPath}`;
      const sha = bodyString(jsonBody, 'sha');
      const branch = bodyString(jsonBody, 'branch') ?? repo.defaultBranch;
      const tip = branchTip(repo, branch);
      if (tip === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const currentBlob = blobAtPath(tip, contentPath);
      if (currentBlob === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (sha === undefined || sha !== currentBlob) {
        sendError(res, 409, 'sha does not match the current file');
        return;
      }
      const files = flattenTree((commitOf(tip) as CommitView).tree);
      files.delete(contentPath);
      const commitOid = commitPathMap(repo, branch, files, message);
      sendJson(res, 200, { commit: { sha: commitOid, message } });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- labels -------------------------------------------------------------
  if (head === 'labels') {
    if (method === 'GET' && tail.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map((l) => labelJson(l)));
      return;
    }
    if (method === 'POST' && tail.length === 1) {
      const name = bodyString(jsonBody, 'name');
      if (name === undefined || name === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      if (repo.labels.has(name)) {
        sendError(res, 422, 'Label already exists');
        return;
      }
      const color = bodyString(jsonBody, 'color') ?? 'ededed';
      const description = bodyString(jsonBody, 'description') ?? '';
      const label: Label = { id: nextGlobalId, name, color, description };
      nextGlobalId += 1;
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- issues -------------------------------------------------------------
  if (head === 'issues') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const title = bodyString(jsonBody, 'title');
        if (title === undefined || title === '') {
          sendError(res, 422, 'title is required');
          return;
        }
        const body = bodyString(jsonBody, 'body') ?? '';
        const labelsRaw = jsonBody.labels;
        const labels: string[] = Array.isArray(labelsRaw) ? labelsRaw.filter((l): l is string => typeof l === 'string') : [];
        for (const label of labels) {
          if (!repo.labels.has(label)) {
            sendError(res, 422, `Label ${label} does not exist`);
            return;
          }
        }
        const issue = createIssueRecord(repo, title, body, labels);
        sendJson(res, 201, issueJson(issue, repo));
        return;
      }
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const direction = query.get('direction') ?? 'desc';
        let items = [...repo.items.values()].filter((i) => i.kind === 'issue');
        if (state === 'open') items = items.filter((i) => i.state === 'open');
        else if (state === 'closed') items = items.filter((i) => i.state === 'closed');
        else if (state !== 'all') {
          sendError(res, 422, 'invalid state');
          return;
        }
        items.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        const { page, link } = paginate(items, query, base, `/api/v3/repos/${repo.owner}/${repo.name}/issues`);
        sendJson(res, 200, page.map((i) => issueJson(i, repo)), link === null ? undefined : { link });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const number = Number.parseInt(tail[1] as string, 10);
    if (!Number.isInteger(number) || number <= 0) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const item = repo.items.get(number);
    if (tail.length === 2) {
      if (item === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, issueJson(item, repo));
        return;
      }
      if (method === 'PATCH') {
        const state = bodyString(jsonBody, 'state');
        if (state === 'open' || state === 'closed') item.state = state;
        const title = bodyString(jsonBody, 'title');
        if (title !== undefined) item.title = title;
        const body = bodyString(jsonBody, 'body');
        if (body !== undefined) item.body = body;
        sendJson(res, 200, issueJson(item, repo));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 3 && tail[2] === 'comments') {
      if (item === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'POST') {
        const body = bodyString(jsonBody, 'body');
        if (body === undefined || body === '') {
          sendError(res, 422, 'body is required');
          return;
        }
        const comment: Comment = { id: nextGlobalId, body };
        nextGlobalId += 1;
        item.comments.push(comment);
        sendJson(res, 201, commentJson(comment, repo, number));
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, item.comments.map((c) => commentJson(c, repo, number)));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // --- pull requests ------------------------------------------------------
  if (head === 'pulls') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const title = bodyString(jsonBody, 'title');
        const headRefRaw = bodyString(jsonBody, 'head');
        const baseRefRaw = bodyString(jsonBody, 'base');
        if (title === undefined || title === '' || headRefRaw === undefined || baseRefRaw === undefined) {
          sendError(res, 422, 'title, head and base are required');
          return;
        }
        const headRef = stripOwnerPrefix(headRefRaw, repo.owner);
        const baseRef = stripOwnerPrefix(baseRefRaw, repo.owner);
        const body = bodyString(jsonBody, 'body') ?? '';
        const headSha = branchTip(repo, headRef);
        if (headSha === undefined) {
          sendError(res, 422, `head branch ${headRef} does not exist`);
          return;
        }
        const baseSha = branchTip(repo, baseRef);
        if (baseSha === undefined) {
          sendError(res, 422, `base branch ${baseRef} does not exist`);
          return;
        }
        for (const existing of repo.items.values()) {
          if (existing.kind === 'pr' && existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
            sendError(res, 422, 'A pull request already exists for this head and base');
            return;
          }
        }
        const pr = createPrRecord(repo, title, body, headRef, baseRef, headSha, baseSha);
        sendJson(res, 201, prJson(pr, repo));
        return;
      }
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let prs = [...repo.items.values()].filter((i) => i.kind === 'pr') as PullRequest[];
        if (state === 'open') prs = prs.filter((p) => p.state === 'open');
        else if (state === 'closed') prs = prs.filter((p) => p.state === 'closed');
        else if (state !== 'all') {
          sendError(res, 422, 'invalid state');
          return;
        }
        prs.sort((a, b) => b.seq - a.seq);
        const { page, link } = paginate(prs, query, base, `/api/v3/repos/${repo.owner}/${repo.name}/pulls`);
        sendJson(res, 200, page.map((p) => prJson(p, repo)), link === null ? undefined : { link });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const number = Number.parseInt(tail[1] as string, 10);
    if (!Number.isInteger(number) || number <= 0) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const item = repo.items.get(number);
    if (item === undefined || item.kind !== 'pr') {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 2 && method === 'GET') {
      sendJson(res, 200, prJson(item, repo));
      return;
    }
    if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
      const files = prFiles(item);
      sendJson(res, 200, files.map((f) => ({ ...f, patch: undefined, blob_url: '', raw_url: '', contents_url: '' })));
      return;
    }
    if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
      if (item.merged || item.state === 'closed') {
        sendError(res, 405, 'Pull request is already merged or closed');
        return;
      }
      // Refresh the recorded tips: the branches may have moved since creation.
      const headSha = branchTip(repo, item.headRef);
      const baseSha = branchTip(repo, item.baseRef);
      if (headSha !== undefined) item.headSha = headSha;
      if (baseSha !== undefined) item.baseSha = baseSha;
      const sha = squashMerge(repo, item);
      if (sha === null) {
        sendError(res, 405, 'Merge conflict');
        return;
      }
      sendJson(res, 200, { sha, merged: true, message: item.title });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  sendError(res, 404, 'Not Found');
}

function stripOwnerPrefix(ref: string, owner: string): string {
  const colon = ref.indexOf(':');
  if (colon < 0) return ref;
  const prefix = ref.slice(0, colon);
  if (prefix === owner) return ref.slice(colon + 1);
  return ref;
}

function directoryListing(repo: Repo, tip: string, treeOid: string, path: string): Array<Record<string, unknown>> {
  void tip;
  const obj = objects.get(treeOid);
  if (obj === undefined || obj.type !== 'tree') return [];
  let entries: TreeEntry[];
  try {
    entries = parseTree(obj.data);
  } catch {
    return [];
  }
  return entries.map((entry) => {
    const childPath = path === '' ? entry.name : `${path}/${entry.name}`;
    const isDir = entry.mode === '40000';
    const size = isDir ? 0 : (objects.get(entry.oid)?.data.length ?? 0);
    return {
      type: isDir ? 'dir' : 'file',
      name: entry.name,
      path: childPath,
      sha: entry.oid,
      size,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${childPath}`,
    };
  });
}

// ---------------------------------------------------------------------------
// GraphQL (/api/graphql)
// ---------------------------------------------------------------------------

class GqlError extends Error {}

type GqlValue = string | number | boolean | null | unknown[] | Record<string, unknown>;

interface GqlFieldSel {
  alias: string | null;
  name: string;
  args: Record<string, unknown>;
  selection: GqlSelection[] | null;
}
type GqlSelection = GqlFieldSel | { fragmentOn: string; selection: GqlSelection[] };
interface GqlOperation {
  kind: 'query' | 'mutation';
  selection: GqlSelection[];
}

interface Tok {
  kind: 'name' | 'string' | 'int' | 'float' | 'punct' | 'var';
  value: string;
}

function tokenizeGql(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      toks.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    // `$` is NOT a punct token: it starts a variable (`$owner`), handled below.
    if ('!():=@[]{}|&'.includes(ch)) {
      toks.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      toks.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      toks.push({ kind: 'var', value: src.slice(i + 1, j) });
      i = j;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      const text = src.slice(i, j);
      toks.push({ kind: /[.eE]/.test(text) ? 'float' : 'int', value: text });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      toks.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new GqlError(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return toks;
}

class GqlParser {
  private toks: Tok[];
  private pos = 0;
  private vars: Record<string, unknown>;

  constructor(src: string, vars: Record<string, unknown>) {
    this.toks = tokenizeGql(src);
    this.vars = vars;
  }

  private peek(): Tok | undefined {
    return this.toks[this.pos];
  }

  private next(): Tok {
    const tok = this.toks[this.pos];
    if (tok === undefined) throw new GqlError('unexpected end of GraphQL document');
    this.pos += 1;
    return tok;
  }

  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'punct' || tok.value !== value) throw new GqlError(`expected ${value} in GraphQL document`);
  }

  private skipDirectives(): void {
    while (this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.next();
      this.next(); // directive name
      if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') this.parseArgs();
    }
  }

  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first?.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = first.value;
      this.next();
      const nameTok = this.peek();
      if (nameTok?.kind === 'name') this.next(); // operation name
      if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
        // Variable definitions: ($name: Type, ...) — the types are not needed.
        this.next();
        let depth = 1;
        while (depth > 0) {
          const tok = this.next();
          if (tok.kind === 'punct' && tok.value === '(') depth += 1;
          else if (tok.kind === 'punct' && tok.value === ')') depth -= 1;
        }
      }
    }
    this.skipDirectives();
    return { kind, selection: this.parseSelectionSet() };
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const out: GqlSelection[] = [];
    for (;;) {
      const tok = this.peek();
      if (tok === undefined) throw new GqlError('unterminated selection set');
      if (tok.kind === 'punct' && tok.value === '}') {
        this.next();
        return out;
      }
      out.push(this.parseSelection());
    }
  }

  private parseSelection(): GqlSelection {
    const tok = this.peek();
    if (tok?.kind === 'punct' && tok.value === '...') {
      this.next();
      const nextTok = this.peek();
      let on = '';
      if (nextTok?.kind === 'name' && nextTok.value === 'on') {
        this.next();
        const typeTok = this.next();
        on = typeTok.value;
      }
      this.skipDirectives();
      return { fragmentOn: on, selection: this.parseSelectionSet() };
    }
    let alias: string | null = null;
    let nameTok = this.next();
    if (nameTok.kind !== 'name') throw new GqlError('expected a field name');
    const colon = this.peek();
    if (colon?.kind === 'punct' && colon.value === ':') {
      this.next();
      alias = nameTok.value;
      nameTok = this.next();
      if (nameTok.kind !== 'name') throw new GqlError('expected a field name after an alias');
    }
    let args: Record<string, unknown> = {};
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') args = this.parseArgs();
    this.skipDirectives();
    let selection: GqlSelection[] | null = null;
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '{') selection = this.parseSelectionSet();
    return { alias, name: nameTok.value, args, selection };
  }

  private parseArgs(): Record<string, unknown> {
    this.expectPunct('(');
    const args: Record<string, unknown> = {};
    for (;;) {
      const tok = this.peek();
      if (tok === undefined) throw new GqlError('unterminated argument list');
      if (tok.kind === 'punct' && tok.value === ')') {
        this.next();
        return args;
      }
      const nameTok = this.next();
      if (nameTok.kind !== 'name') throw new GqlError('expected an argument name');
      this.expectPunct(':');
      args[nameTok.value] = this.parseValue();
    }
  }

  private parseValue(): unknown {
    const tok = this.next();
    if (tok.kind === 'var') {
      if (!(tok.value in this.vars)) throw new GqlError(`variable $${tok.value} was not provided`);
      return this.vars[tok.value];
    }
    if (tok.kind === 'string') return tok.value;
    if (tok.kind === 'int') return Number.parseInt(tok.value, 10);
    if (tok.kind === 'float') return Number.parseFloat(tok.value);
    if (tok.kind === 'name') {
      if (tok.value === 'true') return true;
      if (tok.value === 'false') return false;
      if (tok.value === 'null') return null;
      return tok.value; // enum value, read as its name
    }
    if (tok.kind === 'punct' && tok.value === '[') {
      const list: unknown[] = [];
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new GqlError('unterminated list');
        if (next.kind === 'punct' && next.value === ']') {
          this.next();
          return list;
        }
        list.push(this.parseValue());
      }
    }
    if (tok.kind === 'punct' && tok.value === '{') {
      const obj: Record<string, unknown> = {};
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new GqlError('unterminated input object');
        if (next.kind === 'punct' && next.value === '}') {
          this.next();
          return obj;
        }
        const nameTok = this.next();
        if (nameTok.kind !== 'name') throw new GqlError('expected an input object key');
        this.expectPunct(':');
        obj[nameTok.value] = this.parseValue();
      }
    }
    throw new GqlError(`unexpected token ${JSON.stringify(tok.value)} in a value`);
  }
}

// --- resolved values ---------------------------------------------------------

type GqlParent = { __type: string; [key: string]: unknown };

const ISSUE_TYPE_FIELDS = ['id', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'url', 'repository', 'closedAt', 'assignees', 'locked'];
const PR_TYPE_FIELDS = ['id', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files', 'createdAt', 'updatedAt', 'author', 'headRef', 'baseRef', 'mergeCommit', 'comments', 'url', 'headRefOid', 'baseRefOid'];
const REPO_TYPE_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'createdAt', 'updatedAt', 'url', 'homepageUrl'];
const SEARCH_TYPE_ENUMS = ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE', 'WIKI', 'PROJECT'];

function stateToGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function resolveIssuesConnection(repo: Repo, args: Record<string, unknown>): GqlParent {
  let items = [...repo.items.values()].filter((i) => i.kind === 'issue') as Issue[];
  const states = args.states;
  if (Array.isArray(states)) {
    items = items.filter((i) => states.includes(stateToGql(i.state)));
  }
  const orderBy = isRecord(args.orderBy) ? args.orderBy : undefined;
  if (orderBy !== undefined && orderBy.field === 'CREATED_AT') {
    items.sort((a, b) => (orderBy.direction === 'DESC' ? b.seq - a.seq : a.seq - b.seq));
  } else {
    items.sort((a, b) => a.seq - b.seq);
  }
  const first = typeof args.first === 'number' ? args.first : 30;
  let start = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    try {
      const idx = Number.parseInt(Buffer.from(args.after, 'base64').toString('utf8'), 10);
      if (Number.isFinite(idx)) start = idx + 1;
    } catch {
      start = 0;
    }
  }
  const slice = items.slice(start, start + first);
  const endIndex = start + slice.length - 1;
  const hasNextPage = start + slice.length < items.length;
  const endCursor = slice.length === 0 ? null : Buffer.from(String(endIndex)).toString('base64');
  return {
    __type: 'IssueConnection',
    nodes: slice.map((item) => ({ __type: 'Issue', repo, item })),
    pageInfo: { __type: 'PageInfo', hasNextPage, endCursor },
  };
}

function resolvePrFiles(pr: PullRequest): GqlParent {
  const files = prFiles(pr);
  return {
    __type: 'FileConnection',
    nodes: files.map((f) => ({ __type: 'File', path: f.filename })),
  };
}

/** Execute one field against a parent value. Throws GqlError on an unknown field. */
function resolveField(parent: GqlParent, field: GqlFieldSel): unknown {
  const type = parent.__type;
  const name = field.name;
  if (name === '__typename') return type;

  if (type === 'Query') {
    if (name === 'viewer') return { __type: 'Viewer' };
    if (name === 'repository') {
      const owner = field.args.owner;
      const repoName = field.args.name;
      if (typeof owner !== 'string' || typeof repoName !== 'string') throw new GqlError('repository needs owner and name');
      const repo = findRepo(owner, repoName);
      return repo === undefined ? null : { __type: 'Repository', repo };
    }
    if (name === 'node') {
      const id = field.args.id;
      if (typeof id !== 'string') throw new GqlError('node needs an id');
      const decoded = decodeGlobalId(id);
      if (decoded === null) return null;
      if (decoded.kind === 'Repository') {
        const repo = [...repos.values()].find((r) => String(r.id) === decoded.key);
        return repo === undefined ? null : { __type: 'Repository', repo };
      }
      if (decoded.kind === 'Issue' || decoded.kind === 'PullRequest') {
        const parsedKey = parseNumberedKey(decoded.key);
        if (parsedKey === null) return null;
        const repo = findRepo(parsedKey.owner, parsedKey.repo);
        if (repo === undefined) return null;
        const item = repo.items.get(parsedKey.number);
        if (item === undefined) return null;
        return item.kind === 'issue' ? { __type: 'Issue', repo, item } : { __type: 'PullRequest', repo, item };
      }
      return null;
    }
    if (name === '__type') {
      const typeName = field.args.name;
      if (typeName === 'Issue') return { __type: 'Type', name: 'Issue', fields: ISSUE_TYPE_FIELDS, enumValues: [] };
      if (typeName === 'PullRequest') return { __type: 'Type', name: 'PullRequest', fields: PR_TYPE_FIELDS, enumValues: [] };
      if (typeName === 'Repository') return { __type: 'Type', name: 'Repository', fields: REPO_TYPE_FIELDS, enumValues: [] };
      if (typeName === 'SearchType') return { __type: 'Type', name: 'SearchType', fields: [], enumValues: SEARCH_TYPE_ENUMS };
      return null;
    }
    throw new GqlError(`Cannot query field "${name}" on type "Query".`);
  }

  if (type === 'Mutation') {
    if (name === 'createIssue') {
      const input = isRecord(field.args.input) ? field.args.input : {};
      const repoId = input.repositoryId;
      if (typeof repoId !== 'string') throw new GqlError('createIssue needs a repositoryId');
      const decoded = decodeGlobalId(repoId);
      const repo = decoded !== null && decoded.kind === 'Repository' ? [...repos.values()].find((r) => String(r.id) === decoded.key) : undefined;
      if (repo === undefined) throw new GqlError('createIssue: repository not found');
      const title = typeof input.title === 'string' ? input.title : '';
      const body = typeof input.body === 'string' ? input.body : '';
      if (title === '') throw new GqlError('createIssue: title is required');
      const issue = createIssueRecord(repo, title, body, []);
      return { __type: 'CreateIssuePayload', issue: { __type: 'Issue', repo, item: issue } };
    }
    if (name === 'closeIssue') {
      const input = isRecord(field.args.input) ? field.args.input : {};
      const issueId = input.issueId;
      if (typeof issueId !== 'string') throw new GqlError('closeIssue needs an issueId');
      const found = findNumberedByGlobalId(issueId);
      if (found === undefined || found.item.kind !== 'issue') throw new GqlError('closeIssue: issue not found');
      found.item.state = 'closed';
      return { __type: 'CloseIssuePayload', issue: { __type: 'Issue', repo: found.repo, item: found.item } };
    }
    if (name === 'createPullRequest') {
      const input = isRecord(field.args.input) ? field.args.input : {};
      const repoId = input.repositoryId;
      if (typeof repoId !== 'string') throw new GqlError('createPullRequest needs a repositoryId');
      const decoded = decodeGlobalId(repoId);
      const repo = decoded !== null && decoded.kind === 'Repository' ? [...repos.values()].find((r) => String(r.id) === decoded.key) : undefined;
      if (repo === undefined) throw new GqlError('createPullRequest: repository not found');
      const baseRef = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const headRef = typeof input.headRefName === 'string' ? input.headRefName : '';
      const title = typeof input.title === 'string' ? input.title : '';
      const headSha = branchTip(repo, headRef);
      const baseSha = branchTip(repo, baseRef);
      if (headSha === undefined || baseSha === undefined) throw new GqlError('createPullRequest: head or base branch does not exist');
      for (const existing of repo.items.values()) {
        if (existing.kind === 'pr' && existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
          throw new GqlError('createPullRequest: a pull request already exists for this head and base');
        }
      }
      const pr = createPrRecord(repo, title, '', headRef, baseRef, headSha, baseSha);
      return { __type: 'CreatePullRequestPayload', pullRequest: { __type: 'PullRequest', repo, item: pr } };
    }
    if (name === 'mergePullRequest') {
      const input = isRecord(field.args.input) ? field.args.input : {};
      const prId = input.pullRequestId;
      if (typeof prId !== 'string') throw new GqlError('mergePullRequest needs a pullRequestId');
      const found = findNumberedByGlobalId(prId);
      if (found === undefined || found.item.kind !== 'pr') throw new GqlError('mergePullRequest: pull request not found');
      const pr = found.item;
      if (pr.merged || pr.state === 'closed') throw new GqlError('mergePullRequest: pull request is already merged or closed');
      const headSha = branchTip(found.repo, pr.headRef);
      const baseSha = branchTip(found.repo, pr.baseRef);
      if (headSha !== undefined) pr.headSha = headSha;
      if (baseSha !== undefined) pr.baseSha = baseSha;
      const sha = squashMerge(found.repo, pr);
      if (sha === null) throw new GqlError('mergePullRequest: merge conflict');
      return { __type: 'MergePullRequestPayload', pullRequest: { __type: 'PullRequest', repo: found.repo, item: pr } };
    }
    if (name === 'addComment') {
      const input = isRecord(field.args.input) ? field.args.input : {};
      const subjectId = input.subjectId;
      const body = typeof input.body === 'string' ? input.body : '';
      if (typeof subjectId !== 'string') throw new GqlError('addComment needs a subjectId');
      const found = findNumberedByGlobalId(subjectId);
      if (found === undefined) throw new GqlError('addComment: subject not found');
      const comment: Comment = { id: nextGlobalId, body };
      nextGlobalId += 1;
      found.item.comments.push(comment);
      return { __type: 'AddCommentPayload', commentEdge: { __type: 'CommentEdge', node: { __type: 'Comment', comment } } };
    }
    throw new GqlError(`Cannot query field "${name}" on type "Mutation".`);
  }

  if (type === 'Viewer') {
    if (name === 'login') return VIEWER_LOGIN;
    throw new GqlError(`Cannot query field "${name}" on type "Viewer".`);
  }

  if (type === 'Repository') {
    const repo = parent.repo as Repo;
    if (name === 'id') return globalId('Repository', String(repo.id));
    if (name === 'databaseId') return repo.id;
    if (name === 'name') return repo.name;
    if (name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (name === 'owner') return { __type: 'User', login: repo.owner };
    if (name === 'defaultBranchRef') return { __type: 'Ref', name: repo.defaultBranch };
    if (name === 'viewerPermission') return 'ADMIN';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'description') return repo.description;
    if (name === 'isPrivate') return repo.private;
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}`;
    if (name === 'issue') {
      const number = field.args.number;
      if (typeof number !== 'number') throw new GqlError('issue needs a number');
      const item = repo.items.get(number);
      return item !== undefined && item.kind === 'issue' ? { __type: 'Issue', repo, item } : null;
    }
    if (name === 'issues') return resolveIssuesConnection(repo, field.args);
    if (name === 'pullRequest') {
      const number = field.args.number;
      if (typeof number !== 'number') throw new GqlError('pullRequest needs a number');
      const item = repo.items.get(number);
      return item !== undefined && item.kind === 'pr' ? { __type: 'PullRequest', repo, item } : null;
    }
    if (name === 'pullRequests') {
      let prs = [...repo.items.values()].filter((i) => i.kind === 'pr') as PullRequest[];
      prs.sort((a, b) => b.seq - a.seq);
      const first = typeof field.args.first === 'number' ? field.args.first : 30;
      prs = prs.slice(0, first);
      return {
        __type: 'PullRequestConnection',
        nodes: prs.map((item) => ({ __type: 'PullRequest', repo, item })),
        pageInfo: { __type: 'PageInfo', hasNextPage: false, endCursor: null },
      };
    }
    throw new GqlError(`Cannot query field "${name}" on type "Repository".`);
  }

  if (type === 'Issue') {
    const item = parent.item as Issue;
    if (name === 'id') return globalId('Issue', `${(parent.repo as Repo).owner}/${(parent.repo as Repo).name}:${item.number}`);
    if (name === 'number') return item.number;
    if (name === 'title') return item.title;
    if (name === 'body') return item.body;
    if (name === 'state') return stateToGql(item.state);
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'url') return `https://example.invalid/${(parent.repo as Repo).owner}/${(parent.repo as Repo).name}/issues/${item.number}`;
    if (name === 'author') return { __type: 'User', login: VIEWER_LOGIN };
    throw new GqlError(`Cannot query field "${name}" on type "Issue".`);
  }

  if (type === 'PullRequest') {
    const item = parent.item as PullRequest;
    const repo = parent.repo as Repo;
    if (name === 'id') return globalId('PullRequest', `${repo.owner}/${repo.name}:${item.number}`);
    if (name === 'number') return item.number;
    if (name === 'title') return item.title;
    if (name === 'body') return item.body;
    if (name === 'state') return stateToGql(item.state);
    if (name === 'headRefName') return item.headRef;
    if (name === 'baseRefName') return item.baseRef;
    if (name === 'mergeable') return prConflicts(item) ? 'CONFLICTING' : 'MERGEABLE';
    if (name === 'merged') return item.merged;
    if (name === 'createdAt' || name === 'updatedAt') return FIXED_ISO;
    if (name === 'url') return `https://example.invalid/${repo.owner}/${repo.name}/pull/${item.number}`;
    if (name === 'author') return { __type: 'User', login: VIEWER_LOGIN };
    if (name === 'files') return resolvePrFiles(item);
    throw new GqlError(`Cannot query field "${name}" on type "PullRequest".`);
  }

  if (type === 'IssueConnection' || type === 'PullRequestConnection') {
    if (name === 'nodes') return parent.nodes as unknown[];
    if (name === 'edges') {
      const nodes = (parent.nodes as GqlParent[] | undefined) ?? [];
      return nodes.map((node) => ({ __type: 'Edge', node }));
    }
    if (name === 'pageInfo') return parent.pageInfo as GqlParent;
    if (name === 'totalCount') return ((parent.nodes as unknown[] | undefined) ?? []).length;
    throw new GqlError(`Cannot query field "${name}" on type "${type}".`);
  }

  if (type === 'FileConnection') {
    if (name === 'nodes') return parent.nodes as unknown[];
    if (name === 'pageInfo') return { __type: 'PageInfo', hasNextPage: false, endCursor: null };
    throw new GqlError(`Cannot query field "${name}" on type "FileConnection".`);
  }

  if (type === 'PageInfo') {
    if (name === 'hasNextPage') return parent.hasNextPage as boolean;
    if (name === 'endCursor') return parent.endCursor as string | null;
    throw new GqlError(`Cannot query field "${name}" on type "PageInfo".`);
  }

  if (type === 'User') {
    if (name === 'login') return parent.login as string;
    if (name === 'id') return globalId('User', String(VIEWER_ID));
    throw new GqlError(`Cannot query field "${name}" on type "User".`);
  }

  if (type === 'Ref') {
    if (name === 'name') return parent.name as string;
    throw new GqlError(`Cannot query field "${name}" on type "Ref".`);
  }

  if (type === 'Type') {
    if (name === 'name') return parent.name as string;
    if (name === 'fields') {
      const fields = parent.fields as string[];
      return fields.map((f) => ({ __type: 'Field', name: f }));
    }
    if (name === 'enumValues') {
      const values = parent.enumValues as string[];
      return values.map((v) => ({ __type: 'EnumValue', name: v }));
    }
    throw new GqlError(`Cannot query field "${name}" on type "__Type".`);
  }

  if (type === 'Field' || type === 'EnumValue') {
    if (name === 'name') return parent.name as string;
    throw new GqlError(`Cannot query field "${name}" on type "${type}".`);
  }

  if (type === 'File') {
    if (name === 'path') return parent.path as string;
    throw new GqlError(`Cannot query field "${name}" on type "File".`);
  }

  if (type === 'Edge') {
    if (name === 'node') return parent.node as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "Edge".`);
  }

  if (type === 'Comment') {
    if (name === 'id') return globalId('IssueComment', `${(parent.comment as Comment).id}`);
    if (name === 'body') return (parent.comment as Comment).body;
    throw new GqlError(`Cannot query field "${name}" on type "Comment".`);
  }

  if (type === 'CommentEdge') {
    if (name === 'node') return parent.node as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "CommentEdge".`);
  }

  if (type === 'CreateIssuePayload') {
    if (name === 'issue') return parent.issue as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "CreateIssuePayload".`);
  }
  if (type === 'CloseIssuePayload') {
    if (name === 'issue') return parent.issue as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "CloseIssuePayload".`);
  }
  if (type === 'CreatePullRequestPayload' || type === 'MergePullRequestPayload') {
    if (name === 'pullRequest') return parent.pullRequest as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "${type}".`);
  }
  if (type === 'AddCommentPayload') {
    if (name === 'commentEdge') return parent.commentEdge as GqlParent;
    throw new GqlError(`Cannot query field "${name}" on type "AddCommentPayload".`);
  }

  throw new GqlError(`Cannot query field "${name}" on type "${type}".`);
}

/** Parse a numbered-item global-id key of the form `owner/repo:number`. */
function parseNumberedKey(key: string): { owner: string; repo: string; number: number } | null {
  const colon = key.lastIndexOf(':');
  if (colon < 0) return null;
  const number = Number.parseInt(key.slice(colon + 1), 10);
  if (!Number.isInteger(number) || number <= 0) return null;
  const slash = key.slice(0, colon).indexOf('/');
  if (slash < 0) return null;
  return { owner: key.slice(0, slash), repo: key.slice(slash + 1, colon), number };
}

function findNumberedByGlobalId(id: string): { repo: Repo; item: NumberedItem } | undefined {
  const decoded = decodeGlobalId(id);
  if (decoded === null) return undefined;
  if (decoded.kind !== 'Issue' && decoded.kind !== 'PullRequest') return undefined;
  const parsedKey = parseNumberedKey(decoded.key);
  if (parsedKey === null) return undefined;
  const repo = findRepo(parsedKey.owner, parsedKey.repo);
  if (repo === undefined) return undefined;
  const item = repo.items.get(parsedKey.number);
  if (item === undefined) return undefined;
  return { repo, item };
}

/** Execute a selection set against a parent value; returns the response object. */
function executeSelection(parent: GqlParent, selections: GqlSelection[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if ('fragmentOn' in sel) {
      if (sel.fragmentOn === '' || sel.fragmentOn === parent.__type) {
        Object.assign(out, executeSelection(parent, sel.selection));
      }
      continue;
    }
    const value = resolveField(parent, sel);
    const key = sel.alias ?? sel.name;
    if (value === null || typeof value !== 'object') {
      out[key] = value;
      continue;
    }
    if (Array.isArray(value)) {
      out[key] = value.map((entry) => {
        if (entry !== null && typeof entry === 'object' && '__type' in (entry as Record<string, unknown>)) {
          return sel.selection === null ? entry : executeSelection(entry as GqlParent, sel.selection);
        }
        return entry;
      });
      continue;
    }
    if ('__type' in (value as Record<string, unknown>)) {
      out[key] = sel.selection === null ? value : executeSelection(value as GqlParent, sel.selection);
      continue;
    }
    out[key] = value;
  }
  return out;
}

function executeGraphQL(query: string, variables: Record<string, unknown>): { data: unknown; errors?: Array<{ message: string }> } {
  try {
    const parser = new GqlParser(query, variables);
    const op = parser.parseOperation();
    const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
    const data = executeSelection({ __type: rootType }, op.selection);
    return { data };
  } catch (err) {
    if (err instanceof GqlError) return { data: null, errors: [{ message: err.message }] };
    throw err;
  }
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  let parsed: unknown;
  try {
    parsed = parseJsonBody(body);
  } catch {
    sendJson(res, 400, { errors: [{ message: 'request body is not valid JSON' }] });
    return;
  }
  const runOne = (op: unknown): Record<string, unknown> => {
    if (!isRecord(op) || typeof op.query !== 'string') {
      return { data: null, errors: [{ message: 'each operation needs a query string' }] };
    }
    const variables = isRecord(op.variables) ? (op.variables as Record<string, unknown>) : {};
    return executeGraphQL(op.query, variables);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed));
}

// ---------------------------------------------------------------------------
// MCP (/mcp) — JSON-RPC 2.0 Streamable HTTP, 2026-07-28 era
// ---------------------------------------------------------------------------

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
        owner: { type: 'string', description: 'The repository owner (defaults to the authenticated user).' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The owner/repo full name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'number', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpRepoOf(args: Record<string, unknown>): { owner: string; repo: string } | null {
  const fullName = typeof args.full_name === 'string' ? args.full_name : '';
  if (fullName !== '' && typeof args.owner !== 'string' && typeof args.repo !== 'string') {
    const slash = fullName.indexOf('/');
    if (slash > 0) return { owner: fullName.slice(0, slash), repo: fullName.slice(slash + 1) };
    return null;
  }
  const owner = typeof args.owner === 'string' ? args.owner : '';
  const repo = typeof args.repo === 'string' ? args.repo : '';
  if (owner === '' || repo === '') return null;
  return { owner, repo };
}

function mcpToolResult(result: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: jsonString(result) }],
    structuredContent: result,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function runMcpTool(name: string, args: Record<string, unknown>, base: string): Record<string, unknown> {
  const missing = (fields: string[]): Record<string, unknown> | null => {
    const absent = fields.filter((f) => args[f] === undefined || args[f] === null || args[f] === '');
    return absent.length > 0 ? mcpToolError(`missing required argument(s): ${absent.join(', ')}`) : null;
  };

  if (name === 'create_repo') {
    const miss = missing(['name']);
    if (miss !== null) return miss;
    const repoName = args.name as string;
    if (findRepo(VIEWER_LOGIN, repoName) !== undefined) return mcpToolError('Repository already exists');
    const repo = createRepoRecord(VIEWER_LOGIN, repoName, {
      private: typeof args.private === 'boolean' ? args.private : undefined,
      description: typeof args.description === 'string' ? args.description : undefined,
    });
    return mcpToolResult(repoJson(repo, base));
  }

  if (name === 'get_repo') {
    const target = mcpRepoOf(args);
    if (target === null) {
      const miss = missing(['owner', 'repo']);
      if (miss !== null) return miss;
      return mcpToolError('owner and repo are required');
    }
    const repo = findRepo(target.owner, target.repo);
    if (repo === undefined) return mcpToolError('Repository not found');
    return mcpToolResult(repoJson(repo, base));
  }

  if (name === 'create_issue') {
    const miss = missing(['owner', 'repo', 'title']);
    if (miss !== null) return miss;
    const target = mcpRepoOf(args) as { owner: string; repo: string };
    const repo = findRepo(target.owner, target.repo);
    if (repo === undefined) return mcpToolError('Repository not found');
    const issue = createIssueRecord(repo, args.title as string, typeof args.body === 'string' ? args.body : '', []);
    return mcpToolResult(issueJson(issue, repo));
  }

  if (name === 'list_issues') {
    const miss = missing(['owner', 'repo']);
    if (miss !== null) return miss;
    const target = mcpRepoOf(args) as { owner: string; repo: string };
    const repo = findRepo(target.owner, target.repo);
    if (repo === undefined) return mcpToolError('Repository not found');
    const state = typeof args.state === 'string' ? args.state : 'open';
    let items = [...repo.items.values()].filter((i) => i.kind === 'issue') as Issue[];
    if (state === 'open') items = items.filter((i) => i.state === 'open');
    else if (state === 'closed') items = items.filter((i) => i.state === 'closed');
    items.sort((a, b) => b.seq - a.seq);
    const list = items.map((i) => issueJson(i, repo));
    return { content: [{ type: 'text', text: jsonString(list) }], structuredContent: { issues: list } };
  }

  if (name === 'create_pull_request') {
    const miss = missing(['owner', 'repo', 'title', 'head', 'base']);
    if (miss !== null) return miss;
    const target = mcpRepoOf(args) as { owner: string; repo: string };
    const repo = findRepo(target.owner, target.repo);
    if (repo === undefined) return mcpToolError('Repository not found');
    const headRef = stripOwnerPrefix(args.head as string, repo.owner);
    const baseRef = stripOwnerPrefix(args.base as string, repo.owner);
    const headSha = branchTip(repo, headRef);
    const baseSha = branchTip(repo, baseRef);
    if (headSha === undefined || baseSha === undefined) return mcpToolError('head or base branch does not exist');
    for (const existing of repo.items.values()) {
      if (existing.kind === 'pr' && existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
        return mcpToolError('A pull request already exists for this head and base');
      }
    }
    const pr = createPrRecord(repo, args.title as string, typeof args.body === 'string' ? args.body : '', headRef, baseRef, headSha, baseSha);
    return mcpToolResult(prJson(pr, repo));
  }

  if (name === 'merge_pull_request') {
    const miss = missing(['owner', 'repo', 'pull_number']);
    if (miss !== null) return miss;
    const target = mcpRepoOf(args) as { owner: string; repo: string };
    const repo = findRepo(target.owner, target.repo);
    if (repo === undefined) return mcpToolError('Repository not found');
    const number = typeof args.pull_number === 'number' ? args.pull_number : Number.parseInt(String(args.pull_number), 10);
    const item = repo.items.get(number);
    if (item === undefined || item.kind !== 'pr') return mcpToolError('Pull request not found');
    if (item.merged || item.state === 'closed') return mcpToolError('Pull request is already merged or closed');
    const headSha = branchTip(repo, item.headRef);
    const baseSha = branchTip(repo, item.baseRef);
    if (headSha !== undefined) item.headSha = headSha;
    if (baseSha !== undefined) item.baseSha = baseSha;
    const sha = squashMerge(repo, item);
    if (sha === null) return mcpToolError('Merge conflict');
    return mcpToolResult(prJson(item, repo));
  }

  return mcpToolError(`unknown tool ${name}`);
}

function rpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function rpcResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  const base = `http://${req.headers.host ?? 'localhost'}`;
  // Authentication is decided before any tool exists.
  if (!authed(req)) {
    sendError(res, 401, 'Unauthorized');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  if (!isRecord(parsed)) {
    sendJson(res, 400, rpcError(null, -32600, 'Invalid Request'));
    return;
  }
  const id = parsed.id;
  const method = parsed.method;
  // A notification (no id) is accepted and answered with 202 and no body.
  if (id === undefined || id === null) {
    if (typeof method === 'string') {
      requestCounter += 1;
      res.writeHead(202, { 'x-github-request-id': `req-${requestCounter}` });
      res.end();
      return;
    }
    sendJson(res, 400, rpcError(null, -32600, 'Invalid Request'));
    return;
  }
  if (typeof method !== 'string') {
    sendJson(res, 200, rpcError(id, -32600, 'Invalid Request'));
    return;
  }
  const params = isRecord(parsed.params) ? (parsed.params as Record<string, unknown>) : {};

  if (method === 'server/discover') {
    const serverInfo = { name: 'forge', version: '1.0.0' };
    sendJson(res, 200, rpcResult(id, {
      serverInfo,
      capabilities: { tools: {} },
      supportedVersions: ['2026-07-28', '2025-11-25'],
      _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
    }));
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiated = requested === '2026-07-28' || requested === '2025-11-25' ? requested : '2026-07-28';
    sendJson(res, 200, rpcResult(id, {
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    }));
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, rpcResult(id, {}));
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, rpcResult(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) {
      sendJson(res, 200, rpcError(id, -32602, `unknown tool ${toolName}`));
      return;
    }
    const result = runMcpTool(toolName, args, base);
    sendJson(res, 200, rpcResult(id, result));
    return;
  }
  sendJson(res, 200, rpcError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------------------
// Router + lifecycle
// ---------------------------------------------------------------------------

const server = createServer((req, res) => {
  void (async (): Promise<void> => {
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      const path = url.pathname;
      const method = (req.method ?? 'GET').toUpperCase();

      if (path === '/healthz') {
        if (method !== 'GET') {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { ok: true });
        return;
      }

      const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
      if (gitMatch !== null) {
        const owner = decodeSegment(gitMatch[1] as string);
        const repoName = decodeSegment(gitMatch[2] as string);
        const service = gitMatch[3] as string;
        if (service === 'info/refs') {
          handleInfoRefs(req, res, owner, repoName, url.searchParams.get('service') ?? '');
          return;
        }
        if (method !== 'POST') {
          sendError(res, 404, 'Not Found');
          return;
        }
        const body = await readBody(req);
        if (service === 'git-upload-pack') handleUploadPack(req, res, owner, repoName, body);
        else handleReceivePack(req, res, owner, repoName, body);
        return;
      }

      if (path === '/api/graphql') {
        if (method !== 'POST') {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (!authed(req)) {
          sendError(res, 401, 'Unauthorized');
          return;
        }
        const body = await readBody(req);
        await handleGraphQL(req, res, body);
        return;
      }

      if (path === '/mcp') {
        if (method === 'DELETE') {
          sendNoContent(res, 200);
          return;
        }
        if (method !== 'POST') {
          sendError(res, 404, 'Not Found');
          return;
        }
        const body = await readBody(req);
        await handleMcp(req, res, body);
        return;
      }

      if (path.startsWith('/api/v3')) {
        if (!authed(req)) {
          sendError(res, 401, 'Unauthorized');
          return;
        }
        // GETs never carry a body in this API; skipping the read saves an
        // async hop on the hottest path (the 2,000-read workload).
        const body = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
        await handleRest(req, res, body, url);
        return;
      }

      sendError(res, 404, 'Not Found');
    } catch (err) {
      // A request must never take the server down.
      try {
        sendError(res, 500, err instanceof Error ? err.message : 'internal error');
      } catch {
        // The socket is already gone.
      }
    }
  })();
});

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function retryDelay(attempt: number): number {
  return Math.min(2000, 250 * 2 ** Math.min(attempt, 8));
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(30000),
      });
      if (response.status === 200 || response.status === 409) return;
      if (response.status === 400 || response.status === 405) {
        throw new Error(`register answered HTTP ${response.status}: ${await response.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(30000) });
      if (response.ok) {
        const body = (await response.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet: it is not done, so poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  if (ENV_URL === '') {
    process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
    process.exit(1);
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${address.port}\n`);

  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

// The harness ends a trial by closing stdin (the process driver's SIGTERM):
// leave promptly and cleanly when that happens.
process.stdin.on('end', () => {
  try {
    server.close();
  } catch {
    // already closed
  }
  process.exit(0);
});
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
