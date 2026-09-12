/**
 * Inline SVG for the lab pages. One parametrised picture of the fleet, so
 * every stage shows the same six agents with a different thing highlighted,
 * plus a vertical chain picture for the Tenuo stages.
 *
 * Text is measured with a per-glyph width table and shrunk or clipped to
 * fit its box. Arrows are elbows on a grid, with heads that point the way
 * the line travels. Colours come from the site's CSS variables where the
 * SVG inherits them and from a small fixed palette where it cannot.
 */

export type AgentKey = "travel" | "flight" | "hotel" | "activity" | "checkin" | "boarding";
export type NodeKey = AgentKey | "cp" | "service" | "wallet";
export type NodeState = "normal" | "focus" | "rogue" | "compromised" | "dim" | "ok";
export type EdgeKey = "cp-travel" | "travel-flight" | "flight-checkin" | "checkin-boarding" | "travel-hotel" | "travel-activity";
export type EdgeStyle = "normal" | "focus" | "terminal" | "blocked" | "dim" | "you";

export interface ExtraArrow {
  readonly from: NodeKey;
  readonly to: NodeKey;
  readonly label?: string;
  readonly style: "stolen" | "ask" | "handoff" | "blocked";
}

export interface FleetOptions {
  /** Draw the control plane above Travel Agent, with this label. */
  readonly controlPlane?: string;
  /** Requests feeding Travel Agent, e.g. "Alice → Cancún". */
  readonly travelers?: readonly string[];
  /** A wallet pill, e.g. "$1,200". */
  readonly wallet?: string;
  /** A policy service / registry node, with this label. */
  readonly service?: string;
  readonly sub?: Partial<Record<AgentKey, string>>;
  readonly state?: Partial<Record<AgentKey, NodeState>>;
  readonly tag?: Partial<Record<AgentKey, string>>;
  readonly edges?: Partial<Record<EdgeKey, EdgeStyle>>;
  readonly edgeLabels?: Partial<Record<EdgeKey, string>>;
  readonly extra?: readonly ExtraArrow[];
  readonly caption?: string;
}

const W = 760;
const NODE_W = 150;
const NODE_H = 48;
const GAP = 35;
const COL = [22, 22 + NODE_W + GAP, 22 + 2 * (NODE_W + GAP), 22 + 3 * (NODE_W + GAP)] as const;
const ROW_STEP = 84;
const HEAD = 9;

const PALETTE = {
  edge: "#6a6a6a",
  focus: "var(--accent)",
  rogue: "#ff5c5c",
  warn: "#ffb000",
  ok: "#3ddc84",
  dim: "#3a3a3a",
  ink: "#0a0a0a",
} as const;

const NAMES: Record<AgentKey, string> = {
  travel: "Travel Agent",
  flight: "Flight Agent",
  hotel: "Hotel Agent",
  activity: "Activity Agent",
  checkin: "Check-in Agent",
  boarding: "Boarding Agent",
};

interface Box {
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
}

type Point = readonly [number, number];

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* ---------- text measurement ---------- */

const NARROW = new Set("iljft.,:;'!|()[] ");
const WIDE = new Set("mwMW@");
const SYMBOL: Record<string, number> = { "→": 10, "≤": 7.5, "$": 6, "✕": 9, "…": 9, "—": 10, "–": 6 };

/** Approximate advance width, in px, of `s` set in a system sans at `size` px. */
export function textWidth(s: string, size: number, bold = false): number {
  let units = 0;
  for (const ch of s) {
    if (SYMBOL[ch] !== undefined) units += SYMBOL[ch];
    else if (NARROW.has(ch)) units += 2.9;
    else if (WIDE.has(ch)) units += 9;
    else if (ch >= "A" && ch <= "Z") units += 7;
    else if (ch >= "0" && ch <= "9") units += 5.8;
    else units += 5.6;
  }
  return units * (size / 10) * (bold ? 1.06 : 1);
}

interface Fitted {
  readonly text: string;
  readonly size: number;
}

/** Shrink a little, then clip with an ellipsis, so text never leaves its box. */
function fit(s: string, max: number, size: number, bold = false, minSize = size - 2): Fitted {
  for (let sz = size; sz >= minSize; sz -= 0.5) {
    if (textWidth(s, sz, bold) <= max) return { text: s, size: sz };
  }
  let t = s;
  while (t.length > 1 && textWidth(`${t}…`, minSize, bold) > max) t = t.slice(0, -1).trimEnd();
  return { text: `${t}…`, size: minSize };
}

/* ---------- primitives ---------- */

function stateColor(state: NodeState): string {
  switch (state) {
    case "focus": return PALETTE.focus;
    case "rogue": return PALETTE.rogue;
    case "compromised": return PALETTE.rogue;
    case "ok": return PALETTE.ok;
    case "dim": return PALETTE.dim;
    default: return "var(--border)";
  }
}

function label(x: number, y: number, s: string, size: number, fill: string, anchor: "start" | "middle" | "end" = "start", bold = false): string {
  return `<text x="${x}" y="${y}" font-size="${size}"${bold ? ' font-weight="600"' : ""} text-anchor="${anchor}" fill="${fill}">${esc(s)}</text>`;
}

function node(box: Box, name: string, sub: string | undefined, state: NodeState, tag: string | undefined): string {
  const stroke = stateColor(state);
  const width = state === "normal" || state === "dim" ? 1 : 2;
  const textFill = state === "dim" ? "var(--text-muted)" : "var(--text)";
  const pad = 11;
  const inner = box.w - pad * 2;
  const title = fit(name, inner, 13, true);
  const parts = [
    `<rect x="${box.x}" y="${box.y}" width="${box.w}" height="${box.h}" rx="8" fill="var(--surface-2)" stroke="${stroke}" stroke-width="${width}"/>`,
    label(box.x + pad, box.y + (sub === undefined ? 29 : 21), title.text, title.size, textFill, "start", true),
  ];
  if (sub !== undefined) {
    const s = fit(sub, inner, 11, false, 9.5);
    parts.push(label(box.x + pad, box.y + 38, s.text, s.size, "var(--text-muted)"));
  }
  if (tag !== undefined) {
    const t = fit(tag, box.w - 24, 10, true, 9);
    const tw = textWidth(t.text, t.size, true) + 14;
    const color = state === "rogue" || state === "compromised" ? PALETTE.rogue : state === "ok" ? PALETTE.ok : PALETTE.warn;
    const tx = box.x + box.w - tw - 8;
    parts.push(
      `<rect x="${tx}" y="${box.y - 9}" width="${tw}" height="17" rx="8.5" fill="${color}"/>`,
      label(tx + tw / 2, box.y + 3.5, t.text, t.size, PALETTE.ink, "middle", true),
    );
  }
  return parts.join("");
}

function pill(x: number, y: number, text: string, color: string): { svg: string; w: number } {
  const w = Math.round(textWidth(text, 12) + 24);
  const svg =
    `<rect x="${x}" y="${y}" width="${w}" height="26" rx="13" fill="var(--surface)" stroke="${color}" stroke-width="1.5"/>` +
    label(x + w / 2, y + 17, text, 12, "var(--text)", "middle");
  return { svg, w };
}

function edgeColor(style: EdgeStyle): string {
  switch (style) {
    case "focus": return PALETTE.focus;
    case "you": return PALETTE.focus;
    case "terminal": return PALETTE.warn;
    case "blocked": return PALETTE.rogue;
    case "dim": return PALETTE.dim;
    default: return PALETTE.edge;
  }
}

/** An arrowhead whose apex is at `tip`, pointing along the unit direction (dx, dy). */
function head(tip: Point, dx: number, dy: number, color: string): string {
  const [x, y] = tip;
  const bx = x - dx * HEAD;
  const by = y - dy * HEAD;
  const px = -dy * (HEAD * 0.55);
  const py = dx * (HEAD * 0.55);
  return `<polygon points="${x},${y} ${bx + px},${by + py} ${bx - px},${by - py}" fill="${color}"/>`;
}

interface ArrowOptions {
  readonly label?: string;
  /** Where the label sits relative to the last segment. */
  readonly labelAt?: "above" | "below" | "right";
  readonly dashed?: boolean;
  /** Draw the shaft only. */
  readonly noHead?: boolean;
  readonly color?: string;
  readonly width?: number;
}

/**
 * A polyline with a head that points along its final segment. The shaft
 * stops at the base of the head so the line never pokes through it.
 */
function arrow(points: readonly Point[], style: EdgeStyle, o: ArrowOptions = {}): string {
  const color = o.color ?? edgeColor(style);
  const width = o.width ?? (style === "normal" || style === "dim" ? 1.5 : 2);
  const last = points[points.length - 1]!;
  const prev = points[points.length - 2]!;
  const len = Math.hypot(last[0] - prev[0], last[1] - prev[1]);
  const dx = (last[0] - prev[0]) / len;
  const dy = (last[1] - prev[1]) / len;
  const terminal = style === "terminal";
  const shaftEnd: Point = terminal || o.noHead === true ? last : [last[0] - dx * (HEAD - 1), last[1] - dy * (HEAD - 1)];
  const shaft = [...points.slice(0, -1), shaftEnd];
  const d = shaft.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x} ${y}`).join(" ");
  const dash = o.dashed === true || style === "you" ? ' stroke-dasharray="6 4"' : "";
  const parts = [`<path d="${d}" fill="none" stroke="${color}" stroke-width="${width}" stroke-linejoin="round"${dash}/>`];
  if (terminal) {
    // A bar across the end: nothing passes beyond this hop.
    const px = -dy * 9;
    const py = dx * 9;
    parts.push(`<line x1="${last[0] + px}" y1="${last[1] + py}" x2="${last[0] - px}" y2="${last[1] - py}" stroke="${color}" stroke-width="3" stroke-linecap="round"/>`);
  } else if (o.noHead !== true) {
    parts.push(head(last, dx, dy, color));
  }
  if (style === "blocked") {
    const mx = (last[0] + prev[0]) / 2;
    const my = (last[1] + prev[1]) / 2;
    parts.push(`<circle cx="${mx}" cy="${my}" r="8" fill="var(--surface)"/>`);
    parts.push(label(mx, my + 4.5, "✕", 13, PALETTE.rogue, "middle", true));
  }
  if (o.label !== undefined) {
    const horizontal = Math.abs(dy) < 0.01;
    const fill = color === PALETTE.edge ? "var(--text-muted)" : color;
    if (horizontal) {
      const mx = (last[0] + prev[0]) / 2;
      const ly = o.labelAt === "below" ? last[1] + NODE_H / 2 + 15 : last[1] - 8;
      parts.push(label(mx, ly, o.label, 10.5, fill, "middle"));
    } else {
      parts.push(label(last[0] + 9, (last[1] + prev[1]) / 2 + 4, o.label, 10.5, fill, "start"));
    }
  }
  return parts.join("");
}

const cx = (b: Box) => b.x + b.w / 2;
const cy = (b: Box) => b.y + b.h / 2;

/** Route an extra arrow between two boxes as a clean elbow, entering the target from the side it faces. */
function route(from: Box, to: Box, e: ExtraArrow): string {
  const color = e.style === "stolen" || e.style === "blocked" ? PALETTE.rogue : e.style === "ask" ? PALETTE.warn : PALETTE.focus;
  const style: EdgeStyle = e.style === "blocked" ? "blocked" : "focus";
  const dashed = e.style === "stolen";
  const sameColumn = Math.abs(cx(from) - cx(to)) < NODE_W / 2;
  if (sameColumn) {
    // Straight down (or up) between stacked boxes.
    const down = to.y > from.y;
    const start: Point = [cx(from), down ? from.y + from.h : from.y];
    const end: Point = [cx(from), down ? to.y - 1 : to.y + to.h + 1];
    const svg = arrow([start, end], style, { color, dashed });
    if (e.label === undefined) return svg;
    return svg + label(cx(from) + 9, start[1] + (end[1] - start[1]) * 0.7 + 4, e.label, 10.5, color, "start");
  }
  // Leave the source vertically, turn at the target's row, enter the target's near side.
  const leftward = cx(to) < cx(from);
  const start: Point = [cx(from), to.y > from.y ? from.y + from.h : from.y];
  const turn: Point = [cx(from), cy(to)];
  const end: Point = [leftward ? to.x + to.w + 1 : to.x - 1, cy(to)];
  const svg = arrow([start, turn, end], style, { color, dashed });
  if (e.label === undefined) return svg;
  // Label along the horizontal run, just above it.
  const lx = (turn[0] + end[0]) / 2;
  return svg + label(lx, cy(to) - 8, e.label, 10.5, color, "middle");
}

/* ---------- the fleet ---------- */

/** The six agents, arranged as the mission's tree, with per-stage annotations. */
export function fleetDiagram(o: FleetOptions = {}): string {
  const topRow = o.controlPlane !== undefined || (o.travelers !== undefined && o.travelers.length > 0);
  const y0 = topRow ? 92 : 30;
  const rowY = [y0, y0 + ROW_STEP, y0 + 2 * ROW_STEP] as const;
  const boxes: Record<NodeKey, Box> = {
    cp: { x: COL[0], y: 14, w: NODE_W, h: 44 },
    travel: { x: COL[0], y: rowY[0], w: NODE_W, h: NODE_H },
    flight: { x: COL[1], y: rowY[0], w: NODE_W, h: NODE_H },
    checkin: { x: COL[2], y: rowY[0], w: NODE_W, h: NODE_H },
    boarding: { x: COL[3], y: rowY[0], w: NODE_W, h: NODE_H },
    hotel: { x: COL[1], y: rowY[1], w: NODE_W, h: NODE_H },
    activity: { x: COL[1], y: rowY[2], w: NODE_W, h: NODE_H },
    service: { x: COL[2], y: rowY[1] + 10, w: NODE_W + 36, h: NODE_H },
    wallet: { x: COL[3], y: rowY[2] + 11, w: NODE_W, h: 26 },
  };
  const height = rowY[2] + NODE_H + 22;
  const out: string[] = [];
  const edge = (k: EdgeKey) => o.edges?.[k] ?? "normal";
  const opts = (k: EdgeKey, at: "above" | "below" | "right"): ArrowOptions => {
    const l = o.edgeLabels?.[k];
    return l === undefined ? {} : { label: l, labelAt: at };
  };
  const h = (from: Box, to: Box, k: EdgeKey) => arrow([[from.x + from.w, cy(from)], [to.x - 1, cy(to)]], edge(k), opts(k, "below"));

  // Trunk from Travel Agent down to the hotel and activity branches, then the branches themselves.
  const tx = cx(boxes.travel);
  const trunkStyle: EdgeStyle = edge("travel-hotel") === "dim" && edge("travel-activity") === "dim" ? "dim" : "normal";
  out.push(`<path d="M${tx} ${boxes.travel.y + NODE_H} L${tx} ${cy(boxes.activity)}" fill="none" stroke="${edgeColor(trunkStyle)}" stroke-width="1.5"/>`);
  out.push(arrow([[tx, cy(boxes.hotel)], [boxes.hotel.x - 1, cy(boxes.hotel)]], edge("travel-hotel"), opts("travel-hotel", "below")));
  out.push(arrow([[tx, cy(boxes.activity)], [boxes.activity.x - 1, cy(boxes.activity)]], edge("travel-activity"), opts("travel-activity", "below")));
  out.push(h(boxes.travel, boxes.flight, "travel-flight"));
  out.push(h(boxes.flight, boxes.checkin, "flight-checkin"));
  out.push(h(boxes.checkin, boxes.boarding, "checkin-boarding"));

  if (o.controlPlane !== undefined) {
    out.push(node(boxes.cp, "Control plane", o.controlPlane, "focus", undefined));
    out.push(arrow([[tx, boxes.cp.y + boxes.cp.h], [tx, boxes.travel.y - 1]], edge("cp-travel"), opts("cp-travel", "right")));
  }
  if (o.travelers !== undefined && o.travelers.length > 0) {
    // Requests come in from the top: pills in a row, one elbow down into Travel Agent.
    let x = o.controlPlane !== undefined ? COL[1] : COL[0];
    const y = 22;
    let firstCenter = 0;
    o.travelers.forEach((t, i) => {
      const p = pill(x, y, t, i === 0 ? PALETTE.focus : PALETTE.warn);
      out.push(p.svg);
      if (i === 0) firstCenter = x + p.w / 2;
      x += p.w + 12;
    });
    const entryX = tx;
    const midY = boxes.travel.y - 18;
    const points: Point[] = Math.abs(firstCenter - entryX) < 3
      ? [[firstCenter, y + 26], [entryX, boxes.travel.y - 1]]
      : [[firstCenter, y + 26], [firstCenter, midY], [entryX, midY], [entryX, boxes.travel.y - 1]];
    out.push(arrow(points, "normal", { dashed: true }));
  }
  for (const key of ["travel", "flight", "hotel", "activity", "checkin", "boarding"] as const) {
    out.push(node(boxes[key], NAMES[key], o.sub?.[key], o.state?.[key] ?? "normal", o.tag?.[key]));
  }
  if (o.service !== undefined) {
    out.push(node(boxes.service, o.service, "outside every agent", "focus", undefined));
  }
  if (o.wallet !== undefined) {
    out.push(pill(boxes.wallet.x, boxes.wallet.y, `Wallet ${o.wallet}`, PALETTE.warn).svg);
  }
  for (const e of o.extra ?? []) {
    out.push(route(boxes[e.from], boxes[e.to], e));
  }
  return `<svg class="lab-diagram" viewBox="0 0 ${W} ${height}" aria-hidden="true" focusable="false" data-caption="${esc(o.caption ?? "The six agents")}" xmlns="http://www.w3.org/2000/svg">${out.join("\n")}</svg>`;
}

/* ---------- the chain ---------- */

export interface ChainRow {
  readonly who: string;
  readonly scope: string;
  readonly tag?: "root" | "written" | "tutorial" | "you" | "terminal" | "blocked";
  /** Text on the arrow leading into this row. */
  readonly hop?: string;
}

/** A vertical warrant chain: who holds what, hop by hop. */
export function chainDiagram(rows: readonly ChainRow[], caption?: string): string {
  const rowH = 46;
  const gap = 34;
  const x = 30;
  const w = W - 60;
  const arrowX = x + 90;
  const out: string[] = [];
  rows.forEach((r, i) => {
    const y = 12 + i * (rowH + gap);
    const color = r.tag === "you" || r.tag === "tutorial" ? PALETTE.focus : r.tag === "blocked" ? PALETTE.rogue : r.tag === "terminal" ? PALETTE.warn : "var(--border)";
    if (i > 0) {
      const style: EdgeStyle = r.tag === "blocked" ? "blocked" : r.tag === "terminal" ? "terminal" : r.tag === "you" ? "you" : "normal";
      out.push(arrow([[arrowX, y - gap], [arrowX, y - 1]], style, r.hop !== undefined ? { label: r.hop } : {}));
    }
    out.push(`<rect x="${x}" y="${y}" width="${w}" height="${rowH}" rx="8" fill="var(--surface-2)" stroke="${color}" stroke-width="${r.tag === undefined || r.tag === "written" || r.tag === "root" ? 1 : 2}"/>`);
    out.push(label(x + 14, y + 29, r.who, 13, "var(--text)", "start", true));
    let tagWidth = 0;
    if (r.tag !== undefined) {
      const text = r.tag === "root" ? "signed by the control plane" : r.tag === "written" ? "written for you" : r.tag === "tutorial" ? "tutorial" : r.tag === "you" ? "you write this" : r.tag === "terminal" ? "terminal" : "refused";
      tagWidth = textWidth(text, 10.5, true) + 18;
      const fill = r.tag === "you" || r.tag === "tutorial" ? PALETTE.focus : r.tag === "blocked" ? PALETTE.rogue : r.tag === "terminal" ? PALETTE.warn : "var(--border)";
      const tf = r.tag === "written" || r.tag === "root" ? "var(--text-muted)" : PALETTE.ink;
      out.push(`<rect x="${x + w - tagWidth - 10}" y="${y + 14}" width="${tagWidth}" height="18" rx="9" fill="${fill}"/>`);
      out.push(label(x + w - tagWidth / 2 - 10, y + 27, text, 10.5, tf, "middle", true));
    }
    const scopeX = x + 190;
    const scope = fit(r.scope, x + w - 22 - tagWidth - scopeX, 12.5, false, 11);
    out.push(label(scopeX, y + 29, scope.text, scope.size, "var(--text-muted)"));
  });
  const height = 12 + rows.length * (rowH + gap) - gap + 12;
  return `<svg class="lab-diagram" viewBox="0 0 ${W} ${height}" aria-hidden="true" focusable="false" data-caption="${esc(caption ?? "The warrant chain")}" xmlns="http://www.w3.org/2000/svg">${out.join("\n")}</svg>`;
}
