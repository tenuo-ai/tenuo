/**
 * Inline SVG for the lab pages. One parametrised picture of the fleet, so
 * every stage shows the same six agents with a different thing highlighted,
 * plus a vertical chain picture for the Tenuo stages.
 *
 * Colours come from the site's CSS variables where the SVG inherits them and
 * from a small fixed palette where it cannot.
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
const NODE_W = 140;
const NODE_H = 48;
const COL = [30, 215, 400, 585] as const;

const PALETTE = {
  edge: "#5a5a5a",
  focus: "var(--accent)",
  rogue: "#ff5c5c",
  warn: "#ffb000",
  ok: "#3ddc84",
  dim: "#3a3a3a",
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

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

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

function node(box: Box, name: string, sub: string | undefined, state: NodeState, tag: string | undefined): string {
  const stroke = stateColor(state);
  const width = state === "normal" || state === "dim" ? 1 : 2;
  const textFill = state === "dim" ? "var(--text-muted)" : "var(--text)";
  const parts = [
    `<rect x="${box.x}" y="${box.y}" width="${box.w}" height="${box.h}" rx="8" fill="var(--surface-2)" stroke="${stroke}" stroke-width="${width}"/>`,
    `<text x="${box.x + 12}" y="${box.y + (sub === undefined ? 29 : 21)}" font-size="13" font-weight="600" fill="${textFill}">${esc(name)}</text>`,
  ];
  if (sub !== undefined) {
    parts.push(`<text x="${box.x + 12}" y="${box.y + 38}" font-size="11" fill="var(--text-muted)">${esc(sub)}</text>`);
  }
  if (tag !== undefined) {
    const tw = tag.length * 6.4 + 12;
    const color = state === "rogue" || state === "compromised" ? PALETTE.rogue : state === "ok" ? PALETTE.ok : PALETTE.warn;
    parts.push(
      `<rect x="${box.x + box.w - tw - 6}" y="${box.y - 9}" width="${tw}" height="16" rx="8" fill="${color}"/>`,
      `<text x="${box.x + box.w - tw / 2 - 6}" y="${box.y + 3}" font-size="10" font-weight="700" text-anchor="middle" fill="#0a0a0a">${esc(tag)}</text>`,
    );
  }
  return parts.join("");
}

function pill(x: number, y: number, text: string, color: string): string {
  const w = text.length * 6.8 + 22;
  return (
    `<rect x="${x}" y="${y}" width="${w}" height="26" rx="13" fill="var(--surface)" stroke="${color}" stroke-width="1.5"/>` +
    `<text x="${x + w / 2}" y="${y + 17}" font-size="12" text-anchor="middle" fill="var(--text)">${esc(text)}</text>`
  );
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

/** A straight or elbowed arrow along `points`, with an optional label near its end. */
function arrow(points: ReadonlyArray<readonly [number, number]>, style: EdgeStyle, label?: string, labelAt: "above" | "below" | "right" = "above"): string {
  const color = edgeColor(style);
  const last = points[points.length - 1]!;
  const prev = points[points.length - 2]!;
  const d = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x} ${y}`).join(" ");
  const dash = style === "you" ? ' stroke-dasharray="6 4"' : "";
  const parts = [`<path d="${d}" fill="none" stroke="${color}" stroke-width="${style === "normal" || style === "dim" ? 1.5 : 2}"${dash}/>`];
  const horizontal = Math.abs(last[1] - prev[1]) < 1;
  if (style === "terminal") {
    // A bar across the end: nothing passes beyond this hop.
    parts.push(horizontal
      ? `<line x1="${last[0] - 1}" y1="${last[1] - 9}" x2="${last[0] - 1}" y2="${last[1] + 9}" stroke="${color}" stroke-width="3"/>`
      : `<line x1="${last[0] - 9}" y1="${last[1] - 1}" x2="${last[0] + 9}" y2="${last[1] - 1}" stroke="${color}" stroke-width="3"/>`);
  } else {
    const head = horizontal
      ? `${last[0]},${last[1]} ${last[0] - 8},${last[1] - 5} ${last[0] - 8},${last[1] + 5}`
      : `${last[0]},${last[1]} ${last[0] - 5},${last[1] - 8} ${last[0] + 5},${last[1] - 8}`;
    parts.push(`<polygon points="${head}" fill="${color}"/>`);
  }
  if (style === "blocked") {
    const mx = (last[0] + prev[0]) / 2;
    const my = (last[1] + prev[1]) / 2;
    parts.push(`<text x="${mx}" y="${my + 5}" font-size="15" font-weight="700" text-anchor="middle" fill="${PALETTE.rogue}">✕</text>`);
  }
  if (label !== undefined) {
    const lx = horizontal ? (last[0] + prev[0]) / 2 : last[0] + 8;
    const ly = horizontal ? (labelAt === "below" ? last[1] + NODE_H / 2 + 15 : last[1] - 8) : (last[1] + prev[1]) / 2 + 4;
    parts.push(`<text x="${lx}" y="${ly}" font-size="10.5" text-anchor="${horizontal ? "middle" : "start"}" fill="${color === PALETTE.edge ? "var(--text-muted)" : color}">${esc(label)}</text>`);
  }
  return parts.join("");
}

function curvedArrow(from: Box, to: Box, style: ExtraArrow["style"], label?: string): string {
  const color = style === "stolen" || style === "blocked" ? PALETTE.rogue : style === "ask" ? PALETTE.warn : PALETTE.focus;
  const sx = from.x + from.w / 2;
  const sy = from.y + from.h;
  const ex = to.x + to.w / 2;
  const ey = to.y - 2;
  if (Math.abs(sx - ex) < 40 && ey > sy) {
    const dash = style === "stolen" ? ' stroke-dasharray="6 4"' : "";
    return (
      `<path d="M${sx} ${sy} L${sx} ${ey}" fill="none" stroke="${color}" stroke-width="2"${dash}/>` +
      `<polygon points="${sx},${ey} ${sx - 5},${ey - 8} ${sx + 5},${ey - 8}" fill="${color}"/>` +
      (label !== undefined ? `<text x="${sx + 10}" y="${(sy + ey) / 2 + 4}" font-size="10.5" fill="${color}">${esc(label)}</text>` : "")
    );
  }
  const cy = Math.max(sy, ey) + 36;
  const d = `M${sx} ${sy} C ${sx} ${cy}, ${ex} ${cy}, ${ex} ${ey}`;
  const parts = [
    `<path d="${d}" fill="none" stroke="${color}" stroke-width="2"${style === "stolen" ? ' stroke-dasharray="6 4"' : ""}/>`,
    `<polygon points="${ex},${ey} ${ex - 5},${ey - 8} ${ex + 5},${ey - 8}" fill="${color}"/>`,
  ];
  if (label !== undefined) {
    parts.push(`<text x="${(sx + ex) / 2}" y="${cy - 2}" font-size="10.5" text-anchor="middle" fill="${color}">${esc(label)}</text>`);
  }
  return parts.join("");
}

/** The six agents, arranged as the mission's tree, with per-stage annotations. */
export function fleetDiagram(o: FleetOptions = {}): string {
  const topRow = o.controlPlane !== undefined || (o.travelers !== undefined && o.travelers.length > 0);
  const y0 = topRow ? 96 : 30;
  const rowY = [y0, y0 + 84, y0 + 168] as const;
  const boxes: Record<NodeKey, Box> = {
    cp: { x: COL[0], y: 18, w: NODE_W, h: 40 },
    travel: { x: COL[0], y: rowY[0], w: NODE_W, h: NODE_H },
    flight: { x: COL[1], y: rowY[0], w: NODE_W, h: NODE_H },
    checkin: { x: COL[2], y: rowY[0], w: NODE_W, h: NODE_H },
    boarding: { x: COL[3], y: rowY[0], w: NODE_W, h: NODE_H },
    hotel: { x: COL[1], y: rowY[1], w: NODE_W, h: NODE_H },
    activity: { x: COL[1], y: rowY[2], w: NODE_W, h: NODE_H },
    service: { x: COL[2], y: rowY[1] + 8, w: NODE_W + 40, h: NODE_H },
    wallet: { x: COL[3], y: rowY[2] + 10, w: NODE_W, h: 30 },
  };
  const extraDrop = o.extra?.some((e) => e.style === "stolen") === true ? 44 : 0;
  const height = rowY[2] + NODE_H + 24 + (o.caption !== undefined ? 26 : 0) + extraDrop;
  const out: string[] = [];
  const mid = (b: Box) => b.y + b.h / 2;
  const edge = (k: EdgeKey) => o.edges?.[k] ?? "normal";
  const label = (k: EdgeKey) => o.edgeLabels?.[k];

  // Trunk from Travel Agent down to the hotel and activity branches.
  const tx = boxes.travel.x + boxes.travel.w / 2;
  const trunkStyle: EdgeStyle = edge("travel-hotel") === "dim" && edge("travel-activity") === "dim" ? "dim" : "normal";
  out.push(`<path d="M${tx} ${boxes.travel.y + NODE_H} L${tx} ${mid(boxes.activity)}" fill="none" stroke="${edgeColor(trunkStyle)}" stroke-width="1.5"/>`);
  out.push(arrow([[tx, mid(boxes.hotel)], [boxes.hotel.x, mid(boxes.hotel)]], edge("travel-hotel"), label("travel-hotel")));
  out.push(arrow([[tx, mid(boxes.activity)], [boxes.activity.x, mid(boxes.activity)]], edge("travel-activity"), label("travel-activity")));
  out.push(arrow([[boxes.travel.x + NODE_W, mid(boxes.travel)], [boxes.flight.x, mid(boxes.flight)]], edge("travel-flight"), label("travel-flight"), "below"));
  out.push(arrow([[boxes.flight.x + NODE_W, mid(boxes.flight)], [boxes.checkin.x, mid(boxes.checkin)]], edge("flight-checkin"), label("flight-checkin"), "below"));
  out.push(arrow([[boxes.checkin.x + NODE_W, mid(boxes.checkin)], [boxes.boarding.x, mid(boxes.boarding)]], edge("checkin-boarding"), label("checkin-boarding"), "below"));

  if (o.controlPlane !== undefined) {
    out.push(node(boxes.cp, "Control plane", o.controlPlane, "focus", undefined));
    out.push(arrow([[tx, boxes.cp.y + boxes.cp.h], [tx, boxes.travel.y]], edge("cp-travel"), label("cp-travel")));
  }
  if (o.travelers !== undefined && o.travelers.length > 0) {
    let x = o.controlPlane !== undefined ? COL[1] : COL[0];
    const y = 24;
    o.travelers.forEach((t, i) => {
      out.push(pill(x, y, t, i === 0 ? PALETTE.focus : PALETTE.warn));
      x += t.length * 6.8 + 22 + 14;
    });
    const startX = o.controlPlane !== undefined ? COL[1] : COL[0] + 60;
    out.push(`<path d="M${startX} ${y + 26} L${tx + 30} ${boxes.travel.y}" fill="none" stroke="${PALETTE.edge}" stroke-width="1.5" stroke-dasharray="3 3"/>`);
  }
  for (const key of ["travel", "flight", "hotel", "activity", "checkin", "boarding"] as const) {
    out.push(node(boxes[key], NAMES[key], o.sub?.[key], o.state?.[key] ?? "normal", o.tag?.[key]));
  }
  if (o.service !== undefined) {
    out.push(node(boxes.service, o.service, "outside every agent", "focus", undefined));
  }
  if (o.wallet !== undefined) {
    out.push(pill(boxes.wallet.x, boxes.wallet.y, `Wallet ${o.wallet}`, PALETTE.warn));
  }
  for (const e of o.extra ?? []) {
    out.push(curvedArrow(boxes[e.from], boxes[e.to], e.style, e.label));
  }
  if (o.caption !== undefined) {
    out.push(`<text x="${W / 2}" y="${height - 8}" font-size="12" text-anchor="middle" fill="var(--text-muted)">${esc(o.caption)}</text>`);
  }
  return `<svg class="lab-diagram" viewBox="0 0 ${W} ${height}" role="img" aria-label="${esc(o.caption ?? "The six agents")}" xmlns="http://www.w3.org/2000/svg">${out.join("")}</svg>`;
}

export interface ChainRow {
  readonly who: string;
  readonly scope: string;
  readonly tag?: "root" | "written" | "you" | "terminal" | "blocked";
  /** Text on the arrow leading into this row. */
  readonly hop?: string;
}

/** A vertical warrant chain: who holds what, hop by hop. */
export function chainDiagram(rows: readonly ChainRow[], caption?: string): string {
  const rowH = 46;
  const gap = 34;
  const x = 30;
  const w = W - 60;
  const out: string[] = [];
  rows.forEach((r, i) => {
    const y = 12 + i * (rowH + gap);
    const color = r.tag === "you" ? PALETTE.focus : r.tag === "blocked" ? PALETTE.rogue : r.tag === "terminal" ? PALETTE.warn : "var(--border)";
    if (i > 0) {
      const prevBottom = y - gap;
      const style: EdgeStyle = r.tag === "blocked" ? "blocked" : r.tag === "terminal" ? "terminal" : r.tag === "you" ? "you" : "normal";
      out.push(arrow([[x + 90, prevBottom], [x + 90, y - 2]], style, r.hop));
    }
    out.push(`<rect x="${x}" y="${y}" width="${w}" height="${rowH}" rx="8" fill="var(--surface-2)" stroke="${color}" stroke-width="${r.tag === undefined || r.tag === "written" || r.tag === "root" ? 1 : 2}"/>`);
    out.push(`<text x="${x + 14}" y="${y + 29}" font-size="13" font-weight="600" fill="var(--text)">${esc(r.who)}</text>`);
    const room = r.tag === undefined ? 78 : r.tag === "root" || r.tag === "written" ? 56 : 62;
    const scope = r.scope.length > room ? `${r.scope.slice(0, room - 1).trimEnd()}…` : r.scope;
    out.push(`<text x="${x + 190}" y="${y + 29}" font-size="12.5" fill="var(--text-muted)">${esc(scope)}</text>`);
    if (r.tag !== undefined) {
      const text = r.tag === "root" ? "signed by the control plane" : r.tag === "written" ? "written for you" : r.tag === "you" ? "you write this" : r.tag === "terminal" ? "terminal" : "refused";
      const tw = text.length * 6.6 + 16;
      const fill = r.tag === "you" ? PALETTE.focus : r.tag === "blocked" ? PALETTE.rogue : r.tag === "terminal" ? PALETTE.warn : "var(--border)";
      const tf = r.tag === "written" || r.tag === "root" ? "var(--text-muted)" : "#0a0a0a";
      out.push(`<rect x="${x + w - tw - 10}" y="${y + 14}" width="${tw}" height="18" rx="9" fill="${fill}"/>`);
      out.push(`<text x="${x + w - tw / 2 - 10}" y="${y + 27}" font-size="10.5" font-weight="700" text-anchor="middle" fill="${tf}">${esc(text)}</text>`);
    }
  });
  const height = 12 + rows.length * (rowH + gap) - gap + 12 + (caption !== undefined ? 24 : 0);
  if (caption !== undefined) {
    out.push(`<text x="${W / 2}" y="${height - 8}" font-size="12" text-anchor="middle" fill="var(--text-muted)">${esc(caption)}</text>`);
  }
  return `<svg class="lab-diagram" viewBox="0 0 ${W} ${height}" role="img" aria-label="${esc(caption ?? "The warrant chain")}" xmlns="http://www.w3.org/2000/svg">${out.join("")}</svg>`;
}
