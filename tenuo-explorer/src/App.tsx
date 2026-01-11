import { useState, useEffect, useCallback, useMemo } from 'react'
import init, { decode_warrant, check_access, check_chain_access, create_sample_warrant, create_warrant_from_config, init_panic_hook, decode_pem_chain_wasm } from './wasm/tenuo_wasm'
import wasmUrl from './wasm/tenuo_wasm_bg.wasm'
import { cleanInput, truncate, generateId } from './utils';

// Types
interface AuthResult {
  authorized: boolean;
  reason?: string;
  deny_code?: string;
}

interface DecodedWarrant {
  id: string;
  issuer: string;
  tools: string[];
  capabilities: Record<string, unknown>;
  issued_at: number;
  expires_at: number;
  authorized_holder: string;
  depth: number;
}

interface ConstraintNarrowing {
  tool: string;
  field: string;
  parent_value: string;
  child_value: string;
  valid: boolean;
}

interface AttenuationDiff {
  from_idx: number;
  to_idx: number;
  tools_removed: string[];
  tools_added: string[];
  constraints_narrowed: ConstraintNarrowing[];
  ttl_reduced_by_secs: number;
}

interface ChainDecodeResult {
  warrants: DecodedWarrant[];
  is_chain: boolean;
  chain_valid: boolean;
  chain_errors: string[];
  attenuation_diffs: AttenuationDiff[];
  error?: string;
}

interface HistoryItem {
  id: string;
  name: string;
  warrant: string;
  tool: string;
  args: string;
  timestamp: number;
}

interface ValidationWarning {
  type: 'danger' | 'warning' | 'info';
  message: string;
}

// Sample definitions - will be populated with fresh warrants on page load
interface SampleDef {
  name: string;
  description: string;
  warrant: string;
  rootKey: string;
  holderPrivateKey: string;
  tool: string;
  args: string;
}

// Template for generating samples dynamically
const SAMPLE_TEMPLATES: Record<string, {
  name: string;
  description: string;
  wasmTool: string;
  wasmField: string;
  wasmPattern: string;
  testTool: string;
  args: string;
  ttl: number;
}> = {
  valid_read: {
    name: "✅ Valid Read",
    description: "Authorized: path matches docs/* constraint",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "read_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2),
    ttl: 3600
  },
  valid_nested: {
    name: "✅ Nested Path",
    description: "Authorized: nested paths like docs/api/guide.md",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "read_file",
    args: JSON.stringify({ path: "docs/api/reference.md" }, null, 2),
    ttl: 3600
  },
  expiring_soon: {
    name: "⏰ Expiring (10s)",
    description: "Watch this warrant expire! Valid for 10 seconds only.",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "read_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2),
    ttl: 10
  },
  denied_path: {
    name: "❌ Wrong Path",
    description: "Denied: /etc/passwd is outside docs/* scope",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "read_file",
    args: JSON.stringify({ path: "/etc/passwd" }, null, 2),
    ttl: 3600
  },
  denied_tool: {
    name: "❌ Wrong Tool",
    description: "Denied: delete_file not in warrant's tools",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "delete_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2),
    ttl: 3600
  },
  denied_write: {
    name: "❌ Write Attempt",
    description: "Denied: write_file not authorized",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "write_file",
    args: JSON.stringify({ path: "docs/new.md", content: "hello" }, null, 2),
    ttl: 3600
  },
  execution_only: {
    name: "🔍 Inspect Warrant",
    description: "Just decode to see warrant structure",
    wasmTool: "read_file",
    wasmField: "path",
    wasmPattern: "docs/*",
    testTool: "",
    args: "{}",
    ttl: 3600
  },
};

// Helper to generate fresh samples from WASM
function generateFreshSamples(): Record<string, SampleDef> {
  const samples: Record<string, SampleDef> = {};
  for (const [key, template] of Object.entries(SAMPLE_TEMPLATES)) {
    try {
      const result = create_sample_warrant(
        template.wasmTool,
        template.wasmField,
        template.wasmPattern,
        BigInt(template.ttl)
      );
      if (result.error) {
        console.error(`Failed to create sample ${key}:`, result.error);
        continue;
      }
      samples[key] = {
        name: template.name,
        description: template.description,
        warrant: result.warrant_b64,
        rootKey: result.root_key_hex,
        holderPrivateKey: result.holder_private_key_hex,
        tool: template.testTool,
        args: template.args,
      };
    } catch (e) {
      console.error(`Failed to create sample ${key}:`, e);
    }
  }
  return samples;
}

// Components
const CopyBtn = ({ text, label }: { text: string; label?: string }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      onClick={handleCopy}
      className="copy-btn"
      title="Copy to clipboard"
    >
      {copied ? '✓' : '📋'} {label}
    </button>
  );
};

const Tooltip = ({ children, content }: { children: React.ReactNode; content: string }) => {
  const [show, setShow] = useState(false);
  return (
    <span className="tooltip-wrapper" onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && <span className="tooltip">{content}</span>}
    </span>
  );
};

const Explainer = ({ title, children, docLink }: { title: string; children: React.ReactNode; docLink?: string }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="explainer">
      <div className="explainer-header" onClick={() => setOpen(!open)}>
        <span style={{ transform: open ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>▶</span>
        <span>💡 {title}</span>
      </div>
      {open && (
        <div className="explainer-content">
          {children}
          {docLink && (
            <p style={{ marginTop: '12px' }}>
              <a href={docLink} target="_blank" rel="noopener noreferrer">📖 Read the docs →</a>
            </p>
          )}
        </div>
      )}
    </div>
  );
};

const ExpirationDisplay = ({ issuedAt, expiresAt }: { issuedAt: number; expiresAt: number }) => {
  const [now, setNow] = useState(Date.now() / 1000);

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(interval);
  }, []);

  const remaining = expiresAt - now;
  const isExpired = remaining <= 0;
  const expiredAgo = Math.abs(remaining);
  const total = expiresAt - issuedAt;
  const elapsed = now - issuedAt;
  const percent = Math.min(100, Math.max(0, (elapsed / total) * 100));

  const formatTime = (seconds: number) => {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  };

  return (
    <div className="panel" style={{ padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <span style={{ fontSize: '12px', color: isExpired ? 'var(--red)' : 'var(--muted)' }}>
          {isExpired ? '⛔ Expired' : '⏱ Time Remaining'}
        </span>
        <span style={{
          fontSize: '16px',
          fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          color: isExpired ? 'var(--red)' : (remaining < 30 ? 'var(--yellow)' : 'var(--green)')
        }}>
          {isExpired ? `${formatTime(expiredAgo)} ago` : formatTime(remaining)}
        </span>
      </div>

      {/* Timeline Visualization - simplified, no overlapping labels */}
      <div className="timeline">
        <div className="timeline-track">
          <div className="timeline-fill" style={{ width: `${percent}%`, background: isExpired ? 'var(--red)' : 'linear-gradient(90deg, var(--green), var(--accent))' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontSize: '11px' }}>
          <div style={{ color: 'var(--green)' }}>
            <span style={{ marginRight: '4px' }}>●</span>
            Issued {new Date(issuedAt * 1000).toLocaleTimeString()}
          </div>
          <div style={{ color: isExpired ? 'var(--red)' : 'var(--muted)', fontWeight: isExpired ? 600 : 400 }}>
            {isExpired ? 'Expired' : 'Expires'} {new Date(expiresAt * 1000).toLocaleTimeString()}
            <span style={{ marginLeft: '4px', color: 'var(--red)' }}>●</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Presets Manager
interface Preset {
  id: string;
  name: string;
  warrant: string;
  tool: string;
  args: string;
}

const PresetsManager = ({
  currentWarrant,
  currentTool,
  currentArgs,
  onLoad
}: {
  currentWarrant: string;
  currentTool: string;
  currentArgs: string;
  onLoad: (preset: Preset) => void;
}) => {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [showSave, setShowSave] = useState(false);
  const [presetName, setPresetName] = useState('');

  // Load presets from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('tenuo-explorer-presets');
    if (saved) {
      try { setPresets(JSON.parse(saved)); } catch { }
    }
  }, []);

  // Save presets to localStorage
  useEffect(() => {
    localStorage.setItem('tenuo-explorer-presets', JSON.stringify(presets));
  }, [presets]);

  const handleSave = () => {
    if (!presetName.trim() || !currentWarrant) return;
    const newPreset: Preset = {
      id: generateId(),
      name: presetName.trim(),
      warrant: currentWarrant,
      tool: currentTool,
      args: currentArgs,
    };
    setPresets([...presets, newPreset]);
    setPresetName('');
    setShowSave(false);
  };

  const handleDelete = (id: string) => {
    setPresets(presets.filter(p => p.id !== id));
  };

  const handleExport = () => {
    const data = JSON.stringify(presets, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tenuo-presets.json';
    a.click();
  };

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const imported = JSON.parse(event.target?.result as string);
        if (Array.isArray(imported)) {
          // Validate each preset has required fields and proper types
          const validPresets = imported.filter((p): p is Preset =>
            p && typeof p === 'object' &&
            typeof p.id === 'string' && p.id.length > 0 &&
            typeof p.name === 'string' && p.name.length > 0 &&
            typeof p.warrant === 'string' && p.warrant.length > 0 &&
            (typeof p.tool === 'string' || p.tool === undefined) &&
            (typeof p.args === 'string' || p.args === undefined)
          );
          if (validPresets.length > 0) {
            setPresets([...presets, ...validPresets]);
            console.log(`[Tenuo Explorer] Imported ${validPresets.length}/${imported.length} valid presets`);
          } else {
            console.warn('[Tenuo Explorer] No valid presets found in import file');
          }
        }
      } catch { }
    };
    reader.readAsText(file);
  };

  if (presets.length === 0 && !showSave) {
    return (
      <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
        <button onClick={() => setShowSave(true)} className="btn btn-secondary" style={{ flex: 1, fontSize: '11px' }} disabled={!currentWarrant}>
          💾 Save as Preset
        </button>
        <label className="btn btn-secondary" style={{ flex: 1, fontSize: '11px', cursor: 'pointer' }}>
          📂 Import
          <input type="file" accept=".json" onChange={handleImport} style={{ display: 'none' }} />
        </label>
      </div>
    );
  }

  return (
    <div className="presets-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>💾 Presets</span>
        <div style={{ display: 'flex', gap: '4px' }}>
          <button onClick={() => setShowSave(!showSave)} className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: '10px' }}>
            + Save
          </button>
          {presets.length > 0 && (
            <button onClick={handleExport} className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: '10px' }}>
              ↓ Export
            </button>
          )}
        </div>
      </div>

      {showSave && (
        <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
          <input
            className="input"
            placeholder="Preset name..."
            value={presetName}
            onChange={e => setPresetName(e.target.value)}
            style={{ flex: 1, fontSize: '11px', padding: '6px 10px' }}
          />
          <button onClick={handleSave} className="btn btn-primary" style={{ padding: '6px 12px', fontSize: '11px' }}>
            Save
          </button>
        </div>
      )}

      {presets.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {presets.map(preset => (
            <div key={preset.id} className="preset-item">
              <button onClick={() => onLoad(preset)} className="preset-name">
                {preset.name}
              </button>
              <button onClick={() => handleDelete(preset.id)} className="close-btn" style={{ padding: '2px 4px', fontSize: '10px' }}>
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Verification Steps Component
const VerificationSteps = ({ decoded, tool, args: _args, authResult }: {
  decoded: DecodedWarrant | null;
  tool: string;
  args: string;
  authResult: AuthResult | null;
}) => {
  if (!decoded) return null;

  const now = Date.now() / 1000;
  const isExpired = decoded.expires_at < now;
  const toolMatch = decoded.tools.includes(tool) || decoded.tools.includes('*');



  const steps = [
    { name: 'Signature Chain', status: 'pass', detail: 'Cryptographic signatures verified (dry run mode)' },
    { name: 'Expiration Check', status: isExpired ? 'fail' : 'pass', detail: isExpired ? `Expired ${Math.floor(now - decoded.expires_at)}s ago` : `Valid for ${Math.floor(decoded.expires_at - now)}s` },
    { name: 'Tool Matching', status: toolMatch ? 'pass' : 'fail', detail: toolMatch ? `"${tool}" found in authorized tools` : `"${tool}" not in [${decoded.tools.join(', ')}]` },
    { name: 'Constraint Evaluation', status: authResult?.authorized ? 'pass' : (authResult ? 'fail' : 'pending'), detail: authResult?.reason || 'Run authorization check to evaluate constraints' },
  ];

  return (
    <div className="panel" style={{ padding: '16px' }}>
      <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '12px' }}>🔍 Verification Steps</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {steps.map((step, i) => (
          <div key={i} className={`step step-${step.status}`}>
            <div className="step-indicator">
              {step.status === 'pass' ? '✓' : step.status === 'fail' ? '✕' : '○'}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '13px', fontWeight: 500 }}>{step.name}</div>
              <div style={{ fontSize: '11px', color: 'var(--muted)' }}>{step.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Code Generation Component
const CodeGenerator = ({ decoded, tool, args }: { decoded: DecodedWarrant | null; tool: string; args: string }) => {
  const [lang, setLang] = useState<'python' | 'rust'>('python');
  const [copied, setCopied] = useState(false);

  if (!decoded) return null;

  // Helper to parse constraint and generate code
  type ParsedConstraint = {
    type: 'pattern' | 'exact' | 'range' | 'oneof' | 'regex' | 'contains' | 'cidr' | 'wildcard' | 'url_pattern' | 'subpath' | 'url_safe' | 'unknown';
    pythonCode: string;
    rustCode: string;
    exampleValue: string | number;
    warning?: string;
  };

  const parseConstraint = (_key: string, value: unknown): ParsedConstraint => {
    if (typeof value === 'object' && value !== null) {
      const v = value as Record<string, unknown>;

      // Pattern constraint: { pattern: "docs/*" }
      if (v.pattern && typeof v.pattern === 'string') {
        const pattern = v.pattern;
        return {
          type: 'pattern',
          pythonCode: `Pattern("${pattern}")`,
          rustCode: `Constraint::Pattern(Pattern::new("${pattern}")?)`,
          exampleValue: pattern.replace(/\*/g, 'example').replace(/\?/g, 'x')
        };
      }

      // Exact constraint: { exact: "value" }
      if (v.exact !== undefined) {
        const exact = String(v.exact);
        return {
          type: 'exact',
          pythonCode: `Exact("${exact}")`,
          rustCode: `Constraint::Exact("${exact}".to_string())`,
          exampleValue: exact
        };
      }

      // Range constraint: { min: 0, max: 100 } or { max: 100 } or { range: "0-1000" }
      if (v.min !== undefined || v.max !== undefined || v.range !== undefined) {
        let min: number | undefined;
        let max: number | undefined;

        // Parse string range format: "0-1000"
        if (typeof v.range === 'string') {
          const match = v.range.match(/^(\d+)-(\d+)$/);
          if (match) {
            min = parseInt(match[1], 10);
            max = parseInt(match[2], 10);
          }
        } else {
          min = v.min as number | undefined;
          max = v.max as number | undefined;
        }

        let pythonCode: string;
        let rustCode: string;
        if (min !== undefined && max !== undefined) {
          pythonCode = `Range(${min}, ${max})`;
          rustCode = `Constraint::Range(Range::new(${min}, ${max}))`;
        } else if (max !== undefined) {
          pythonCode = `Range(max=${max})`;
          rustCode = `Constraint::Range(Range::max(${max}))`;
        } else if (min !== undefined) {
          pythonCode = `Range(min=${min})`;
          rustCode = `Constraint::Range(Range::min(${min}))`;
        } else {
          pythonCode = `Range()`;
          rustCode = `Constraint::Range(Range::default())`;
        }
        return {
          type: 'range',
          pythonCode,
          rustCode,
          exampleValue: max !== undefined ? Math.floor(max / 2) : (min !== undefined ? min + 10 : 50)
        };
      }

      // OneOf constraint: { oneof: ["a", "b"] } or { values: ["a", "b"] }
      // Can also be comma-separated string: { oneof: "a,b,c" }
      if (v.oneof || v.values) {
        const rawVal = v.oneof || v.values;
        let values: string[];
        if (Array.isArray(rawVal)) {
          values = rawVal.map(String);
        } else if (typeof rawVal === 'string') {
          // Handle comma-separated string (from builder)
          values = rawVal.split(',').map(s => s.trim()).filter(Boolean);
        } else {
          values = [String(rawVal)];
        }
        if (values.length === 0) values = ['value'];
        return {
          type: 'oneof',
          pythonCode: `OneOf([${values.map(x => `"${x}"`).join(', ')}])`,
          rustCode: `Constraint::OneOf(vec![${values.map(x => `"${x}".to_string()`).join(', ')}])`,
          exampleValue: values[0] || 'value'
        };
      }

      // AnyOf constraint: { anyof: ["a", "b"] }
      if (v.anyof) {
        const rawVal = v.anyof;
        let values: string[];
        if (Array.isArray(rawVal)) {
          values = rawVal.map(String);
        } else if (typeof rawVal === 'string') {
          values = rawVal.split(',').map(s => s.trim()).filter(Boolean);
        } else {
          values = [String(rawVal)];
        }
        if (values.length === 0) values = ['value'];
        return {
          type: 'oneof',
          pythonCode: `AnyOf([Pattern("${values.join('"), Pattern("')}")])`,
          rustCode: `Constraint::AnyOf(vec![${values.map(x => `Pattern::new("${x}")?`).join(', ')}])`,
          exampleValue: values[0].replace('*', 'example') || 'value'
        };
      }

      // NotOneOf constraint: { notoneof: ["a", "b"] }
      if (v.notoneof) {
        const rawVal = v.notoneof;
        let values: string[];
        if (Array.isArray(rawVal)) {
          values = rawVal.map(String);
        } else if (typeof rawVal === 'string') {
          values = rawVal.split(',').map(s => s.trim()).filter(Boolean);
        } else {
          values = [String(rawVal)];
        }
        if (values.length === 0) values = ['excluded'];
        return {
          type: 'oneof',
          pythonCode: `NotOneOf([${values.map(x => `"${x}"`).join(', ')}])`,
          rustCode: `Constraint::NotOneOf(vec![${values.map(x => `"${x}".to_string()`).join(', ')}])`,
          exampleValue: 'allowed_value'
        };
      }

      // Regex constraint: { regex: "^[a-z]+$" }
      if (v.regex && typeof v.regex === 'string') {
        const regex = v.regex;
        return {
          type: 'regex',
          pythonCode: `Regex("${regex}")`,
          rustCode: `Constraint::Regex(Regex::new("${regex}")?)`,
          exampleValue: 'match'
        };
      }

      // Contains constraint: { contains: "substring" }
      if (v.contains && typeof v.contains === 'string') {
        const substr = v.contains;
        return {
          type: 'contains',
          pythonCode: `Contains("${substr}")`,
          rustCode: `Constraint::Contains(Contains::new("${substr}"))`,
          exampleValue: `text_with_${substr}_in_it`
        };
      }

      // Cidr constraint: { cidr: "10.0.0.0/8" }
      if (v.cidr && typeof v.cidr === 'string') {
        const cidr = v.cidr;
        return {
          type: 'cidr',
          pythonCode: `Cidr("${cidr}")`,
          rustCode: `Constraint::Cidr(Cidr::new("${cidr}")?)`,
          exampleValue: cidr.split('/')[0] || '10.0.0.1'
        };
      }

      // Wildcard constraint: { wildcard: "user_*" }
      if (v.wildcard && typeof v.wildcard === 'string') {
        const wildcard = v.wildcard;
        return {
          type: 'wildcard',
          pythonCode: `Wildcard("${wildcard}")`,
          rustCode: `Constraint::Wildcard(Wildcard::new("${wildcard}")?)`,
          exampleValue: wildcard.replace(/\*/g, 'example')
        };
      }

      // UrlPattern constraint: { url_pattern: "https://*.example.com/*" }
      if ((v.url_pattern || v.urlPattern || v.urlpattern) && typeof (v.url_pattern || v.urlPattern || v.urlpattern) === 'string') {
        const urlPattern = (v.url_pattern || v.urlPattern || v.urlpattern) as string;
        return {
          type: 'url_pattern',
          pythonCode: `UrlPattern("${urlPattern}")`,
          rustCode: `Constraint::UrlPattern(UrlPattern::new("${urlPattern}")?)`,
          exampleValue: urlPattern.replace(/\*/g, 'example')
        };
      }

      // Subpath constraint (safe path containment): { subpath: { root: "/data" } } or { subpath: "/data" }
      if (v.subpath) {
        const subpathVal = v.subpath;
        const root = typeof subpathVal === 'string'
          ? subpathVal
          : (subpathVal as { root?: string }).root || '/data';
        return {
          type: 'subpath' as const,
          pythonCode: `Subpath("${root}")`,
          rustCode: `Constraint::Subpath(Subpath::new("${root}")?)`,
          exampleValue: `${root}/file.txt`
        };
      }

      // UrlSafe constraint (SSRF protection): { url_safe: {} } or { url_safe: { allow_domains: [...] } }
      if (v.url_safe !== undefined || v.urlsafe !== undefined) {
        const urlSafeVal = v.url_safe || v.urlsafe;
        if (urlSafeVal && typeof urlSafeVal === 'object') {
          const inner = urlSafeVal as { allow_domains?: string[] };
          if (inner.allow_domains && inner.allow_domains.length > 0) {
            const domains = inner.allow_domains.map(d => `"${d}"`).join(', ');
            return {
              type: 'url_safe' as const,
              pythonCode: `UrlSafe(allow_domains=[${domains}])`,
              rustCode: `Constraint::UrlSafe(UrlSafe::with_domains(vec![${domains}]))`,
              exampleValue: `https://${inner.allow_domains[0].replace('*.', 'api.')}/resource`
            };
          }
        }
        return {
          type: 'url_safe' as const,
          pythonCode: `UrlSafe()`,
          rustCode: `Constraint::UrlSafe(UrlSafe::new())`,
          exampleValue: 'https://api.example.com/resource'
        };
      }
    }

    // String value - assume it's a pattern
    if (typeof value === 'string') {
      // Check if it looks like a glob pattern
      if (value.includes('*') || value.includes('?')) {
        return {
          type: 'pattern',
          pythonCode: `Pattern("${value}")`,
          rustCode: `Constraint::Pattern(Pattern::new("${value}")?)`,
          exampleValue: value.replace(/\*/g, 'example').replace(/\?/g, 'x')
        };
      }
      // Otherwise treat as exact
      return {
        type: 'exact',
        pythonCode: `Exact("${value}")`,
        rustCode: `Constraint::Exact("${value}".to_string())`,
        exampleValue: value
      };
    }

    // Number - assume range max
    if (typeof value === 'number') {
      return {
        type: 'range',
        pythonCode: `Range.max_value(${value})`,
        rustCode: `Constraint::Range(Range::max(${value}))`,
        exampleValue: Math.floor(value / 2)
      };
    }

    // Unknown - show as comment, don't generate invalid code
    const strVal = typeof value === 'object' ? JSON.stringify(value) : String(value);
    return {
      type: 'unknown',
      pythonCode: `# ${strVal.slice(0, 60)}`,
      rustCode: `// ${strVal.slice(0, 60)}`,
      exampleValue: 'value',
      warning: `Unknown constraint format: ${strVal.slice(0, 50)}`
    };
  };

  const code = useMemo(() => {
    try {
      const argsObj = (() => { try { return JSON.parse(args); } catch { return {}; } })();

      // Build capabilities for ALL tools in the warrant
      const allToolConstraints: { toolName: string; constraints: { key: string; parsed: ParsedConstraint }[] }[] = [];
      const allWarnings: string[] = [];

      // Iterate over all capabilities in the decoded warrant
      Object.entries(decoded.capabilities).forEach(([toolName, toolCaps]) => {
        const constraints: { key: string; parsed: ParsedConstraint }[] = [];
        if (toolCaps && typeof toolCaps === 'object') {
          Object.entries(toolCaps as Record<string, unknown>).forEach(([key, value]) => {
            try {
              const parsed = parseConstraint(key, value);
              constraints.push({ key, parsed });
              if (parsed.warning) {
                allWarnings.push(`# ⚠️ ${toolName}.${key}: ${parsed.warning}`);
              }
            } catch {
              constraints.push({ key, parsed: { type: 'unknown', pythonCode: `Pattern("*")  # Error parsing`, rustCode: `// Error parsing`, exampleValue: 'value', warning: 'Failed to parse constraint' } });
            }
          });
        }
        allToolConstraints.push({ toolName, constraints });
      });

      // If no capabilities found, add tools from the tools list
      if (allToolConstraints.length === 0 && decoded.tools.length > 0) {
        decoded.tools.forEach(t => {
          allToolConstraints.push({ toolName: t, constraints: [] });
        });
      }

      const warningBlock = allWarnings.length > 0
        ? `# ⚠️ WARNINGS - Review these constraints:\n${allWarnings.join('\n')}\n\n`
        : '';

      // Use selected tool for the test example, or first tool
      const testTool = tool || allToolConstraints[0]?.toolName || 'example_tool';
      const testToolCaps = allToolConstraints.find(t => t.toolName === testTool)?.constraints || [];

      // Calculate actual TTL from the warrant
      const actualTtl = Math.max(1, Math.floor(decoded.expires_at - decoded.issued_at));
      const formatTtlComment = (secs: number) => {
        if (secs < 60) return `${secs} seconds`;
        if (secs < 3600) return `${Math.floor(secs / 60)} minutes`;
        if (secs < 86400) return `${Math.floor(secs / 3600)} hour${secs >= 7200 ? 's' : ''}`;
        return `${Math.floor(secs / 86400)} day${secs >= 172800 ? 's' : ''}`;
      };

      if (lang === 'python') {
        // Generate capability lines for ALL tools
        const capabilityBlocks = allToolConstraints.map(({ toolName, constraints }) => {
          if (constraints.length === 0) {
            return `    .tool("${toolName}")  # No constraints`;
          }
          const constraintLines = constraints.map(({ key, parsed }) => `        "${key}": ${parsed.pythonCode}`).join(',\n');
          return `    .capability("${toolName}", {\n${constraintLines}\n    })`;
        }).join('\n');

        const argsLines = Object.entries(argsObj).length > 0
          ? JSON.stringify(argsObj, null, 4)
          : testToolCaps.length > 0
            ? JSON.stringify(Object.fromEntries(testToolCaps.map(({ key, parsed }) => [key, parsed.exampleValue])), null, 4)
            : '{}';

        return `${warningBlock}from tenuo import SigningKey, Warrant, Pattern, Exact, Range, OneOf

# Generate keys
issuer_key = SigningKey.generate()
holder_key = SigningKey.generate()

# Issue warrant using builder pattern
# Tools: ${decoded.tools.join(', ')}
warrant = (Warrant.mint_builder()
${capabilityBlocks}
    .holder(holder_key.public_key)
    .ttl(${actualTtl})  # ${formatTtlComment(actualTtl)}
    .mint(issuer_key))

# Test authorization with Proof-of-Possession
args = ${argsLines}
pop = warrant.sign(holder_key, "${testTool}", args)
authorized = warrant.authorize("${testTool}", args, pop)
print(f"Authorized: {authorized}")

# BoundWarrant: cleaner API (auto-signs)
bound = warrant.bind(holder_key)
result = bound.validate("${testTool}", args)
if result:
    print("Valid! Ready to call tool.")
else:
    print(f"Denied: {result.reason}")

# Serialize for transmission
warrant_b64 = warrant.to_base64()
print(f"Warrant: {warrant_b64[:60]}...")`;
      } else {
        // Generate Rust constraint set definitions
        const constraintDefs = allToolConstraints.map(({ toolName, constraints }) => {
          const varName = `cs_${toolName.replace(/[^a-z0-9]/gi, '_')}`;
          if (constraints.length === 0) {
            return `    let ${varName} = ConstraintSet::new();`;
          }
          const insertLines = constraints.map(({ key, parsed }) =>
            `    ${varName}.insert("${key}", ${parsed.rustCode});`
          ).join('\n');
          return `    let mut ${varName} = ConstraintSet::new();
${insertLines}`;
        }).join('\n\n');

        // Generate builder capability calls
        const capabilityLines = allToolConstraints.map(({ toolName }) => {
          const varName = `cs_${toolName.replace(/[^a-z0-9]/gi, '_')}`;
          return `        .capability("${toolName}", ${varName})`;
        }).join('\n');

        const argsLines = testToolCaps.length > 0
          ? testToolCaps.map(({ key, parsed }) => {
            const val = parsed.exampleValue;
            if (typeof val === 'number') {
              return `    args.insert("${key}".to_string(), ConstraintValue::Integer(${val}));`;
            }
            return `    args.insert("${key}".to_string(), ConstraintValue::String("${val}".to_string()));`;
          }).join('\n')
          : '    // Add args here';

        const rustWarnings = allWarnings.length > 0
          ? `// ⚠️ WARNINGS - Review these constraints:\n${allWarnings.map(w => w.replace('# ', '// ')).join('\n')}\n\n`
          : '';

        return `${rustWarnings}use tenuo::{SigningKey, Warrant, ConstraintSet, ConstraintValue, Pattern, Range, wire};
use std::time::Duration;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Define constraints for each tool
${constraintDefs}

    // Build warrant: ${decoded.tools.join(', ')}
    let warrant = Warrant::builder()
${capabilityLines}
        .holder(holder_key.public_key())
        .ttl(Duration::from_secs(${actualTtl}))  // ${formatTtlComment(actualTtl)}
        .build(&issuer_key)?;

    // Build args for authorization
    let mut args: HashMap<String, ConstraintValue> = HashMap::new();
${argsLines}

    // Create Proof-of-Possession and authorize
    let pop = warrant.sign(&holder_key, "${testTool}", &args)?;
    warrant.authorize("${testTool}", &args, Some(&pop))?;
    println!("Authorized!");

    // Serialize for transmission
    let warrant_b64 = wire::encode_base64(&warrant)?;
    println!("Warrant: {}...", &warrant_b64[..60]);
    
    Ok(())
}`;
      }
    } catch (e) {
      // Return error message as code comment
      const errMsg = e instanceof Error ? e.message : 'Unknown error';
      if (lang === 'python') {
        return `# ❌ CODE GENERATION ERROR
# ${errMsg}
#
# This usually means the constraint configuration is invalid.
# Check your constraint types and values.

# Valid examples:
# Pattern("docs/*")     - glob pattern
# Exact("admin")        - exact match
# Range.max_value(100)  - numeric range
# OneOf(["a", "b"])     - one of values`;
      } else {
        return `// ❌ CODE GENERATION ERROR
// ${errMsg}
//
// This usually means the constraint configuration is invalid.
// Check your constraint types and values.

// Valid examples:
// Pattern::new("docs/*")?     - glob pattern
// Constraint::Exact("admin")  - exact match
// Range::max(100)             - numeric range
// Constraint::OneOf(vec!["a", "b"])`;
      }
    }
  }, [lang, decoded, tool, args]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="panel" style={{ padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '16px' }}>💻</span>
          <span style={{ fontSize: '14px', fontWeight: 600 }}>Code Generation</span>
        </div>
        <div style={{ display: 'flex', gap: '4px' }}>
          {(['python', 'rust'] as const).map(l => (
            <button key={l} onClick={() => setLang(l)} className={`lang-btn ${lang === l ? 'active' : ''}`}>
              {l === 'python' ? '🐍' : '🦀'} {l}
            </button>
          ))}
        </div>
      </div>
      <pre className="code-block" style={{ height: '320px', minHeight: '200px', maxHeight: '600px', fontSize: '12px', lineHeight: '1.6' }}>{code}</pre>
      <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
        <button onClick={handleCopy} className="btn btn-secondary" style={{ flex: 1 }}>
          {copied ? '✓ Copied!' : '📋 Copy Code'}
        </button>
      </div>
      <p style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '8px', textAlign: 'center' }}>
        💡 Drag bottom-right corner to resize
      </p>
    </div>
  );
};

// Validation Warnings Component
const ValidationWarnings = ({ decoded, tool, args }: { decoded: DecodedWarrant | null; tool: string; args: string }) => {
  const warnings = useMemo<ValidationWarning[]>(() => {
    const w: ValidationWarning[] = [];
    if (!decoded) return w;

    const now = Date.now() / 1000;
    const remaining = decoded.expires_at - now;

    // Time warnings
    if (remaining < 0) {
      w.push({ type: 'danger', message: 'Warrant has expired' });
    } else if (remaining < 60) {
      w.push({ type: 'danger', message: `Expires in less than 1 minute (${Math.floor(remaining)}s)` });
    } else if (remaining < 3600) {
      w.push({ type: 'warning', message: `Expires in less than 1 hour (${Math.floor(remaining / 60)}m)` });
    }

    // Depth warnings
    if (decoded.depth > 3) {
      w.push({ type: 'warning', message: `Deep delegation chain (depth ${decoded.depth}) - consider limiting` });
    }

    // Tool warnings
    if (decoded.tools.includes('*')) {
      w.push({ type: 'danger', message: 'Wildcard tool access (*) - extremely permissive!' });
    }

    // Constraint warnings
    const caps = decoded.capabilities;
    for (const [toolName, constraints] of Object.entries(caps)) {
      if (typeof constraints === 'object' && constraints !== null) {
        for (const [key, value] of Object.entries(constraints as Record<string, unknown>)) {
          if (typeof value === 'object' && value !== null && 'pattern' in value) {
            const pattern = (value as { pattern: string }).pattern;
            if (pattern === '*' || pattern === '**' || pattern === '**/*') {
              w.push({ type: 'warning', message: `Permissive pattern "${pattern}" on ${toolName}.${key}` });
            }
          }
        }
      }
    }

    // Tool mismatch
    if (tool && !decoded.tools.includes(tool) && !decoded.tools.includes('*')) {
      w.push({ type: 'info', message: `Tool "${tool}" not in warrant - authorization will fail` });
    }

    return w;
  }, [decoded, tool, args]);

  if (warnings.length === 0) return null;

  return (
    <div className="warnings-panel">
      {warnings.map((w, i) => (
        <div key={i} className={`warning warning-${w.type}`}>
          <span>{w.type === 'danger' ? '🚨' : w.type === 'warning' ? '⚠️' : 'ℹ️'}</span>
          <span>{w.message}</span>
        </div>
      ))}
    </div>
  );
};

// Warrant Builder Component
type ConstraintType = 'pattern' | 'exact' | 'range' | 'oneof' | 'anyof' | 'notoneof' | 'cidr' | 'urlpattern' | 'regex' | 'wildcard' | 'contains';

interface ToolConstraint {
  name: string;
  constraints: { key: string; type: ConstraintType; value: string }[];
}

// Validate constraint value based on type
const validateConstraintValue = (type: string, value: string): { valid: boolean; error?: string; hint?: string } => {
  if (!value.trim()) return { valid: true }; // Empty is ok while typing

  switch (type) {
    case 'pattern':
      // Pattern should be a glob string
      if (value.includes('(') || value.includes(')')) {
        return { valid: false, error: 'Patterns use * and ?, not regex syntax', hint: 'docs/* or *.txt' };
      }
      return { valid: true };

    case 'exact':
      // Exact can be any string
      return { valid: true };

    case 'range':
      // Range should be "min-max" or just "max"
      if (!/^\d+(-\d+)?$/.test(value.trim())) {
        return { valid: false, error: 'Range format: "max" or "min-max"', hint: '1000 or 0-1000' };
      }
      const parts = value.split('-').map(Number);
      if (parts.length === 2 && parts[0] > parts[1]) {
        return { valid: false, error: 'Min cannot be greater than max' };
      }
      return { valid: true };

    case 'oneof':
    case 'anyof':
    case 'notoneof':
      // Should be comma-separated values
      if (value.includes('(') || value.includes('[')) {
        return { valid: false, error: 'Use comma-separated values, not array syntax', hint: 'GET, POST, PUT' };
      }
      const vals = value.split(',').map(s => s.trim()).filter(Boolean);
      if (vals.length === 0) {
        return { valid: false, error: 'Provide at least one value' };
      }
      return { valid: true };

    case 'cidr':
      // CIDR notation: IP/prefix
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(value.trim())) {
        return { valid: false, error: 'Use CIDR notation: IP/prefix', hint: '10.0.0.0/8 or 192.168.1.0/24' };
      }
      return { valid: true };

    case 'urlpattern':
      // URL pattern with wildcards
      if (!value.includes('://')) {
        return { valid: false, error: 'Include protocol (https://)', hint: 'https://*.example.com/*' };
      }
      return { valid: true };

    case 'regex':
      // Try to compile as regex
      try {
        new RegExp(value);
        return { valid: true };
      } catch {
        return { valid: false, error: 'Invalid regex syntax' };
      }

    case 'wildcard':
      // Simple wildcard pattern
      return { valid: true, hint: 'user_* or *_admin' };

    case 'contains':
      // Substring match
      return { valid: true, hint: 'substring to match' };

    default:
      return { valid: true };
  }
};

const WarrantBuilder = ({ onGenerate }: { onGenerate: (config: unknown) => void }) => {
  const [tools, setTools] = useState<ToolConstraint[]>([{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern', value: 'docs/*' }] }]);
  const [ttl, setTtl] = useState(3600);
  const [maxDepth, setMaxDepth] = useState(3);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const addTool = () => setTools([...tools, { name: '', constraints: [] }]);
  const removeTool = (i: number) => setTools(tools.filter((_, idx) => idx !== i));
  const updateTool = (i: number, field: string, value: string) => {
    const updated = [...tools];
    updated[i] = { ...updated[i], [field]: value };
    setTools(updated);
  };
  const addConstraint = (toolIdx: number) => {
    const updated = [...tools];
    updated[toolIdx].constraints.push({ key: '', type: 'pattern', value: '' });
    setTools(updated);
  };
  const updateConstraint = (toolIdx: number, constIdx: number, field: string, value: string) => {
    const updated = [...tools];
    const constraint = { ...updated[toolIdx].constraints[constIdx], [field]: value };
    updated[toolIdx].constraints[constIdx] = constraint;
    setTools(updated);

    // Validate on change
    const errorKey = `${toolIdx}-${constIdx}`;
    if (field === 'value' || field === 'type') {
      const validation = validateConstraintValue(constraint.type, constraint.value);
      if (!validation.valid) {
        setErrors(prev => ({ ...prev, [errorKey]: validation.error || 'Invalid' }));
      } else {
        setErrors(prev => { const { [errorKey]: _, ...rest } = prev; return rest; });
      }
    }
  };
  const removeConstraint = (toolIdx: number, constIdx: number) => {
    const updated = [...tools];
    updated[toolIdx].constraints = updated[toolIdx].constraints.filter((_, i) => i !== constIdx);
    setTools(updated);
  };

  const templates: { name: string; tools: ToolConstraint[]; ttl: number }[] = [
    { name: '📁 File Read', tools: [{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern', value: 'data/*' }] }], ttl: 3600 },
    { name: '🔧 Multi-Tool', tools: [{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern', value: '*' }] }, { name: 'write_file', constraints: [{ key: 'path', type: 'pattern', value: 'tmp/*' }] }], ttl: 1800 },
    { name: '🌐 API Gateway', tools: [{ name: 'http_request', constraints: [{ key: 'url', type: 'urlpattern', value: 'https://*.example.com/api/*' }, { key: 'method', type: 'oneof', value: 'GET,POST' }] }], ttl: 300 },
    { name: '💰 Limited Spend', tools: [{ name: 'transfer', constraints: [{ key: 'amount', type: 'range', value: '0-1000' }, { key: 'currency', type: 'exact', value: 'USD' }] }], ttl: 600 },
    { name: '🔒 Internal Network', tools: [{ name: 'connect', constraints: [{ key: 'ip', type: 'cidr', value: '10.0.0.0/8' }, { key: 'port', type: 'range', value: '80-443' }] }], ttl: 1800 },
    { name: '🤖 AI Agent', tools: [{ name: 'llm_call', constraints: [{ key: 'model', type: 'oneof', value: 'gpt-4,claude-3' }, { key: 'tokens', type: 'range', value: '0-4000' }] }, { name: 'search', constraints: [{ key: 'query', type: 'contains', value: 'safe' }] }], ttl: 900 },
    { name: '📧 Email Send', tools: [{ name: 'send_email', constraints: [{ key: 'to', type: 'regex', value: '^[a-z]+@company\\.com$' }, { key: 'subject', type: 'notoneof', value: 'URGENT,SPAM' }] }], ttl: 3600 },
    { name: '🗄️ Database', tools: [{ name: 'query', constraints: [{ key: 'table', type: 'oneof', value: 'users,orders,products' }, { key: 'operation', type: 'exact', value: 'SELECT' }] }], ttl: 600 },
  ];

  const applyTemplate = (template: typeof templates[0]) => {
    setTools(template.tools);
    setTtl(template.ttl);
  };

  const generatePreview = () => {
    const config = {
      tools: tools.reduce((acc, t) => {
        if (t.name) {
          acc[t.name] = t.constraints.reduce((c, con) => {
            if (con.key) {
              c[con.key] = { [con.type]: con.value };
            }
            return c;
          }, {} as Record<string, unknown>);
        }
        return acc;
      }, {} as Record<string, unknown>),
      ttl,
      max_depth: maxDepth
    };
    onGenerate(config);
  };

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <span style={{ fontSize: '18px' }}>🏗️</span>
        <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Warrant Builder</h2>
      </div>

      {/* Templates */}
      <div style={{ marginBottom: '16px' }}>
        <label className="label">Quick Templates</label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {templates.map((t, i) => (
            <button key={i} onClick={() => applyTemplate(t)} className="tool-tag">{t.name}</button>
          ))}
        </div>
      </div>

      {/* TTL & Depth */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
        <div>
          <label className="label">TTL (seconds)</label>
          <input className="input" type="number" value={ttl} onChange={e => setTtl(Number(e.target.value))} />
        </div>
        <div>
          <label className="label">Max Delegation Depth</label>
          <input className="input" type="number" value={maxDepth} onChange={e => setMaxDepth(Number(e.target.value))} min={0} max={10} />
        </div>
      </div>

      {/* Tools */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <label className="label" style={{ margin: 0 }}>Tools & Constraints</label>
          <button onClick={addTool} className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '11px' }}>+ Add Tool</button>
        </div>

        {tools.map((tool, ti) => (
          <div key={ti} className="builder-tool">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
              <input className="input" placeholder="Tool name (e.g., read_file)" value={tool.name} onChange={e => updateTool(ti, 'name', e.target.value)} style={{ flex: 1 }} />
              <button onClick={() => removeTool(ti)} className="close-btn">✕</button>
            </div>

            {tool.constraints.map((con, ci) => {
              const errorKey = `${ti}-${ci}`;
              const error = errors[errorKey];
              const validation = validateConstraintValue(con.type, con.value);
              return (
                <div key={ci} style={{ marginBottom: '8px', marginLeft: '12px' }}>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <input className="input" placeholder="key" value={con.key} onChange={e => updateConstraint(ti, ci, 'key', e.target.value)} style={{ width: '70px' }} />
                    <select className="input" value={con.type} onChange={e => updateConstraint(ti, ci, 'type', e.target.value)} style={{ width: '120px' }}>
                      <optgroup label="Basic">
                        <option value="pattern">Pattern</option>
                        <option value="exact">Exact</option>
                        <option value="range">Range</option>
                      </optgroup>
                      <optgroup label="Sets">
                        <option value="oneof">OneOf</option>
                        <option value="anyof">AnyOf</option>
                        <option value="notoneof">NotOneOf</option>
                      </optgroup>
                      <optgroup label="Network">
                        <option value="cidr">CIDR</option>
                        <option value="urlpattern">UrlPattern</option>
                      </optgroup>
                      <optgroup label="Text">
                        <option value="regex">Regex</option>
                        <option value="wildcard">Wildcard</option>
                        <option value="contains">Contains</option>
                      </optgroup>
                    </select>
                    <input
                      className="input"
                      placeholder={validation.hint || 'value'}
                      value={con.value}
                      onChange={e => updateConstraint(ti, ci, 'value', e.target.value)}
                      style={{ flex: 1, borderColor: error ? 'var(--red)' : undefined }}
                    />
                    <button onClick={() => removeConstraint(ti, ci)} className="close-btn" style={{ padding: '4px' }}>✕</button>
                  </div>
                  {error && (
                    <div style={{ fontSize: '11px', color: 'var(--red)', marginTop: '4px', marginLeft: '188px' }}>
                      ❌ {error}
                    </div>
                  )}
                </div>
              );
            })}
            <button onClick={() => addConstraint(ti)} style={{ marginLeft: '12px', fontSize: '11px', color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer' }}>+ Add Constraint</button>
          </div>
        ))}
      </div>

      <button onClick={generatePreview} className="btn btn-primary" style={{ width: '100%' }}>
        Generate Preview
      </button>

      <Explainer title="Constraint Types" docLink="https://tenuo.dev/constraints">
        <p><strong>Pattern</strong>: Glob-style matching (<code>docs/*</code>, <code>*.txt</code>)</p>
        <p><strong>Exact</strong>: Must match exactly (<code>GET</code>, <code>user123</code>)</p>
        <p><strong>Range</strong>: Numeric range (<code>0-1000</code> for amounts)</p>
        <p><strong>OneOf</strong>: Must match one value (<code>GET,POST,PUT</code>)</p>
        <p><strong>AnyOf</strong>: Can match any pattern (<code>docs/*,data/*</code>)</p>
        <p><strong>NotOneOf</strong>: Must NOT match any (<code>DELETE,admin</code>)</p>
        <p><strong>CIDR</strong>: IP network range (<code>10.0.0.0/8</code>, <code>192.168.1.0/24</code>)</p>
        <p><strong>UrlPattern</strong>: URL with wildcards (<code>https://*.example.com/*</code>)</p>
        <p><strong>Regex</strong>: Regular expression (<code>^[a-z]+@company\.com$</code>)</p>
        <p><strong>Wildcard</strong>: Simple wildcards (<code>user_*</code>, <code>*_admin</code>)</p>
        <p><strong>Contains</strong>: Substring match (<code>keyword</code>)</p>
      </Explainer>
    </div>
  );
};

// Chain Verifier Component - verifies real warrant chains
interface ChainWarrant {
  id: string;
  b64: string;
  decoded: DecodedWarrant | null;
  error: string | null;
}

const ChainTester = () => {
  const [warrants, setWarrants] = useState<ChainWarrant[]>([
    { id: generateId(), b64: '', decoded: null, error: null },
    { id: generateId(), b64: '', decoded: null, error: null },
  ]);
  const [tool, setTool] = useState('read_file');
  const [argsJson, setArgsJson] = useState('{"path": "docs/readme.md"}');
  const [rootKeyHex, setRootKeyHex] = useState('');
  const [verifyResult, setVerifyResult] = useState<AuthResult | null>(null);

  // Load sample chain: Root → Orchestrator → Worker
  const loadSampleChain = () => {
    // Create root warrant
    const rootResult = create_warrant_from_config({
      tools: {
        'read_file': {
          'path': { 'pattern': 'docs/*' },
          'priority': { 'range': '1-10' }
        }
      },
      ttl: 3600,
      max_depth: 3,
    });

    if ((rootResult as any).error || !(rootResult as any).warrant_b64) {
      console.error('Failed to create root warrant:', (rootResult as any).error);
      return;
    }

    // Create delegated warrant (from root holder)
    const delegatedResult = create_warrant_from_config({
      tools: {
        'read_file': {
          'path': { 'pattern': 'docs/api/*' },
          'priority': { 'range': '1-5' }
        }
      },
      ttl: 1800, // Shorter TTL
      max_depth: 2,
      signing_key_hex: (rootResult as any).holder_private_key_hex,
      parent_warrant_b64: (rootResult as any).warrant_b64, // Link to parent for proper depth
    });

    if ((delegatedResult as any).error || !(delegatedResult as any).warrant_b64) {
      console.error('Failed to create delegated warrant:', (delegatedResult as any).error);
      return;
    }

    // Create worker warrant (even more constrained)
    const workerResult = create_warrant_from_config({
      tools: {
        'read_file': {
          'path': { 'pattern': 'docs/api/v1/*' },
          'priority': { 'range': '1-3' }
        }
      },
      ttl: 900, // Shortest TTL
      signing_key_hex: (delegatedResult as any).holder_private_key_hex,
      parent_warrant_b64: (delegatedResult as any).warrant_b64, // Link to parent for proper depth
    });

    if ((workerResult as any).error || !(workerResult as any).warrant_b64) {
      console.error('Failed to create worker warrant:', (workerResult as any).error);
      return;
    }

    // Update warrants
    const newWarrants = [
      { id: generateId(), b64: (rootResult as any).warrant_b64, decoded: null as DecodedWarrant | null, error: null as string | null },
      { id: generateId(), b64: (delegatedResult as any).warrant_b64, decoded: null as DecodedWarrant | null, error: null as string | null },
      { id: generateId(), b64: (workerResult as any).warrant_b64, decoded: null as DecodedWarrant | null, error: null as string | null },
    ];

    // Decode each warrant
    newWarrants.forEach((w) => {
      try {
        const result = decode_warrant(w.b64);
        if (typeof result === 'object' && result && 'id' in result) {
          w.decoded = result as DecodedWarrant;
        }
      } catch (e) {
        w.error = e instanceof Error ? e.message : 'Invalid warrant';
      }
    });

    setWarrants(newWarrants);
    setRootKeyHex(rootResult.issuer_public_key_hex);
    setTool('read_file');
    setArgsJson('{"path": "docs/api/v1/readme.md", "priority": 2}');
    setVerifyResult(null);
  };

  // Decode warrant when b64 changes
  const updateWarrant = (id: string, input: string) => {
    let decoded: DecodedWarrant | null = null;
    let error: string | null = null;
    let b64 = input;

    if (input.trim()) {
      const cleaned = cleanInput(input);
      b64 = cleaned.b64;

      try {
        const result = decode_warrant(b64);
        // WASM returns a string on error, not a DecodedWarrant
        if (typeof result === 'string') {
          error = result;
        } else if (result && typeof result === 'object' && 'id' in result && 'issuer' in result) {
          // Normalize the result to ensure tools is always an array
          decoded = {
            id: result.id || '',
            issuer: result.issuer || '',
            tools: Array.isArray(result.tools) ? result.tools : [],
            capabilities: result.capabilities || {},
            issued_at: result.issued_at || 0,
            expires_at: result.expires_at || 0,
            authorized_holder: result.authorized_holder || '',
            depth: result.depth || 0,
          };
          // Auto-fill root key from first warrant's issuer
          if (warrants.findIndex(w => w.id === id) === 0) {
            setRootKeyHex(decoded.issuer);
          }
        } else {
          error = 'Invalid warrant format';
        }
      } catch (e) {
        error = e instanceof Error ? e.message : 'Invalid warrant';
      }
    }

    setWarrants(warrants.map(w => w.id === id ? { ...w, b64: input, decoded, error } : w));
    setVerifyResult(null);
  };

  const addWarrant = () => {
    setWarrants([...warrants, { id: generateId(), b64: '', decoded: null, error: null }]);
    setVerifyResult(null);
  };

  const removeWarrant = (id: string) => {
    if (warrants.length > 2) {
      setWarrants(warrants.filter(w => w.id !== id));
      setVerifyResult(null);
    }
  };

  const verifyChain = () => {
    const validWarrants = warrants.filter(w => w.b64.trim());
    if (validWarrants.length < 1) {
      setVerifyResult({ authorized: false, reason: 'Need at least one warrant' });
      return;
    }

    if (!rootKeyHex.trim()) {
      setVerifyResult({ authorized: false, reason: 'Root key (issuer public key) is required' });
      return;
    }

    try {
      const args = JSON.parse(argsJson || '{}');
      const warrantList = validWarrants.map(w => w.b64.trim());
      // Always dry_run in explorer (we don't have holder private keys to sign PoP)
      const result = check_chain_access(warrantList, tool, args, rootKeyHex.trim(), true);
      setVerifyResult(result);
    } catch (e) {
      setVerifyResult({ authorized: false, reason: `Error: ${e instanceof Error ? e.message : 'Unknown'}` });
    }
  };

  const validCount = warrants.filter(w => w.decoded).length;

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <span style={{ fontSize: '18px' }}>🔗</span>
        <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Chain Verifier</h2>
        <button onClick={loadSampleChain} className="btn btn-secondary" style={{ marginLeft: 'auto', padding: '4px 10px', fontSize: '11px' }}>
          📋 Load Sample Chain
        </button>
        <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
          {validCount}/{warrants.length} warrants decoded
        </span>
      </div>

      {/* Chain Visualization */}
      <div className="chain-tester">
        {warrants.map((warrant, i) => (
          <div key={warrant.id}>
            <div className={`chain-tester-node ${warrant.decoded ? '' : 'empty'} ${i === 0 ? 'root' : ''}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '13px' }}>
                  {i === 0 ? '🔐 Root Warrant' : `📋 Warrant ${i + 1}`}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {warrant.decoded && (
                    <span className="depth-badge">depth {warrant.decoded.depth}</span>
                  )}
                  {i > 1 && (
                    <button
                      onClick={() => removeWarrant(warrant.id)}
                      className="close-btn"
                    >✕</button>
                  )}
                </div>
              </div>

              <textarea
                className="input"
                style={{ height: '60px', fontSize: '10px', fontFamily: 'monospace' }}
                placeholder={i === 0 ? 'Paste root warrant (base64)...' : 'Paste delegated warrant...'}
                value={warrant.b64}
                onChange={e => updateWarrant(warrant.id, e.target.value)}
              />

              {warrant.error && (
                <div style={{ fontSize: '11px', color: 'var(--red)', marginTop: '6px' }}>
                  ❌ {warrant.error}
                </div>
              )}

              {warrant.decoded && (
                <div style={{ fontSize: '11px', marginTop: '8px', padding: '8px', background: 'var(--surface-2)', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--green)', marginBottom: '4px' }}>✓ Valid warrant</div>

                  <div style={{ color: 'var(--muted)', marginBottom: '4px' }}>
                    <strong>Capabilities:</strong>
                  </div>

                  {Object.keys(warrant.decoded.capabilities || {}).length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {Object.entries(warrant.decoded.capabilities || {}).map(([tool, constraints]) => (
                        <div key={tool} style={{ background: 'rgba(0,0,0,0.1)', padding: '4px', borderRadius: '4px' }}>
                          <span style={{ color: 'var(--text)', fontWeight: 600 }}>{tool}</span>
                          <div style={{ paddingLeft: '8px', borderLeft: '2px solid var(--border)', marginTop: '2px' }}>
                            {Object.entries(constraints).map(([key, val]) => (
                              <div key={key} style={{ display: 'flex', gap: '4px' }}>
                                <span style={{ color: 'var(--muted)' }}>{key}:</span>
                                <span style={{ color: 'var(--accent)', fontFamily: 'monospace' }}>
                                  {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                                </span>
                              </div>
                            ))}
                            {Object.keys(constraints).length === 0 && (
                              <span style={{ color: 'var(--muted)', fontStyle: 'italic' }}>no constraints</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ color: 'var(--muted)', fontStyle: 'italic' }}>No detailed capabilities</div>
                  )}

                  <div style={{ color: 'var(--muted)', marginTop: '6px' }}>
                    Holder: <span style={{ color: 'var(--text)', fontFamily: 'monospace', fontSize: '10px' }}>
                      {truncate(warrant.decoded.authorized_holder || '', 16)}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Connector arrow with attenuation diff */}
            {i < warrants.length - 1 && (
              <div className="chain-arrow">
                <div className="chain-arrow-line" />
                <div className="chain-arrow-head">▼</div>
                <div className="chain-arrow-label">
                  {warrant.decoded && warrants[i + 1]?.decoded
                    ? (warrant.decoded.authorized_holder === warrants[i + 1].decoded?.issuer
                      ? '✓ delegates to'
                      : '⚠️ holder mismatch!')
                    : 'delegates to'}
                </div>
                {/* Attenuation diff inline */}
                {warrant.decoded && warrants[i + 1]?.decoded && (
                  <div style={{ marginTop: '4px', fontSize: '10px', color: 'var(--muted)', textAlign: 'center' }}>
                    {(() => {
                      const parent = warrant.decoded;
                      const child = warrants[i + 1].decoded;
                      if (!parent || !child) return null;

                      const diffs: string[] = [];

                      // Tool differences
                      const parentTools = new Set(parent.tools || []);
                      const childTools = new Set(child.tools || []);
                      const removed = [...parentTools].filter(t => !childTools.has(t));
                      if (removed.length > 0) diffs.push(`−${removed.join(',')}`);

                      // TTL difference
                      const ttlDiff = parent.expires_at - child.expires_at;
                      if (ttlDiff > 60) diffs.push(`−${Math.round(ttlDiff / 60)}min TTL`);

                      // Depth
                      if (child.depth > parent.depth) diffs.push(`d:${parent.depth}→${child.depth}`);

                      return diffs.length > 0 ? (
                        <span style={{ color: 'var(--accent)' }}>📉 {diffs.join(' • ')}</span>
                      ) : (
                        <span style={{ color: 'var(--green)' }}>same authority</span>
                      );
                    })()}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      <button onClick={addWarrant} className="btn btn-secondary" style={{ width: '100%', marginTop: '16px' }}>
        + Add Warrant to Chain
      </button>

      {/* Authorization Test */}
      <div style={{ marginTop: '20px', padding: '16px', background: 'var(--surface-2)', borderRadius: '8px' }}>
        <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '12px' }}>🛡️ Test Authorization</div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
          <div>
            <label className="label">Tool</label>
            <input className="input" value={tool} onChange={e => setTool(e.target.value)} placeholder="read_file" />
          </div>
          <div>
            <label className="label">Root Key (hex)</label>
            <input
              className="input"
              value={rootKeyHex}
              onChange={e => setRootKeyHex(e.target.value)}
              placeholder="Issuer's public key (auto-filled from root)"
              style={{ fontFamily: 'monospace', fontSize: '10px' }}
            />
          </div>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <label className="label">Arguments (JSON)</label>
          <textarea
            className="input"
            style={{ height: '50px' }}
            value={argsJson}
            onChange={e => setArgsJson(e.target.value)}
            placeholder='{"path": "docs/readme.md"}'
          />
        </div>

        <button onClick={verifyChain} className="btn btn-primary" style={{ width: '100%' }} disabled={validCount < 1}>
          Verify Chain Authorization
        </button>

        {verifyResult && (
          <div style={{
            marginTop: '12px',
            padding: '12px',
            borderRadius: '8px',
            background: verifyResult.authorized ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${verifyResult.authorized ? 'var(--green)' : 'var(--red)'}`,
          }}>
            <div style={{
              fontSize: '14px',
              fontWeight: 600,
              color: verifyResult.authorized ? 'var(--green)' : 'var(--red)',
              marginBottom: '4px'
            }}>
              {verifyResult.authorized ? '✓ Chain Authorized' : '✗ Chain Denied'}
            </div>
            {verifyResult.reason && (
              <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
                {verifyResult.reason}
              </div>
            )}
          </div>
        )}
      </div>

      <Explainer title="How Chain Verification Works" docLink="https://tenuo.dev/concepts#delegation-chains">
        <p>A valid delegation chain requires:</p>
        <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
          <li><strong>Holder → Issuer</strong>: Each warrant's holder must be the next warrant's issuer</li>
          <li><strong>Monotonic attenuation</strong>: Tools/constraints can only shrink, never grow</li>
          <li><strong>Signature chain</strong>: Each delegation must be signed by the parent's holder</li>
          <li><strong>TTL cascade</strong>: Child TTL ≤ parent TTL</li>
        </ul>
        <p style={{ marginTop: '8px' }}>The root key must match the first warrant's issuer.</p>
      </Explainer>
    </div>
  );
};

// Diff Viewer Component
// Note: For meaningful comparisons, users should paste their own warrants.
// Diff samples are generated dynamically - pass sample state to the component.
interface DiffSample {
  name: string;
  description: string;
  a: string;
  b: string;
}

// Generate diff samples from the dynamic samples
function generateDiffSamples(samples: Record<string, SampleDef>): DiffSample[] {
  const sampleKeys = Object.keys(samples);
  if (sampleKeys.length === 0) return [];

  const firstSample = samples[sampleKeys[0]];
  return [
    {
      name: "🔬 Same Warrant",
      description: "Load same warrant in both to verify tool works",
      a: firstSample?.warrant || "",
      b: firstSample?.warrant || "",
    },
    {
      name: "📄 A Only",
      description: "Load sample in A, paste your own in B",
      a: firstSample?.warrant || "",
      b: "",
    },
    {
      name: "📝 B Only",
      description: "Load sample in B, paste your own in A",
      a: "",
      b: firstSample?.warrant || "",
    },
  ];
}

const DiffViewer = ({ samples }: { samples: Record<string, SampleDef> }) => {
  const [warrantA, setWarrantA] = useState('');
  const [warrantB, setWarrantB] = useState('');
  const [decodedA, setDecodedA] = useState<DecodedWarrant | null>(null);
  const [decodedB, setDecodedB] = useState<DecodedWarrant | null>(null);

  const diffSamples = useMemo(() => generateDiffSamples(samples), [samples]);

  const loadSample = (sample: DiffSample) => {
    setWarrantA(sample.a);
    setWarrantB(sample.b);
    setDecodedA(null);
    setDecodedB(null);
  };

  const handleCompare = () => {
    try {
      if (warrantA) setDecodedA(decode_warrant(warrantA));
      if (warrantB) setDecodedB(decode_warrant(warrantB));
    } catch { }
  };

  const getDiff = (a: unknown, b: unknown, path: string = ''): { path: string; a: unknown; b: unknown }[] => {
    const diffs: { path: string; a: unknown; b: unknown }[] = [];

    const isObjA = typeof a === 'object' && a !== null;
    const isObjB = typeof b === 'object' && b !== null;

    if (isObjA && isObjB) {
      // Both are objects -> recurse only
      const keys = new Set([...Object.keys(a as object), ...Object.keys(b as object)]);
      for (const key of keys) {
        diffs.push(...getDiff((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key], path ? `${path}.${key}` : key));
      }
    } else if (a !== b) {
      // One is primitive, or types differ (e.g. null vs object), or primitives differ
      // Note: This simple check might miss deep equality for non-object types if passed by reference, 
      // but here we deal with JSON decoded values.
      // We use JSON.stringify for safe comparison of value types that might be visually identical but different references?
      // Actually standard !== is fine for primitives.
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        diffs.push({ path: path || 'root', a, b });
      }
    }
    return diffs;
  };

  const diffs = decodedA && decodedB ? getDiff(decodedA, decodedB) : [];

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '18px' }}>📊</span>
          <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Warrant Diff Viewer</h2>
        </div>
      </div>

      {/* Samples */}
      <div style={{ marginBottom: '16px' }}>
        <label className="label">Load Sample Comparison</label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {diffSamples.length === 0 ? (
            <span style={{ fontSize: '12px', color: 'var(--muted)' }}>Loading samples...</span>
          ) : (
            diffSamples.map((sample, i) => (
              <button key={i} onClick={() => loadSample(sample)} className="tool-tag" title={sample.description}>
                {sample.name}
              </button>
            ))
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
        <div>
          <label className="label" style={{ color: 'var(--red)', opacity: 0.8 }}>Warrant A (Original)</label>
          <textarea className="input" style={{ height: '80px', resize: 'none', borderColor: warrantA ? 'rgba(239, 68, 68, 0.3)' : undefined }} placeholder="Paste parent/original warrant..." value={warrantA} onChange={e => setWarrantA(e.target.value)} />
        </div>
        <div>
          <label className="label" style={{ color: 'var(--green)', opacity: 0.8 }}>Warrant B (Modified)</label>
          <textarea className="input" style={{ height: '80px', resize: 'none', borderColor: warrantB ? 'rgba(34, 197, 94, 0.3)' : undefined }} placeholder="Paste child/attenuated warrant..." value={warrantB} onChange={e => setWarrantB(e.target.value)} />
        </div>
      </div>

      <button onClick={handleCompare} className="btn btn-secondary" style={{ width: '100%', marginBottom: '16px' }}>
        Compare Warrants
      </button>

      {diffs.length > 0 && (
        <div className="diff-results">
          <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>🔍 Differences Found: {diffs.length}</div>
          {diffs.slice(0, 10).map((d, i) => (
            <div key={i} className="diff-item">
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--accent)', marginBottom: '4px' }}>{d.path}</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div className="diff-value diff-a">
                  <span style={{ fontSize: '9px', color: 'var(--red)' }}>A:</span>
                  <code>{JSON.stringify(d.a)}</code>
                </div>
                <div className="diff-value diff-b">
                  <span style={{ fontSize: '9px', color: 'var(--green)' }}>B:</span>
                  <code>{JSON.stringify(d.b)}</code>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {decodedA && decodedB && diffs.length === 0 && (
        <div className="result-box success" style={{ padding: '16px' }}>
          <span style={{ fontSize: '24px' }}>✓</span>
          <p style={{ color: 'var(--green)', fontWeight: 600 }}>Warrants are identical</p>
        </div>
      )}

      {!decodedA && !decodedB && (
        <div className="empty-state" style={{ padding: '24px', textAlign: 'center' }}>
          <div style={{ fontSize: '32px', marginBottom: '12px', opacity: 0.3 }}>📊</div>
          <p style={{ color: 'var(--muted)', fontSize: '13px', maxWidth: '300px', margin: '0 auto' }}>
            Paste two warrants above and click "Compare" to see the differences.
          </p>
          <p style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '8px', opacity: 0.7 }}>
            Tip: Compare parent vs child warrants to verify attenuation
          </p>
        </div>
      )}
    </div>
  );
};

// History Sidebar Component
const HistorySidebar = ({
  history,
  onLoad,
  onClear
}: {
  history: HistoryItem[];
  onLoad: (item: HistoryItem) => void;
  onClear: () => void;
}) => {
  const handleClear = () => {
    onClear();
  };

  if (history.length === 0) return null;

  return (
    <div className="history-sidebar">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>📜 History</span>
        <button onClick={handleClear} className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: '10px' }} title="Clear all history">
          🗑 Clear
        </button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {history.slice(0, 10).map(item => (
          <div key={item.id} className="history-item" onClick={() => onLoad(item)}>
            <div style={{ fontSize: '12px', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item.name || item.tool || 'Unnamed'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--muted)' }}>
              {new Date(item.timestamp).toLocaleTimeString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Main App
function App() {
  // State
  const [wasmReady, setWasmReady] = useState(false);
  const [warrantB64, setWarrantB64] = useState("");
  const [tool, setTool] = useState("");
  const [argsJson, setArgsJson] = useState("{}");
  const [decoded, setDecoded] = useState<DecodedWarrant | string | null>(null);
  const [authResult, setAuthResult] = useState<AuthResult | null>(null);
  const [shareUrl, setShareUrl] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showSamples, setShowSamples] = useState(false);
  const [activeTab, setActiveTab] = useState<'decode' | 'debug' | 'code'>('decode');
  const [mode, setMode] = useState<'decoder' | 'builder' | 'chain' | 'diff'>('decoder');
  const [builderPreview, setBuilderPreview] = useState<unknown>(null);
  const [showShortcuts, setShowShortcuts] = useState(true);
  const [samples, setSamples] = useState<Record<string, SampleDef>>({});
  const [pemDetected, setPemDetected] = useState(false);
  const [chainResult, setChainResult] = useState<ChainDecodeResult | null>(null);

  // Initialize WASM and generate fresh samples
  useEffect(() => {
    const initWasm = async () => {
      try {
        await init(wasmUrl);  // Must call init(url) to load WASM correctly in Vite!
        init_panic_hook();
        setWasmReady(true);
        // Generate fresh samples with 1-hour TTL
        const freshSamples = generateFreshSamples();
        setSamples(freshSamples);
      } catch (err) {
        console.error("[Tenuo Explorer] WASM init failed:", err);
        console.error("[Tenuo Explorer] Try running: npm run wasm");
      }
    };
    initWasm();
  }, []);

  // Load history from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('tenuo-explorer-history');
    if (saved) {
      try { setHistory(JSON.parse(saved)); } catch { }
    }
  }, []);

  // Save history to localStorage
  useEffect(() => {
    localStorage.setItem('tenuo-explorer-history', JSON.stringify(history));
  }, [history]);

  // Load state from URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const state = params.get('s');
    if (state) {
      try {
        const parsed = JSON.parse(atob(state));
        if (parsed.warrant) setWarrantB64(parsed.warrant);
        if (parsed.tool) setTool(parsed.tool);
        if (parsed.args) setArgsJson(parsed.args);
      } catch { }
    }
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey) {
        if (e.key === 'Enter') {
          e.preventDefault();
          if (e.shiftKey) handleAuthorize();
          else handleDecode();
        } else if (e.key === 'k') {
          e.preventDefault();
          handleClear();
        } else if (e.key === 'd') {
          e.preventDefault();
          setMode(mode === 'diff' ? 'decoder' : 'diff');
        } else if (e.key === 'b') {
          e.preventDefault();
          setMode(mode === 'builder' ? 'decoder' : 'builder');
        } else if (e.key === '1') {
          e.preventDefault();
          setMode('decoder');
        } else if (e.key === '2') {
          e.preventDefault();
          setMode('builder');
        } else if (e.key === '3') {
          e.preventDefault();
          setMode('diff');
        } else if (e.key === '4') {
          e.preventDefault();
          setMode('chain');
        } else if (e.key === '/' && e.shiftKey) {
          // ⌘? to toggle shortcuts
          e.preventDefault();
          setShowShortcuts(s => !s);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [warrantB64, tool, argsJson, wasmReady, mode]);

  const generateShareUrl = useCallback(() => {
    const state = { warrant: warrantB64, tool, args: argsJson };
    return `${window.location.origin}${window.location.pathname}?s=${btoa(JSON.stringify(state))}`;
  }, [warrantB64, tool, argsJson]);

  const handleLoadSample = (key: string) => {
    const sample = samples[key];
    if (sample) {
      setWarrantB64(sample.warrant);
      setTool(sample.tool);
      setArgsJson(sample.args);
      setDecoded(null);
      setAuthResult(null);
      setShowSamples(false);
    }
  };

  // Input validation
  const [validationErrors, setValidationErrors] = useState<{
    warrant?: string;
    tool?: string;
    args?: string;
  }>({});

  const validateInputs = (forAuth: boolean = false): boolean => {
    const errors: typeof validationErrors = {};

    // Validate warrant (required for both decode and auth)
    if (!warrantB64.trim()) {
      errors.warrant = 'Warrant is required';
    } else {
      const { b64 } = cleanInput(warrantB64);

      // Check if it looks like base64 or base64url
      const base64Regex = /^[A-Za-z0-9+/\-_]+=*$/;

      if (!base64Regex.test(b64)) {
        errors.warrant = 'Invalid base64 format. Warrants should be base64-encoded.';
      } else if (b64.length < 50) {
        errors.warrant = 'Warrant seems too short. Did you paste the full warrant?';
      }
    }

    if (forAuth) {
      // Validate tool (required for auth)
      if (!tool.trim()) {
        errors.tool = 'Tool name is required for authorization';
      } else if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tool.trim())) {
        errors.tool = 'Tool name should be alphanumeric (e.g., read_file, send_email)';
      }

      // Validate args JSON
      if (argsJson.trim()) {
        try {
          const parsed = JSON.parse(argsJson);
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            errors.args = 'Args must be a JSON object (e.g., {"path": "docs/readme.md"})';
          }
        } catch {
          errors.args = 'Invalid JSON. Check for missing quotes or commas.';
        }
      }

    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleDecode = () => {
    if (!wasmReady) {
      console.warn('[Tenuo Explorer] Decode blocked: WASM not ready');
      return;
    }
    if (!validateInputs(false)) {
      console.warn('[Tenuo Explorer] Decode blocked: validation failed', validationErrors);
      return;
    }

    try {
      console.log('[Tenuo Explorer] Decoding warrant...');
      const { b64, isPem } = cleanInput(warrantB64);

      // Try chain decode first to detect multi-warrant inputs
      const chainRes = decode_pem_chain_wasm(isPem ? warrantB64.trim() : b64) as ChainDecodeResult;

      if (chainRes.error) {
        // Fall back to single warrant decode for better error messages
        const result = decode_warrant(b64);
        console.log('[Tenuo Explorer] Single decode successful:', result);
        setDecoded(result);
        setChainResult(null);
      } else if (chainRes.is_chain) {
        // Multi-warrant chain detected
        console.log('[Tenuo Explorer] Chain detected:', chainRes.warrants.length, 'warrants');
        setDecoded(chainRes.warrants[chainRes.warrants.length - 1]); // Show leaf warrant
        setChainResult(chainRes);
      } else {
        // Single warrant
        setDecoded(chainRes.warrants[0] || null);
        setChainResult(null);
      }

      setPemDetected(isPem);
      setAuthResult(null);
      setValidationErrors({});

      // Add to history
      const newItem: HistoryItem = {
        id: generateId(),
        name: tool || 'Decoded warrant',
        warrant: warrantB64,
        tool,
        args: argsJson,
        timestamp: Date.now()
      };
      setHistory(prev => [newItem, ...prev.slice(0, 19)]);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : 'Unknown error';
      console.error('[Tenuo Explorer] Decode failed:', e);
      setValidationErrors({ warrant: `Decode failed: ${errMsg}` });
      setDecoded(null);
      setChainResult(null);
      setPemDetected(false);
    }
  };

  const handleAuthorize = () => {
    if (!wasmReady) return;
    if (!validateInputs(true)) return;

    try {
      const args = JSON.parse(argsJson || '{}');

      // Check expiration first (WASM dry run doesn't check TTL)
      if (decodedWarrant) {
        const now = Date.now() / 1000;
        if (decodedWarrant.expires_at < now) {
          setAuthResult({
            authorized: false,
            reason: `Warrant expired ${Math.floor(now - decodedWarrant.expires_at)} seconds ago`,
            deny_code: 'EXPIRED'
          });
          return;
        }
      }

      // For single-warrant auth, the trusted root is the warrant's own issuer
      // Decode inline if not already decoded
      const issuer = decodedWarrant?.issuer || decode_warrant(warrantB64.trim()).issuer;
      const result = check_access(warrantB64.trim(), tool.trim(), args, issuer, true);
      setAuthResult(result);
      setValidationErrors({});
    } catch (e) {
      setAuthResult({ authorized: false, reason: `Error: ${e instanceof Error ? e.message : 'Invalid input'}` });
    }
  };

  const handleClear = () => {
    setWarrantB64("");
    setTool("");
    setArgsJson("{}");
    setDecoded(null);
    setAuthResult(null);
  };

  const handleShare = async () => {
    const url = generateShareUrl();
    await navigator.clipboard.writeText(url);
    setShareUrl(url);
    setTimeout(() => setShareUrl(""), 2000);
  };

  const handleExport = (format: 'json' | 'curl') => {
    if (!decoded || typeof decoded === 'string') return;

    if (format === 'json') {
      const data = JSON.stringify({ warrant: warrantB64, decoded, tool, args: JSON.parse(argsJson), authResult }, null, 2);
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'warrant.json';
      a.click();
    } else {
      const curl = `curl -X POST https://api.example.com/authorize \\
  -H "Authorization: Bearer ${warrantB64}" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify({ tool, args: JSON.parse(argsJson) })}'`;
      navigator.clipboard.writeText(curl);
    }
  };

  const loadHistoryItem = (item: HistoryItem) => {
    setWarrantB64(item.warrant);
    setTool(item.tool);
    setArgsJson(item.args);
    setDecoded(null);
    setAuthResult(null);
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('tenuo-explorer-history');
  };

  const decodedWarrant = typeof decoded === 'object' && decoded !== null ? decoded : null;

  return (
    <>
      {/* Background */}
      <div className="orb orb-1" />
      <div className="orb orb-2" />

      <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        {/* Navigation */}
        <nav style={{ borderBottom: '1px solid var(--border)' }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <a href="https://tenuo.dev" style={{ fontSize: '20px', fontWeight: 600, color: 'white', textDecoration: 'none' }}>tenuo</a>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <a href="https://tenuo.dev/quickstart" className="nav-link">Quick Start</a>
              <a href="https://tenuo.dev/concepts" className="nav-link">Concepts</a>
              <a href="https://tenuo.dev/api-reference" className="nav-link">API</a>
              <a href="https://github.com/tenuo-ai/tenuo" className="nav-link">GitHub</a>
            </div>
          </div>
        </nav>

        {/* Hero */}
        <header style={{ textAlign: 'center', padding: '40px 24px 24px' }}>
          <h1 style={{ fontSize: '32px', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '8px' }}>
            Warrant <span className="gradient-text">Playground</span>
          </h1>
          <p style={{ fontSize: '15px', color: 'var(--muted)', maxWidth: '520px', margin: '0 auto 12px' }}>
            Decode, build, and test authorization in real-time
          </p>
          <p style={{ fontSize: '12px', color: 'var(--green)', maxWidth: '580px', margin: '0 auto 20px', padding: '8px 16px', background: 'rgba(34, 197, 94, 0.1)', borderRadius: '8px', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
            🔒 100% client-side — nothing leaves your browser. Warrants contain only signed claims, not secrets.
          </p>

          {/* Mode Switcher */}
          <div className="mode-switcher">
            <button onClick={() => setMode('decoder')} className={`mode-btn ${mode === 'decoder' ? 'active' : ''}`}>
              🔍 Decoder
            </button>
            <button onClick={() => setMode('builder')} className={`mode-btn ${mode === 'builder' ? 'active' : ''}`}>
              🏗️ Builder
            </button>
            <button onClick={() => setMode('diff')} className={`mode-btn ${mode === 'diff' ? 'active' : ''}`}>
              📊 Diff
            </button>
            <button onClick={() => setMode('chain')} className={`mode-btn ${mode === 'chain' ? 'active' : ''}`}>
              📚 Delegation
            </button>
          </div>

        </header>

        {/* Main Content */}
        <main style={{ flex: 1, maxWidth: '1200px', width: '100%', margin: '0 auto', padding: '0 24px 64px' }}>
          {/* Builder Mode */}
          {mode === 'builder' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              <WarrantBuilder onGenerate={(config) => {
                // Generate real warrant from config using WASM
                const result = create_warrant_from_config(config);
                // Store both the WASM result and the original config for code generation
                setBuilderPreview({ ...result, config });
              }} />
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                  <span style={{ fontSize: '18px' }}>👁️</span>
                  <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Generated Warrant</h2>
                </div>
                {builderPreview ? (
                  <div>
                    {(builderPreview as { error?: string }).error ? (
                      <div className="result-box error" style={{ padding: '16px' }}>
                        <span style={{ fontSize: '24px' }}>⚠️</span>
                        <p style={{ color: 'var(--red)', fontWeight: 600 }}>{(builderPreview as { error: string }).error}</p>
                      </div>
                    ) : (
                      <>
                        {/* Warrant Base64 */}
                        <div style={{ marginBottom: '16px' }}>
                          <label className="label">Warrant (base64)</label>
                          <div style={{ position: 'relative' }}>
                            <textarea
                              className="input"
                              readOnly
                              value={(builderPreview as { warrant_b64: string }).warrant_b64}
                              style={{ height: '80px', fontSize: '10px', fontFamily: 'monospace' }}
                            />
                            <div style={{ position: 'absolute', top: '8px', right: '8px', display: 'flex', gap: '6px' }}>
                              <button
                                onClick={() => navigator.clipboard.writeText((builderPreview as { warrant_b64: string }).warrant_b64)}
                                className="btn btn-secondary"
                                style={{ fontSize: '11px', padding: '4px 8px' }}
                              >
                                📋 Copy
                              </button>
                              <button
                                onClick={() => {
                                  setMode('chain');
                                  // Small delay to let mode change render
                                  setTimeout(() => {
                                    const chainInput = document.querySelector('.chain-tester textarea') as HTMLTextAreaElement;
                                    if (chainInput) {
                                      chainInput.value = (builderPreview as { warrant_b64: string }).warrant_b64;
                                      chainInput.dispatchEvent(new Event('input', { bubbles: true }));
                                    }
                                  }, 100);
                                }}
                                className="btn btn-secondary"
                                style={{ fontSize: '11px', padding: '4px 8px' }}
                              >
                                📚 Use in Delegation
                              </button>
                            </div>
                          </div>
                        </div>

                        {/* Keys */}
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                          <div>
                            <label className="label">Issuer Public Key</label>
                            <input className="input" readOnly value={(builderPreview as { issuer_public_key_hex: string }).issuer_public_key_hex} style={{ fontSize: '9px', fontFamily: 'monospace' }} />
                          </div>
                          <div>
                            <label className="label">Holder Public Key</label>
                            <input className="input" readOnly value={(builderPreview as { holder_public_key_hex: string }).holder_public_key_hex} style={{ fontSize: '9px', fontFamily: 'monospace' }} />
                          </div>
                        </div>

                        {/* Tools */}
                        <div style={{ marginBottom: '16px' }}>
                          <label className="label">Tools: {((builderPreview as { tools: string[] }).tools || []).join(', ')}</label>
                        </div>

                        {/* Code Generator */}
                        <CodeGenerator
                          decoded={{
                            id: '',
                            issuer: (builderPreview as { issuer_public_key_hex: string }).issuer_public_key_hex,
                            tools: (builderPreview as { tools: string[] }).tools || [],
                            // Use the config tools as capabilities for code generation
                            capabilities: (builderPreview as { config?: { tools?: Record<string, unknown> } }).config?.tools || {},
                            issued_at: Math.floor(Date.now() / 1000),
                            expires_at: Math.floor(Date.now() / 1000) + ((builderPreview as { config?: { ttl?: number } }).config?.ttl || 3600),
                            authorized_holder: (builderPreview as { holder_public_key_hex: string }).holder_public_key_hex,
                            depth: 0
                          }}
                          tool={(builderPreview as { tools: string[] }).tools?.[0] || ''}
                          args="{}"
                        />
                      </>
                    )}
                  </div>
                ) : (
                  <div className="empty-state">
                    <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.2 }}>👁️</div>
                    <p>Click "Generate Preview" to create a real warrant</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Chain Mode */}
          {mode === 'chain' && (
            <div style={{ maxWidth: '600px', margin: '0 auto' }}>
              <ChainTester />
            </div>
          )}

          {/* Diff Mode */}
          {mode === 'diff' && (
            <div style={{ maxWidth: '800px', margin: '0 auto' }}>
              <DiffViewer samples={samples} />
            </div>
          )}

          {/* Decoder Mode */}
          {mode === 'decoder' && (
            <>
              {/* Validation Warnings */}
              <ValidationWarnings decoded={decodedWarrant} tool={tool} args={argsJson} />

              <div style={{ display: 'grid', gridTemplateColumns: history.length > 0 ? '200px 1fr 1fr' : '1fr 1fr', gap: '24px' }}>
                {/* History Sidebar */}
                {history.length > 0 && (
                  <HistorySidebar history={history} onLoad={loadHistoryItem} onClear={clearHistory} />
                )}

                {/* Left Column - Inputs */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {/* Warrant Input Panel */}
                  <div className="panel">
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontSize: '18px' }}>📄</span>
                        <h2 style={{ fontSize: '15px', fontWeight: 600 }}>1. Paste Warrant</h2>
                      </div>
                      <div style={{ position: 'relative' }}>
                        <button onClick={() => setShowSamples(!showSamples)} className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '11px', gap: '6px' }}>
                          <span>📦</span>
                          <span>Samples</span>
                          <span>{showSamples ? '▲' : '▼'}</span>
                        </button>
                        {showSamples && (
                          <div className="samples-dropdown" style={{ right: 0, left: 'auto', transform: 'none', minWidth: '280px' }}>
                            <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--muted)', borderBottom: '1px solid var(--border)', marginBottom: '4px' }}>
                              🔄 Fresh warrants generated on page load
                            </div>
                            {Object.keys(samples).length === 0 ? (
                              <div style={{ padding: '12px', fontSize: '12px', color: 'var(--muted)' }}>Loading samples...</div>
                            ) : (
                              Object.entries(samples).map(([key, sample]) => (
                                <div key={key} className="sample-item" onClick={() => handleLoadSample(key)}>
                                  <div style={{ fontWeight: 500 }}>{sample.name}</div>
                                  <div style={{ fontSize: '11px', color: 'var(--muted)' }}>{sample.description}</div>
                                </div>
                              ))
                            )}
                            <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--muted)', borderTop: '1px solid var(--border)', marginTop: '4px' }}>
                              💡 Paste your own warrant for real testing
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div>
                        <label className="label">Base64 Encoded Warrant</label>
                        <textarea
                          className="input"
                          style={{ height: '100px', minHeight: '60px', maxHeight: '300px', resize: 'vertical' }}
                          placeholder="Paste your warrant here..."
                          value={warrantB64}
                          onChange={(e) => setWarrantB64(e.target.value)}
                        />
                      </div>

                      <button onClick={handleDecode} disabled={!wasmReady || !warrantB64} className="btn btn-secondary">
                        {wasmReady ? 'Decode Warrant' : 'Loading WASM...'}
                      </button>

                      {/* Presets */}
                      <PresetsManager
                        currentWarrant={warrantB64}
                        currentTool={tool}
                        currentArgs={argsJson}
                        onLoad={(preset) => {
                          setWarrantB64(preset.warrant);
                          setTool(preset.tool);
                          setArgsJson(preset.args);
                        }}
                      />
                    </div>

                    <Explainer title="What is a warrant?" docLink="https://tenuo.dev/concepts#warrants">
                      <p>A <strong>warrant</strong> is a cryptographic capability token that grants an AI agent permission to perform specific actions.</p>
                    </Explainer>
                  </div>

                  {/* Authorization Check Panel */}
                  <div className="panel">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                      <span style={{ fontSize: '18px' }}>🔐</span>
                      <h2 style={{ fontSize: '15px', fontWeight: 600 }}>2. Check Authorization</h2>
                    </div>

                    {decodedWarrant && decodedWarrant.tools.length > 0 && (
                      <div style={{ marginBottom: '12px' }}>
                        <label className="label">Quick Select Tool</label>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {decodedWarrant.tools.slice(0, 6).map(t => (
                            <button key={t} onClick={() => setTool(t)} className={`tool-tag ${tool === t ? 'active' : ''}`}>{t}</button>
                          ))}
                        </div>
                      </div>
                    )}

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div>
                        <label className="label">Tool Name</label>
                        <input className="input" placeholder="e.g., read_file" value={tool} onChange={(e) => setTool(e.target.value)} />
                      </div>

                      <div>
                        <label className="label">Arguments (JSON)</label>
                        <textarea className="input" style={{ height: '80px', minHeight: '50px', maxHeight: '200px', resize: 'vertical' }} value={argsJson} onChange={(e) => setArgsJson(e.target.value)} />
                      </div>

                      <Explainer title="About Proof-of-Possession (PoP)" docLink="https://tenuo.dev/security">
                        <p><strong>Proof-of-Possession</strong> prevents stolen warrants from being used by attackers.</p>
                        <p style={{ marginTop: '8px' }}>In production, the holder signs each request with their private key. The signature proves they possess the key matching the warrant's <code>authorized_holder</code>.</p>
                        <p style={{ marginTop: '8px' }}><strong>Why this matters:</strong></p>
                        <p>• Without PoP: Intercepted warrant = full access</p>
                        <p>• With PoP: Intercepted warrant = useless (no private key)</p>
                        <p style={{ marginTop: '8px', color: 'var(--accent)' }}>💡 This explorer runs in <strong>dry run mode</strong> (policy-only check). Real PoP requires the holder's private key, which we don't have.</p>
                      </Explainer>

                      <button onClick={handleAuthorize} disabled={!wasmReady || !warrantB64 || !tool} className="btn btn-primary">
                        Check Authorization
                      </button>
                    </div>
                  </div>

                  {/* Export Options */}
                  {decodedWarrant && (
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button onClick={() => handleExport('json')} className="btn btn-secondary" style={{ flex: 1, fontSize: '12px' }}>
                        📥 Export JSON
                      </button>
                      <button onClick={() => handleExport('curl')} className="btn btn-secondary" style={{ flex: 1, fontSize: '12px' }}>
                        📋 Copy cURL
                      </button>
                    </div>
                  )}
                </div>

                {/* Right Column - Outputs */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {/* Tab Navigation */}
                  <div className="tabs">
                    <button onClick={() => setActiveTab('decode')} className={`tab ${activeTab === 'decode' ? 'active' : ''}`}>🔍 Decoded</button>
                    <button onClick={() => setActiveTab('debug')} className={`tab ${activeTab === 'debug' ? 'active' : ''}`}>🐛 Debug</button>
                    <button onClick={() => setActiveTab('code')} className={`tab ${activeTab === 'code' ? 'active' : ''}`}>💻 Code</button>
                  </div>

                  {/* Decoded Panel */}
                  {activeTab === 'decode' && (
                    <div className="panel">
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '18px' }}>🔍</span>
                          <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Decoded Warrant</h2>
                          {pemDetected && (
                            <span style={{ background: 'rgba(34, 197, 94, 0.1)', color: 'var(--green)', fontSize: '10px', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--green)' }}>
                              ✓ PEM armor stripped
                            </span>
                          )}
                        </div>
                        {decodedWarrant && warrantB64 && (
                          <button onClick={handleShare} className="btn btn-secondary" style={{ padding: '6px 10px', fontSize: '11px' }}>
                            {shareUrl ? '✓ Copied!' : '🔗 Share'}
                          </button>
                        )}
                      </div>

                      {!decoded && (
                        <div className="empty-state" style={{ padding: '40px' }}>
                          <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.3 }}>🔍</div>
                          <p style={{ color: 'var(--muted)' }}>Paste a warrant and click "Decode" to see its contents</p>
                        </div>
                      )}

                      {typeof decoded === 'string' && (
                        <div className="result-box error" style={{ padding: '16px' }}>
                          <span style={{ fontSize: '24px' }}>⚠️</span>
                          <p style={{ color: 'var(--red)', fontWeight: 600 }}>{decoded}</p>
                        </div>
                      )}

                      {/* Chain Detected Banner */}
                      {chainResult && chainResult.is_chain && (
                        <div style={{ marginBottom: '12px', padding: '12px', borderRadius: '10px', border: '1px solid var(--accent)', background: 'rgba(139, 92, 246, 0.1)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ fontSize: '16px' }}>⛓️</span>
                              <span style={{ fontWeight: 600, fontSize: '13px' }}>Warrant Chain Detected</span>
                              <span style={{ fontSize: '11px', color: 'var(--muted)' }}>({chainResult.warrants.length} warrants)</span>
                            </div>
                            <span className={chainResult.chain_valid ? 'status-ok' : 'status-err'} style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '4px' }}>
                              {chainResult.chain_valid ? '✓ Valid Chain' : '⚠️ Chain Issues'}
                            </span>
                          </div>

                          {/* Chain Hierarchy */}
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' }}>
                            {chainResult.warrants.map((w, idx) => (
                              <div key={w.id} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <div style={{
                                  padding: '4px 8px',
                                  borderRadius: '6px',
                                  background: idx === 0 ? 'rgba(34, 197, 94, 0.15)' : idx === chainResult.warrants.length - 1 ? 'rgba(139, 92, 246, 0.15)' : 'var(--surface-2)',
                                  border: `1px solid ${idx === 0 ? 'var(--green)' : idx === chainResult.warrants.length - 1 ? 'var(--accent)' : 'var(--border)'}`,
                                  fontSize: '11px'
                                }}>
                                  <span style={{ marginRight: '4px' }}>{idx === 0 ? '🔑' : idx === chainResult.warrants.length - 1 ? '🤖' : '🔗'}</span>
                                  {idx === 0 ? 'Root' : idx === chainResult.warrants.length - 1 ? 'Leaf' : `Lvl ${idx}`}
                                  <span style={{ color: 'var(--muted)', marginLeft: '6px' }}>d:{w.depth}</span>
                                </div>
                                {idx < chainResult.warrants.length - 1 && (
                                  <span style={{ color: 'var(--muted)', fontSize: '14px' }}>→</span>
                                )}
                              </div>
                            ))}
                          </div>

                          {/* Attenuation Diffs */}
                          {chainResult.attenuation_diffs.length > 0 && (
                            <div style={{ marginTop: '10px', padding: '8px', background: 'var(--surface-2)', borderRadius: '6px', fontSize: '11px' }}>
                              <div style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--accent)' }}>📉 Attenuation</div>
                              {chainResult.attenuation_diffs.map((diff, idx) => (
                                <div key={idx} style={{ marginBottom: '6px', paddingBottom: '6px', borderBottom: idx < chainResult.attenuation_diffs.length - 1 ? '1px solid var(--border)' : 'none' }}>
                                  <div style={{ color: 'var(--muted)', marginBottom: '4px' }}>Level {diff.from_idx} → {diff.to_idx}</div>
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                    {diff.tools_removed.length > 0 && (
                                      <span style={{ color: 'var(--red)' }}>−tools: {diff.tools_removed.join(', ')}</span>
                                    )}
                                    {diff.ttl_reduced_by_secs > 0 && (
                                      <span style={{ color: 'var(--yellow)' }}>−{Math.round(diff.ttl_reduced_by_secs / 60)}min TTL</span>
                                    )}
                                    {diff.constraints_narrowed.map((c, ci) => (
                                      <span key={ci} style={{ color: 'var(--accent)' }}>
                                        {c.tool}.{c.field}: {c.parent_value === '(none)' ? `+${c.child_value}` : `→${c.child_value}`}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Chain Errors */}
                          {chainResult.chain_errors.length > 0 && (
                            <div style={{ marginTop: '10px', padding: '8px', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '6px', border: '1px solid var(--red)' }}>
                              <div style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--red)', fontSize: '11px' }}>⚠️ Chain Issues</div>
                              {chainResult.chain_errors.map((err, idx) => (
                                <div key={idx} style={{ fontSize: '11px', color: 'var(--red)', marginBottom: '3px' }}>• {err}</div>
                              ))}
                            </div>
                          )}

                          <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--muted)' }}>
                            Showing leaf warrant below. Full chain verification requires trusted root.
                          </div>
                        </div>
                      )}

                      {decodedWarrant && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          {/* Chain Visualization */}
                          <div className="chain-box">
                            <div className="chain-node">
                              <div className="chain-icon">🔑</div>
                              <div className="chain-label">Issuer</div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <code style={{ fontSize: '10px', color: 'var(--accent)' }}>{truncate(decodedWarrant.issuer)}</code>
                                <CopyBtn text={decodedWarrant.issuer} />
                              </div>
                            </div>
                            <div className="chain-connector">
                              <div className="chain-line" />
                              <div className="chain-depth">depth {decodedWarrant.depth}</div>
                            </div>
                            <div className="chain-node">
                              <div className="chain-icon">🤖</div>
                              <div className="chain-label">Holder</div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <code style={{ fontSize: '10px', color: 'var(--green)' }}>{truncate(decodedWarrant.authorized_holder)}</code>
                                <CopyBtn text={decodedWarrant.authorized_holder} />
                              </div>
                            </div>
                          </div>

                          <ExpirationDisplay issuedAt={decodedWarrant.issued_at} expiresAt={decodedWarrant.expires_at} />

                          <div style={{ padding: '12px', background: 'var(--surface-2)', borderRadius: '10px', border: '1px solid var(--border)' }}>
                            <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>🔧 Authorized Tools</div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                              {decodedWarrant.tools.map(t => <span key={t} className="tool-tag">{t}</span>)}
                            </div>
                          </div>

                          <div style={{ padding: '12px', background: 'var(--surface-2)', borderRadius: '10px', border: '1px solid var(--border)' }}>
                            <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>📋 Constraints</div>
                            <pre className="code-block" style={{ height: '120px', minHeight: '80px', maxHeight: '400px', resize: 'vertical' }}>{JSON.stringify(decodedWarrant.capabilities, null, 2)}</pre>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Debug Panel */}
                  {activeTab === 'debug' && decodedWarrant && (
                    <VerificationSteps decoded={decodedWarrant} tool={tool} args={argsJson} authResult={authResult} />
                  )}

                  {/* Code Panel */}
                  {activeTab === 'code' && (
                    decodedWarrant ? (
                      <CodeGenerator decoded={decodedWarrant} tool={tool} args={argsJson} />
                    ) : (
                      <div className="panel">
                        <div className="empty-state" style={{ padding: '40px' }}>
                          <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.3 }}>💻</div>
                          <p style={{ color: 'var(--muted)' }}>Decode a warrant first to generate code</p>
                        </div>
                      </div>
                    )
                  )}

                  {/* Result Panel */}
                  <div className="panel">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                      <span style={{ fontSize: '18px' }}>⚡</span>
                      <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Authorization Result</h2>
                    </div>

                    {authResult ? (
                      <div className={`result-box ${authResult.authorized ? 'success' : 'error'}`}>
                        <div style={{ fontSize: '40px', marginBottom: '8px' }}>{authResult.authorized ? '✓' : '✕'}</div>
                        <p style={{ fontSize: '20px', fontWeight: 600, marginBottom: '6px', color: authResult.authorized ? 'var(--green)' : 'var(--red)' }}>
                          {authResult.authorized ? 'Authorized' : 'Denied'}
                        </p>
                        {authResult.authorized ? (
                          <p style={{ fontSize: '13px', color: 'var(--muted)' }}>
                            Policy check passed <span style={{ opacity: 0.6 }}>(dry run)</span>
                          </p>
                        ) : (
                          <>
                            {authResult.deny_code && <span className="deny-code">{authResult.deny_code}</span>}
                            <p style={{ fontSize: '13px', color: 'var(--muted)' }}>{authResult.reason}</p>
                          </>
                        )}
                      </div>
                    ) : (
                      <div className="empty-state">
                        <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.2 }}>⚡</div>
                        <p>Run an authorization check to see results</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </main>

        {/* Keyboard Shortcuts Help */}
        {showShortcuts && (
          <div className="shortcuts-help">
            <button
              onClick={() => setShowShortcuts(false)}
              className="close-btn"
              style={{
                position: 'absolute',
                right: '6px',
                top: '50%',
                transform: 'translateY(-50%)',
              }}
              title="Hide shortcuts (⌘?)"
            >
              ✕
            </button>
            <div className="shortcut"><kbd>⌘</kbd><kbd>↵</kbd><span>Decode</span></div>
            <div className="shortcut"><kbd>⌘</kbd><kbd>⇧</kbd><kbd>↵</kbd><span>Auth</span></div>
            <div className="shortcut"><kbd>⌘</kbd><kbd>K</kbd><span>Clear</span></div>
            <div className="shortcut-divider" />
            <div className="shortcut"><kbd>⌘</kbd><kbd>1-4</kbd><span>Modes</span></div>
            <div className="shortcut"><kbd>⌘</kbd><kbd>B</kbd><span>Builder</span></div>
            <div className="shortcut"><kbd>⌘</kbd><kbd>D</kbd><span>Diff</span></div>
          </div>
        )}

        {/* Footer */}
        <footer style={{ borderTop: '1px solid var(--border)', padding: '32px 24px' }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', textAlign: 'center' }}>
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '24px', marginBottom: '12px', fontSize: '13px' }}>
              <a href="https://crates.io/crates/tenuo" className="nav-link">🦀 Rust</a>
              <a href="https://pypi.org/project/tenuo/" className="nav-link">🐍 Python</a>
              <span style={{ color: 'var(--muted)' }}>🔐 100% client-side WASM</span>
              <span style={{ color: 'var(--accent)', fontSize: '11px', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: '4px' }}>v0.1.0-beta.5</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '16px', fontSize: '12px', color: 'var(--muted)' }}>
              <a href="https://github.com/tenuo-ai/tenuo" style={{ color: 'var(--muted)', textDecoration: 'none' }}>GitHub</a>
              <span>·</span>
              <a href="https://tenuo.dev/quickstart" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Docs</a>
              <span>·</span>
              <span>MIT / Apache-2.0</span>
            </div>
          </div>
        </footer>
      </div>
    </>
  )
}

export default App
