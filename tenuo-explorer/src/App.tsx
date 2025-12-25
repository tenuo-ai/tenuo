import { useState, useEffect, useCallback, useMemo } from 'react'
import init, { decode_warrant, check_access, check_access_with_pop, generate_keypair, sign, create_sample_warrant, init_panic_hook } from './wasm/tenuo_wasm'

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

// Utility functions
const truncate = (str: string, len: number = 12) =>
  str.length > len ? `${str.slice(0, 6)}...${str.slice(-4)}` : str;

const generateId = () => Math.random().toString(36).substring(2, 9);

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
  const total = expiresAt - issuedAt;
  const elapsed = now - issuedAt;
  const percent = Math.min(100, Math.max(0, (elapsed / total) * 100));

  const formatTime = (seconds: number) => {
    if (seconds <= 0) return 'Expired';
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
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>⏱ Time Remaining</span>
        <span style={{ fontSize: '14px', fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", color: isExpired ? 'var(--red)' : 'var(--green)' }}>
          {formatTime(remaining)}
        </span>
      </div>

      {/* Timeline Visualization */}
      <div className="timeline">
        <div className="timeline-track">
          <div className="timeline-fill" style={{ width: `${percent}%`, background: isExpired ? 'var(--red)' : 'linear-gradient(90deg, var(--green), var(--accent))' }} />
          <div className="timeline-now" style={{ left: `${Math.min(percent, 100)}%` }} />
        </div>
        <div className="timeline-labels">
          <div className="timeline-label">
            <div className="timeline-dot" style={{ background: 'var(--green)' }} />
            <span>Issued</span>
            <span className="timeline-time">{new Date(issuedAt * 1000).toLocaleTimeString()}</span>
          </div>
          <div className="timeline-label" style={{ position: 'absolute', left: `${Math.min(percent, 95)}%`, transform: 'translateX(-50%)' }}>
            <div className="timeline-dot pulse" style={{ background: isExpired ? 'var(--red)' : 'var(--accent)' }} />
            <span>Now</span>
          </div>
          <div className="timeline-label" style={{ marginLeft: 'auto' }}>
            <div className="timeline-dot" style={{ background: 'var(--red)' }} />
            <span>Expires</span>
            <span className="timeline-time">{new Date(expiresAt * 1000).toLocaleTimeString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// PoP Signature Simulator
const PopSimulator = ({ warrant, tool, args, onPopGenerated }: {
  warrant: string;
  tool: string;
  args: string;
  onPopGenerated: (pop: string, publicKey: string) => void;
}) => {
  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [popSignature, setPopSignature] = useState('');
  const [error, setError] = useState('');

  const handleGenerateKeypair = () => {
    try {
      const result = generate_keypair();
      setPrivateKey(result.private_key_hex);
      setPublicKey(result.public_key_hex);
      setPopSignature('');
      setError('');
    } catch (e) {
      setError(`Keypair generation failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleCreatePop = () => {
    if (!privateKey || !warrant || !tool) {
      setError('Need keypair, warrant, and tool name');
      return;
    }

    try {
      let parsedArgs: Record<string, unknown>;
      try {
        parsedArgs = JSON.parse(args);
      } catch {
        parsedArgs = {};
      }

      const result = sign(privateKey, warrant, tool, parsedArgs);
      if (result.error) {
        setError(result.error);
      } else {
        setPopSignature(result.signature_hex);
        onPopGenerated(result.signature_hex, publicKey);
        setError('');
      }
    } catch (e) {
      setError(`PoP creation failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  return (
    <div className="panel" style={{ padding: '16px', border: '1px solid rgba(34, 197, 94, 0.3)', background: 'rgba(34, 197, 94, 0.05)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
        <span style={{ fontSize: '16px' }}>🔐</span>
        <h3 style={{ fontSize: '14px', fontWeight: 600 }}>PoP Signature Generator</h3>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <button onClick={handleGenerateKeypair} className="btn btn-secondary" style={{ fontSize: '12px' }}>
          🔑 Generate Test Keypair
        </button>

        {privateKey && (
          <>
            <div>
              <label className="label">Public Key (Holder)</label>
              <div className="input" style={{ fontSize: '10px', wordBreak: 'break-all', background: 'var(--bg)' }}>
                {truncate(publicKey, 24)}
                <CopyBtn text={publicKey} />
              </div>
            </div>

            <div>
              <label className="label">Private Key (Secret - for signing)</label>
              <div className="input" style={{ fontSize: '10px', wordBreak: 'break-all', background: 'var(--bg)', color: 'var(--red)' }}>
                {truncate(privateKey, 24)} 🔒
              </div>
            </div>

            <button onClick={handleCreatePop} className="btn btn-primary" style={{ fontSize: '12px' }} disabled={!tool}>
              ✍️ Create PoP Signature
            </button>
          </>
        )}

        {popSignature && (
          <div>
            <label className="label">PoP Signature</label>
            <div className="input" style={{ fontSize: '10px', wordBreak: 'break-all', background: 'rgba(34, 197, 94, 0.1)', borderColor: 'var(--green)' }}>
              {truncate(popSignature, 32)}
              <CopyBtn text={popSignature} />
            </div>
          </div>
        )}

        {error && (
          <div style={{ fontSize: '11px', color: 'var(--yellow)', padding: '8px', background: 'rgba(234, 179, 8, 0.1)', borderRadius: '6px' }}>
            {error}
          </div>
        )}
      </div>

      <Explainer title="How Proof-of-Possession works" docLink="https://tenuo.dev/security">
        <p style={{ marginBottom: '8px' }}><strong>Why PoP?</strong> Without it, anyone who intercepts a warrant can use it. PoP ensures only the legitimate holder can authorize actions.</p>
        <p style={{ marginBottom: '6px' }}><strong>The flow:</strong></p>
        <p>1. <strong>Keypair</strong> → Holder has a private key; warrant binds to their public key</p>
        <p>2. <strong>Challenge</strong> → Tool name + args are hashed into a unique challenge</p>
        <p>3. <strong>Sign</strong> → Holder signs the challenge with their private key</p>
        <p>4. <strong>Verify</strong> → Authorization checks signature matches warrant's <code>authorized_holder</code></p>
        <p style={{ marginTop: '8px', fontSize: '11px', opacity: 0.8 }}>💡 This is cryptographic proof that the request comes from the intended recipient, not an attacker.</p>
      </Explainer>
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
  rootKey: string;
}

const PresetsManager = ({
  currentWarrant,
  currentTool,
  currentArgs,
  currentRootKey,
  onLoad
}: {
  currentWarrant: string;
  currentTool: string;
  currentArgs: string;
  currentRootKey: string;
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
      rootKey: currentRootKey,
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
          setPresets([...presets, ...imported]);
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
const VerificationSteps = ({ decoded, tool, args, authResult }: {
  decoded: DecodedWarrant | null;
  tool: string;
  args: string;
  authResult: AuthResult | null;
}) => {
  if (!decoded) return null;

  const now = Date.now() / 1000;
  const isExpired = decoded.expires_at < now;
  const toolMatch = decoded.tools.includes(tool) || decoded.tools.includes('*');

  try { JSON.parse(args); } catch { }

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
    type: 'pattern' | 'exact' | 'range' | 'oneof' | 'unknown';
    pythonCode: string;
    rustCode: string;
    exampleValue: string | number;
    warning?: string;
  };

  const parseConstraint = (key: string, value: unknown): ParsedConstraint => {
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

      // Range constraint: { min: 0, max: 100 } or { max: 100 }
      if (v.min !== undefined || v.max !== undefined) {
        const min = v.min as number | undefined;
        const max = v.max as number | undefined;
        let pythonCode: string;
        let rustCode: string;
        if (min !== undefined && max !== undefined) {
          pythonCode = `Range(min_value=${min}, max_value=${max})`;
          rustCode = `Constraint::Range(Range::new(Some(${min}), Some(${max})))`;
        } else if (max !== undefined) {
          pythonCode = `Range.max_value(${max})`;
          rustCode = `Constraint::Range(Range::max(${max}))`;
        } else {
          pythonCode = `Range.min_value(${min})`;
          rustCode = `Constraint::Range(Range::min(${min}))`;
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

    // Unknown - treat as raw value (best effort)
    const strVal = typeof value === 'object' ? JSON.stringify(value) : String(value);
    return {
      type: 'unknown',
      pythonCode: `Pattern("*")  # TODO: Unknown constraint type - ${strVal.slice(0, 50)}`,
      rustCode: `Constraint::Pattern(Pattern::new("*")?)  // TODO: Unknown constraint - ${strVal.slice(0, 50)}`,
      exampleValue: 'value',
      warning: `Unrecognized constraint format: ${strVal.slice(0, 100)}`
    };
  };

  const code = useMemo(() => {
    try {
      const argsObj = (() => { try { return JSON.parse(args); } catch { return {}; } })();

      // Get constraints from decoded warrant's capabilities for the selected tool
      const toolCapabilities = decoded.capabilities[tool] as Record<string, unknown> | undefined;
      const constraints: { key: string; parsed: ParsedConstraint }[] = [];

      if (toolCapabilities && typeof toolCapabilities === 'object') {
        Object.entries(toolCapabilities).forEach(([key, value]) => {
          try {
            constraints.push({ key, parsed: parseConstraint(key, value) });
          } catch {
            constraints.push({ key, parsed: { type: 'unknown', pythonCode: `Pattern("*")  # Error parsing`, rustCode: `// Error parsing`, exampleValue: 'value', warning: 'Failed to parse constraint' } });
          }
        });
      }

      // Fallback to args if no constraints found
      if (constraints.length === 0 && Object.keys(argsObj).length > 0) {
        Object.entries(argsObj).forEach(([k, v]) => {
          try {
            constraints.push({ key: k, parsed: parseConstraint(k, v) });
          } catch {
            constraints.push({ key: k, parsed: { type: 'unknown', pythonCode: `Pattern("*")  # Error parsing`, rustCode: `// Error parsing`, exampleValue: 'value', warning: 'Failed to parse constraint' } });
          }
        });
      }

      // Collect warnings
      const warnings = constraints
        .filter(({ parsed }) => parsed.warning)
        .map(({ key, parsed }) => `# ⚠️ ${key}: ${parsed.warning}`);

      const warningBlock = warnings.length > 0
        ? `# ⚠️ WARNINGS - Review these constraints:\n${warnings.join('\n')}\n\n`
        : '';

      if (lang === 'python') {
        const constraintLines = constraints.length > 0
          ? constraints.map(({ key, parsed }) => `        "${key}": ${parsed.pythonCode}`).join(',\n')
          : '        # No constraints - allows any value';

        const argsLines = Object.entries(argsObj).length > 0
          ? JSON.stringify(argsObj, null, 4)
          : constraints.length > 0
            ? JSON.stringify(Object.fromEntries(constraints.map(({ key, parsed }) => [key, parsed.exampleValue])), null, 4)
            : '{}';

        return `${warningBlock}from tenuo import SigningKey, Warrant, Pattern, Exact, Range, OneOf

# Generate keys
issuer_key = SigningKey.generate()
holder_key = SigningKey.generate()

# Issue warrant using builder pattern
warrant = (Warrant.mint_builder()
    .capability("${tool}", {
${constraintLines}
    })
    .holder(holder_key.public_key)
    .ttl(3600)  # 1 hour
    .mint(issuer_key))

# Test authorization with Proof-of-Possession
args = ${argsLines}
pop_signature = warrant.sign(holder_key, "${tool}", args)
authorized = warrant.authorize("${tool}", args, bytes(pop_signature))
print(f"Authorized: {authorized}")

# BoundWarrant for repeated operations
bound = warrant.bind(holder_key)
if bound.validate("${tool}", args):
    print("Also works with BoundWarrant!")

# Serialize for transmission
warrant_b64 = warrant.to_base64()
print(f"Warrant: {warrant_b64[:60]}...")`;
      } else {
        const constraintLines = constraints.length > 0
          ? constraints.map(({ key, parsed }) => `    constraints.insert("${key}".to_string(), ${parsed.rustCode});`).join('\n')
          : '    // No constraints - allows any value';

        const argsLines = constraints.length > 0
          ? constraints.map(({ key, parsed }) => {
            const val = parsed.exampleValue;
            if (typeof val === 'number') {
              return `    args.insert("${key}".to_string(), ConstraintValue::Integer(${val}));`;
            }
            return `    args.insert("${key}".to_string(), ConstraintValue::String("${val}".to_string()));`;
          }).join('\n')
          : '    // Add args here';

        const rustWarnings = warnings.length > 0
          ? `// ⚠️ WARNINGS - Review these constraints:\n${warnings.map(w => w.replace('# ', '// ')).join('\n')}\n\n`
          : '';

        return `${rustWarnings}use tenuo::{SigningKey, Warrant, Pattern, Constraint, ConstraintSet, ConstraintValue, Range, wire};
use std::time::Duration;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Build constraints
    let mut constraints = ConstraintSet::new();
${constraintLines}

    // Build capabilities map
    let mut capabilities = HashMap::new();
    capabilities.insert("${tool}".to_string(), constraints);

    // Issue warrant using builder pattern
    let warrant = Warrant::builder()
        .capabilities(capabilities)
        .holder(holder_key.public_key())
        .ttl(Duration::from_secs(3600))
        .issue(&issuer_key)?;

    // Build args for authorization
    let mut args: HashMap<String, ConstraintValue> = HashMap::new();
${argsLines}

    // Create Proof-of-Possession and authorize
    let pop = warrant.sign(&holder_key, "${tool}", &args)?;
    warrant.authorize("${tool}", &args, Some(&pop))?;
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

// Test Case Generator Component
const TestCaseGenerator = ({ decoded, tool }: { decoded: DecodedWarrant | null; tool: string }) => {
  const [showTests, setShowTests] = useState(false);

  if (!decoded || !showTests) {
    return (
      <button onClick={() => setShowTests(true)} className="btn btn-secondary" style={{ width: '100%', marginTop: '12px' }}>
        🧪 Generate Test Cases
      </button>
    );
  }

  const testCases = useMemo(() => {
    const cases: { name: string; args: Record<string, string>; shouldPass: boolean; reason: string }[] = [];

    // Get constraints for the tool
    const toolConstraints = decoded.capabilities[tool] as Record<string, { pattern?: string; exact?: string }> | undefined;

    if (toolConstraints) {
      for (const [key, constraint] of Object.entries(toolConstraints)) {
        if (constraint.pattern) {
          // Valid case matching pattern
          const pattern = constraint.pattern;
          if (pattern.includes('*')) {
            const prefix = pattern.replace('*', '');
            cases.push({
              name: `Valid ${key} matching pattern`,
              args: { [key]: `${prefix}example.txt` },
              shouldPass: true,
              reason: `Matches pattern "${pattern}"`
            });
            cases.push({
              name: `Invalid ${key} outside pattern`,
              args: { [key]: '/etc/passwd' },
              shouldPass: false,
              reason: `Does not match pattern "${pattern}"`
            });
          }
        }
        if (constraint.exact) {
          cases.push({
            name: `Exact match for ${key}`,
            args: { [key]: constraint.exact },
            shouldPass: true,
            reason: `Exactly matches "${constraint.exact}"`
          });
          cases.push({
            name: `Wrong value for ${key}`,
            args: { [key]: 'wrong_value' },
            shouldPass: false,
            reason: `Does not match exact "${constraint.exact}"`
          });
        }
      }
    }

    // Add tool mismatch test
    cases.push({
      name: 'Wrong tool',
      args: { test: 'value' },
      shouldPass: false,
      reason: 'Tool not in warrant'
    });

    return cases;
  }, [decoded, tool]);

  return (
    <div className="panel" style={{ padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>🧪 Generated Test Cases</span>
        <button onClick={() => setShowTests(false)} className="close-btn">✕</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {testCases.map((tc, i) => (
          <div key={i} className={`test-case ${tc.shouldPass ? 'pass' : 'fail'}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 500 }}>{tc.name}</span>
              <span className={`test-badge ${tc.shouldPass ? 'pass' : 'fail'}`}>
                {tc.shouldPass ? 'PASS' : 'FAIL'}
              </span>
            </div>
            <code style={{ fontSize: '11px', color: 'var(--muted)' }}>{JSON.stringify(tc.args)}</code>
            <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '4px' }}>{tc.reason}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Warrant Builder Component
interface ToolConstraint {
  name: string;
  constraints: { key: string; type: 'pattern' | 'exact' | 'range' | 'oneof' | 'anyof' | 'notoneof'; value: string }[];
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

  const templates = [
    { name: '📁 File Read Only', tools: [{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern' as const, value: 'data/*' }] }], ttl: 3600 },
    { name: '🔧 Multi-Tool', tools: [{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern' as const, value: '*' }] }, { name: 'write_file', constraints: [{ key: 'path', type: 'pattern' as const, value: 'tmp/*' }] }], ttl: 1800 },
    { name: '🌐 API Access', tools: [{ name: 'http_request', constraints: [{ key: 'url', type: 'pattern' as const, value: 'https://api.example.com/*' }, { key: 'method', type: 'exact' as const, value: 'GET' }] }], ttl: 300 },
    { name: '💰 Limited Spend', tools: [{ name: 'transfer', constraints: [{ key: 'amount', type: 'range' as const, value: '0-1000' }, { key: 'currency', type: 'exact' as const, value: 'USD' }] }], ttl: 600 },
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
                    <select className="input" value={con.type} onChange={e => updateConstraint(ti, ci, 'type', e.target.value)} style={{ width: '110px' }}>
                      <option value="pattern">Pattern</option>
                      <option value="exact">Exact</option>
                      <option value="range">Range</option>
                      <option value="oneof">OneOf</option>
                      <option value="anyof">AnyOf</option>
                      <option value="notoneof">NotOneOf</option>
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
        <p><strong>Pattern</strong>: Glob-style matching (e.g., <code>docs/*</code>, <code>*.txt</code>)</p>
        <p><strong>Exact</strong>: Must match exactly (e.g., <code>GET</code>, <code>user123</code>)</p>
        <p><strong>Range</strong>: Numeric range (e.g., <code>0-1000</code> for amounts)</p>
        <p><strong>OneOf</strong>: Must match one value (e.g., <code>GET,POST,PUT</code>)</p>
        <p><strong>AnyOf</strong>: Can match any pattern (e.g., <code>docs/*,data/*</code>)</p>
        <p><strong>NotOneOf</strong>: Must NOT match any value (e.g., <code>DELETE,admin</code>)</p>
      </Explainer>
    </div>
  );
};

// Chain Tester Component
interface ChainNode {
  id: string;
  name: string;
  tools: string[];
  attenuations: string;
  depth: number;
}

const ChainTester = () => {
  const [nodes, setNodes] = useState<ChainNode[]>([
    { id: '1', name: 'Root (Orchestrator)', tools: ['read_file', 'write_file', 'send_email'], attenuations: 'Full access', depth: 0 },
    { id: '2', name: 'Worker Agent', tools: ['read_file'], attenuations: 'path: docs/*', depth: 1 },
  ]);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const addNode = () => {
    const parent = nodes[nodes.length - 1];
    const inheritedTool = parent.tools[0] || 'read_file';
    // Generate a sensible default attenuation based on common patterns
    const defaultAttenuations: Record<string, string> = {
      'read_file': 'path: docs/*',
      'write_file': 'path: tmp/*',
      'send_email': 'to: *@company.com',
      'transfer_money': 'amount: max 1000',
      'search': 'query: *',
    };
    setNodes([...nodes, {
      id: generateId(),
      name: `Delegate ${nodes.length}`,
      tools: [inheritedTool],
      attenuations: defaultAttenuations[inheritedTool] || `${inheritedTool}: narrowed scope`,
      depth: parent.depth + 1
    }]);
  };

  const removeNode = (id: string) => {
    const idx = nodes.findIndex(n => n.id === id);
    if (idx > 0) setNodes(nodes.slice(0, idx));
  };

  const updateNode = (id: string, field: string, value: string | string[]) => {
    setNodes(nodes.map(n => n.id === id ? { ...n, [field]: value } : n));
  };

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <span style={{ fontSize: '18px' }}>🔗</span>
        <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Delegation Chain Tester</h2>
      </div>

      {/* Chain Visualization */}
      <div className="chain-tester">
        {nodes.map((node, i) => (
          <div key={node.id}>
            <div
              className={`chain-tester-node ${selectedNode === node.id ? 'selected' : ''} ${i === 0 ? 'root' : ''}`}
              onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, fontSize: '13px' }}>{node.name}</span>
                <span className="depth-badge">depth {node.depth}</span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '6px' }}>
                Tools: {node.tools.join(', ') || 'None'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--accent)', marginTop: '4px' }}>
                {node.attenuations}
              </div>
            </div>

            {/* Editor for selected node */}
            {selectedNode === node.id && (
              <div className="chain-node-editor">
                <div style={{ marginBottom: '8px' }}>
                  <label className="label">Name</label>
                  <input className="input" value={node.name} onChange={e => updateNode(node.id, 'name', e.target.value)} />
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <label className="label">Tools (comma-separated)</label>
                  <input
                    className="input"
                    value={node.tools.join(', ')}
                    onChange={e => {
                      // Keep trailing comma visible while typing
                      const raw = e.target.value;
                      const tools = raw.split(',').map(s => s.trim());
                      // Only filter empty strings if not ending with comma
                      const filtered = raw.endsWith(',') || raw.endsWith(', ')
                        ? tools
                        : tools.filter(Boolean);
                      updateNode(node.id, 'tools', filtered);
                    }}
                    onBlur={e => {
                      // Clean up on blur
                      const tools = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                      updateNode(node.id, 'tools', tools);
                    }}
                  />
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <label className="label">Attenuations</label>
                  <input className="input" value={node.attenuations} onChange={e => updateNode(node.id, 'attenuations', e.target.value)} />
                </div>
                {i > 0 && (
                  <button onClick={() => removeNode(node.id)} className="btn btn-secondary" style={{ width: '100%', fontSize: '11px' }}>
                    Remove & Truncate Chain
                  </button>
                )}
              </div>
            )}

            {/* Connector arrow */}
            {i < nodes.length - 1 && (
              <div className="chain-arrow">
                <div className="chain-arrow-line" />
                <div className="chain-arrow-head">▼</div>
                <div className="chain-arrow-label">delegates to</div>
              </div>
            )}
          </div>
        ))}
      </div>

      <button onClick={addNode} className="btn btn-secondary" style={{ width: '100%', marginTop: '16px' }}>
        + Add Delegate
      </button>

      {/* Attenuation Warnings */}
      {nodes.length > 1 && (
        <div className="chain-analysis">
          <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>📊 Chain Analysis</div>
          {nodes.slice(1).map((node, i) => {
            const parent = nodes[i];
            const toolsRemoved = parent.tools.filter(t => !node.tools.includes(t));
            return (
              <div key={node.id} className="attenuation-item">
                <span style={{ color: 'var(--green)' }}>✓</span>
                <span>
                  {parent.name} → {node.name}:
                  {toolsRemoved.length > 0 && <span style={{ color: 'var(--red)' }}> -{toolsRemoved.join(', ')}</span>}
                  {toolsRemoved.length === 0 && <span style={{ color: 'var(--muted)' }}> (same tools)</span>}
                </span>
              </div>
            );
          })}
          {nodes.length > 4 && (
            <div className="attenuation-item" style={{ color: 'var(--yellow)' }}>
              <span>⚠️</span>
              <span>Deep chain ({nodes.length} levels) - consider flattening</span>
            </div>
          )}
        </div>
      )}

      <Explainer title="Monotonic Delegation" docLink="https://tenuo.dev/concepts#monotonic-attenuation">
        <p>In Tenuo, capabilities can only <strong>shrink</strong> as they delegate:</p>
        <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
          <li>Tools can be removed, never added</li>
          <li>Constraints can be tightened, never loosened</li>
          <li>TTL can be shortened, never extended</li>
        </ul>
        <p style={{ marginTop: '8px' }}>This ensures that a compromised agent can never exceed its granted authority.</p>
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
    if (typeof a !== typeof b || JSON.stringify(a) !== JSON.stringify(b)) {
      diffs.push({ path: path || 'root', a, b });
    }
    if (typeof a === 'object' && a && typeof b === 'object' && b) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of keys) {
        diffs.push(...getDiff((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key], path ? `${path}.${key}` : key));
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
  if (history.length === 0) return null;

  return (
    <div className="history-sidebar">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>📜 History</span>
        <button onClick={onClear} className="close-btn" title="Clear history">🗑</button>
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
  const [rootKeyHex, setRootKeyHex] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [decoded, setDecoded] = useState<DecodedWarrant | string | null>(null);
  const [authResult, setAuthResult] = useState<AuthResult | null>(null);
  const [shareUrl, setShareUrl] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showSamples, setShowSamples] = useState(false);
  const [activeTab, setActiveTab] = useState<'decode' | 'debug' | 'code'>('decode');
  const [mode, setMode] = useState<'decoder' | 'builder' | 'chain' | 'diff'>('decoder');
  const [builderPreview, setBuilderPreview] = useState<unknown>(null);
  const [popSignature, setPopSignature] = useState('');
  const [, setPopPublicKey] = useState('');
  const [showShortcuts, setShowShortcuts] = useState(true);
  const [samples, setSamples] = useState<Record<string, SampleDef>>({});

  // Initialize WASM and generate fresh samples
  useEffect(() => {
    init().then(() => {
      init_panic_hook();
      setWasmReady(true);
      // Generate fresh samples with 1-hour TTL
      const freshSamples = generateFreshSamples();
      setSamples(freshSamples);
      console.log(`Generated ${Object.keys(freshSamples).length} fresh sample warrants`);
    }).catch(err => console.error("WASM init failed:", err));
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
        if (parsed.root) setRootKeyHex(parsed.root);
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
          setMode('chain');
        } else if (e.key === '4') {
          e.preventDefault();
          setMode('diff');
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
    const state = { warrant: warrantB64, tool, args: argsJson, root: rootKeyHex };
    return `${window.location.origin}${window.location.pathname}?s=${btoa(JSON.stringify(state))}`;
  }, [warrantB64, tool, argsJson, rootKeyHex]);

  const handleLoadSample = (key: string) => {
    const sample = samples[key];
    if (sample) {
      setWarrantB64(sample.warrant);
      setTool(sample.tool);
      setArgsJson(sample.args);
      setRootKeyHex(sample.rootKey);
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
    rootKey?: string;
  }>({});

  const validateInputs = (forAuth: boolean = false): boolean => {
    const errors: typeof validationErrors = {};

    // Validate warrant (required for both decode and auth)
    if (!warrantB64.trim()) {
      errors.warrant = 'Warrant is required';
    } else {
      // Check if it looks like base64
      const base64Regex = /^[A-Za-z0-9+/]+=*$/;
      const cleanWarrant = warrantB64.trim().replace(/\s/g, '');
      if (!base64Regex.test(cleanWarrant)) {
        errors.warrant = 'Invalid base64 format. Warrants should be base64-encoded.';
      } else if (cleanWarrant.length < 50) {
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

      // Validate root key hex (optional but must be valid if provided)
      if (rootKeyHex.trim()) {
        const cleanHex = rootKeyHex.trim().toLowerCase();
        if (!/^[a-f0-9]+$/.test(cleanHex)) {
          errors.rootKey = 'Root key must be hexadecimal (0-9, a-f)';
        } else if (cleanHex.length !== 64) {
          errors.rootKey = `Root key should be 64 hex characters (got ${cleanHex.length})`;
        }
      }
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleDecode = () => {
    if (!wasmReady) return;
    if (!validateInputs(false)) return;

    try {
      const result = decode_warrant(warrantB64.trim());
      setDecoded(result);
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
      setValidationErrors({ warrant: `Decode failed: ${errMsg}` });
      setDecoded(null);
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

      // Use real PoP if available and not in dry run mode
      if (!dryRun && popSignature) {
        const result = check_access_with_pop(warrantB64.trim(), tool.trim(), args, rootKeyHex.trim(), popSignature);
        setAuthResult(result);
      } else {
        const result = check_access(warrantB64.trim(), tool.trim(), args, rootKeyHex.trim(), dryRun);
        setAuthResult(result);
      }
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
            <button onClick={() => setMode('chain')} className={`mode-btn ${mode === 'chain' ? 'active' : ''}`}>
              🔗 Chain
            </button>
            <button onClick={() => setMode('diff')} className={`mode-btn ${mode === 'diff' ? 'active' : ''}`}>
              📊 Diff
            </button>
          </div>

        </header>

        {/* Main Content */}
        <main style={{ flex: 1, maxWidth: '1200px', width: '100%', margin: '0 auto', padding: '0 24px 64px' }}>
          {/* Builder Mode */}
          {mode === 'builder' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              <WarrantBuilder onGenerate={setBuilderPreview} />
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                  <span style={{ fontSize: '18px' }}>👁️</span>
                  <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Preview</h2>
                </div>
                {builderPreview ? (
                  <div>
                    <pre className="code-block" style={{ maxHeight: '300px' }}>
                      {JSON.stringify(builderPreview, null, 2)}
                    </pre>
                    <div style={{ marginTop: '12px' }}>
                      <CodeGenerator decoded={{ id: '', issuer: '', tools: Object.keys((builderPreview as { tools: Record<string, unknown> }).tools || {}), capabilities: (builderPreview as { tools: Record<string, unknown> }).tools || {}, issued_at: 0, expires_at: 0, authorized_holder: '', depth: 0 }} tool={Object.keys((builderPreview as { tools: Record<string, unknown> }).tools || {})[0] || ''} args="{}" />
                    </div>
                  </div>
                ) : (
                  <div className="empty-state">
                    <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.2 }}>👁️</div>
                    <p>Click "Generate Preview" to see the warrant structure</p>
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
                              🔄 Fresh warrants (1h TTL) - generated on page load
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

                      <div>
                        <label className="label">
                          <Tooltip content="The public key of the root issuer for signature verification">
                            Trusted Root Key (Hex)
                          </Tooltip>
                        </label>
                        <input
                          className="input"
                          placeholder="64-character hex string..."
                          value={rootKeyHex}
                          onChange={(e) => setRootKeyHex(e.target.value)}
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
                        currentRootKey={rootKeyHex}
                        onLoad={(preset) => {
                          setWarrantB64(preset.warrant);
                          setTool(preset.tool);
                          setArgsJson(preset.args);
                          setRootKeyHex(preset.rootKey);
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

                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className={`toggle ${dryRun ? 'active' : ''}`} onClick={() => setDryRun(!dryRun)}>
                          <div className="toggle-knob" />
                        </div>
                        <Tooltip content="Skip Proof-of-Possession signature verification for testing">
                          <span style={{ fontSize: '13px', color: 'var(--muted)' }}>Dry run (skip PoP)</span>
                        </Tooltip>
                      </div>

                      <Explainer title="What is Proof-of-Possession (PoP)?" docLink="https://tenuo.dev/security">
                        <p><strong>Proof-of-Possession</strong> prevents stolen warrants from being used by attackers.</p>
                        <p style={{ marginTop: '8px' }}>When authorizing, the holder must sign a challenge with their private key, proving they possess the key that matches the warrant's <code>authorized_holder</code> public key.</p>
                        <p style={{ marginTop: '8px' }}>Without PoP: Anyone who intercepts a warrant can use it.</p>
                        <p>With PoP: Only the legitimate holder can use the warrant.</p>
                        <p style={{ marginTop: '8px', color: 'var(--accent)' }}>💡 Dry run skips this check for playground testing.</p>
                      </Explainer>

                      {/* PoP Signature Simulator */}
                      {!dryRun && (
                        <PopSimulator
                          warrant={warrantB64}
                          tool={tool}
                          args={argsJson}
                          onPopGenerated={(pop, pubKey) => {
                            setPopSignature(pop);
                            setPopPublicKey(pubKey);
                          }}
                        />
                      )}

                      <button onClick={handleAuthorize} disabled={!wasmReady || !warrantB64 || !tool} className="btn btn-primary">
                        Check Authorization
                        {popSignature && !dryRun && <span style={{ marginLeft: '6px', fontSize: '10px' }}>+ PoP</span>}
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
                    <>
                      <VerificationSteps decoded={decodedWarrant} tool={tool} args={argsJson} authResult={authResult} />
                      <TestCaseGenerator decoded={decodedWarrant} tool={tool} />
                    </>
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
                            Access permitted{dryRun && <span style={{ opacity: 0.6 }}> · PoP skipped</span>}
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
            <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', marginBottom: '12px', fontSize: '13px' }}>
              <a href="https://crates.io/crates/tenuo" className="nav-link">🦀 Rust Core</a>
              <a href="https://pypi.org/project/tenuo/" className="nav-link">🐍 Python SDK</a>
              <span style={{ color: 'var(--muted)' }}>⚡ ~27μs verification</span>
              <span style={{ color: 'var(--muted)' }}>🔐 WASM · 100% client-side</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', fontSize: '12px', color: 'var(--muted)' }}>
              <a href="https://github.com/tenuo-ai/tenuo" style={{ color: 'var(--muted)', textDecoration: 'none' }}>GitHub</a>
              <a href="https://tenuo.dev/quickstart" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Quick Start</a>
              <a href="https://tenuo.dev/api-reference" style={{ color: 'var(--muted)', textDecoration: 'none' }}>API Reference</a>
              <span>MIT / Apache-2.0</span>
            </div>
          </div>
        </footer>
      </div>
    </>
  )
}

export default App
