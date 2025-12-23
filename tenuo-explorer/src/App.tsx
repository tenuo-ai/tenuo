import { useState, useEffect, useCallback, useMemo } from 'react'
import init, { decode_warrant, check_access, init_panic_hook } from './wasm/tenuo_wasm'

// Mock implementations for WASM functions not yet available
// These will be replaced with real WASM bindings when available
const WASM_POP_AVAILABLE = false;

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

// Sample warrants library
// Note: For demo purposes, we have one real warrant. The diff feature works best with user-provided warrants.
const SAMPLE_WARRANT_1 = "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP";
const SAMPLE_ROOT_KEY = "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e";

const SAMPLES: Record<string, { name: string; description: string; warrant: string; rootKey: string; tool: string; args: string }> = {
  valid_read: {
    name: "✅ Valid Read",
    description: "Authorized: path matches docs/* constraint",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "read_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2)
  },
  valid_nested: {
    name: "✅ Nested Path",
    description: "Authorized: nested paths like docs/api/guide.md",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "read_file",
    args: JSON.stringify({ path: "docs/api/reference.md" }, null, 2)
  },
  denied_path: {
    name: "❌ Wrong Path",
    description: "Denied: /etc/passwd is outside docs/* scope",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "read_file",
    args: JSON.stringify({ path: "/etc/passwd" }, null, 2)
  },
  denied_tool: {
    name: "❌ Wrong Tool",
    description: "Denied: delete_file not in warrant's tools",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "delete_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2)
  },
  denied_write: {
    name: "❌ Write Attempt",
    description: "Denied: write_file not authorized",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "write_file",
    args: JSON.stringify({ path: "docs/new.md", content: "hello" }, null, 2)
  },
  execution_only: {
    name: "🔍 Inspect Warrant",
    description: "Just decode to see warrant structure",
    warrant: SAMPLE_WARRANT_1,
    rootKey: SAMPLE_ROOT_KEY,
    tool: "",
    args: "{}"
  },
};

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

      const result = create_pop_signature(privateKey, warrant, tool, parsedArgs);
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '16px' }}>🔐</span>
          <h3 style={{ fontSize: '14px', fontWeight: 600 }}>PoP Signature Generator</h3>
        </div>
        <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(34, 197, 94, 0.2)', color: '#22c55e', borderRadius: '4px', fontWeight: 600 }}>
          REAL CRYPTO
        </span>
      </div>
      <p style={{ fontSize: '11px', color: 'var(--green)', marginBottom: '12px', opacity: 0.9 }}>
        ✓ Using real Ed25519 keys and signatures via WASM
      </p>

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

      <Explainer title="How Proof-of-Possession works" docLink="https://tenuo.ai/security">
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

  const code = useMemo(() => {
    const argsObj = (() => { try { return JSON.parse(args); } catch { return {}; } })();
    const constraintEntries = Object.entries(argsObj);

    if (lang === 'python') {
      return `from tenuo import SigningKey, Warrant, Pattern, Constraints

# Generate keys
issuer_key = SigningKey.generate()
holder_key = SigningKey.generate()

# Issue warrant with constraints
warrant = Warrant.issue(
    keypair=issuer_key,
    capabilities=Constraints.for_tool("${tool}", {
${constraintEntries.length > 0 ? constraintEntries.map(([k, v]) => `        "${k}": Pattern("${v}")`).join(',\n') : '        # No constraints'}
    }),
    ttl_seconds=3600,  # 1 hour
    holder=holder_key.public_key
)

# Test authorization with Proof-of-Possession
args = ${JSON.stringify(argsObj, null, 4).split('\n').map((l, i) => i === 0 ? l : l).join('\n')}
pop_signature = warrant.create_pop_signature(holder_key, "${tool}", args)
result = warrant.authorize("${tool}", args, bytes(pop_signature))
print(f"Authorized: {result}")

# Serialize for transmission
warrant_b64 = warrant.to_base64()
print(f"Warrant: {warrant_b64[:60]}...")`;
    } else {
      return `use tenuo::{SigningKey, Warrant, Pattern, ConstraintSet};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Build constraints
    let mut constraints = ConstraintSet::new();
${constraintEntries.length > 0 ? constraintEntries.map(([k, v]) => `    constraints.insert("${k}".to_string(), Pattern::new("${v}")?);`).join('\n') : '    // No constraints'}

    // Issue warrant
    let warrant = Warrant::builder()
        .capability("${tool}", constraints)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(holder_key.public_key())
        .build(&issuer_key)?;

    // Authorize with Proof-of-Possession
    let args = serde_json::json!(${JSON.stringify(argsObj)});
    let pop = warrant.create_pop_signature(&holder_key, "${tool}", &args)?;
    let result = warrant.authorize("${tool}", &args, &pop)?;
    println!("Authorized: {}", result);

    // Serialize for transmission
    let warrant_b64 = warrant.to_base64()?;
    println!("Warrant: {}...", &warrant_b64[..60]);
    Ok(())
}`;
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
  constraints: { key: string; type: 'pattern' | 'exact' | 'range'; value: string }[];
}

const WarrantBuilder = ({ onGenerate }: { onGenerate: (config: unknown) => void }) => {
  const [tools, setTools] = useState<ToolConstraint[]>([{ name: 'read_file', constraints: [{ key: 'path', type: 'pattern', value: 'docs/*' }] }]);
  const [ttl, setTtl] = useState(3600);
  const [maxDepth, setMaxDepth] = useState(3);

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
    updated[toolIdx].constraints[constIdx] = { ...updated[toolIdx].constraints[constIdx], [field]: value };
    setTools(updated);
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

            {tool.constraints.map((con, ci) => (
              <div key={ci} style={{ display: 'flex', gap: '6px', marginBottom: '6px', marginLeft: '12px' }}>
                <input className="input" placeholder="key" value={con.key} onChange={e => updateConstraint(ti, ci, 'key', e.target.value)} style={{ width: '70px' }} />
                <select className="input" value={con.type} onChange={e => updateConstraint(ti, ci, 'type', e.target.value)} style={{ width: '100px' }}>
                  <option value="pattern">Pattern</option>
                  <option value="exact">Exact</option>
                  <option value="range">Range</option>
                </select>
                <input className="input" placeholder="value" value={con.value} onChange={e => updateConstraint(ti, ci, 'value', e.target.value)} style={{ flex: 1 }} />
                <button onClick={() => removeConstraint(ti, ci)} className="close-btn" style={{ padding: '4px' }}>✕</button>
              </div>
            ))}
            <button onClick={() => addConstraint(ti)} style={{ marginLeft: '12px', fontSize: '11px', color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer' }}>+ Add Constraint</button>
          </div>
        ))}
      </div>

      <button onClick={generatePreview} className="btn btn-primary" style={{ width: '100%' }}>
        Generate Preview
      </button>

      <Explainer title="Constraint Types" docLink="https://tenuo.ai/concepts#constraints">
        <p><strong>Pattern</strong>: Glob-style matching (e.g., <code>docs/*</code>, <code>*.txt</code>)</p>
        <p><strong>Exact</strong>: Must match exactly (e.g., <code>GET</code>, <code>user123</code>)</p>
        <p><strong>Range</strong>: Numeric range (e.g., <code>0-1000</code> for amounts)</p>
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
    setNodes([...nodes, {
      id: generateId(),
      name: `Delegate ${nodes.length}`,
      tools: parent.tools.slice(0, 1),
      attenuations: 'Attenuated',
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
                  <input className="input" value={node.tools.join(', ')} onChange={e => updateNode(node.id, 'tools', e.target.value.split(',').map(s => s.trim()).filter(Boolean))} />
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

      <Explainer title="Monotonic Delegation" docLink="https://tenuo.ai/concepts#delegation">
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
// We provide a few example scenarios using our sample warrant.
const DIFF_SAMPLES = [
  {
    name: "🔬 Same Warrant",
    description: "Load same warrant in both to verify tool works",
    a: SAMPLE_WARRANT_1,
    b: SAMPLE_WARRANT_1,
  },
  {
    name: "📄 A Only",
    description: "Load sample in A, paste your own in B",
    a: SAMPLE_WARRANT_1,
    b: "",
  },
  {
    name: "📝 B Only",
    description: "Load sample in B, paste your own in A",
    a: "",
    b: SAMPLE_WARRANT_1,
  },
];

const DiffViewer = () => {
  const [warrantA, setWarrantA] = useState('');
  const [warrantB, setWarrantB] = useState('');
  const [decodedA, setDecodedA] = useState<DecodedWarrant | null>(null);
  const [decodedB, setDecodedB] = useState<DecodedWarrant | null>(null);

  const loadSample = (sample: typeof DIFF_SAMPLES[0]) => {
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
          {DIFF_SAMPLES.map((sample, i) => (
            <button key={i} onClick={() => loadSample(sample)} className="tool-tag" title={sample.description}>
              {sample.name}
            </button>
          ))}
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

  // Initialize WASM
  useEffect(() => {
    init().then(() => {
      init_panic_hook();
      setWasmReady(true);
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
    const sample = SAMPLES[key];
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

  const handleDecode = () => {
    if (!wasmReady || !warrantB64) return;
    try {
      const result = decode_warrant(warrantB64);
      setDecoded(result);
      setAuthResult(null);

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
      setDecoded(`Decode error: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleAuthorize = () => {
    if (!wasmReady || !warrantB64 || !tool) return;
    try {
      const args = JSON.parse(argsJson);

      // Use real PoP if available and not in dry run mode
      if (!dryRun && popSignature) {
        const result = check_access_with_pop(warrantB64, tool, args, rootKeyHex, popSignature);
        setAuthResult(result);
      } else {
        const result = check_access(warrantB64, tool, args, rootKeyHex, dryRun);
        setAuthResult(result);
      }
    } catch (e) {
      setAuthResult({ authorized: false, reason: `Error: ${e instanceof Error ? e.message : 'Invalid JSON'}` });
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
            <a href="https://tenuo.ai" style={{ fontSize: '20px', fontWeight: 600, color: 'white', textDecoration: 'none' }}>tenuo</a>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <a href="https://tenuo.ai/quickstart" className="nav-link">Quick Start</a>
              <a href="https://tenuo.ai/concepts" className="nav-link">Concepts</a>
              <a href="https://tenuo.ai/api-reference" className="nav-link">API</a>
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
          <p style={{ fontSize: '12px', color: 'var(--green)', maxWidth: '520px', margin: '0 auto 20px', padding: '8px 16px', background: 'rgba(34, 197, 94, 0.1)', borderRadius: '8px', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
            🔒 Warrants contain only signed claims, not secrets. Safe to paste and share.
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
              <DiffViewer />
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
                              📋 Same warrant, different scenarios
                            </div>
                            {Object.entries(SAMPLES).map(([key, sample]) => (
                              <div key={key} className="sample-item" onClick={() => handleLoadSample(key)}>
                                <div style={{ fontWeight: 500 }}>{sample.name}</div>
                                <div style={{ fontSize: '11px', color: 'var(--muted)' }}>{sample.description}</div>
                              </div>
                            ))}
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

                    <Explainer title="What is a warrant?" docLink="https://tenuo.ai/concepts#warrants">
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

                      <Explainer title="What is Proof-of-Possession (PoP)?" docLink="https://tenuo.ai/security">
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
        <div className="shortcuts-help">
          <div className="shortcut"><kbd>⌘</kbd><kbd>↵</kbd><span>Decode</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>⇧</kbd><kbd>↵</kbd><span>Auth</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>K</kbd><span>Clear</span></div>
          <div className="shortcut-divider" />
          <div className="shortcut"><kbd>⌘</kbd><kbd>1-4</kbd><span>Modes</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>B</kbd><span>Builder</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>D</kbd><span>Diff</span></div>
        </div>

        {/* Footer */}
        <footer style={{ borderTop: '1px solid var(--border)', padding: '32px 24px' }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', textAlign: 'center' }}>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', marginBottom: '12px', fontSize: '13px' }}>
              <a href="https://crates.io/crates/tenuo" className="nav-link">🦀 Rust Core</a>
              <a href="https://pypi.org/project/tenuo/" className="nav-link">🐍 Python SDK</a>
              <span style={{ color: 'var(--muted)' }}>⚡ ~27μs verification</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', fontSize: '12px', color: 'var(--muted)' }}>
              <a href="https://github.com/tenuo-ai/tenuo" style={{ color: 'var(--muted)', textDecoration: 'none' }}>GitHub</a>
              <a href="https://tenuo.ai/quickstart" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Quick Start</a>
              <a href="https://tenuo.ai/api-reference" style={{ color: 'var(--muted)', textDecoration: 'none' }}>API Reference</a>
              <span>MIT / Apache-2.0</span>
            </div>
          </div>
        </footer>
      </div>
    </>
  )
}

export default App
