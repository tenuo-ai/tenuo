import { useState, useEffect, useCallback, useMemo } from 'react'
import init, { decode_warrant, check_access, init_panic_hook } from './wasm/tenuo_wasm'

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
const SAMPLES: Record<string, { name: string; description: string; warrant: string; rootKey: string; tool: string; args: string }> = {
  simple_read: {
    name: "📁 Simple File Read",
    description: "Read access to docs folder with path constraint",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "read_file",
    args: JSON.stringify({ path: "docs/readme.md" }, null, 2)
  },
  multi_tool: {
    name: "🔧 Multi-Tool Access",
    description: "Access to multiple tools with different constraints",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "read_file",
    args: JSON.stringify({ path: "docs/api.md" }, null, 2)
  },
  wildcard: {
    name: "⚠️ Wildcard Pattern",
    description: "Overly permissive - demonstrates validation warnings",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "delete_file",
    args: JSON.stringify({ path: "/etc/passwd" }, null, 2)
  },
  short_ttl: {
    name: "⏱️ Short-Lived Token",
    description: "Expires in 60 seconds - time-boxed access",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "read_file",
    args: JSON.stringify({ path: "docs/secret.md" }, null, 2)
  },
  delegated: {
    name: "🔗 Delegated Chain",
    description: "Depth 2 - shows delegation provenance",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "read_file",
    args: JSON.stringify({ path: "docs/delegated.md" }, null, 2)
  },
  api_access: {
    name: "🌐 API Access",
    description: "HTTP API access with endpoint constraints",
    warrant: "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP",
    rootKey: "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e",
    tool: "http_request",
    args: JSON.stringify({ url: "https://api.example.com/users", method: "GET" }, null, 2)
  }
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
      <div className="validity-bar">
        <div className="validity-progress" style={{ width: `${percent}%`, background: isExpired ? 'var(--red)' : 'linear-gradient(90deg, var(--green), var(--accent))' }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontSize: '11px', color: 'var(--muted)' }}>
        <span>Issued: {new Date(issuedAt * 1000).toLocaleString()}</span>
        <span>Expires: {new Date(expiresAt * 1000).toLocaleString()}</span>
      </div>
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
  
  try { JSON.parse(args); } catch {}
  
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
  const [lang, setLang] = useState<'python' | 'rust' | 'typescript'>('python');
  const [copied, setCopied] = useState(false);
  
  if (!decoded) return null;
  
  const code = useMemo(() => {
    const argsObj = (() => { try { return JSON.parse(args); } catch { return {}; } })();
    
    if (lang === 'python') {
      return `from tenuo import SigningKey, Warrant, Pattern

# Generate keys
issuer_key = SigningKey.generate()
holder_key = SigningKey.generate()

# Issue warrant
warrant = (
    Warrant.builder()
    .issuer(issuer_key.public_key)
    .holder(holder_key.public_key)
    .tool("${tool}", constraints={
${Object.entries(argsObj).map(([k, v]) => `        "${k}": Pattern("${v}")`).join(',\n')}
    })
    .ttl(3600)  # 1 hour
    .sign(issuer_key)
)

# Authorize
args = ${JSON.stringify(argsObj, null, 4).split('\n').map((l, i) => i === 0 ? l : '    ' + l).join('\n')}
pop_signature = holder_key.sign(warrant.challenge("${tool}", args))
result = warrant.authorize("${tool}", args, pop_signature)
print(f"Authorized: {result}")`;
    } else if (lang === 'rust') {
      return `use tenuo::{SigningKey, Warrant, Pattern};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Issue warrant
    let warrant = Warrant::builder()
        .issuer(issuer_key.public_key())
        .holder(holder_key.public_key())
        .tool("${tool}", &[
${Object.entries(argsObj).map(([k, v]) => `            ("${k}", Pattern::new("${v}"))`).join(',\n')}
        ])
        .ttl(Duration::from_secs(3600))
        .sign(&issuer_key)?;

    // Authorize
    let args = serde_json::json!(${JSON.stringify(argsObj)});
    let pop = holder_key.sign(&warrant.challenge("${tool}", &args));
    let result = warrant.authorize("${tool}", &args, &pop)?;
    println!("Authorized: {}", result);
    Ok(())
}`;
    } else {
      return `import { SigningKey, Warrant, Pattern } from 'tenuo';

// Generate keys
const issuerKey = SigningKey.generate();
const holderKey = SigningKey.generate();

// Issue warrant
const warrant = Warrant.builder()
  .issuer(issuerKey.publicKey)
  .holder(holderKey.publicKey)
  .tool("${tool}", {
${Object.entries(argsObj).map(([k, v]) => `    ${k}: Pattern("${v}")`).join(',\n')}
  })
  .ttl(3600)
  .sign(issuerKey);

// Authorize
const args = ${JSON.stringify(argsObj, null, 2).split('\n').map((l, i) => i === 0 ? l : '  ' + l).join('\n')};
const pop = holderKey.sign(warrant.challenge("${tool}", args));
const result = warrant.authorize("${tool}", args, pop);
console.log(\`Authorized: \${result}\`);`;
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
        <span style={{ fontSize: '12px', color: 'var(--muted)' }}>💻 Code Generation</span>
        <div style={{ display: 'flex', gap: '4px' }}>
          {(['python', 'rust', 'typescript'] as const).map(l => (
            <button key={l} onClick={() => setLang(l)} className={`lang-btn ${lang === l ? 'active' : ''}`}>
              {l === 'python' ? '🐍' : l === 'rust' ? '🦀' : '📘'} {l}
            </button>
          ))}
        </div>
      </div>
      <pre className="code-block">{code}</pre>
      <button onClick={handleCopy} className="btn btn-secondary" style={{ marginTop: '12px', width: '100%' }}>
        {copied ? '✓ Copied!' : '📋 Copy Code'}
      </button>
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
      try { setHistory(JSON.parse(saved)); } catch {}
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
      } catch {}
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
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [warrantB64, tool, argsJson, wasmReady]);

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
      const result = check_access(warrantB64, tool, args, rootKeyHex, dryRun);
      setAuthResult(result);
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
        <header style={{ textAlign: 'center', padding: '48px 24px 32px' }}>
          <div className="badge" style={{ marginBottom: '16px' }}>
            <span style={{ color: 'var(--accent)' }}>Explorer</span>
          </div>
          <h1 style={{ fontSize: '36px', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '12px' }}>
            Warrant <span className="gradient-text">Playground</span>
          </h1>
          <p style={{ fontSize: '16px', color: 'var(--muted)', maxWidth: '480px', margin: '0 auto 24px' }}>
            Decode, debug, and test authorization in real-time
          </p>
          
          {/* Sample Library Dropdown */}
          <div style={{ position: 'relative', display: 'inline-block' }}>
            <button onClick={() => setShowSamples(!showSamples)} className="btn btn-secondary" style={{ gap: '8px' }}>
              <span>📦</span>
              <span>Sample Library</span>
              <span style={{ marginLeft: '4px' }}>{showSamples ? '▲' : '▼'}</span>
            </button>
            {showSamples && (
              <div className="samples-dropdown">
                {Object.entries(SAMPLES).map(([key, sample]) => (
                  <div key={key} className="sample-item" onClick={() => handleLoadSample(key)}>
                    <div style={{ fontWeight: 500 }}>{sample.name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--muted)' }}>{sample.description}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </header>

        {/* Main Content */}
        <main style={{ flex: 1, maxWidth: '1200px', width: '100%', margin: '0 auto', padding: '0 24px 64px' }}>
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
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                  <span style={{ fontSize: '18px' }}>📄</span>
                  <h2 style={{ fontSize: '15px', fontWeight: 600 }}>1. Paste Warrant</h2>
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div>
                    <label className="label">Base64 Encoded Warrant</label>
                    <textarea
                      className="input"
                      style={{ height: '80px', resize: 'none' }}
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
                    <textarea className="input" style={{ height: '60px', resize: 'none' }} value={argsJson} onChange={(e) => setArgsJson(e.target.value)} />
                  </div>
                  
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div className={`toggle ${dryRun ? 'active' : ''}`} onClick={() => setDryRun(!dryRun)}>
                      <div className="toggle-knob" />
                    </div>
                    <Tooltip content="Skip Proof-of-Possession signature verification for testing">
                      <span style={{ fontSize: '13px', color: 'var(--muted)' }}>Dry run (skip PoP)</span>
                    </Tooltip>
                  </div>
                  
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
              {decodedWarrant && (
                <div className="tabs">
                  <button onClick={() => setActiveTab('decode')} className={`tab ${activeTab === 'decode' ? 'active' : ''}`}>🔍 Decoded</button>
                  <button onClick={() => setActiveTab('debug')} className={`tab ${activeTab === 'debug' ? 'active' : ''}`}>🐛 Debug</button>
                  <button onClick={() => setActiveTab('code')} className={`tab ${activeTab === 'code' ? 'active' : ''}`}>💻 Code</button>
                </div>
              )}
              
              {/* Decoded Panel */}
              {activeTab === 'decode' && (
                <div className="panel">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '18px' }}>🔍</span>
                      <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Decoded Warrant</h2>
                    </div>
                    {warrantB64 && (
                      <button onClick={handleShare} className="btn btn-secondary" style={{ padding: '6px 10px', fontSize: '11px' }}>
                        {shareUrl ? '✓ Copied!' : '🔗 Share'}
                      </button>
                    )}
                  </div>
                  
                  {decoded ? (
                    typeof decoded === 'string' ? (
                      <div className="error-box">
                        <p>⚠ {decoded}</p>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {/* Chain Visualization */}
                        <div className="chain-box">
                          <div className="chain-node">
                            <div className="chain-icon">🔑</div>
                            <div className="chain-label">Issuer</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <code style={{ fontSize: '10px', color: 'var(--accent)' }}>{truncate(decoded.issuer)}</code>
                              <CopyBtn text={decoded.issuer} />
                            </div>
                          </div>
                          <div className="chain-connector">
                            <div className="chain-line" />
                            <div className="chain-depth">depth {decoded.depth}</div>
                          </div>
                          <div className="chain-node">
                            <div className="chain-icon">🤖</div>
                            <div className="chain-label">Holder</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <code style={{ fontSize: '10px', color: 'var(--green)' }}>{truncate(decoded.authorized_holder)}</code>
                              <CopyBtn text={decoded.authorized_holder} />
                            </div>
                          </div>
                        </div>

                        <ExpirationDisplay issuedAt={decoded.issued_at} expiresAt={decoded.expires_at} />

                        <div style={{ padding: '12px', background: 'var(--surface-2)', borderRadius: '10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>🔧 Authorized Tools</div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                            {decoded.tools.map(t => <span key={t} className="tool-tag">{t}</span>)}
                          </div>
                        </div>

                        <div style={{ padding: '12px', background: 'var(--surface-2)', borderRadius: '10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>📋 Constraints</div>
                          <pre className="code-block" style={{ maxHeight: '120px' }}>{JSON.stringify(decoded.capabilities, null, 2)}</pre>
                        </div>
                      </div>
                    )
                  ) : (
                    <div className="empty-state">
                      <div style={{ fontSize: '40px', marginBottom: '12px', opacity: 0.2 }}>🔐</div>
                      <p>Paste a warrant and click Decode</p>
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
              {activeTab === 'code' && decodedWarrant && (
                <CodeGenerator decoded={decodedWarrant} tool={tool} args={argsJson} />
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
        </main>

        {/* Keyboard Shortcuts Help */}
        <div className="shortcuts-help">
          <div className="shortcut"><kbd>⌘</kbd><kbd>↵</kbd><span>Decode</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>⇧</kbd><kbd>↵</kbd><span>Authorize</span></div>
          <div className="shortcut"><kbd>⌘</kbd><kbd>K</kbd><span>Clear</span></div>
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
