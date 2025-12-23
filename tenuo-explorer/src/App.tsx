import { useState, useEffect, useCallback } from 'react'
import init, { decode_warrant, check_access, init_panic_hook } from './wasm/tenuo_wasm'

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

const SAMPLE_ROOT_KEY = "4013c36794f0eae95c0262ee4788f6cf8f2dceb5dacb0e6ebcc34cde0a4e564e";
const SAMPLE_WARRANT = "gwFYq6oAAQFQAZtInVrHd8GeImZh3XfXOQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0aIICoWdwYXR0ZXJuZmRvY3MvKgSCAVggWVfWp8pMNgmK3yrmtHztN1zP-Bp3ttO7RcWoOJuhDa8FggFYIEATw2eU8OrpXAJi7keI9s-PLc612ssObrzDTN4KTlZOBhppSeKmBxppSfC2CBASAIIBWECJwEZ27MILOh05dBsPqS7CNVMiMJwN0YJNoFUJil2-AbIksCE7pLKQPpQeJelXcrrkBtK_wdHeeRjlS9cn4IEP";

const truncate = (str: string, len: number = 12) => 
  str.length > len ? `${str.slice(0, 6)}...${str.slice(-4)}` : str;

// Copy button component
const CopyBtn = ({ text }: { text: string }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      onClick={handleCopy}
      className="text-xs px-2 py-1 rounded text-[var(--muted)] hover:text-[var(--accent)] hover:bg-[var(--surface-2)] transition-all"
      title="Copy to clipboard"
    >
      {copied ? '✓' : '📋'}
    </button>
  );
};

// Collapsible explainer
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
              <a href={docLink} target="_blank" rel="noopener noreferrer">
                📖 Read the docs →
              </a>
            </p>
          )}
        </div>
      )}
    </div>
  );
};

// Expiration display with live countdown
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
        <span style={{ 
          fontSize: '14px', 
          fontWeight: 600, 
          fontFamily: "'JetBrains Mono', monospace",
          color: isExpired ? 'var(--red)' : 'var(--green)' 
        }}>
          {formatTime(remaining)}
        </span>
      </div>
      <div className="validity-bar">
        <div 
          className="validity-progress"
          style={{ 
            width: `${percent}%`,
            background: isExpired 
              ? 'var(--red)' 
              : `linear-gradient(90deg, var(--green), var(--accent))`
          }}
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontSize: '11px', color: 'var(--muted)' }}>
        <span>Issued: {new Date(issuedAt * 1000).toLocaleString()}</span>
        <span>Expires: {new Date(expiresAt * 1000).toLocaleString()}</span>
      </div>
    </div>
  );
};

function App() {
  const [wasmReady, setWasmReady] = useState(false);
  const [warrantB64, setWarrantB64] = useState("");
  const [tool, setTool] = useState("");
  const [argsJson, setArgsJson] = useState("{}");
  const [rootKeyHex, setRootKeyHex] = useState(SAMPLE_ROOT_KEY);
  const [dryRun, setDryRun] = useState(true);
  const [decoded, setDecoded] = useState<DecodedWarrant | string | null>(null);
  const [authResult, setAuthResult] = useState<AuthResult | null>(null);
  const [shareUrl, setShareUrl] = useState("");

  // Initialize WASM
  useEffect(() => {
    init().then(() => {
      init_panic_hook();
      setWasmReady(true);
    }).catch(err => {
      console.error("WASM init failed:", err);
    });
  }, []);
  
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
  
  const generateShareUrl = useCallback(() => {
    const state = { warrant: warrantB64, tool, args: argsJson, root: rootKeyHex };
    return `${window.location.origin}${window.location.pathname}?s=${btoa(JSON.stringify(state))}`;
  }, [warrantB64, tool, argsJson, rootKeyHex]);

  const handleLoadSample = () => {
    setWarrantB64(SAMPLE_WARRANT);
    setTool("read_file");
    setArgsJson(JSON.stringify({ path: "docs/readme.md" }, null, 2));
    setRootKeyHex(SAMPLE_ROOT_KEY);
    setDecoded(null);
    setAuthResult(null);
  };

  const handleDecode = () => {
    if (!wasmReady || !warrantB64) return;
    try {
      const result = decode_warrant(warrantB64);
      setDecoded(result);
      setAuthResult(null);
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
      setAuthResult({ 
        authorized: false, 
        reason: `Error: ${e instanceof Error ? e.message : 'Invalid JSON'}` 
      });
    }
  };

  const handleShare = async () => {
    const url = generateShareUrl();
    await navigator.clipboard.writeText(url);
    setShareUrl(url);
    setTimeout(() => setShareUrl(""), 2000);
  };

  return (
    <>
      {/* Background orbs */}
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      
      <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        {/* Navigation */}
        <nav style={{ borderBottom: '1px solid var(--border)' }}>
          <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <a href="https://tenuo.ai" style={{ fontSize: '20px', fontWeight: 600, color: 'white', textDecoration: 'none' }}>
              tenuo
            </a>
            <div style={{ display: 'flex', gap: '8px' }}>
              <a href="https://tenuo.ai/quickstart" className="nav-link">Quick Start</a>
              <a href="https://tenuo.ai/concepts" className="nav-link">Concepts</a>
              <a href="https://tenuo.ai/api-reference" className="nav-link">API</a>
              <a href="https://github.com/tenuo-ai/tenuo" className="nav-link">GitHub</a>
            </div>
          </div>
        </nav>

        {/* Hero */}
        <header style={{ textAlign: 'center', padding: '64px 24px 48px' }}>
          <div className="badge" style={{ marginBottom: '20px' }}>
            <span style={{ color: 'var(--accent)' }}>Explorer</span>
          </div>
          <h1 style={{ fontSize: '42px', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '16px' }}>
            Warrant <span className="gradient-text">Playground</span>
          </h1>
          <p style={{ fontSize: '18px', color: 'var(--muted)', maxWidth: '480px', margin: '0 auto 32px' }}>
            Decode warrants, inspect constraints, and simulate authorization checks
          </p>
          
          {/* Load Sample */}
          <button onClick={handleLoadSample} className="btn btn-secondary" style={{ gap: '10px' }}>
            <span>📦</span>
            <span>Load Sample Warrant</span>
          </button>
        </header>

        {/* Main Content */}
        <main style={{ flex: 1, maxWidth: '1100px', width: '100%', margin: '0 auto', padding: '0 24px 64px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '32px' }}>
            
            {/* Left Column - Inputs */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              
              {/* Warrant Input Panel */}
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                  <span style={{ fontSize: '20px' }}>📄</span>
                  <h2 style={{ fontSize: '16px', fontWeight: 600 }}>1. Paste Warrant</h2>
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>
                      Base64 Encoded Warrant
                    </label>
                    <textarea
                      className="input"
                      style={{ height: '100px', resize: 'none' }}
                      placeholder="Paste your warrant here..."
                      value={warrantB64}
                      onChange={(e) => setWarrantB64(e.target.value)}
                    />
                  </div>
                  
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>
                      Trusted Root Public Key (Hex)
                    </label>
                    <input
                      className="input"
                      placeholder="64-character hex string..."
                      value={rootKeyHex}
                      onChange={(e) => setRootKeyHex(e.target.value)}
                    />
                  </div>
                  
                  <button
                    onClick={handleDecode}
                    disabled={!wasmReady || !warrantB64}
                    className="btn btn-secondary"
                  >
                    {wasmReady ? 'Decode Warrant' : 'Loading WASM...'}
                  </button>
                </div>
                
                <Explainer title="What is a warrant?" docLink="https://tenuo.ai/concepts#warrants">
                  <p>A <strong>warrant</strong> is a cryptographic capability token that grants an AI agent permission to perform specific actions. It contains:</p>
                  <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
                    <li>Authorized tools and their constraints</li>
                    <li>Issuer and holder public keys</li>
                    <li>Expiration time and delegation depth</li>
                  </ul>
                </Explainer>
              </div>

              {/* Authorization Check Panel */}
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                  <span style={{ fontSize: '20px' }}>🔐</span>
                  <h2 style={{ fontSize: '16px', fontWeight: 600 }}>2. Check Authorization</h2>
                </div>
                
                {/* Tool quick-select */}
                {decoded && typeof decoded !== 'string' && decoded.tools.length > 0 && (
                  <div style={{ marginBottom: '16px' }}>
                    <label style={{ display: 'block', fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>
                      Quick Select Tool
                    </label>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {decoded.tools.slice(0, 6).map(t => (
                        <button
                          key={t}
                          onClick={() => setTool(t)}
                          className={`tool-tag ${tool === t ? 'active' : ''}`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>
                      Tool Name
                    </label>
                    <input
                      className="input"
                      placeholder="e.g., read_file"
                      value={tool}
                      onChange={(e) => setTool(e.target.value)}
                    />
                  </div>
                  
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: 'var(--muted)', marginBottom: '8px' }}>
                      Arguments (JSON)
                    </label>
                    <textarea
                      className="input"
                      style={{ height: '80px', resize: 'none' }}
                      value={argsJson}
                      onChange={(e) => setArgsJson(e.target.value)}
                    />
                  </div>
                  
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div 
                      className={`toggle ${dryRun ? 'active' : ''}`}
                      onClick={() => setDryRun(!dryRun)}
                    >
                      <div className="toggle-knob" />
                    </div>
                    <span style={{ fontSize: '14px', color: 'var(--muted)' }}>
                      Dry run (skip signature verification)
                    </span>
                  </div>
                  
                  <button
                    onClick={handleAuthorize}
                    disabled={!wasmReady || !warrantB64 || !tool}
                    className="btn btn-primary"
                  >
                    Check Authorization
                  </button>
                </div>
                
                <Explainer title="How does authorization work?" docLink="https://tenuo.ai/concepts#authorization">
                  <p>Authorization checks verify that:</p>
                  <ol style={{ marginTop: '8px', paddingLeft: '20px' }}>
                    <li>The tool is listed in the warrant</li>
                    <li>The arguments satisfy all constraints</li>
                    <li>The warrant hasn't expired</li>
                    <li>The signature chain is valid (unless dry run)</li>
                  </ol>
                </Explainer>
              </div>
            </div>

            {/* Right Column - Outputs */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              
              {/* Decoded Panel */}
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '20px' }}>🔍</span>
                    <h2 style={{ fontSize: '16px', fontWeight: 600 }}>Decoded Warrant</h2>
                  </div>
                  {warrantB64 && (
                    <button onClick={handleShare} className="btn btn-secondary" style={{ padding: '8px 12px', fontSize: '12px' }}>
                      {shareUrl ? '✓ Copied!' : '🔗 Share'}
                    </button>
                  )}
                </div>
                
                {decoded ? (
                  typeof decoded === 'string' ? (
                    <div style={{ padding: '16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '12px' }}>
                      <p style={{ fontSize: '14px', color: 'var(--red)' }}>⚠ {decoded}</p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {/* Chain Visualization */}
                      <div className="chain-box">
                        <div className="chain-node">
                          <div className="chain-icon">🔑</div>
                          <div className="chain-label">Issuer</div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <code style={{ fontSize: '11px', color: 'var(--accent)' }}>{truncate(decoded.issuer)}</code>
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
                            <code style={{ fontSize: '11px', color: 'var(--green)' }}>{truncate(decoded.authorized_holder)}</code>
                            <CopyBtn text={decoded.authorized_holder} />
                          </div>
                        </div>
                      </div>

                      {/* Expiration */}
                      <ExpirationDisplay issuedAt={decoded.issued_at} expiresAt={decoded.expires_at} />

                      {/* Tools */}
                      <div style={{ padding: '16px', background: 'var(--surface-2)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '10px' }}>🔧 Authorized Tools</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {decoded.tools.map(t => (
                            <span key={t} className="tool-tag">{t}</span>
                          ))}
                        </div>
                      </div>

                      {/* Constraints */}
                      <div style={{ padding: '16px', background: 'var(--surface-2)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '10px' }}>📋 Constraints</div>
                        <pre style={{ 
                          fontSize: '11px', 
                          fontFamily: "'JetBrains Mono', monospace",
                          color: 'var(--muted)', 
                          overflowX: 'auto',
                          maxHeight: '150px',
                          overflowY: 'auto'
                        }}>
                          {JSON.stringify(decoded.capabilities, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )
                ) : (
                  <div style={{ padding: '48px', textAlign: 'center', color: 'var(--muted)' }}>
                    <div style={{ fontSize: '48px', marginBottom: '16px', opacity: 0.2 }}>🔐</div>
                    <p style={{ fontSize: '14px' }}>Paste a warrant and click Decode</p>
                  </div>
                )}
              </div>

              {/* Result Panel */}
              <div className="panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                  <span style={{ fontSize: '20px' }}>⚡</span>
                  <h2 style={{ fontSize: '16px', fontWeight: 600 }}>Authorization Result</h2>
                </div>
                
                {authResult ? (
                  <div 
                    className={authResult.authorized ? 'result-success' : 'result-error'}
                    style={{ padding: '32px', borderRadius: '12px', textAlign: 'center' }}
                  >
                    <div style={{ fontSize: '48px', marginBottom: '12px' }}>
                      {authResult.authorized ? '✓' : '✕'}
                    </div>
                    <p style={{ 
                      fontSize: '24px', 
                      fontWeight: 600, 
                      marginBottom: '8px',
                      color: authResult.authorized ? 'var(--green)' : 'var(--red)'
                    }}>
                      {authResult.authorized ? 'Authorized' : 'Denied'}
                    </p>
                    {authResult.authorized ? (
                      <p style={{ fontSize: '14px', color: 'var(--muted)' }}>
                        Access permitted by warrant constraints
                        {dryRun && <span style={{ opacity: 0.6 }}> · PoP verification skipped</span>}
                      </p>
                    ) : (
                      <>
                        {authResult.deny_code && (
                          <span style={{ 
                            display: 'inline-block', 
                            padding: '4px 12px', 
                            marginBottom: '8px',
                            fontSize: '12px', 
                            fontFamily: "'JetBrains Mono', monospace",
                            borderRadius: '6px', 
                            background: 'rgba(239, 68, 68, 0.15)', 
                            color: 'var(--red)' 
                          }}>
                            {authResult.deny_code}
                          </span>
                        )}
                        <p style={{ fontSize: '14px', color: 'var(--muted)' }}>{authResult.reason}</p>
                      </>
                    )}
                  </div>
                ) : (
                  <div style={{ padding: '48px', textAlign: 'center', color: 'var(--muted)' }}>
                    <div style={{ fontSize: '48px', marginBottom: '16px', opacity: 0.2 }}>⚡</div>
                    <p style={{ fontSize: '14px' }}>Run an authorization check to see results</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer style={{ borderTop: '1px solid var(--border)', padding: '48px 24px' }}>
          <div style={{ maxWidth: '1100px', margin: '0 auto', textAlign: 'center' }}>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '32px', marginBottom: '16px', fontSize: '14px' }}>
              <a href="https://crates.io/crates/tenuo" style={{ color: 'var(--muted)', textDecoration: 'none' }} className="nav-link">🦀 Rust Core</a>
              <a href="https://pypi.org/project/tenuo/" style={{ color: 'var(--muted)', textDecoration: 'none' }} className="nav-link">🐍 Python SDK</a>
              <span style={{ color: 'var(--muted)' }}>⚡ ~27μs verification</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', fontSize: '13px', color: 'var(--muted)' }}>
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
