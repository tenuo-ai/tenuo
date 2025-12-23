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

const truncateKey = (hex: string) => `${hex.slice(0, 6)}...${hex.slice(-4)}`;

// Copy button
const CopyBtn = ({ text, label = "Copy" }: { text: string; label?: string }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      onClick={handleCopy}
      className="text-[10px] px-2 py-1 rounded text-[var(--muted)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] transition-all"
    >
      {copied ? '✓' : label}
    </button>
  );
};

// Collapsible explainer
const Explainer = ({ title, children, docLink }: { title: string; children: React.ReactNode; docLink?: string }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4">
      <button 
        onClick={() => setOpen(!open)}
        className="group flex items-center gap-2 text-[11px] text-[var(--muted)] hover:text-[var(--accent)] transition-colors"
      >
        <span className={`text-[10px] transition-transform duration-200 ${open ? 'rotate-90' : ''}`}>▶</span>
        <span className="opacity-60 group-hover:opacity-100">?</span>
        <span>{title}</span>
      </button>
      {open && (
        <div className="mt-2 ml-6 p-3 rounded-lg font-readable text-[12px] text-[#a0a0a0] leading-[1.7] bg-[var(--surface)] border border-[var(--border)]">
          <div className="space-y-1">
            {children}
          </div>
          {docLink && (
            <a 
              href={docLink} 
              className="mt-3 inline-flex items-center gap-1 text-[11px] text-[var(--accent)] hover:underline"
              target="_blank"
              rel="noopener noreferrer"
            >
              Read the docs →
            </a>
          )}
        </div>
      )}
    </div>
  );
};

// Chain Visualizer
const ChainVisualizer = ({ decoded }: { decoded: DecodedWarrant }) => (
  <div className="relative overflow-hidden rounded-lg" style={{ background: 'linear-gradient(135deg, rgba(0,212,255,0.05), rgba(168,85,247,0.05))' }}>
    <div className="absolute inset-0 opacity-30" style={{ background: 'radial-gradient(circle at 20% 50%, rgba(0,212,255,0.15), transparent 50%), radial-gradient(circle at 80% 50%, rgba(0,255,136,0.15), transparent 50%)' }} />
    <div className="relative p-4 flex items-center justify-between">
      <div className="flex flex-col items-center gap-2">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center text-lg" style={{ background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,212,255,0.05))', border: '1px solid rgba(0,212,255,0.3)' }}>
          🔑
        </div>
        <div className="text-center">
          <span className="block text-[9px] text-[var(--muted)] uppercase tracking-wider">Issuer</span>
          <code className="text-[10px] text-[var(--accent)] font-medium">{truncateKey(decoded.issuer)}</code>
        </div>
      </div>
      
      <div className="flex-1 flex items-center justify-center gap-3 px-4">
        <div className="flex-1 h-px" style={{ background: 'linear-gradient(90deg, var(--accent), var(--accent2))' }} />
        <div className="px-3 py-1.5 rounded-full text-[10px] font-medium" style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)', color: 'var(--accent2)' }}>
          depth {decoded.depth}
        </div>
        <div className="flex-1 h-px" style={{ background: 'linear-gradient(90deg, var(--accent2), var(--green))' }} />
      </div>
      
      <div className="flex flex-col items-center gap-2">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center text-lg" style={{ background: 'linear-gradient(135deg, rgba(0,255,136,0.2), rgba(0,255,136,0.05))', border: '1px solid rgba(0,255,136,0.3)' }}>
          🤖
        </div>
        <div className="text-center">
          <span className="block text-[9px] text-[var(--muted)] uppercase tracking-wider">Holder</span>
          <code className="text-[10px] text-[var(--green)] font-medium">{truncateKey(decoded.authorized_holder)}</code>
        </div>
      </div>
    </div>
  </div>
);

// Info Row
const InfoRow = ({ label, value, color, copyable }: { label: string; value: string; color?: string; copyable?: string }) => (
  <div className="flex items-center justify-between py-2 border-b border-[var(--border)] last:border-0">
    <span className="text-[10px] text-[var(--muted)] uppercase tracking-wide">{label}</span>
    <div className="flex items-center gap-1">
      <span className={`text-[11px] font-mono ${color || 'text-[var(--text)]'}`}>{value}</span>
      {copyable && <CopyBtn text={copyable} label="📋" />}
    </div>
  </div>
);

// Expiration Bar
const ExpirationBar = ({ issuedAt, expiresAt }: { issuedAt: number; expiresAt: number }) => {
  const [now, setNow] = useState(Date.now() / 1000);
  
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(interval);
  }, []);
  
  const total = expiresAt - issuedAt;
  const elapsed = now - issuedAt;
  const percent = Math.min(100, Math.max(0, (elapsed / total) * 100));
  const remaining = expiresAt - now;
  const isExpired = remaining <= 0;
  const isWarning = percent > 75;
  
  const formatTime = (secs: number) => {
    if (secs <= 0) return 'Expired';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = Math.floor(secs % 60);
    if (d > 0) return `${d}d ${h}h remaining`;
    if (h > 0) return `${h}h ${m}m remaining`;
    if (m > 0) return `${m}m ${s}s remaining`;
    return `${s}s remaining`;
  };
  
  return (
    <div className="panel-inner p-3">
      <div className="flex justify-between items-center mb-2">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full pulse ${isExpired ? 'bg-[var(--red)]' : isWarning ? 'bg-yellow-500' : 'bg-[var(--green)]'}`} />
          <span className={`text-[11px] font-medium ${isExpired ? 'text-[var(--red)]' : isWarning ? 'text-yellow-500' : 'text-[var(--green)]'}`}>
            {formatTime(remaining)}
          </span>
        </div>
        <span className="text-[10px] text-[var(--muted)]">
          expires {new Date(expiresAt * 1000).toLocaleString()}
        </span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
        <div 
          className="h-full rounded-full transition-all duration-1000"
          style={{ 
            width: `${Math.min(100, percent)}%`,
            background: isExpired 
              ? 'var(--red)' 
              : isWarning 
                ? 'linear-gradient(90deg, #eab308, var(--red))'
                : 'linear-gradient(90deg, var(--green), var(--accent))'
          }}
        />
      </div>
    </div>
  );
};

// Tool Badge
const ToolBadge = ({ name }: { name: string }) => (
  <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono" style={{ background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--accent)' }}>
    <span style={{ color: 'var(--green)' }}>✓</span> {name}
  </span>
);

// Constraint Display
const ConstraintDisplay = ({ capabilities }: { capabilities: Record<string, unknown> }) => {
  const entries = Object.entries(capabilities);
  if (entries.length === 0) return <span className="text-[11px] text-[var(--muted)]">No constraints</span>;
  
  return (
    <div className="space-y-2">
      {entries.map(([tool, constraints]) => (
        <div key={tool} className="panel-inner p-2">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono text-[var(--accent)]">{tool}</span>
          </div>
          <pre className="text-[9px] text-[var(--muted)] overflow-x-auto">
            {JSON.stringify(constraints, null, 2)}
          </pre>
        </div>
      ))}
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
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    init().then(() => {
      init_panic_hook();
      setWasmReady(true);
    });
  }, []);
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const shared = params.get('s');
    if (shared) {
      try {
        const state = JSON.parse(atob(shared));
        if (state.warrant) setWarrantB64(state.warrant);
        if (state.tool) setTool(state.tool);
        if (state.args) setArgsJson(state.args);
        if (state.root) setRootKeyHex(state.root);
      } catch { /* ignore */ }
    }
  }, []);
  
  const getShareUrl = useCallback(() => {
    const state = { warrant: warrantB64, tool, args: argsJson, root: rootKeyHex };
    return `${window.location.origin}${window.location.pathname}?s=${btoa(JSON.stringify(state))}`;
  }, [warrantB64, tool, argsJson, rootKeyHex]);

  const handleCopyShare = async () => {
    await navigator.clipboard.writeText(getShareUrl());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLoadSample = () => {
    setWarrantB64(SAMPLE_WARRANT);
    setTool("read_file");
    setArgsJson(JSON.stringify({ path: "docs/readme.md" }, null, 2));
    setRootKeyHex(SAMPLE_ROOT_KEY);
    setDecoded(null);
    setAuthResult(null);
  };

  const handleDecode = () => {
    if (!wasmReady) return;
    setDecoded(decode_warrant(warrantB64));
    setAuthResult(null);
  };

  const handleAuthorize = () => {
    if (!wasmReady) return;
    try {
      setAuthResult(check_access(warrantB64, tool, JSON.parse(argsJson), rootKeyHex, dryRun));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error';
      setAuthResult({ authorized: false, reason: "Invalid JSON: " + msg });
    }
  };

  return (
    <>
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      
      <div className="relative z-10 min-h-screen flex flex-col">
        {/* Nav */}
        <nav className="border-b border-[var(--border)]">
          <div className="max-w-[900px] mx-auto px-4 md:px-6 py-4 md:py-6 flex justify-between items-center">
            <a href="https://tenuo.ai" className="text-lg md:text-[1.25rem] font-semibold">tenuo</a>
            <div className="flex gap-4 md:gap-8">
              <a href="https://tenuo.ai/quickstart" className="text-xs md:text-sm text-[var(--muted)] hover:text-white transition-colors hidden sm:block">Quick Start</a>
              <a href="https://tenuo.ai/concepts" className="text-xs md:text-sm text-[var(--muted)] hover:text-white transition-colors hidden md:block">Concepts</a>
              <a href="https://tenuo.ai/api-reference" className="text-xs md:text-sm text-[var(--muted)] hover:text-white transition-colors">Docs</a>
              <a href="https://github.com/tenuo-ai/tenuo" className="text-xs md:text-sm text-[var(--muted)] hover:text-white transition-colors">GitHub</a>
            </div>
          </div>
        </nav>

        {/* Main content - centered */}
        <main className="flex-1 flex items-start justify-center py-6 md:py-8 px-4 md:px-6">
          <div className="w-full max-w-[900px]">
            {/* Header */}
            <header className="text-center mb-6">
              <div className="badge text-[11px] px-3 py-1 mb-3">
                <span className="text-[var(--accent)]">explorer</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight mb-2">
                Warrant <span className="bg-gradient-to-r from-[var(--accent)] to-[var(--accent2)] bg-clip-text text-transparent">Playground</span>
              </h1>
              <p className="text-sm text-[var(--muted)] mb-4">Decode warrants and simulate authorization</p>
              <div className="flex justify-center gap-2">
                <button onClick={handleLoadSample} className="btn btn-secondary text-xs py-2 px-4">
                  Load Sample
                </button>
                <button onClick={handleCopyShare} className="btn btn-ghost text-xs">
                  {copied ? '✓ Copied' : '🔗 Share'}
                </button>
              </div>
            </header>

            {/* Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Left: Input */}
              <div className="space-y-4">
                {/* Warrant Input */}
                <section className="panel p-4">
                  <h2 className="section-title mb-3 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)]" />
                    <span className="text-[var(--accent)]">01</span>
                    <span>Warrant Input</span>
                  </h2>
                  
                  <Explainer title="What is a warrant?" docLink="https://tenuo.ai/concepts">
                    A <strong className="text-[var(--text)]">warrant</strong> is a signed capability token that grants specific permissions to an AI agent. 
                    It contains: <span className="text-[var(--accent)]">issuer</span>, <span className="text-[var(--green)]">holder</span>, allowed tools, constraints, and TTL. 
                    Warrants can only be <em>attenuated</em> (narrowed), never expanded.
                  </Explainer>
                  
                  <div className="space-y-3">
                    <div>
                      <label className="label">Base64 Warrant</label>
                      <textarea
                        className="h-20 text-xs"
                        placeholder="Paste base64 encoded warrant..."
                        value={warrantB64}
                        onChange={(e) => setWarrantB64(e.target.value)}
                      />
                    </div>
                    <div>
                      <label className="label">Trusted Root Key (Hex)</label>
                      <input
                        type="text"
                        className="text-xs"
                        placeholder="64-char hex public key..."
                        value={rootKeyHex}
                        onChange={(e) => setRootKeyHex(e.target.value)}
                      />
                    </div>
                    <button
                      onClick={handleDecode}
                      disabled={!wasmReady || !warrantB64}
                      className="btn btn-secondary w-full text-xs py-2"
                    >
                      Decode
                    </button>
                  </div>
                </section>

                {/* Authorization */}
                <section className="panel p-4">
                  <h2 className="section-title mb-3 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--green)]" />
                    <span className="text-[var(--green)]">02</span>
                    <span>Authorization Check</span>
                  </h2>
                  
                  <Explainer title="How does authorization work?" docLink="https://tenuo.ai/enforcement">
                    Authorization verifies: <strong className="text-[var(--text)]">1)</strong> tool is in warrant, 
                    <strong className="text-[var(--text)]">2)</strong> arguments match constraints (patterns, ranges, exact values), 
                    <strong className="text-[var(--text)]">3)</strong> warrant hasn't expired, 
                    <strong className="text-[var(--text)]">4)</strong> chain verifies to trusted root.
                    In production, a <span className="text-[var(--accent)]">Proof-of-Possession</span> signature is also required.
                  </Explainer>
                  
                  <div className="space-y-3">
                    {decoded && typeof decoded !== 'string' && (
                      <div className="flex flex-wrap gap-1.5">
                        {decoded.tools.slice(0, 5).map(t => (
                          <button
                            key={t}
                            onClick={() => setTool(t)}
                            className={`tool-chip text-[10px] py-1 px-2 ${tool === t ? 'active' : ''}`}
                          >
                            {t}
                          </button>
                        ))}
                      </div>
                    )}
                    <div>
                      <label className="label">Tool Name</label>
                      <input
                        type="text"
                        className="text-xs"
                        placeholder="e.g. read_file"
                        value={tool}
                        onChange={(e) => setTool(e.target.value)}
                      />
                    </div>
                    <div>
                      <label className="label">Arguments (JSON)</label>
                      <textarea
                        className="h-16 text-xs"
                        value={argsJson}
                        onChange={(e) => setArgsJson(e.target.value)}
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <div
                        className={`toggle ${dryRun ? 'active' : ''}`}
                        onClick={() => setDryRun(!dryRun)}
                      />
                      <span className="text-[11px] text-[var(--muted)]">Dry run (skip PoP)</span>
                    </div>
                    <button
                      onClick={handleAuthorize}
                      disabled={!wasmReady || !warrantB64 || !tool}
                      className="btn btn-primary w-full text-xs py-2"
                    >
                      Check
                    </button>
                  </div>
                </section>
              </div>

              {/* Right: Output */}
              <div className="space-y-4">
                {/* Decoded */}
                <section className="panel p-4">
                  <h2 className="section-title mb-3 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent2)]" />
                    <span>Decoded Warrant</span>
                  </h2>
                  
                  <Explainer title="Understanding the decoded warrant" docLink="https://tenuo.ai/constraints">
                    <span className="text-[var(--accent)]">Issuer</span> → <span className="text-[var(--green)]">Holder</span> shows the delegation chain. 
                    <strong className="text-[var(--text)]">Depth</strong> = how many times delegated (0 = root authority).
                    <strong className="text-[var(--text)]">Constraints</strong> define allowed argument values using patterns (<code className="px-1 py-0.5 rounded bg-[var(--surface)] text-[10px]">docs/*</code>), 
                    ranges (<code className="px-1 py-0.5 rounded bg-[var(--surface)] text-[10px]">0..1000</code>), or exact values.
                  </Explainer>
                  
                  {decoded ? (
                    typeof decoded === 'string' ? (
                      <div className="p-3 rounded-lg" style={{ background: 'rgba(255,68,102,0.08)', border: '1px solid rgba(255,68,102,0.2)' }}>
                        <p className="text-xs text-[var(--red)]">⚠ {decoded}</p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {/* Chain */}
                        <ChainVisualizer decoded={decoded} />
                        
                        {/* Expiration */}
                        <ExpirationBar issuedAt={decoded.issued_at} expiresAt={decoded.expires_at} />
                        
                        {/* Info */}
                        <div className="panel-inner px-3 py-1">
                          <InfoRow label="Warrant ID" value={decoded.id.slice(0, 16) + '...'} copyable={decoded.id} />
                          <InfoRow label="Issuer" value={truncateKey(decoded.issuer)} color="text-[var(--accent)]" copyable={decoded.issuer} />
                          <InfoRow label="Holder" value={truncateKey(decoded.authorized_holder)} color="text-[var(--green)]" copyable={decoded.authorized_holder} />
                        </div>
                        
                        {/* Tools */}
                        <div>
                          <span className="label text-[9px] mb-2 block">Authorized Tools</span>
                          <div className="flex flex-wrap gap-1.5">
                            {decoded.tools.map(t => <ToolBadge key={t} name={t} />)}
                          </div>
                        </div>
                        
                        {/* Constraints */}
                        <div>
                          <span className="label text-[9px] mb-2 block">Constraints</span>
                          <ConstraintDisplay capabilities={decoded.capabilities} />
                        </div>
                      </div>
                    )
                  ) : (
                    <div className="py-10 text-center">
                      <div className="w-12 h-12 mx-auto mb-3 rounded-xl flex items-center justify-center text-2xl opacity-20" style={{ background: 'var(--surface-2)' }}>
                        🔐
                      </div>
                      <p className="text-[11px] text-[var(--muted)]">Decode a warrant to inspect</p>
                    </div>
                  )}
                </section>

                {/* Result */}
                <section className="panel p-4">
                  <h2 className="section-title mb-3 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'linear-gradient(135deg, var(--green), var(--accent))' }} />
                    <span>Result</span>
                  </h2>
                  
                  <Explainer title="What does the result mean?" docLink="https://tenuo.ai/debugging">
                    <div className="space-y-1.5">
                      <div><span className="text-[var(--green)]">✓ Authorized</span> — Tool and arguments satisfy all constraints. In production, PoP signature would also be verified.</div>
                      <div><span className="text-[var(--red)]">✕ Denied</span> — Tool not in warrant, argument violates constraint, or chain verification failed. Error code tells you why.</div>
                    </div>
                  </Explainer>
                  
                  {authResult ? (
                    <div className={`rounded-lg p-4 text-center ${authResult.authorized ? 'result-success' : 'result-error'}`}>
                      <div className={`text-2xl mb-1 ${authResult.authorized ? 'text-[var(--green)]' : 'text-[var(--red)]'}`}>
                        {authResult.authorized ? '✓' : '✕'}
                      </div>
                      <p className={`text-sm font-semibold mb-1 ${authResult.authorized ? 'text-[var(--green)]' : 'text-[var(--red)]'}`}>
                        {authResult.authorized ? 'Authorized' : 'Denied'}
                      </p>
                      {authResult.authorized ? (
                        <p className="text-[11px] text-[var(--muted)]">
                          Permitted{dryRun && ' · PoP skipped'}
                        </p>
                      ) : (
                        <div>
                          {authResult.deny_code && (
                            <span className="badge badge-red text-[9px] px-2 py-0.5 mb-1">{authResult.deny_code}</span>
                          )}
                          <p className="text-[11px] text-[var(--muted)]">{authResult.reason}</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="py-6 text-center text-[var(--muted)]">
                      <div className="text-xl mb-1 opacity-30">⚡</div>
                      <p className="text-[11px]">Run a check to see results</p>
                    </div>
                  )}
                </section>
              </div>
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer className="border-t border-[var(--border)] py-6">
          <div className="max-w-[900px] mx-auto px-4 md:px-6">
            {/* Tech badges */}
            <div className="flex justify-center flex-wrap gap-2 md:gap-3 mb-4">
              <a href="https://crates.io/crates/tenuo" className="flex items-center gap-1.5 px-2 md:px-3 py-1 md:py-1.5 rounded-lg text-[10px] md:text-xs transition-all hover:bg-[var(--surface)]" style={{ background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.1)' }}>
                <span>🦀</span>
                <span className="text-[var(--muted)]">Rust</span>
              </a>
              <a href="https://pypi.org/project/tenuo/" className="flex items-center gap-1.5 px-2 md:px-3 py-1 md:py-1.5 rounded-lg text-[10px] md:text-xs transition-all hover:bg-[var(--surface)]" style={{ background: 'rgba(0,255,136,0.05)', border: '1px solid rgba(0,255,136,0.1)' }}>
                <span>🐍</span>
                <span className="text-[var(--muted)]">Python</span>
              </a>
              <div className="flex items-center gap-1.5 px-2 md:px-3 py-1 md:py-1.5 rounded-lg text-[10px] md:text-xs" style={{ background: 'rgba(168,85,247,0.05)', border: '1px solid rgba(168,85,247,0.1)' }}>
                <span>⚡</span>
                <span className="text-[var(--muted)]">~27μs</span>
              </div>
            </div>
            
            {/* Links */}
            <div className="flex justify-center items-center flex-wrap gap-x-3 gap-y-1 text-[10px] md:text-xs text-[var(--muted)]">
              <a href="https://tenuo.ai" className="hover:text-[var(--text)] transition-colors">Home</a>
              <span className="opacity-30">·</span>
              <a href="https://tenuo.ai/quickstart" className="hover:text-[var(--text)] transition-colors">Docs</a>
              <span className="opacity-30">·</span>
              <a href="https://github.com/tenuo-ai/tenuo" className="hover:text-[var(--text)] transition-colors">GitHub</a>
              <span className="opacity-30 hidden md:inline">·</span>
              <span className="opacity-60 hidden md:inline">MIT/Apache-2.0</span>
            </div>
          </div>
        </footer>
      </div>
    </>
  )
}

export default App
