import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../api'
import EntropyHeatmap from '../components/EntropyHeatmap'
import MitreMap from '../components/MitreMap'
import {
    ArrowLeft, Check, X, Shield, Info, ExternalLink, Globe, FileCode,
    AlertTriangle, BarChart3, Cpu, Copy, Search, FileType, HardDrive,
    Activity, Clock, ShieldCheck, ShieldAlert, ShieldX, Loader2, Filter
} from 'lucide-react'

export default function ScanResult() {
    const { sha256 } = useParams()
    const navigate = useNavigate()
    const [data, setData] = useState(null)
    const [loading, setLoading] = useState(true)
    const [tab, setTab] = useState('engines')
    const [stringFilter, setStringFilter] = useState('all')
    const [vendorSearch, setVendorSearch] = useState('')
    const [showEntTip, setShowEntTip] = useState(false)

    useEffect(() => {
        let interval
        const fetchResult = () => {
            api.getResult(sha256)
                .then(d => {
                    setData(d)
                    setLoading(false)
                    if (d.status && d.status !== 'completed' && d.status !== 'failed') {
                        if (!interval) {
                            interval = setInterval(fetchResult, 2000)
                        }
                    } else {
                        if (interval) clearInterval(interval)
                    }
                })
                .catch(() => {
                    setLoading(false)
                    if (interval) clearInterval(interval)
                })
        }
        fetchResult()
        return () => interval && clearInterval(interval)
    }, [sha256])

    if (loading) return <div className="loading-container"><div className="spinner"></div><p>Loading results...</p></div>
    if (!data) return (
        <div className="empty-state">
            <div className="empty-icon"><Search size={48} /></div>
            <p>File not found. Upload it first.</p>
            <button className="btn btn-primary" onClick={() => navigate('/')}>Scan a File</button>
        </div>
    )

    const isScanning = data.status === 'queued' || data.status === 'scanning'

    const detections = data.detections || 0
    const total = data.total_engines || 0
    const pct = total > 0 ? (detections / total) * 100 : 0
    const circumference = 2 * Math.PI * 90
    const offset = circumference - (pct / 100) * circumference

    let gaugeColor = '#10b981'
    let statusText = 'No Threats Detected'
    let StatusIcon = ShieldCheck
    let statusClass = 'clean'

    if (isScanning) {
        gaugeColor = '#818cf8'
        statusText = 'Analysis In Progress'
        StatusIcon = Loader2
        statusClass = 'scanning'
    } else if (detections > total * 0.4) {
        gaugeColor = '#ef4444'
        statusText = 'Malicious'
        StatusIcon = ShieldX
        statusClass = 'malicious'
    } else if (detections > total * 0.15) {
        gaugeColor = '#f59e0b'
        statusText = 'Suspicious'
        StatusIcon = ShieldAlert
        statusClass = 'suspicious'
    } else if (detections > 0) {
        gaugeColor = '#f59e0b'
        statusText = 'Low Risk'
        StatusIcon = ShieldAlert
        statusClass = 'suspicious'
    }

    const engines = data.engine_results || []
    const detected = engines.filter(e => e.detected)
    const clean = engines.filter(e => !e.detected)

    const deep = data.deep_analysis || {}
    const strings = deep.strings || {}
    const pe = deep.pe_info || null
    const iocs = deep.network_iocs || {}
    const entropyMap = deep.entropy_map || null
    const mitre = deep.mitre_attacks || []
    const risk = deep.risk_score || null

    const formatSize = (bytes) => {
        if (!bytes || bytes === 0) return '0 B'
        const k = 1024
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text).catch(() => { })
    }

    const vtLink = data.vt_link || ('https://www.virustotal.com/gui/file/' + data.sha256)

    const filteredEngines = [...detected, ...clean].filter(eng =>
        eng.engine_name.toLowerCase().includes(vendorSearch.toLowerCase())
    )

    const entropyLevel = data.entropy > 7 ? 'High' : data.entropy > 5 ? 'Medium' : 'Low'
    const entropyColor = data.entropy > 7 ? '#ef4444' : data.entropy > 5 ? '#f59e0b' : '#10b981'

    const tabs = [
        { id: 'engines', icon: Shield, label: `Engines (${detections}/${total})` },
        { id: 'risk', icon: AlertTriangle, label: 'Risk Score' },
        { id: 'strings', icon: Search, label: `Strings (${strings.total_strings || 0})` },
        { id: 'pe', icon: Cpu, label: 'PE Info', hide: !pe },
        { id: 'iocs', icon: Globe, label: `IOCs (${iocs.total_iocs || 0})` },
        { id: 'entropy', icon: BarChart3, label: 'Entropy Map' },
        { id: 'mitre', icon: FileCode, label: `ATT&CK (${mitre.length})` },
        { id: 'details', icon: Info, label: 'Details' },
    ].filter(t => !t.hide)

    return (
        <>
            {/* ── Breadcrumb Header ── */}
            <div className="page-header">
                <div>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/')}>
                            <ArrowLeft size={14} /> New Scan
                        </button>
                        <a href={vtLink} target="_blank" rel="noopener noreferrer"
                            className="btn btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
                            <ExternalLink size={14} /> VirusTotal Report
                        </a>
                    </div>
                    <h2 style={{ wordBreak: 'break-all' }}>{data.filename}</h2>
                    <p className="subtitle" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', opacity: 0.6 }}>
                        SHA-256: {data.sha256}
                    </p>
                </div>
            </div>

            {/* ── HERO: Detection Summary ── */}
            <div className={`scan-hero ${statusClass}`}>
                {isScanning && <div className="scan-hero-shimmer" />}

                {/* Gauge */}
                <div className="scan-hero-gauge">
                    <div className="scan-gauge-wrap">
                        <svg viewBox="0 0 200 200" className={isScanning ? 'scanning-gauge' : ''}>
                            <circle className="gauge-track" cx="100" cy="100" r="90" />
                            <circle
                                className="gauge-fill"
                                cx="100" cy="100" r="90"
                                stroke={gaugeColor}
                                strokeDasharray={circumference}
                                strokeDashoffset={isScanning ? circumference * 0.7 : (detections === 0 ? circumference : offset)}
                                strokeLinecap="round"
                            />
                        </svg>
                        <div className="gauge-center-content">
                            <span className="gauge-label-top">DETECTIONS</span>
                            <span className="gauge-number" style={{ color: gaugeColor }}>
                                {isScanning ? '—' : detections}
                            </span>
                            <span className="gauge-divider" />
                            <span className="gauge-total">{isScanning ? '—' : total}</span>
                        </div>
                    </div>
                </div>

                {/* Status */}
                <div className="scan-hero-status">
                    <div className={`status-banner ${statusClass}`}>
                        <StatusIcon size={28} className={isScanning ? 'spin-icon' : ''} />
                        <span>{statusText}</span>
                    </div>
                    <div className="status-meta">
                        {risk && !isScanning && (
                            <div className={`risk-pill ${risk.level}`}>
                                <span className="risk-pill-label">Risk Score</span>
                                <span className="risk-pill-value">{risk.total_score}<small>/100</small></span>
                            </div>
                        )}
                        {isScanning && (
                            <p className="scanning-hint">Results updating live every 3 seconds…</p>
                        )}
                        {pe?.packers_detected?.length > 0 && (
                            <span className="badge badge-packer"><Cpu size={12} /> {pe.packers_detected.join(', ')}</span>
                        )}
                    </div>
                </div>

                {/* File Details Cards */}
                <div className="scan-hero-details">
                    <div className="info-card">
                        <div className="info-card-icon"><FileType size={18} /></div>
                        <span className="info-card-label">File Type</span>
                        <span className="info-card-value">{data.file_type || (isScanning ? 'scanning…' : '—')}</span>
                    </div>
                    <div className="info-card">
                        <div className="info-card-icon"><HardDrive size={18} /></div>
                        <span className="info-card-label">Size</span>
                        <span className="info-card-value">{formatSize(data.file_size)}</span>
                    </div>
                    <div className="info-card" style={{ position: 'relative' }}>
                        <div className="info-card-icon" style={{ color: entropyColor }}><Activity size={18} /></div>
                        <span className="info-card-label">
                            Entropy
                            <button className="ent-tip-btn" onClick={() => setShowEntTip(!showEntTip)} title="What is entropy?">?</button>
                        </span>
                        <span className="info-card-value" style={{ color: entropyColor }}>
                            {data.entropy != null ? `${data.entropy} bits/byte` : '—'}
                        </span>
                        <span className="info-card-sub" style={{ color: entropyColor }}>{entropyLevel}</span>
                        {showEntTip && (
                            <div className="entropy-tooltip">
                                <strong>Entropy in Malware Analysis</strong>
                                <p>Entropy measures the randomness of data in a file (0‒8 bits/byte). High entropy (&gt;7) indicates encryption, compression, or packing — common in malware trying to evade signature-based detection. Low entropy (&lt;5) suggests plain text or uncompressed data.</p>
                                <button className="btn btn-sm btn-secondary" onClick={() => setShowEntTip(false)}>Got it</button>
                            </div>
                        )}
                    </div>
                    {mitre.length > 0 && !isScanning && (
                        <div className="info-card warn">
                            <div className="info-card-icon"><FileCode size={18} /></div>
                            <span className="info-card-label">ATT&CK</span>
                            <span className="info-card-value">{mitre.length} techniques</span>
                        </div>
                    )}
                </div>
            </div>

            {/* ── Analysis Tabs ── */}
            <div className="analysis-tabs">
                {tabs.map(t => (
                    <button key={t.id} className={`analysis-tab ${tab === t.id ? 'active' : ''}`}
                        onClick={() => setTab(t.id)}>
                        <t.icon size={14} /> {t.label}
                    </button>
                ))}
            </div>

            {/* ── ENGINES TAB ── */}
            {tab === 'engines' && (
                <div className="card vendor-card">
                    <div className="card-header">
                        <span className="card-title">Security Vendor Analysis</span>
                        <span className="vendor-summary">
                            <span className="vendor-count detected-count">{detected.length} detected</span>
                            <span className="vendor-sep">·</span>
                            <span className="vendor-count clean-count">{clean.length} clean</span>
                        </span>
                    </div>
                    <div className="vendor-search-bar">
                        <Search size={14} />
                        <input type="text" placeholder="Filter vendors…" value={vendorSearch} onChange={e => setVendorSearch(e.target.value)} />
                        {vendorSearch && <button className="vendor-search-clear" onClick={() => setVendorSearch('')}><X size={14} /></button>}
                    </div>
                    <div className="vendor-table-wrap">
                        <table className="vendor-table">
                            <thead>
                                <tr>
                                    <th style={{ width: 40 }}></th>
                                    <th>Vendor</th>
                                    <th>Version</th>
                                    <th>Result</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredEngines.map(eng => (
                                    <tr key={eng.engine_name} className={eng.detected ? 'row-detected' : 'row-clean'}>
                                        <td className="vendor-status-cell">
                                            {eng.detected
                                                ? <span className="vendor-icon-bad"><X size={14} /></span>
                                                : <span className="vendor-icon-ok"><Check size={14} /></span>
                                            }
                                        </td>
                                        <td className="vendor-name-cell">{eng.engine_name}</td>
                                        <td className="vendor-ver-cell">{eng.engine_version || '—'}</td>
                                        <td className={eng.detected ? 'vendor-result-bad' : 'vendor-result-ok'}>
                                            {eng.detected ? eng.threat_name : 'Clean'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ── RISK SCORE TAB ── */}
            {tab === 'risk' && risk && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Composite Risk Assessment</span>
                        <span className={`badge risk-badge-${risk.level}`}>{risk.level.toUpperCase()}</span>
                    </div>
                    <div className="risk-score-display">
                        <div className="risk-gauge-large">
                            <svg viewBox="0 0 200 200">
                                <circle className="bg-ring" cx="100" cy="100" r="85" />
                                <circle className="fill-ring" cx="100" cy="100" r="85"
                                    stroke={risk.level === 'critical' ? '#e74c3c' : risk.level === 'high' ? '#e17055' : risk.level === 'medium' ? '#fdcb6e' : '#00b894'}
                                    strokeDasharray={circumference} strokeDashoffset={circumference - (risk.total_score / 100) * circumference} />
                            </svg>
                            <div className="gauge-center">
                                <div className="gauge-ratio" style={{ color: risk.level === 'critical' ? '#e74c3c' : risk.level === 'high' ? '#e17055' : risk.level === 'medium' ? '#fdcb6e' : '#00b894', fontSize: '2rem' }}>{risk.total_score}</div>
                                <div className="gauge-label">/ 100</div>
                            </div>
                        </div>
                        <div className="risk-factors">
                            {Object.entries(risk.factors).map(([key, f]) => (
                                <div className="risk-factor" key={key}>
                                    <div className="risk-factor-header">
                                        <span className="risk-factor-label">{f.label}</span>
                                        <span className="risk-factor-score">{f.score}/{f.max}</span>
                                    </div>
                                    <div className="risk-bar-bg">
                                        <div className="risk-bar-fill" style={{
                                            width: `${(f.score / f.max) * 100}%`,
                                            background: f.score / f.max > 0.6 ? '#e74c3c' : f.score / f.max > 0.3 ? '#fdcb6e' : '#00b894',
                                        }}></div>
                                    </div>
                                    <div className="risk-factor-detail">{f.detail}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* ── STRINGS TAB ── */}
            {tab === 'strings' && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">String Analysis — {strings.total_strings || 0} total strings extracted</span>
                    </div>
                    {strings.suspicious && Object.keys(strings.suspicious).length > 0 && (
                        <div className="strings-section">
                            <h4 className="section-title" style={{ color: 'var(--color-danger)' }}>
                                <AlertTriangle size={16} /> Suspicious Strings
                            </h4>
                            <div className="suspicious-grid">
                                {Object.entries(strings.suspicious).map(([cat, items]) => (
                                    <div key={cat} className="suspicious-category">
                                        <div className="suspicious-cat-name">{cat.replace(/_/g, ' ')}</div>
                                        <div className="suspicious-items">
                                            {items.map((item, i) => (
                                                <span key={i} className="suspicious-tag" onClick={() => copyToClipboard(item)} title="Click to copy">{item}</span>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {strings.categorized && Object.keys(strings.categorized).length > 0 && (
                        <div className="strings-section">
                            <h4 className="section-title">Categorized Strings</h4>
                            <div className="string-filter-bar">
                                <button className={`btn btn-sm ${stringFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                                    onClick={() => setStringFilter('all')}>All</button>
                                {Object.keys(strings.categorized).map(cat => (
                                    <button key={cat} className={`btn btn-sm ${stringFilter === cat ? 'btn-primary' : 'btn-secondary'}`}
                                        onClick={() => setStringFilter(cat)}>
                                        {cat.replace(/_/g, ' ')} ({strings.categorized[cat].length})
                                    </button>
                                ))}
                            </div>
                            <div className="strings-list">
                                {(stringFilter === 'all'
                                    ? Object.entries(strings.categorized).flatMap(([cat, items]) => items.map(v => ({ cat, value: v })))
                                    : (strings.categorized[stringFilter] || []).map(v => ({ cat: stringFilter, value: v }))
                                ).slice(0, 100).map((item, i) => (
                                    <div key={i} className="string-item">
                                        <span className={`string-cat-badge cat-${item.cat}`}>{item.cat}</span>
                                        <span className="string-value">{item.value}</span>
                                        <button className="copy-btn" onClick={() => copyToClipboard(item.value)} title="Copy"><Copy size={12} /></button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {strings.interesting_strings?.length > 0 && (
                        <div className="strings-section">
                            <h4 className="section-title">Interesting Strings (Top 50)</h4>
                            <div className="strings-list mono">
                                {strings.interesting_strings.slice(0, 50).map((s, i) => (
                                    <div key={i} className="string-item">
                                        <span className="string-value">{s}</span>
                                        <button className="copy-btn" onClick={() => copyToClipboard(s)} title="Copy"><Copy size={12} /></button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── PE INFO TAB ── */}
            {tab === 'pe' && pe && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">PE Binary Analysis</span>
                        {pe.packers_detected?.length > 0 && (
                            <span className="badge badge-packer">Packed: {pe.packers_detected.join(', ')}</span>
                        )}
                    </div>
                    <div className="pe-overview">
                        <div className="pe-info-grid">
                            {[
                                ['Architecture', pe.architecture],
                                ['PE Type', pe.pe_type],
                                ['Subsystem', pe.subsystem],
                                ['Entry Point', pe.entry_point],
                                ['Image Base', pe.image_base],
                                ['Compile Time', pe.compile_time],
                            ].map(([label, value]) => (
                                <div className="pe-info-item" key={label}>
                                    <span className="pe-label">{label}</span>
                                    <span className="pe-value">{value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                    {pe.security_features && (
                        <div className="pe-section">
                            <h4 className="section-title">Security Features</h4>
                            <div className="security-badges">
                                {Object.entries(pe.security_features).map(([feat, enabled]) => (
                                    <span key={feat} className={`security-badge ${enabled ? 'enabled' : 'disabled'}`}>
                                        {enabled ? <Check size={12} /> : <X size={12} />} {feat}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                    {pe.sections?.length > 0 && (
                        <div className="pe-section">
                            <h4 className="section-title">Sections ({pe.num_sections})</h4>
                            <div className="table-scroll">
                                <table className="data-table">
                                    <thead><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Flags</th><th>Status</th></tr></thead>
                                    <tbody>
                                        {pe.sections.map((sec, i) => (
                                            <tr key={i} className={sec.suspicious ? 'row-suspicious' : ''}>
                                                <td className="mono">{sec.name}</td>
                                                <td>{sec.virtual_size.toLocaleString()}</td>
                                                <td>{sec.raw_size.toLocaleString()}</td>
                                                <td style={{ color: sec.entropy > 7 ? 'var(--color-danger)' : sec.entropy > 6 ? 'var(--color-warn)' : 'var(--color-clean)' }}>{sec.entropy}</td>
                                                <td><span className="flags-list">{sec.flags.join(', ')}</span></td>
                                                <td>{sec.suspicious ? <span className="suspicious-text"><AlertTriangle size={12} /> Suspicious</span> : <span style={{ color: 'var(--color-clean)' }}>Normal</span>}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {pe.imports && Object.keys(pe.imports).length > 0 && (
                        <div className="pe-section">
                            <h4 className="section-title">Imports ({Object.keys(pe.imports).length} DLLs)</h4>
                            <div className="imports-list">
                                {Object.entries(pe.imports).map(([dll, info]) => (
                                    <details key={dll} className={`import-dll ${info.suspicious ? 'suspicious-dll' : ''}`}>
                                        <summary>
                                            <span className="dll-name">{dll}</span>
                                            <span className="dll-count">{info.count} functions</span>
                                            {info.suspicious && <span className="badge badge-packer" style={{ fontSize: '0.7rem' }}>Suspicious</span>}
                                            {info.description && <span className="dll-desc">{info.description}</span>}
                                        </summary>
                                        <div className="dll-functions">
                                            {info.functions.map((fn, i) => (
                                                <span key={i} className="fn-tag">{fn}</span>
                                            ))}
                                        </div>
                                    </details>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── NETWORK IOCs TAB ── */}
            {tab === 'iocs' && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Network Indicators of Compromise</span>
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>{iocs.total_iocs || 0} indicators found</span>
                    </div>
                    {(!iocs.ioc_list || iocs.ioc_list.length === 0) ? (
                        <div className="empty-state" style={{ padding: 40 }}>
                            <Globe size={40} color="var(--color-clean)" />
                            <p>No network indicators found in this file</p>
                        </div>
                    ) : (
                        <div className="ioc-list">
                            {iocs.ioc_list.map((ioc, i) => (
                                <div key={i} className={`ioc-item severity-${ioc.severity}`}>
                                    <span className={`ioc-type-badge type-${ioc.type}`}>{ioc.type}</span>
                                    <span className="ioc-value">{ioc.value}</span>
                                    <span className={`ioc-severity sev-${ioc.severity}`}>{ioc.severity}</span>
                                    <button className="copy-btn" onClick={() => copyToClipboard(ioc.value)} title="Copy"><Copy size={12} /></button>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* ── ENTROPY MAP TAB ── */}
            {tab === 'entropy' && (
                <div className="card">
                    <EntropyHeatmap entropyMap={entropyMap} />
                </div>
            )}

            {/* ── MITRE ATT&CK TAB ── */}
            {tab === 'mitre' && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">MITRE ATT&CK Mapping</span>
                    </div>
                    <MitreMap techniques={mitre} />
                </div>
            )}

            {/* ── DETAILS TAB ── */}
            {tab === 'details' && (
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">File Details</span>
                    </div>
                    <div className="file-details">
                        <div>
                            <div className="detail-row"><span className="detail-label">SHA-256</span><span className="detail-value mono">{data.sha256}</span></div>
                            <div className="detail-row"><span className="detail-label">SHA-1</span><span className="detail-value mono">{data.sha1}</span></div>
                            <div className="detail-row"><span className="detail-label">MD5</span><span className="detail-value mono">{data.md5}</span></div>
                            <div className="detail-row"><span className="detail-label">File Name</span><span className="detail-value">{data.filename}</span></div>
                            <div className="detail-row"><span className="detail-label">External Report</span>
                                <span className="detail-value"><a href={vtLink} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--brand-light)' }}>View Full Report ↗</a></span>
                            </div>
                        </div>
                        <div>
                            <div className="detail-row"><span className="detail-label">File Type</span><span className="detail-value">{data.file_type}</span></div>
                            <div className="detail-row"><span className="detail-label">MIME Type</span><span className="detail-value">{data.mime_type}</span></div>
                            <div className="detail-row"><span className="detail-label">File Size</span><span className="detail-value">{formatSize(data.file_size)} ({data.file_size?.toLocaleString()} bytes)</span></div>
                            <div className="detail-row"><span className="detail-label">Entropy</span><span className="detail-value">{data.entropy} bits/byte</span></div>
                            <div className="detail-row"><span className="detail-label">Magic Bytes</span><span className="detail-value">{data.magic_bytes || 'N/A'}</span></div>
                            <div className="detail-row"><span className="detail-label">Last Scanned</span><span className="detail-value">{data.last_scanned?.slice(0, 19)}</span></div>
                        </div>
                    </div>
                </div>
            )}
        </>
    )
}
