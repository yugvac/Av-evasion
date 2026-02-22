import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { Eye, FileText, Search, Shield, ArrowUpDown, Filter, Download, Copy, Check } from 'lucide-react'

export default function History() {
    const [data, setData] = useState(null)
    const [loading, setLoading] = useState(true)
    const [searchTerm, setSearchTerm] = useState('')
    const [copiedHash, setCopiedHash] = useState(null)
    const navigate = useNavigate()

    useEffect(() => {
        api.getHistory(100).then(d => { setData(d); setLoading(false) }).catch(() => setLoading(false))
    }, [])

    if (loading) return <div className="loading-container"><div className="spinner"></div><p>Loading history...</p></div>

    const scans = data?.scans || []

    const formatSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B'
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
    }

    const filteredScans = scans.filter(s =>
        s.filename?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        s.sha256?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        s.file_type?.toLowerCase().includes(searchTerm.toLowerCase())
    )

    const copyHash = (hash, e) => {
        e.stopPropagation()
        navigator.clipboard.writeText(hash)
        setCopiedHash(hash)
        setTimeout(() => setCopiedHash(null), 2000)
    }

    const formatDate = (dateStr) => {
        if (!dateStr) return '—'
        const d = new Date(dateStr)
        const now = new Date()
        const diff = now - d
        if (diff < 60000) return 'Just now'
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    }

    return (
        <>
            <div className="page-header-v2">
                <div>
                    <h2>Scan History</h2>
                    <p className="subtitle">{data?.total || 0} files analyzed</p>
                </div>
                <div className="page-header-actions">
                    <div className="history-search-wrap">
                        <Search size={16} className="history-search-icon" />
                        <input
                            type="text"
                            placeholder="Filter by name, hash, or type..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="history-search-input"
                        />
                    </div>
                </div>
            </div>

            <div className="history-card">
                {filteredScans.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon"><FileText size={48} /></div>
                        {scans.length === 0
                            ? <p>No files scanned yet. Upload your first file!</p>
                            : <p>No results match your filter.</p>
                        }
                        <button className="btn btn-primary" onClick={() => navigate('/')}>Scan a File</button>
                    </div>
                ) : (
                    <div className="history-table-wrap">
                        <table className="data-table history-table">
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th>Detection</th>
                                    <th>Entropy</th>
                                    <th>SHA-256</th>
                                    <th>Scanned</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredScans.map(scan => {
                                    const pct = scan.total_engines > 0 ? (scan.detections / scan.total_engines) : 0
                                    let cellClass = 'clean'
                                    if (pct > 0.4) cellClass = 'danger'
                                    else if (pct > 0) cellClass = 'warn'

                                    return (
                                        <tr key={scan.sha256}
                                            className="history-row"
                                            onClick={() => navigate(`/result/${scan.sha256}`)}>
                                            <td>
                                                <div className="file-name-cell">
                                                    <div className="file-icon-mini">
                                                        <FileText size={14} />
                                                    </div>
                                                    <span className="file-name-text">{scan.filename}</span>
                                                </div>
                                            </td>
                                            <td><span className="type-badge">{scan.file_type}</span></td>
                                            <td className="mono-cell">{formatSize(scan.file_size)}</td>
                                            <td>
                                                <span className={`detection-badge ${cellClass}`}>
                                                    {scan.detection_ratio}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={`entropy-cell ${scan.entropy > 7 ? 'high' : scan.entropy > 5 ? 'mid' : 'low'}`}>
                                                    {scan.entropy?.toFixed(2)}
                                                </span>
                                            </td>
                                            <td>
                                                <div className="hash-cell-v2">
                                                    <span className="hash-text">{scan.sha256?.slice(0, 16)}...</span>
                                                    <button
                                                        className="hash-copy-btn"
                                                        onClick={(e) => copyHash(scan.sha256, e)}
                                                        title="Copy SHA-256"
                                                    >
                                                        {copiedHash === scan.sha256 ? <Check size={12} /> : <Copy size={12} />}
                                                    </button>
                                                </div>
                                            </td>
                                            <td className="date-cell">{formatDate(scan.last_scanned)}</td>
                                            <td>
                                                <button
                                                    className="view-btn"
                                                    title="View Details"
                                                    onClick={e => { e.stopPropagation(); navigate(`/result/${scan.sha256}`) }}
                                                >
                                                    <Eye size={14} />
                                                </button>
                                            </td>
                                        </tr>
                                    )
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </>
    )
}
