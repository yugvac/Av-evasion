import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { Upload, Search, FileUp, Shield, Zap, Eye, Lock } from 'lucide-react'

export default function ScanUpload() {
    const [dragOver, setDragOver] = useState(false)
    const [scanning, setScanning] = useState(false)
    const [scanFile, setScanFile] = useState(null)
    const [scanStatus, setScanStatus] = useState('')
    const [searchQuery, setSearchQuery] = useState('')
    const [error, setError] = useState('')
    const fileRef = useRef()
    const navigate = useNavigate()

    const handleFiles = async (files) => {
        if (!files || !files.length) return
        const file = files[0]
        if (file.size > 50 * 1024 * 1024) {
            setError('File too large (max 50MB)')
            return
        }
        setError('')
        setScanning(true)
        setScanFile(file.name)
        setScanStatus('Uploading to Analysis Engine...')

        setScanStatus('Uploading to Analysis Engine...')

        try {
            const result = await api.scanFile(file)
            navigate(`/result/${result.sha256}`)
        } catch (e) {
            setError(e.message || 'Scan failed')
            setScanning(false)
        }
    }

    const handleDrop = (e) => {
        e.preventDefault()
        setDragOver(false)
        handleFiles(e.dataTransfer.files)
    }

    const handleSearchSubmit = async (e) => {
        e.preventDefault()
        if (!searchQuery.trim()) return
        setError('')
        try {
            const results = await api.search(searchQuery.trim())
            if (results.length > 0) {
                navigate(`/result/${results[0].sha256}`)
            } else {
                setError('No results found for that hash or filename')
            }
        } catch (e) {
            setError('Search failed')
        }
    }

    return (
        <div className="upload-page">
            {/* Animated background orbs */}
            <div className="upload-bg-orbs">
                <div className="orb orb-1" />
                <div className="orb orb-2" />
                <div className="orb orb-3" />
            </div>

            <div className="upload-content">
                <div className="upload-hero">
                    <div className="hero-badge">
                        <Shield size={14} />
                        <span>Multi-Engine Threat Analysis</span>
                    </div>
                    <h1 className="upload-hero-title">
                        Scan Files with <span className="gradient-text">70+ AV Engines</span>
                    </h1>
                    <p className="upload-hero-sub">
                        Upload any file for instant deep analysis against the world's leading antivirus engines.
                        Get comprehensive threat detection, entropy analysis, and behavioral insights.
                    </p>
                </div>

                {scanning ? (
                    <div className="scan-progress-card">
                        <div className="scan-progress-glow" />
                        <div className="scan-spinner-wrap">
                            <div className="spinner" style={{ width: 64, height: 64, borderWidth: 3 }}></div>
                            <Shield size={24} className="scan-spinner-icon" />
                        </div>
                        <div className="scan-progress-text">{scanStatus}</div>
                        <div className="scan-progress-file">{scanFile}</div>
                        <div className="scan-progress-hint">
                            This may take 30-60 seconds — Real-time multi-engine scanning
                        </div>
                    </div>
                ) : (
                    <>
                        <div
                            className={`dropzone-v2 ${dragOver ? 'drag-over' : ''}`}
                            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                            onDragLeave={() => setDragOver(false)}
                            onDrop={handleDrop}
                            onClick={() => fileRef.current?.click()}
                        >
                            <div className="dropzone-grid" />
                            <div className="dropzone-inner">
                                <div className="dropzone-icon-wrap">
                                    {dragOver
                                        ? <FileUp size={44} strokeWidth={1.5} />
                                        : <Upload size={44} strokeWidth={1.5} />
                                    }
                                </div>
                                <div className="dropzone-label">
                                    {dragOver ? 'Release to start analysis' : 'Drop your file here or click to browse'}
                                </div>
                                <div className="dropzone-sub">
                                    Supports any file type · Max 50 MB · Analyzed by real AV engines
                                </div>
                                <div className="dropzone-formats">
                                    <span className="format-tag">EXE</span>
                                    <span className="format-tag">DLL</span>
                                    <span className="format-tag">PDF</span>
                                    <span className="format-tag">ZIP</span>
                                    <span className="format-tag">PY</span>
                                    <span className="format-tag">DOC</span>
                                    <span className="format-tag">+more</span>
                                </div>
                            </div>
                            <input
                                type="file"
                                ref={fileRef}
                                onChange={(e) => handleFiles(e.target.files)}
                            />
                        </div>

                        <div className="search-section">
                            <div className="search-divider-v2">
                                <div className="divider-line" />
                                <span>OR SEARCH BY HASH</span>
                                <div className="divider-line" />
                            </div>
                            <form className="search-bar-v2" onSubmit={handleSearchSubmit}>
                                <div className="search-input-wrap">
                                    <Search size={18} className="search-input-icon" />
                                    <input
                                        type="text"
                                        placeholder="SHA-256, SHA-1, MD5, or filename..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                    />
                                </div>
                                <button type="submit" className="btn btn-primary btn-search">
                                    <Search size={16} /> Search
                                </button>
                            </form>
                        </div>

                        {/* Feature pills */}
                        <div className="upload-features">
                            <div className="feature-pill">
                                <Zap size={14} />
                                <span>Real-time scanning</span>
                            </div>
                            <div className="feature-pill">
                                <Eye size={14} />
                                <span>Behavioral analysis</span>
                            </div>
                            <div className="feature-pill">
                                <Lock size={14} />
                                <span>Entropy detection</span>
                            </div>
                        </div>
                    </>
                )}

                {error && (
                    <div className="upload-error">
                        <span>{error}</span>
                    </div>
                )}
            </div>
        </div>
    )
}
