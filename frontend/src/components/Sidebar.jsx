import { useLocation, useNavigate } from 'react-router-dom'
import { Upload, Clock, BarChart3, Shield, Sparkles, ChevronRight } from 'lucide-react'

export default function Sidebar() {
    const location = useLocation()
    const navigate = useNavigate()

    const navItems = [
        { path: '/', label: 'Scan File', icon: Upload, desc: 'Upload & analyze' },
        { path: '/history', label: 'History', icon: Clock, desc: 'Past scan results' },
        { path: '/stats', label: 'Statistics', icon: BarChart3, desc: 'Analytics dashboard' },
    ]

    return (
        <aside className="sidebar">
            <div className="sidebar-brand" style={{ cursor: 'pointer' }} onClick={() => navigate('/')}>
                <div className="brand-icon-wrap">
                    <div className="brand-icon-glow" />
                    <Shield size={28} strokeWidth={2.2} />
                </div>
                <div>
                    <h1>SentinelLab</h1>
                    <div className="version-tag">Advanced Malware Scanner</div>
                </div>
            </div>

            <nav className="sidebar-nav">
                <div className="nav-section">
                    <div className="nav-section-title">Menu</div>
                    {navItems.map(item => {
                        const isActive = location.pathname === item.path
                        return (
                            <button
                                key={item.path}
                                className={`nav-item ${isActive ? 'active' : ''}`}
                                onClick={() => navigate(item.path)}
                            >
                                <div className="nav-item-icon">
                                    <item.icon size={18} />
                                </div>
                                <div className="nav-item-text">
                                    <span className="nav-item-label">{item.label}</span>
                                    <span className="nav-item-desc">{item.desc}</span>
                                </div>
                                {isActive && <ChevronRight size={14} className="nav-chevron" />}
                            </button>
                        )
                    })}
                </div>
            </nav>

            <div className="sidebar-footer">
                <div className="sidebar-footer-inner">
                    <Sparkles size={13} />
                    <span>Multi-Engine Analysis Platform</span>
                </div>
                <div className="sidebar-footer-version">v2.0 · VirusTotal API</div>
            </div>
        </aside>
    )
}
