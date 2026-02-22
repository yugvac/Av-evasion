import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import {
    Chart as ChartJS, CategoryScale, LinearScale, BarElement,
    ArcElement, Title, Tooltip, Legend
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import { BarChart3, PieChart, Shield, AlertTriangle, Zap, FileSearch, ShieldAlert, TrendingUp, Target, Activity } from 'lucide-react'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend)

export default function Stats() {
    const [data, setData] = useState(null)
    const [loading, setLoading] = useState(true)
    const navigate = useNavigate()

    useEffect(() => {
        api.getStats().then(d => { setData(d); setLoading(false) }).catch(() => setLoading(false))
    }, [])

    if (loading) return <div className="loading-container"><div className="spinner"></div><p>Loading statistics...</p></div>
    if (!data || data.total_files === 0) return (
        <div className="empty-state">
            <div className="empty-icon"><BarChart3 size={48} /></div>
            <p>No scan data yet. Upload files to see statistics!</p>
            <button className="btn btn-primary" onClick={() => navigate('/')}>Scan a File</button>
        </div>
    )

    const colors = ['#818cf8', '#34d399', '#f472b6', '#fbbf24', '#60a5fa', '#f87171', '#2dd4bf', '#a78bfa', '#fb923c', '#4ade80', '#67e8f9', '#fde68a', '#e2e8f0', '#94a3b8', '#cbd5e1']

    const engineChart = {
        labels: data.engine_rates.map(e => e.engine),
        datasets: [{
            label: 'Detection Rate %',
            data: data.engine_rates.map(e => e.detection_rate),
            backgroundColor: colors.map(c => c + '55'),
            borderColor: colors,
            borderWidth: 2,
            borderRadius: 8,
            borderSkipped: false,
        }],
    }

    const ftLabels = Object.keys(data.file_type_distribution)
    const ftChart = {
        labels: ftLabels,
        datasets: [{
            data: Object.values(data.file_type_distribution),
            backgroundColor: ftLabels.map((_, i) => colors[i % colors.length]),
            borderColor: '#0f1020',
            borderWidth: 3,
            hoverOffset: 8,
        }],
    }

    const chartOpts = {
        responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#94a3b8', font: { family: 'Inter', size: 11, weight: '500' }, padding: 16 } },
            tooltip: {
                backgroundColor: 'rgba(15, 16, 32, 0.95)', titleColor: '#f8fafc', bodyColor: '#94a3b8',
                borderColor: 'rgba(99, 102, 241, 0.3)', borderWidth: 1, cornerRadius: 10,
                padding: 12, titleFont: { weight: '600' },
            },
        },
        scales: {
            x: {
                ticks: { color: '#64748b', font: { size: 9, weight: '500' } },
                grid: { color: 'rgba(99, 102, 241, 0.05)', drawBorder: false },
            },
            y: {
                ticks: { color: '#64748b', font: { weight: '500' } },
                grid: { color: 'rgba(99, 102, 241, 0.05)', drawBorder: false },
            },
        },
    }

    const statCards = [
        { icon: FileSearch, label: 'Total Files Scanned', value: data.total_files, accent: 'purple', glow: 'rgba(129,140,248,0.15)' },
        { icon: ShieldAlert, label: 'Avg Detection Rate', value: `${data.avg_detection_rate}%`, accent: 'orange', glow: 'rgba(251,191,36,0.15)' },
        { icon: Target, label: 'Total Detections', value: data.total_detections, accent: 'pink', glow: 'rgba(244,114,182,0.15)' },
        { icon: Zap, label: 'Total Engine Runs', value: data.total_engines_run?.toLocaleString(), accent: 'blue', glow: 'rgba(96,165,250,0.15)' },
    ]

    return (
        <>
            <div className="page-header-v2">
                <div>
                    <h2>Scan Statistics</h2>
                    <p className="subtitle">Comprehensive overview of all scanning activity</p>
                </div>
            </div>

            {/* Premium Stat Cards */}
            <div className="stats-grid-v2">
                {statCards.map((card, i) => (
                    <div key={i} className={`stat-card-v2 ${card.accent}`} style={{ '--card-glow': card.glow }}>
                        <div className="stat-card-header">
                            <div className={`stat-icon-wrap ${card.accent}`}>
                                <card.icon size={20} />
                            </div>
                        </div>
                        <div className="stat-card-value">{card.value}</div>
                        <div className="stat-card-label">{card.label}</div>
                        <div className="stat-card-glow-bar" />
                    </div>
                ))}
            </div>

            {/* Charts */}
            <div className="charts-grid-v2">
                <div className="chart-card-v2">
                    <div className="chart-card-header">
                        <div className="chart-title-wrap">
                            <BarChart3 size={18} className="chart-title-icon" />
                            <span className="chart-title">Engine Detection Rates</span>
                        </div>
                        <span className="chart-subtitle">{data.engine_rates.length} engines tracked</span>
                    </div>
                    <div className="chart-container-v2">
                        <Bar data={engineChart} options={{ ...chartOpts, plugins: { ...chartOpts.plugins, legend: { display: false } } }} />
                    </div>
                </div>
                <div className="chart-card-v2">
                    <div className="chart-card-header">
                        <div className="chart-title-wrap">
                            <PieChart size={18} className="chart-title-icon" />
                            <span className="chart-title">File Type Distribution</span>
                        </div>
                        <span className="chart-subtitle">{ftLabels.length} types identified</span>
                    </div>
                    <div className="chart-container-v2 doughnut-container">
                        <Doughnut data={ftChart} options={{
                            responsive: true, maintainAspectRatio: false, cutout: '65%',
                            plugins: {
                                legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11, weight: '500' }, padding: 14, boxWidth: 12, usePointStyle: true, pointStyle: 'rectRounded' } },
                                tooltip: chartOpts.plugins.tooltip,
                            },
                        }} />
                    </div>
                </div>
            </div>

            {/* Top Threats */}
            {data.top_threats.length > 0 && (
                <div className="card-v2">
                    <div className="card-header-v2">
                        <div className="chart-title-wrap">
                            <AlertTriangle size={18} className="chart-title-icon danger" />
                            <span className="chart-title">Top Threats Detected</span>
                        </div>
                    </div>
                    <div className="threats-list">
                        {data.top_threats.map((t, i) => (
                            <div key={t.name} className="threat-item">
                                <div className="threat-rank">#{i + 1}</div>
                                <div className="threat-info">
                                    <span className="threat-name">{t.name}</span>
                                </div>
                                <div className="threat-count">
                                    <span className="threat-count-value">{t.count}</span>
                                    <span className="threat-count-label">detections</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Most Detected Files */}
            {data.most_detected.length > 0 && (
                <div className="card-v2">
                    <div className="card-header-v2">
                        <div className="chart-title-wrap">
                            <ShieldAlert size={18} className="chart-title-icon warn" />
                            <span className="chart-title">Most Detected Files</span>
                        </div>
                    </div>
                    <table className="data-table premium-table">
                        <thead>
                            <tr><th>Filename</th><th>Type</th><th>Detection</th><th>SHA-256</th></tr>
                        </thead>
                        <tbody>
                            {data.most_detected.map(s => (
                                <tr key={s.sha256} className="clickable-row" onClick={() => navigate(`/result/${s.sha256}`)}>
                                    <td className="file-cell">{s.filename}</td>
                                    <td><span className="type-badge">{s.file_type}</span></td>
                                    <td><span className="detection-badge danger">{s.detection_ratio}</span></td>
                                    <td className="hash-cell-v2"><span className="hash-text">{s.sha256?.slice(0, 20)}...</span></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Engine Breakdown */}
            <div className="card-v2">
                <div className="card-header-v2">
                    <div className="chart-title-wrap">
                        <Activity size={18} className="chart-title-icon" />
                        <span className="chart-title">Full Engine Metrics</span>
                    </div>
                    <span className="chart-subtitle">{data.engine_rates.length} engines</span>
                </div>
                <table className="data-table premium-table">
                    <thead>
                        <tr><th>Engine</th><th>Total Scans</th><th>Detections</th><th>Detection Rate</th></tr>
                    </thead>
                    <tbody>
                        {data.engine_rates.map((e, i) => (
                            <tr key={e.engine}>
                                <td>
                                    <div className="engine-name-cell">
                                        <div className="engine-dot" style={{ background: colors[i % colors.length] }} />
                                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{e.engine}</span>
                                    </div>
                                </td>
                                <td className="mono-cell">{e.total_scans}</td>
                                <td className="mono-cell danger-text">{e.detections}</td>
                                <td>
                                    <div className="rate-cell">
                                        <div className="rate-bar">
                                            <div className="rate-fill" style={{ width: `${Math.min(e.detection_rate, 100)}%`, background: colors[i % colors.length] }} />
                                        </div>
                                        <span className="rate-value">{e.detection_rate}%</span>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    )
}
