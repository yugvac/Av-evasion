import { Shield, AlertTriangle, Target } from 'lucide-react'

const TACTIC_COLORS = {
    'Execution': '#e17055',
    'Persistence': '#fdcb6e',
    'Defense Evasion': '#a29bfe',
    'Command and Control': '#fd79a8',
    'Discovery': '#74b9ff',
    'Credential Access': '#ff7675',
}

export default function MitreMap({ techniques }) {
    if (!techniques?.length) {
        return (
            <div className="empty-state" style={{ padding: 40 }}>
                <Shield size={40} color="var(--color-clean)" />
                <p>No MITRE ATT&CK techniques detected</p>
            </div>
        )
    }

    // Group by tactic
    const grouped = {}
    techniques.forEach(t => {
        if (!grouped[t.tactic]) grouped[t.tactic] = []
        grouped[t.tactic].push(t)
    })

    return (
        <div className="mitre-container">
            <div className="mitre-summary">
                <AlertTriangle size={16} />
                <span><strong>{techniques.length}</strong> ATT&CK techniques mapped from file analysis</span>
            </div>

            {Object.entries(grouped).map(([tactic, techs]) => (
                <div key={tactic} className="mitre-tactic-group">
                    <div className="mitre-tactic-header" style={{ borderLeftColor: TACTIC_COLORS[tactic] || '#636e72' }}>
                        <Target size={14} style={{ color: TACTIC_COLORS[tactic] || '#636e72' }} />
                        <span className="mitre-tactic-name">{tactic}</span>
                        <span className="mitre-tactic-count">{techs.length}</span>
                    </div>

                    <div className="mitre-techniques">
                        {techs.map(t => (
                            <div key={t.id} className="mitre-technique-card">
                                <div className="mitre-technique-header">
                                    <span className="mitre-id">{t.id}</span>
                                    <span className="mitre-technique-name">{t.name}</span>
                                    <span className={`mitre-confidence ${t.confidence >= 75 ? 'high' : t.confidence >= 50 ? 'med' : 'low'}`}>
                                        {t.confidence}%
                                    </span>
                                </div>
                                <div className="mitre-description">{t.description}</div>
                                <div className="mitre-indicators">
                                    {t.matched_indicators.map((ind, i) => (
                                        <span key={i} className="mitre-indicator-tag">{ind}</span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ))}
        </div>
    )
}
