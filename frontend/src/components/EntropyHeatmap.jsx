import { useRef, useEffect, useState } from 'react'

/**
 * Inferno-inspired color ramp for entropy visualization.
 * Maps a normalized value [0,1] → [dark purple → red → orange → yellow → white]
 */
function entropyColor(t) {
    // Clamp
    t = Math.max(0, Math.min(1, t))

    // 5-stop inferno-style ramp
    const stops = [
        { p: 0.0, r: 15, g: 10, b: 60 },   // very dark indigo
        { p: 0.25, r: 80, g: 20, b: 160 },   // purple
        { p: 0.5, r: 200, g: 50, b: 80 },   // red-magenta
        { p: 0.75, r: 250, g: 160, b: 20 },   // orange
        { p: 1.0, r: 255, g: 255, b: 120 },   // bright yellow
    ]

    // Find the two stops to interpolate between
    let lo = stops[0], hi = stops[stops.length - 1]
    for (let i = 0; i < stops.length - 1; i++) {
        if (t >= stops[i].p && t <= stops[i + 1].p) {
            lo = stops[i]
            hi = stops[i + 1]
            break
        }
    }

    const range = hi.p - lo.p || 1
    const f = (t - lo.p) / range
    const r = Math.round(lo.r + (hi.r - lo.r) * f)
    const g = Math.round(lo.g + (hi.g - lo.g) * f)
    const b = Math.round(lo.b + (hi.b - lo.b) * f)
    return { r, g, b }
}

export default function EntropyHeatmap({ entropyMap }) {
    const canvasRef = useRef(null)
    const tooltipRef = useRef(null)
    const [tooltip, setTooltip] = useState(null)

    // Compute actual min/max from data for auto-scaling
    const blocks = entropyMap?.blocks || []
    const dataMin = blocks.length ? Math.min(...blocks.map(b => b.entropy)) : 0
    const dataMax = blocks.length ? Math.max(...blocks.map(b => b.entropy)) : 8

    useEffect(() => {
        if (!canvasRef.current || !blocks.length) return

        const canvas = canvasRef.current
        const ctx = canvas.getContext('2d')
        const width = canvas.width
        const height = canvas.height

        // Clear with dark background
        ctx.fillStyle = '#0a0a1a'
        ctx.fillRect(0, 0, width, height)

        // Grid layout
        const cols = Math.ceil(Math.sqrt(blocks.length * (width / height)))
        const rows = Math.ceil(blocks.length / cols)
        const cellW = width / cols
        const cellH = height / rows

        // Normalize range — auto-scale to actual data
        const range = dataMax - dataMin || 1

        blocks.forEach((block, i) => {
            const col = i % cols
            const row = Math.floor(i / cols)
            const x = col * cellW
            const y = row * cellH

            // Normalize to 0–1 based on actual data range
            const norm = (block.entropy - dataMin) / range
            const { r, g, b } = entropyColor(norm)

            ctx.fillStyle = `rgb(${r},${g},${b})`
            ctx.fillRect(x, y, cellW + 0.5, cellH + 0.5)
        })

        // Draw subtle grid lines
        ctx.strokeStyle = 'rgba(255,255,255,0.06)'
        ctx.lineWidth = 0.5
        for (let c = 1; c < cols; c++) {
            ctx.beginPath()
            ctx.moveTo(c * cellW, 0)
            ctx.lineTo(c * cellW, height)
            ctx.stroke()
        }
        for (let r = 1; r < rows; r++) {
            ctx.beginPath()
            ctx.moveTo(0, r * cellH)
            ctx.lineTo(width, r * cellH)
            ctx.stroke()
        }

        // Axis labels
        ctx.fillStyle = 'rgba(255,255,255,0.7)'
        ctx.font = 'bold 11px JetBrains Mono, monospace'
        ctx.fillText('0x0', 6, height - 6)
        if (entropyMap.file_size) {
            const sizeHex = '0x' + entropyMap.file_size.toString(16).toUpperCase()
            ctx.fillText(sizeHex, width - ctx.measureText(sizeHex).width - 6, height - 6)
        }
    }, [entropyMap, blocks, dataMin, dataMax])

    const handleMouseMove = (e) => {
        if (!blocks.length || !canvasRef.current) return
        const canvas = canvasRef.current
        const rect = canvas.getBoundingClientRect()
        const x = e.clientX - rect.left
        const y = e.clientY - rect.top
        const scaleX = canvas.width / rect.width
        const scaleY = canvas.height / rect.height

        const cols = Math.ceil(Math.sqrt(blocks.length * (canvas.width / canvas.height)))
        const cellW = canvas.width / cols
        const cellH = canvas.height / Math.ceil(blocks.length / cols)

        const col = Math.floor(x * scaleX / cellW)
        const row = Math.floor(y * scaleY / cellH)
        const idx = row * cols + col

        if (idx >= 0 && idx < blocks.length) {
            const block = blocks[idx]
            const range = dataMax - dataMin || 1
            const norm = (block.entropy - dataMin) / range
            const { r, g, b } = entropyColor(norm)
            setTooltip({
                x: e.clientX - rect.left,
                y: e.clientY - rect.top - 45,
                offset: '0x' + block.offset.toString(16).toUpperCase(),
                entropy: block.entropy.toFixed(4),
                color: `rgb(${r},${g},${b})`,
                pct: (norm * 100).toFixed(0),
            })
        }
    }

    const handleMouseLeave = () => setTooltip(null)

    if (!blocks.length) {
        return <div className="empty-state" style={{ padding: 40 }}><p>No entropy data available</p></div>
    }

    // Classify entropy
    const overall = entropyMap.overall || 0
    let classification = 'Structured'
    let classColor = '#10b981'
    if (overall >= 7.0) {
        classification = 'Encrypted/Packed'
        classColor = '#ef4444'
    } else if (overall >= 5.5) {
        classification = 'Compressed'
        classColor = '#f59e0b'
    } else if (overall >= 3.0) {
        classification = 'Mixed'
        classColor = '#818cf8'
    }

    return (
        <div className="entropy-heatmap-container">
            <div className="entropy-header">
                <div>
                    <h3 className="section-label">ENTROPY HEATMAP</h3>
                    <span className="text-dim">Visual entropy distribution across file</span>
                </div>
                <div className="entropy-stats-row">
                    <div className="entropy-stat-pill">
                        <span className="stat-label">Overall</span>
                        <span className="stat-value" style={{ color: classColor }}>{overall.toFixed(2)}</span>
                    </div>
                    <div className="entropy-stat-pill">
                        <span className="stat-label">Min</span>
                        <span className="stat-value">{dataMin.toFixed(2)}</span>
                    </div>
                    <div className="entropy-stat-pill">
                        <span className="stat-label">Max</span>
                        <span className="stat-value">{dataMax.toFixed(2)}</span>
                    </div>
                    <div className="entropy-stat-pill">
                        <span className="stat-label">Blocks</span>
                        <span className="stat-value">{blocks.length}</span>
                    </div>
                    <div className="entropy-stat-pill classification" style={{ borderColor: classColor }}>
                        <span className="stat-label">Type</span>
                        <span className="stat-value" style={{ color: classColor }}>{classification}</span>
                    </div>
                </div>
            </div>

            <div className="entropy-canvas-wrap" ref={tooltipRef}>
                <canvas
                    ref={canvasRef}
                    width={960}
                    height={280}
                    className="entropy-canvas"
                    onMouseMove={handleMouseMove}
                    onMouseLeave={handleMouseLeave}
                />
                {tooltip && (
                    <div
                        className="entropy-hover-tooltip"
                        style={{ left: tooltip.x, top: tooltip.y }}
                    >
                        <div className="eht-color" style={{ background: tooltip.color }} />
                        <div className="eht-info">
                            <span className="eht-offset">{tooltip.offset}</span>
                            <span className="eht-val">{tooltip.entropy} bits/byte</span>
                        </div>
                    </div>
                )}
            </div>

            <div className="entropy-legend-v2">
                <span className="legend-label">{dataMin.toFixed(1)}</span>
                <div className="legend-gradient-bar" />
                <span className="legend-label">{dataMax.toFixed(1)}</span>
            </div>
            <div className="legend-desc-row">
                <span>Low entropy (uniform/empty)</span>
                <span>High entropy (random/encrypted)</span>
            </div>
        </div>
    )
}
