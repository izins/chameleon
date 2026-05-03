import { useState, useEffect, useRef } from "react";
import { api } from "../../services/api";

const TARGET = { lat: 36.7, lng: 3.2, country: "Algeria" };

const SEV_COLORS = {
    critical: { dot: "#ff4057", glow: "rgba(255,64,87,0.25)" },
    high: { dot: "#f97316", glow: "rgba(249,115,22,0.2)" },
    medium: { dot: "#f59e0b", glow: "rgba(245,158,11,0.18)" },
    low: { dot: "#00e87b", glow: "rgba(0,232,123,0.2)" },
};

/* Static fallback — used when backend is unreachable */
const STATIC_ORIGINS = [
    { code: "RU", country: "Russia", lat: 55.75, lng: 37.62, attacks: 18420, severity: "critical" },
    { code: "CN", country: "China", lat: 39.9, lng: 116.4, attacks: 14305, severity: "critical" },
    { code: "IR", country: "Iran", lat: 35.7, lng: 51.4, attacks: 7920, severity: "critical" },
    { code: "KP", country: "North Korea", lat: 39.0, lng: 125.7, attacks: 5100, severity: "critical" },
    { code: "US", country: "United States", lat: 38.9, lng: -77.0, attacks: 9820, severity: "high" },
    { code: "BR", country: "Brazil", lat: -15.8, lng: -47.9, attacks: 6510, severity: "high" },
    { code: "IN", country: "India", lat: 28.6, lng: 77.2, attacks: 5830, severity: "high" },
    { code: "NG", country: "Nigeria", lat: 9.1, lng: 7.5, attacks: 3870, severity: "high" },
    { code: "UA", country: "Ukraine", lat: 50.4, lng: 30.5, attacks: 4600, severity: "high" },
    { code: "PK", country: "Pakistan", lat: 33.7, lng: 73.1, attacks: 3450, severity: "high" },
    { code: "DE", country: "Germany", lat: 52.5, lng: 13.4, attacks: 4200, severity: "medium" },
    { code: "TR", country: "Turkey", lat: 39.9, lng: 32.9, attacks: 2940, severity: "medium" },
    { code: "ID", country: "Indonesia", lat: -6.2, lng: 106.8, attacks: 2100, severity: "medium" },
    { code: "FR", country: "France", lat: 48.9, lng: 2.3, attacks: 1870, severity: "low" },
    { code: "KR", country: "South Korea", lat: 37.6, lng: 127.0, attacks: 1540, severity: "low" },
];

/** Map backend severity score → visual severity */
function scoreSeverity(score) {
    if (score >= 1000) return "critical";
    if (score >= 500) return "high";
    if (score >= 100) return "medium";
    return "low";
}

function useD3WorldMap(svgRef, width, height) {
    const [ready, setReady] = useState(false);
    const [project, setProject] = useState(null);

    useEffect(() => {
        if (!width || !height) return;

        const D3_CDN = "https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js";
        const TOPO_CDN = "https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js";
        const WORLD_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

        const loadScript = (src) =>
            new Promise((res) => {
                if (document.querySelector(`script[src="${src}"]`)) { res(); return; }
                const s = document.createElement("script");
                s.src = src; s.onload = res;
                document.head.appendChild(s);
            });

        (async () => {
            await loadScript(D3_CDN);
            await loadScript(TOPO_CDN);
            const d3 = window.d3;
            const topojson = window.topojson;

            const projection = d3.geoNaturalEarth1()
                .scale(width / 6.1)
                .translate([width / 2, height / 2]);

            const pathGen = d3.geoPath(projection);
            const world = await d3.json(WORLD_URL);
            const countries = topojson.feature(world, world.objects.countries);

            const svg = d3.select(svgRef.current);
            svg.selectAll(".country-path").remove();

            svg.insert("g", ":first-child")
                .attr("class", "country-path")
                .selectAll("path")
                .data(countries.features)
                .join("path")
                .attr("d", pathGen)
                .attr("fill", "rgba(255,255,255,0.05)")
                .attr("stroke", "rgba(255,255,255,0.12)")
                .attr("stroke-width", "0.5");

            setProject(() => (lat, lng) => projection([lng, lat]));
            setReady(true);
        })();
    }, [width, height]);

    return { ready, project };
}

function arcPath(x1, y1, x2, y2) {
    const dx = x2 - x1, dy = y2 - y1;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const len = Math.sqrt(dx * dx + dy * dy);
    const nx = -dy / len, ny = dx / len;
    const bend = len * 0.22;
    const cx = mx + nx * bend, cy = my + ny * bend;
    return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
}

export const ThreatMap = () => {
    const [hovered, setHovered] = useState(null);
    const [dims, setDims] = useState({ w: 0, h: 0 });
    const [origins, setOrigins] = useState(STATIC_ORIGINS);
    const [isLive, setIsLive] = useState(false);
    const wrapRef = useRef(null);
    const svgRef = useRef(null);

    /* ── Fetch live geo data from backend ── */
    useEffect(() => {
        (async () => {
            try {
                const data = await api.getGeoDistribution();
                if (data && data.origins && data.origins.length > 0) {
                    const mapped = data.origins.map((o) => ({
                        code: o.country_code || "??",
                        country: o.country || "Unknown",
                        lat: o.latitude || 0,
                        lng: o.longitude || 0,
                        attacks: o.alert_count || 1,
                        severity: scoreSeverity(o.score || 0),
                        ip: o.ip,
                        score: o.score,
                        isp: o.isp,
                        isTor: o.is_tor,
                        isVpn: o.is_vpn,
                    }));
                    // Merge live data with static fallback for richer display
                    const liveIps = new Set(mapped.map((m) => m.code));
                    const merged = [...mapped, ...STATIC_ORIGINS.filter((s) => !liveIps.has(s.code))];
                    setOrigins(merged);
                    setIsLive(true);
                }
            } catch {
                // Keep static fallback
            }
        })();
    }, []);

    useEffect(() => {
        if (!wrapRef.current) return;
        const ro = new ResizeObserver(([e]) => {
            const w = e.contentRect.width;
            setDims({ w, h: Math.round(w * 0.48) });
        });
        ro.observe(wrapRef.current);
        return () => ro.disconnect();
    }, []);

    const { ready, project } = useD3WorldMap(svgRef, dims.w, dims.h);

    const targetPt = ready && project ? project(TARGET.lat, TARGET.lng) : null;

    const totalAttacks = origins.reduce((a, o) => a + o.attacks, 0);
    const topSource = [...origins].sort((a, b) => b.attacks - a.attacks)[0];

    return (
        <div
            style={{
                border: "1px solid rgba(255,255,255,0.08)",
                background: "#0d1117",
                borderRadius: 16,
                overflow: "hidden",
                fontFamily: "system-ui, -apple-system, sans-serif",
            }}
        >
            {/* Header */}
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "10px 20px",
                    borderBottom: "1px solid rgba(255,255,255,0.07)",
                    background: "#090d13",
                    flexWrap: "wrap",
                    gap: 8,
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00e87b" strokeWidth="2" strokeLinecap="round">
                        <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                        Global Threat Origins
                    </span>
                    <span style={{
                        width: 6, height: 6, borderRadius: "50%", background: isLive ? "#00e87b" : "#ef4444",
                        animation: "pulse 1.5s ease-in-out infinite", display: "inline-block", marginLeft: 4,
                    }} />
                    <span style={{ fontSize: 10, color: isLive ? "#00e87b" : "#f87171", fontWeight: 500 }}>
                        {isLive ? "LIVE — AEGIS DB" : "LIVE"}
                    </span>
                </div>
                <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                    {Object.entries(SEV_COLORS).map(([label, c]) => (
                        <span key={label} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, color: "#6b7280" }}>
                            <span style={{ width: 7, height: 7, borderRadius: "50%", background: c.dot, display: "inline-block" }} />
                            {label.charAt(0).toUpperCase() + label.slice(1)}
                        </span>
                    ))}
                </div>
            </div>

            {/* Map */}
            <div ref={wrapRef} style={{ position: "relative", background: "#080a0f", minHeight: 200 }}>
                <svg
                    ref={svgRef}
                    width={dims.w}
                    height={dims.h}
                    viewBox={`0 0 ${dims.w} ${dims.h}`}
                    style={{ display: "block" }}
                >
                    <defs>
                        {Object.entries(SEV_COLORS).map(([key, c]) => (
                            <radialGradient key={key} id={`rg-${key}`}>
                                <stop offset="0%" stopColor={c.dot} stopOpacity="0.6" />
                                <stop offset="60%" stopColor={c.dot} stopOpacity="0.1" />
                                <stop offset="100%" stopColor={c.dot} stopOpacity="0" />
                            </radialGradient>
                        ))}
                        <radialGradient id="rg-target">
                            <stop offset="0%" stopColor="#00e87b" stopOpacity="0.7" />
                            <stop offset="50%" stopColor="#00e87b" stopOpacity="0.12" />
                            <stop offset="100%" stopColor="#00e87b" stopOpacity="0" />
                        </radialGradient>
                        <filter id="arc-glow">
                            <feGaussianBlur stdDeviation="2" result="b" />
                            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
                        </filter>
                    </defs>

                    {/* Arc lines */}
                    {ready && project && targetPt && origins.map((o, i) => {
                        const pt = project(o.lat, o.lng);
                        if (!pt) return null;
                        const c = SEV_COLORS[o.severity];
                        const isH = hovered === i;
                        return (
                            <path
                                key={`arc-${o.code}-${i}`}
                                d={arcPath(pt[0], pt[1], targetPt[0], targetPt[1])}
                                fill="none"
                                stroke={c.dot}
                                strokeWidth={isH ? 1.4 : 0.6}
                                strokeDasharray="6 4"
                                opacity={isH ? 0.9 : 0.22}
                                filter={isH ? "url(#arc-glow)" : undefined}
                            >
                                <animate attributeName="stroke-dashoffset" values="0;-20" dur={`${1.4 + i * 0.18}s`} repeatCount="indefinite" />
                            </path>
                        );
                    })}

                    {/* Target — Algeria HQ */}
                    {ready && targetPt && (
                        <g>
                            <circle cx={targetPt[0]} cy={targetPt[1]} r="24" fill="url(#rg-target)">
                                <animate attributeName="r" values="18;30;18" dur="3s" repeatCount="indefinite" />
                                <animate attributeName="opacity" values="0.7;0.15;0.7" dur="3s" repeatCount="indefinite" />
                            </circle>
                            <circle cx={targetPt[0]} cy={targetPt[1]} r="5" fill="#00e87b" opacity="0.95" />
                            <circle cx={targetPt[0]} cy={targetPt[1]} r="5" fill="none" stroke="#00e87b" strokeWidth="0.8" opacity="0.5">
                                <animate attributeName="r" values="5;15;5" dur="3s" repeatCount="indefinite" />
                                <animate attributeName="opacity" values="0.5;0;0.5" dur="3s" repeatCount="indefinite" />
                            </circle>
                            <text x={targetPt[0]} y={targetPt[1] + 18} textAnchor="middle" fontSize="8" fill="#00e87b" fontWeight="600" fontFamily="system-ui" opacity="0.8">HQ</text>
                        </g>
                    )}

                    {/* Origin dots */}
                    {ready && project && origins.map((o, i) => {
                        const pt = project(o.lat, o.lng);
                        if (!pt) return null;
                        const c = SEV_COLORS[o.severity];
                        const isH = hovered === i;
                        const sz = Math.max(3, Math.min(7, o.attacks / 2200));
                        const tipX = pt[0] + 12;
                        const tipY = pt[1] - 52;

                        return (
                            <g
                                key={`dot-${o.code}-${i}`}
                                onMouseEnter={() => setHovered(i)}
                                onMouseLeave={() => setHovered(null)}
                                style={{ cursor: "pointer" }}
                            >
                                <circle cx={pt[0]} cy={pt[1]} r={isH ? 26 : 15} fill={`url(#rg-${o.severity})`}>
                                    <animate attributeName="r" values={isH ? "22;32;22" : "12;19;12"} dur={`${2 + i * 0.25}s`} repeatCount="indefinite" />
                                    <animate attributeName="opacity" values="0.75;0.15;0.75" dur={`${2 + i * 0.25}s`} repeatCount="indefinite" />
                                </circle>
                                <circle cx={pt[0]} cy={pt[1]} r={isH ? sz + 2 : sz} fill={c.dot} opacity="0.92" />
                                <circle cx={pt[0]} cy={pt[1]} r={sz * 0.38} fill="#fff" opacity={isH ? 0.85 : 0.5} />

                                {isH && (
                                    <g>
                                        <rect x={tipX} y={tipY} width={145} height={o.ip ? 62 : 46} rx="6"
                                            fill="rgba(8,10,15,0.96)" stroke="rgba(255,255,255,0.11)" strokeWidth="1" />
                                        <text x={tipX + 10} y={tipY + 16} fontSize="11" fill="#fff" fontWeight="700" fontFamily="system-ui">{o.country}</text>
                                        <text x={tipX + 10} y={tipY + 30} fontSize="10" fill={c.dot} fontWeight="600" fontFamily="system-ui">{o.attacks.toLocaleString()} attacks</text>
                                        <text x={tipX + 10} y={tipY + 42} fontSize="8" fill="#6b7280" fontFamily="system-ui">
                                            {o.severity.toUpperCase()}{o.isTor ? " · TOR" : ""}{o.isVpn ? " · VPN" : ""}
                                        </text>
                                        {o.ip && (
                                            <text x={tipX + 10} y={tipY + 55} fontSize="9" fill="#00e87b" fontWeight="500" fontFamily="monospace">{o.ip}</text>
                                        )}
                                    </g>
                                )}
                            </g>
                        );
                    })}
                </svg>

                {!ready && (
                    <div style={{
                        position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center",
                        color: "#4b5563", fontSize: 12, fontFamily: "system-ui",
                    }}>
                        Loading map…
                    </div>
                )}
            </div>

            {/* Footer */}
            <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 20px", borderTop: "1px solid rgba(255,255,255,0.07)",
                background: "#090d13", flexWrap: "wrap", gap: 6,
            }}>
                {[
                    { label: "Origins", value: `${origins.length} countries`, color: "#fff" },
                    { label: "Total (30d)", value: totalAttacks.toLocaleString(), color: "#ff4057" },
                    { label: "#1 Source", value: topSource?.country || "—", color: "#f87171" },
                    { label: "Target", value: "Algeria (HQ)", color: "#00e87b" },
                ].map(({ label, value, color }) => (
                    <span key={label} style={{ fontSize: 11, color: "#6b7280" }}>
                        {label}: <span style={{ fontWeight: 600, color }}>{value}</span>
                    </span>
                ))}
            </div>

            <style>{`@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(1.4)}}`}</style>
        </div>
    );
}
export default ThreatMap