import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import random
import time

st.set_page_config(
    page_title="Cyber Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ──────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #080c10; }
[data-testid="stSidebar"] { background-color: #0d1219; }
.metric-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(0,229,160,0.15);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
}
.metric-val { font-size: 2rem; font-weight: 700; color: #00e5a0; }
.metric-label { font-size: 0.75rem; color: #64748b; margin-top: 4px; }
.critical { color: #e24b4a !important; }
.high     { color: #f59e0b !important; }
.medium   { color: #378add !important; }
.low      { color: #00e5a0 !important; }
.section-title {
    font-size: 1rem;
    font-weight: 600;
    color: #00e5a0;
    border-bottom: 1px solid rgba(0,229,160,0.2);
    padding-bottom: 6px;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ── Constants ────────────────────────────────────────────────
ATTACK_TYPES = ["SQL Injection","Brute Force","DDoS","Port Scan","Phishing","Malware C2"]
SEVERITIES   = ["CRITICAL","HIGH","MEDIUM","LOW"]
SEV_COLORS   = {"CRITICAL":"#e24b4a","HIGH":"#f59e0b","MEDIUM":"#378add","LOW":"#00e5a0"}

COUNTRIES = [
    {"name":"Russia",    "lat":55.75, "lon":37.61, "code":"RU"},
    {"name":"China",     "lat":39.90, "lon":116.40,"code":"CN"},
    {"name":"USA",       "lat":38.90, "lon":-77.03,"code":"US"},
    {"name":"N.Korea",   "lat":39.02, "lon":125.75,"code":"KP"},
    {"name":"Iran",      "lat":35.68, "lon":51.42, "code":"IR"},
    {"name":"Ukraine",   "lat":50.45, "lon":30.52, "code":"UA"},
    {"name":"Nigeria",   "lat":9.07,  "lon":7.40,  "code":"NG"},
    {"name":"Germany",   "lat":52.52, "lon":13.40, "code":"DE"},
    {"name":"Brazil",    "lat":-15.78,"lon":-47.92,"code":"BR"},
    {"name":"India",     "lat":28.61, "lon":77.20, "code":"IN"},
]

IP_POOL = [
    {"ip":"192.168.1.105","country":"RU","score":9},
    {"ip":"45.33.32.156", "country":"CN","score":12},
    {"ip":"198.51.100.14","country":"US","score":78},
    {"ip":"203.0.113.45", "country":"IR","score":6},
    {"ip":"104.21.56.78", "country":"DE","score":88},
    {"ip":"91.108.4.230", "country":"KP","score":4},
    {"ip":"172.16.0.99",  "country":"UA","score":18},
    {"ip":"185.220.101.5","country":"NG","score":11},
    {"ip":"103.45.67.89", "country":"CN","score":7},
    {"ip":"77.88.55.66",  "country":"RU","score":15},
]

# ── Session State ─────────────────────────────────────────────
def init_state():
    if "threats" not in st.session_state:
        st.session_state.threats      = []
        st.session_state.total_events = 0
        st.session_state.crit_count   = 0
        st.session_state.blocked      = 0
        st.session_state.attack_counts= {a: 0 for a in ATTACK_TYPES}
        st.session_state.traffic_time = []
        st.session_state.traffic_norm = []
        st.session_state.traffic_mal  = []
        st.session_state.running      = True
        # seed initial traffic
        now = datetime.now()
        for i in range(20):
            t = now - timedelta(seconds=(20-i)*3)
            st.session_state.traffic_time.append(t.strftime("%H:%M:%S"))
            st.session_state.traffic_norm.append(random.randint(200,600))
            st.session_state.traffic_mal.append(random.randint(5,60))

init_state()

# ── Generate new threats ──────────────────────────────────────
def generate_threats(n=5):
    new = []
    for _ in range(n):
        r   = random.random()
        sev = "CRITICAL" if r<0.12 else "HIGH" if r<0.35 else "MEDIUM" if r<0.65 else "LOW"
        atk = random.choice(ATTACK_TYPES)
        src = random.choice(COUNTRIES)
        ip  = random.choice(IP_POOL)
        new.append({
            "time":     datetime.now().strftime("%H:%M:%S"),
            "severity": sev,
            "type":     atk,
            "ip":       ip["ip"],
            "country":  src["name"],
            "lat":      src["lat"] + random.uniform(-2,2),
            "lon":      src["lon"] + random.uniform(-2,2),
        })
        st.session_state.attack_counts[atk] += 1
        st.session_state.total_events += 1
        if sev == "CRITICAL":
            st.session_state.crit_count += 1
            if random.random() < 0.65:
                st.session_state.blocked += 1
        elif sev == "HIGH" and random.random() < 0.2:
            st.session_state.blocked += 1

    st.session_state.threats = (new + st.session_state.threats)[:60]

    now = datetime.now()
    st.session_state.traffic_time.append(now.strftime("%H:%M:%S"))
    st.session_state.traffic_norm.append(random.randint(180,650))
    st.session_state.traffic_mal.append(random.randint(0,120))
    if len(st.session_state.traffic_time) > 30:
        st.session_state.traffic_time = st.session_state.traffic_time[-30:]
        st.session_state.traffic_norm = st.session_state.traffic_norm[-30:]
        st.session_state.traffic_mal  = st.session_state.traffic_mal[-30:]

# ── Sidebar ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ CTI Dashboard")
    st.markdown("**Pramod Prakash Jadhav**")
    st.caption("AI & ML Essentials · IIT Patna")
    st.divider()

    running = st.toggle("▶ Live Simulation", value=st.session_state.running)
    st.session_state.running = running

    refresh_rate = st.slider("Refresh rate (sec)", 2, 10, 3)

    st.divider()
    sev_filter = st.multiselect(
        "Filter by Severity",
        SEVERITIES,
        default=SEVERITIES
    )
    atk_filter = st.multiselect(
        "Filter by Attack Type",
        ATTACK_TYPES,
        default=ATTACK_TYPES
    )

    st.divider()
    if st.button("🔄 Reset Dashboard"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    st.divider()
    st.caption("🔗 [Portfolio](https://pramodjadhav.vercel.app)")
    st.caption("🐙 [GitHub](https://github.com/pramodj551-oss)")

# ── Generate data if running ──────────────────────────────────
if st.session_state.running:
    generate_threats(random.randint(3,7))

# ── Header ────────────────────────────────────────────────────
col_h1, col_h2 = st.columns([3,1])
with col_h1:
    st.markdown("## 🛡️ Cyber Threat Intelligence Dashboard")
    st.caption(f"Network Anomaly Detection · Last updated: {datetime.now().strftime('%H:%M:%S')} · IIT Patna AI/ML Project")
with col_h2:
    status = "🟢 LIVE" if st.session_state.running else "🔴 PAUSED"
    st.markdown(f"**{status}**")
    st.caption(f"Session: {datetime.now().strftime('%d %b %Y')}")

st.divider()

# ── Metric Cards ──────────────────────────────────────────────
total  = st.session_state.total_events
crits  = st.session_state.crit_count
blocked= st.session_state.blocked
health = max(45, 100 - int((crits / max(1,total)) * 150))
health_color = "#00e5a0" if health>80 else "#f59e0b" if health>60 else "#e24b4a"

c1,c2,c3,c4,c5 = st.columns(5)
with c1:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-val">{total}</div>
        <div class="metric-label">Total Events</div></div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-val critical">{crits}</div>
        <div class="metric-label">Critical Alerts</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-val high">{blocked}</div>
        <div class="metric-label">Blocked IPs</div></div>""", unsafe_allow_html=True)
with c4:
    health_val = f"{health}%"
    cls = "low" if health>80 else "high" if health>60 else "critical"
    st.markdown(f"""<div class="metric-card">
        <div class="metric-val {cls}">{health_val}</div>
        <div class="metric-label">Network Health</div></div>""", unsafe_allow_html=True)
with c5:
    pps = (st.session_state.traffic_norm[-1] + st.session_state.traffic_mal[-1]) if st.session_state.traffic_norm else 0
    st.markdown(f"""<div class="metric-card">
        <div class="metric-val">{pps}</div>
        <div class="metric-label">Packets/sec</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Traffic Chart ─────────────────────────────────────────────
st.markdown('<div class="section-title">📈 Network Traffic — Packets/sec (Normal vs Malicious)</div>', unsafe_allow_html=True)

fig_traffic = go.Figure()
fig_traffic.add_trace(go.Scatter(
    x=st.session_state.traffic_time,
    y=st.session_state.traffic_norm,
    name="Normal",
    line=dict(color="#378add", width=2),
    fill="tozeroy",
    fillcolor="rgba(55,138,221,0.08)"
))
fig_traffic.add_trace(go.Scatter(
    x=st.session_state.traffic_time,
    y=st.session_state.traffic_mal,
    name="Malicious",
    line=dict(color="#e24b4a", width=2),
    fill="tozeroy",
    fillcolor="rgba(226,75,74,0.08)"
))
fig_traffic.update_layout(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    height=200,
    margin=dict(l=0,r=0,t=10,b=0),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                font=dict(color="#64748b")),
    xaxis=dict(showgrid=False, tickfont=dict(color="#64748b"), showticklabels=True),
    yaxis=dict(showgrid=True, gridcolor="rgba(100,116,139,0.1)", tickfont=dict(color="#64748b")),
    font=dict(color="#e2e8f0")
)
st.plotly_chart(fig_traffic, use_container_width=True)

# ── Map + Attack Types ────────────────────────────────────────
col_map, col_atk = st.columns([3,2])

with col_map:
    st.markdown('<div class="section-title">🌍 Attack Origin Map</div>', unsafe_allow_html=True)
    threats_df = pd.DataFrame(st.session_state.threats[:50]) if st.session_state.threats else pd.DataFrame()

    if not threats_df.empty:
        fig_map = px.scatter_geo(
            threats_df,
            lat="lat", lon="lon",
            color="severity",
            hover_name="country",
            hover_data={"type":True,"ip":True,"lat":False,"lon":False},
            color_discrete_map=SEV_COLORS,
            size_max=12,
            projection="natural earth",
        )
        fig_map.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=280,
            margin=dict(l=0,r=0,t=0,b=0),
            geo=dict(
                bgcolor="rgba(0,0,0,0)",
                showland=True, landcolor="rgba(0,229,160,0.07)",
                showocean=True, oceancolor="rgba(8,12,16,0.8)",
                showcoastlines=True, coastlinecolor="rgba(0,229,160,0.2)",
                showcountries=True, countrycolor="rgba(0,229,160,0.1)",
                showframe=False,
            ),
            legend=dict(font=dict(color="#64748b"), bgcolor="rgba(0,0,0,0)")
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("Waiting for threat data...")

with col_atk:
    st.markdown('<div class="section-title">📊 Attack Type Classifier</div>', unsafe_allow_html=True)
    atk_df = pd.DataFrame([
        {"Attack": k, "Count": v}
        for k,v in st.session_state.attack_counts.items()
    ]).sort_values("Count", ascending=True)

    fig_atk = go.Figure(go.Bar(
        x=atk_df["Count"],
        y=atk_df["Attack"],
        orientation="h",
        marker_color=["#e24b4a","#f59e0b","#534ab7","#378add","#993556","#1d9e75"],
        text=atk_df["Count"],
        textposition="outside",
        textfont=dict(color="#e2e8f0", size=11)
    ))
    fig_atk.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=280,
        margin=dict(l=0,r=30,t=10,b=0),
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(tickfont=dict(color="#e2e8f0", size=11), showgrid=False),
        showlegend=False,
    )
    st.plotly_chart(fig_atk, use_container_width=True)

# ── Threat Feed + IP Reputation ───────────────────────────────
col_feed, col_ip = st.columns(2)

with col_feed:
    st.markdown('<div class="section-title">🚨 Live Threat Feed</div>', unsafe_allow_html=True)
    filtered = [
        t for t in st.session_state.threats
        if t["severity"] in sev_filter and t["type"] in atk_filter
    ][:20]

    if filtered:
        feed_df = pd.DataFrame(filtered)[["time","severity","type","ip","country"]]
        feed_df.columns = ["Time","Severity","Attack Type","IP Address","Origin"]

        def color_sev(val):
            colors = {"CRITICAL":"background-color:#1a0808;color:#e24b4a",
                      "HIGH":    "background-color:#1a1208;color:#f59e0b",
                      "MEDIUM":  "background-color:#080f1a;color:#378add",
                      "LOW":     "background-color:#04120d;color:#00e5a0"}
            return colors.get(val,"")

        st.dataframe(
            feed_df.style.applymap(color_sev, subset=["Severity"]),
            use_container_width=True,
            height=280,
            hide_index=True
        )
    else:
        st.info("No threats match current filter.")

with col_ip:
    st.markdown('<div class="section-title">🔎 IP Reputation Check</div>', unsafe_allow_html=True)
    ip_data = []
    for r in IP_POOL:
        score = r["score"] + random.randint(-3,3)
        score = max(1, min(99, score))
        status = "✅ Clean" if score>60 else "⚠️ Suspicious" if score>25 else "🔴 Malicious"
        ip_data.append({
            "IP Address": r["ip"],
            "Origin": r["country"],
            "Rep. Score": score,
            "Status": status
        })
    ip_df = pd.DataFrame(ip_data)

    def color_status(val):
        if "Clean"     in val: return "color:#00e5a0"
        if "Suspicious"in val: return "color:#f59e0b"
        if "Malicious" in val: return "color:#e24b4a"
        return ""

    st.dataframe(
        ip_df.style.applymap(color_status, subset=["Status"]),
        use_container_width=True,
        height=280,
        hide_index=True
    )

# ── Footer ────────────────────────────────────────────────────
st.divider()
st.caption("🛡️ Cyber Threat Intelligence Dashboard · Pramod Prakash Jadhav · AI & ML Essentials · IIT Patna (Vishlesan i-Hub) · [Portfolio](https://pramodjadhav.vercel.app) · [GitHub](https://github.com/pramodj551-oss)")

# ── Auto-refresh ──────────────────────────────────────────────
if st.session_state.running:
    time.sleep(refresh_rate)
    st.rerun()
