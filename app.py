"""ECDAT - Enterprise Cryptographic Discovery & Analysis Tool (Phase 1 prototype).

Run:  streamlit run app.py
Fully offline: no network calls, no telemetry (see .streamlit/config.toml).
"""
from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from cbom import cbom_json, validate_cbom
from recommend import add_recommendations, roadmap
from report import to_csv, to_pdf
from risk import (CRITICAL_OVERSHOOT_YEARS, DEFAULT_SHELF_LIFE, DEFAULT_Y_MIGRATION, DEFAULT_Z_CRQC,
                  TIER_RULES_TEXT, TIERS, apply_risk, folder_table, tier_counts)
from rules import FAMILIES
from scanner import NEAR_EXPIRY_DAYS, scan_folder

APP_DIR = Path(__file__).parent
DEFAULT_TARGET = "sample_repo"

# Status palette for tiers (always shown with the tier label, never colour alone).
TIER_COLORS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#0ca30c"}
NAVY, BLUE = "#0b2545", "#1f5fa8"

st.set_page_config(page_title="ECDAT", page_icon="🔐", layout="wide")
st.markdown(f"""
<style>
  .ecdat-header {{background:{NAVY}; color:#fff; padding:18px 24px; border-radius:10px; margin-bottom:12px}}
  .ecdat-header h1 {{color:#fff; margin:0; font-size:2.1rem; letter-spacing:.04em}}
  .ecdat-header p {{color:#c9d6ea; margin:4px 0 0 0}}
  div[data-testid="stMetric"] {{background:#f3f6fb; border:1px solid #d6e0ee; border-left:5px solid {BLUE};
       border-radius:8px; padding:10px 14px}}
  .tier-pill {{display:inline-block; padding:1px 8px; border-radius:10px; color:#111; font-weight:600}}
  .ecdat-footer {{color:#5b6b80; font-size:.85rem; border-top:1px solid #d6e0ee; margin-top:28px; padding-top:8px}}
</style>
<div class="ecdat-header"><h1>ECDAT</h1>
<p>Enterprise Cryptographic Discovery &amp; Analysis Tool - Phase 1 prototype</p></div>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def resolve_target(path_text: str) -> Path:
    """Relative paths are tried against the working dir, then the app folder."""
    p = Path(path_text.strip()).expanduser()
    if not p.is_absolute() and not p.exists():
        p = APP_DIR / p
    return p


def safe_extract(zip_bytes: bytes) -> Path:
    """Extract an uploaded zip to a temp dir, refusing path traversal (zip-slip)."""
    out = Path(tempfile.mkdtemp(prefix="ecdat_"))
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for m in zf.infolist():
            dest = (out / m.filename).resolve()
            if not str(dest).startswith(str(out.resolve())):
                raise ValueError(f"unsafe path in zip: {m.filename}")
        zf.extractall(out)
    return out


def run_scan(target: Path, label: str) -> None:
    try:
        df, summary = scan_folder(target)
    except (FileNotFoundError, NotADirectoryError) as e:
        st.session_state["scan_error"] = str(e)
        return
    st.session_state.update(scan_df=df, scan_summary=summary, scan_label=label, scan_error=None,
                            folders=folder_table(df))


def tier_badge_style(v):
    c = TIER_COLORS.get(v)
    return f"background-color:{c}; color:#111; font-weight:600" if c else ""


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("Scan target")
    path_text = st.text_input("Folder path", value=DEFAULT_TARGET,
                              help="Folder on the machine running ECDAT. Relative paths resolve "
                                   "against the app folder. Default: bundled sample_repo.")
    scan_clicked = st.button("Scan", type="primary", width="stretch")
    upload = st.file_uploader("...or upload a .zip of a repository", type=["zip"])

    st.header("Mosca scenario")
    st.caption("At risk when **X + Y > Z**. Changing these re-ranks instantly (no rescan).")
    x_high = st.slider("X - shelf-life, High-criticality data (years)", 0, 30, DEFAULT_SHELF_LIFE["High"],
                       help="How long data protected in High-criticality folders (e.g. payments/, auth/) must stay confidential.")
    x_med = st.slider("X - shelf-life, Medium-criticality data (years)", 0, 30, DEFAULT_SHELF_LIFE["Medium"])
    x_low = st.slider("X - shelf-life, Low-criticality data (years)", 0, 30, DEFAULT_SHELF_LIFE["Low"])
    y_mig = st.slider("Y - migration time (years)", 0, 20, DEFAULT_Y_MIGRATION,
                      help="Years your organisation needs to migrate a system to post-quantum crypto.")
    z_crqc = st.slider("Z - years until a CRQC (scenario)", 1, 40, DEFAULT_Z_CRQC,
                       help="Years until a cryptographically relevant quantum computer exists.")
    st.info("**Z is a scenario parameter, not a prediction.** Try several values.", icon="ℹ️")

# Scan triggers: first load (sample repo), Scan button, or a new zip upload.
if upload is not None and st.session_state.get("upload_id") != upload.file_id:
    try:
        run_scan(safe_extract(upload.getvalue()), upload.name)
        st.session_state["upload_id"] = upload.file_id
    except (zipfile.BadZipFile, ValueError) as e:
        st.session_state["scan_error"] = f"Could not read zip: {e}"
elif scan_clicked or "scan_df" not in st.session_state:
    target = resolve_target(path_text)
    run_scan(target, target.name)

if st.session_state.get("scan_error"):
    st.error(f"{st.session_state['scan_error']}  \nCheck the folder path in the sidebar "
             f"(default: `{DEFAULT_TARGET}`).")
if "scan_df" not in st.session_state:
    st.stop()

raw_df: pd.DataFrame = st.session_state["scan_df"]
summary: dict = st.session_state["scan_summary"]
label: str = st.session_state["scan_label"]

# Per-folder criticality / X override table (sidebar, so it applies before metrics render).
x_by_crit = {"High": x_high, "Medium": x_med, "Low": x_low}
with st.sidebar.expander("Per-folder criticality & X override", expanded=False):
    st.caption("Criticality comes from path keywords in risk.py. Leave *X override* empty to use the "
               "slider value for that criticality.")
    base = st.session_state["folders"][["folder", "criticality"]].copy()
    if "x_override" not in base:
        base["x_override"] = None
    edited = st.data_editor(
        base, key=f"folder_editor_{label}", hide_index=True, width="stretch",
        disabled=["folder"],
        column_config={
            "criticality": st.column_config.SelectboxColumn("criticality", options=["High", "Medium", "Low"]),
            "x_override": st.column_config.NumberColumn("X override (y)", min_value=0, max_value=50, step=1),
        })
folders = edited.copy()
folders["shelf_life_X"] = [float(o) if pd.notna(o) else float(x_by_crit[c])
                           for o, c in zip(folders["x_override"], folders["criticality"])]

# Recompute tiers from cached scan results - no rescan.
df = add_recommendations(apply_risk(raw_df, y_mig, z_crqc, folders))
counts = tier_counts(df)
rm = roadmap(df)

if df.empty:
    st.warning(f"Scanned **{label}**: {summary['files_scanned']} files, no cryptographic assets found.")
    st.stop()

st.caption(f"Target: **{label}** | {summary['files_scanned']} files scanned, "
           f"{summary['files_skipped']} skipped (binary/oversize/unreadable) | "
           f"{summary['certificates']} certificates parsed | scenario Y={y_mig}, Z={z_crqc}")

cols = st.columns(6)
cols[0].metric("Total assets", len(df), help="Findings after de-duplication")
for c, t in zip(cols[1:5], TIERS):
    c.metric(f"{t}", counts[t])
cols[5].metric(f"Certs expired / ≤{NEAR_EXPIRY_DAYS}d", summary["certs_near_expiry"])

tab_inv, tab_risk, tab_road, tab_cert, tab_exp = st.tabs(
    ["Inventory", "Risk", "Roadmap", "Certificates", "Export"])

# ------------------------------------------------------------------ Inventory
with tab_inv:
    f1, f2, f3, f4 = st.columns([1, 1, 1, 1.4])
    sel_tier = f1.multiselect("Tier", TIERS, default=TIERS)
    present_fams = [f for f in FAMILIES if f in set(df["family"])]
    sel_fam = f2.multiselect("Family", present_fams, default=present_fams)
    sel_conf = f3.multiselect("Confidence", ["high", "medium"], default=["high", "medium"])
    query = f4.text_input("Search (asset, file, snippet)", "")
    view = df[df["tier"].isin(sel_tier) & df["family"].isin(sel_fam) & df["confidence"].isin(sel_conf)]
    if query:
        q = query.lower()
        view = view[view[["asset", "file", "snippet", "algorithm"]].astype(str)
                    .apply(lambda s: s.str.lower().str.contains(q, regex=False)).any(axis=1)]
    show = view[["tier", "asset", "family", "file", "line", "confidence", "quantum_vulnerable",
                 "classically_weak", "criticality", "snippet", "rule_id"]]
    st.caption(f"{len(show)} of {len(df)} findings. *high* = exact API/identifier or parsed certificate; "
               "*medium* = keyword in config/string/comment (review by hand).")
    st.dataframe(show.style.map(tier_badge_style, subset=["tier"]), hide_index=True,
                 width="stretch", height=480,
                 column_config={"quantum_vulnerable": st.column_config.CheckboxColumn("quantum-vulnerable"),
                                "classically_weak": st.column_config.CheckboxColumn("classically weak"),
                                "snippet": st.column_config.TextColumn("snippet", width="large")})

# ------------------------------------------------------------------ Risk
with tab_risk:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Tier distribution")
        fig = go.Figure(go.Bar(x=TIERS, y=[counts[t] for t in TIERS], text=[counts[t] for t in TIERS],
                               textposition="outside", marker_color=[TIER_COLORS[t] for t in TIERS],
                               hovertemplate="%{x}: %{y} findings<extra></extra>"))
        fig.update_layout(height=340, margin=dict(t=20, b=10, l=10, r=10), yaxis_title="findings",
                          plot_bgcolor="rgba(0,0,0,0)", yaxis=dict(gridcolor="#e5e9f0"), bargap=0.45)
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.subheader("Tier by folder")
        pivot = (df.pivot_table(index="folder", columns="tier", values="line", aggfunc="count", fill_value=0)
                   .reindex(columns=TIERS, fill_value=0))
        hm = go.Figure(go.Heatmap(z=pivot.values, x=TIERS, y=pivot.index, text=pivot.values,
                                  texttemplate="%{text}", colorscale="Blues", showscale=False, xgap=2, ygap=2,
                                  hovertemplate="%{y} / %{x}: %{z}<extra></extra>"))
        hm.update_layout(height=340, margin=dict(t=20, b=10, l=10, r=10), plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(hm, width="stretch")

    st.subheader("Mosca timeline for one asset")
    qv = df[df["quantum_vulnerable"]].reset_index(drop=True)
    if qv.empty:
        st.info("No quantum-vulnerable assets in this scan.")
    else:
        labels = [f"[{r.tier}] {r.asset} - {r.file}:{r.line}" for r in qv.itertuples()]
        idx = st.selectbox("Asset", range(len(labels)), format_func=lambda i: labels[i])
        r = qv.iloc[idx]
        x, y, z = float(r["X"]), float(r["Y"]), float(r["Z"])
        tl = go.Figure()
        tl.add_trace(go.Bar(y=["timeline"], x=[y], orientation="h", name=f"Y migration ({y:g} y)",
                            marker_color=BLUE, hovertemplate="Migration: 0-%{x} y<extra></extra>"))
        tl.add_trace(go.Bar(y=["timeline"], x=[x], base=[y], orientation="h", name=f"X shelf-life ({x:g} y)",
                            marker_color="#8fb3de", hovertemplate=f"Shelf-life: {y:g}-{x + y:g} y<extra></extra>"))
        if x + y > z:
            tl.add_vrect(x0=z, x1=x + y, fillcolor=TIER_COLORS["Critical"], opacity=0.18, line_width=0,
                         annotation_text=f"overshoot {x + y - z:g} y", annotation_position="top left")
        tl.add_vline(x=z, line_width=3, line_color=NAVY, annotation_text=f"Z = {z:g} y (CRQC scenario)",
                     annotation_position="bottom right")
        tl.update_layout(barmode="overlay", height=230, margin=dict(t=40, b=30, l=10, r=10),
                         xaxis=dict(title="years from today", range=[0, max(x + y, z) * 1.15 + 1],
                                    gridcolor="#e5e9f0"),
                         yaxis=dict(showticklabels=False), legend=dict(orientation="h", y=1.25),
                         plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(tl, width="stretch")
        verdict = "**AT RISK**" if r["mosca_at_risk"] else "not at risk under this scenario"
        st.markdown(f"X + Y = {x:g} + {y:g} = **{x + y:g}** vs Z = **{z:g}** -> {verdict} "
                    f"(overshoot {x + y - z:+g} y). Tier: **{r['tier']}** | folder `{r['folder']}` "
                    f"({r['criticality']} criticality).")

    with st.expander("Tier rules", expanded=False):
        st.markdown(TIER_RULES_TEXT)
        st.caption(f"Constants in risk.py: CRITICAL_OVERSHOOT_YEARS = {CRITICAL_OVERSHOOT_YEARS}.")

# ------------------------------------------------------------------ Roadmap
with tab_road:
    st.subheader("Prioritised migration roadmap")
    st.caption("Critical -> High -> Medium -> Low. Within a tier: most occurrences first, then lowest effort. "
               "Trade-offs are qualitative; validate against your own environment.")
    for t in TIERS:
        part = rm[rm["tier"] == t]
        if part.empty:
            continue
        st.markdown(f"<span class='tier-pill' style='background:{TIER_COLORS[t]}'>{t}</span> "
                    f"&nbsp; {len(part)} item(s)", unsafe_allow_html=True)
        st.dataframe(part.drop(columns=["tier"]), hide_index=True, width="stretch",
                     column_config={"replacement": st.column_config.TextColumn(width="large"),
                                    "tradeoff": st.column_config.TextColumn(width="large"),
                                    "locations": st.column_config.TextColumn(width="medium")})

# ------------------------------------------------------------------ Certificates
with tab_cert:
    certs = df[df["kind"] == "certificate"].copy()
    if certs.empty:
        st.info("No X.509 certificates (.pem/.crt/.cer/.der) found in this target.")
    else:
        def status(d):
            return "EXPIRED" if d < 0 else (f"expires ≤{NEAR_EXPIRY_DAYS}d" if d <= NEAR_EXPIRY_DAYS else "valid")
        certs["status"] = certs["cert_days_left"].map(status)
        certs["key"] = certs["algorithm"] + "-" + certs["param"].astype(str)
        st.caption("Facts below are parsed from the certificates with the `cryptography` library.")
        st.dataframe(
            certs[["tier", "file", "cert_subject", "cert_issuer", "key", "cert_sig_alg",
                   "cert_not_after", "cert_days_left", "status", "notes"]]
            .style.map(tier_badge_style, subset=["tier"]),
            hide_index=True, width="stretch",
            column_config={"cert_days_left": st.column_config.NumberColumn("days left", format="%d")})

# ------------------------------------------------------------------ Export
with tab_exp:
    cbom_text = cbom_json(df, label)
    problems = validate_cbom(cbom_text)
    if problems:
        st.error("CBOM validation problems: " + "; ".join(problems))
    else:
        st.success("CBOM passes structural validation (CycloneDX 1.6 top-level keys, unique bom-refs, valid JSON).")
    e1, e2, e3 = st.columns(3)
    e1.download_button("Download CBOM (CycloneDX 1.6 JSON)", cbom_text, file_name="ecdat-cbom.json",
                       mime="application/json", width="stretch")
    e2.download_button("Download inventory (CSV)", to_csv(df), file_name="ecdat-inventory.csv",
                       mime="text/csv", width="stretch")
    try:
        pdf = to_pdf(df, rm, {"Y": y_mig, "Z": z_crqc}, label)
        e3.download_button("Download report (PDF)", pdf, file_name="ecdat-report.pdf",
                           mime="application/pdf", width="stretch")
    except Exception as e:     # never let report generation break the dashboard
        e3.error(f"PDF generation failed: {e}")
    with st.expander("Preview CBOM JSON"):
        st.code(cbom_text[:20000], language="json")

st.markdown("<div class='ecdat-footer'>Phase 1 prototype: source and certificate scanning. "
            "Binary, container and KMS/HSM connectors are on the roadmap.</div>", unsafe_allow_html=True)
