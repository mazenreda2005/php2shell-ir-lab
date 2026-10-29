#!/usr/bin/env python3
"""
dashboard.py — NovaEdge Incident-Response Console (Streamlit).

A polished, password-protected local console that shows live fleet state and
incident records and exposes the response controls. Uses YOUR configured AWS
credentials (boto3) — no credentials in this file.

Run (use the SAME python that has boto3):
    python -m pip install streamlit boto3
    python -m streamlit run dashboard.py
"""
import os, json, datetime, urllib.request
from pathlib import Path

import streamlit as st
import boto3
from botocore.exceptions import ClientError

# --- config -----------------------------------------------------------------
FLEET_TAG = os.environ.get("FLEET_NAME", "php2shell-lab")
ROOT = Path(__file__).parent
AUDIT_LOG = ROOT / "logs" / "actions.jsonl"
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "novaedge-admin")
BASELINE = {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36), "8.2": (8, 2, 35)}
SERVICE = {"web-01": "Corporate Website", "web-02": "Customer Portal", "web-03": "Service Status"}

st.set_page_config(page_title="NovaEdge IR Console", page_icon="🛡", layout="wide")

# --- global styling ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
#MainMenu, footer, header {visibility: hidden;}
.block-container { padding-top: 2rem; max-width: 1200px; }
body { background:
  radial-gradient(1200px 600px at 75% -10%, #16233f 0%, #0b1120 55%) fixed; }

.topbar { display:flex; align-items:center; gap:14px; margin-bottom:6px; }
.logo { width:46px; height:46px; border-radius:12px;
  background: linear-gradient(135deg,#3b82f6,#22d3ee); display:grid; place-items:center;
  font-weight:900; color:#04101f; font-size:22px; box-shadow:0 6px 20px rgba(34,211,238,.25); }
.ttl { font-size:26px; font-weight:800; letter-spacing:-.5px; margin:0; }
.sub { color:#8aa0bd; font-size:13px; letter-spacing:.3px; }

.kpis { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:18px 0; }
.kpi { background:#15203a; border:1px solid #223049; border-radius:14px; padding:16px 18px; }
.kpi .lab { color:#8aa0bd; font-size:12px; text-transform:uppercase; letter-spacing:1px; font-weight:700; }
.kpi .val { font-size:32px; font-weight:800; margin-top:2px; }
.kpi.bad .val { color:#f87171; } .kpi.warn .val { color:#fbbf24; } .kpi.ok .val { color:#4ade80; }

.banner { border-radius:14px; padding:16px 20px; font-weight:700; margin:6px 0 18px; }
.banner.ok  { background:rgba(34,197,94,.12); border:1px solid rgba(34,197,94,.35); color:#bbf7d0; }
.banner.bad { background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.4); color:#fecaca; }

.nodes { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
.node { background:#15203a; border:1px solid #223049; border-radius:14px; padding:18px; position:relative; }
.node .nm { font-weight:800; font-size:17px; }
.node .svc { color:#8aa0bd; font-size:13px; margin-bottom:12px; }
.node .ver { font-size:28px; font-weight:800; letter-spacing:-.5px; }
.node .meta { color:#8aa0bd; font-size:12px; margin-top:8px; line-height:1.9; }
.node.vuln { border-color:#ef4444; box-shadow:0 0 0 1px rgba(239,68,68,.25) inset; }
.node.good { border-color:#22c55e33; }

.pill { display:inline-flex; align-items:center; gap:6px; font-weight:700; font-size:12px;
  padding:4px 10px; border-radius:999px; }
.pill .dot{ width:8px;height:8px;border-radius:50%; }
.pill.ok{ color:#bbf7d0; background:rgba(34,197,94,.14);} .pill.ok .dot{background:#22c55e;}
.pill.bad{ color:#fecaca; background:rgba(239,68,68,.14);} .pill.bad .dot{background:#ef4444;}
.pill.warn{ color:#fde68a; background:rgba(245,158,11,.14);} .pill.warn .dot{background:#f59e0b;}
.pill.iso{ color:#fca5a5; background:rgba(239,68,68,.14);}

.sect { font-size:15px; font-weight:800; letter-spacing:.3px; margin:26px 0 10px;
  color:#cdd9ec; text-transform:uppercase; }
.panel { background:#131d33; border:1px solid #223049; border-radius:14px; padding:14px 16px; }
.row { display:flex; justify-content:space-between; gap:10px; padding:7px 0;
  border-bottom:1px solid #1e2b45; font-size:13px; }
.row:last-child{ border-bottom:none; }
.muted{ color:#8aa0bd; }
.stButton>button { border-radius:10px; font-weight:700; border:1px solid #2a3a57; background:#16233f; }
.stButton>button:hover { border-color:#3b82f6; }
</style>
""", unsafe_allow_html=True)

# --- auth gate --------------------------------------------------------------
if not st.session_state.get("authed"):
    st.markdown('<div class="topbar"><div class="logo">N</div>'
                '<div><div class="ttl">NovaEdge · IR Console</div>'
                '<div class="sub">Protected operator console</div></div></div>',
                unsafe_allow_html=True)
    pw = st.text_input("Operator password", type="password")
    if st.button("Sign in"):
        if pw == PASSWORD:
            st.session_state["authed"] = True; st.rerun()
        else:
            st.error("Wrong password.")
    st.stop()

# --- aws + helpers ----------------------------------------------------------
@st.cache_resource
def aws():
    return {k: boto3.client(k) for k in ("ec2", "logs", "s3", "sns", "sts")} | \
           {"ec2r": boto3.resource("ec2")}
A = aws()

def mgmt_token():
    try: return (ROOT / "deploy" / ".mgmt_token").read_text().strip()
    except Exception: return ""

def pver(v):
    try: return tuple(int(x) for x in str(v).split(".")[:3])
    except Exception: return None

def classify(v):
    t = pver(v)
    if not t: return "UNKNOWN"
    b = BASELINE.get(f"{t[0]}.{t[1]}")
    return "UNKNOWN" if not b else ("AFFECTED" if t < b else "PATCHED")

def tagof(inst, k, d=""):
    for t in (inst.tags or []):
        if t["Key"] == k: return t["Value"]
    return d

def live_ver(ip):
    if not ip: return None
    tok = mgmt_token()
    if tok:
        try:
            req = urllib.request.Request(f"http://{ip}/mgmt/version.php", headers={"X-Mgmt-Token": tok})
            with urllib.request.urlopen(req, timeout=4) as r:
                return json.loads(r.read()).get("php")
        except Exception: pass
    return None

def get_fleet():
    out = {}
    f = [{"Name": "tag:Fleet", "Values": [FLEET_TAG]},
         {"Name": "instance-state-name", "Values": ["pending","running","stopping","stopped"]}]
    for inst in A["ec2r"].instances.filter(Filters=f):
        short = tagof(inst, "Name", inst.id).replace(f"{FLEET_TAG}-", "")
        sgs = [g["GroupName"].replace(f"{FLEET_TAG}-", "") for g in inst.security_groups]
        out[short] = {"inst": inst, "id": inst.id, "state": inst.state["Name"],
                      "ip": inst.public_ip_address, "tagv": tagof(inst, "PHPVersion", "-"),
                      "status": tagof(inst, "Status", "-"), "sgs": sgs}
    return dict(sorted(out.items()))

def sg_id(suffix):
    r = A["ec2"].describe_security_groups(Filters=[{"Name":"group-name","Values":[f"{FLEET_TAG}-{suffix}"]}])
    g = r.get("SecurityGroups", []); return g[0]["GroupId"] if g else None

fleet = get_fleet()

# --- header -----------------------------------------------------------------
hc1, hc2 = st.columns([4,1])
with hc1:
    st.markdown(
        '<div class="topbar"><div class="logo">N</div>'
        f'<div><div class="ttl">NovaEdge · Incident Response Console</div>'
        f'<div class="sub">Fleet {FLEET_TAG} &nbsp;·&nbsp; {A["ec2"].meta.region_name} &nbsp;·&nbsp; '
        f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</div></div></div>',
        unsafe_allow_html=True)
with hc2:
    if st.button("🔄 Refresh", use_container_width=True): st.rerun()

enriched = {}
for n, d in fleet.items():
    live = live_ver(d["ip"]) or d["tagv"]
    enriched[n] = {**d, "live": live, "cls": classify(live),
                   "iso": d["status"] == "isolated" or d["sgs"] == ["quarantine-sg"]}

affected = [n for n,d in enriched.items() if d["cls"] == "AFFECTED"]
isolated = [n for n,d in enriched.items() if d["iso"]]
running  = [n for n,d in enriched.items() if d["state"] == "running"]

# --- KPIs -------------------------------------------------------------------
st.markdown(
    '<div class="kpis">'
    f'<div class="kpi"><div class="lab">Fleet nodes</div><div class="val">{len(fleet)}</div></div>'
    f'<div class="kpi {"bad" if affected else "ok"}"><div class="lab">Affected</div><div class="val">{len(affected)}</div></div>'
    f'<div class="kpi {"warn" if isolated else ""}"><div class="lab">Isolated</div><div class="val">{len(isolated)}</div></div>'
    f'<div class="kpi ok"><div class="lab">Running</div><div class="val">{len(running)}</div></div>'
    '</div>', unsafe_allow_html=True)

if affected:
    st.markdown(f'<div class="banner bad">⚠ {len(affected)} node(s) AFFECTED by php2shell '
                f'(CVE-2026-109618 / 109619): {", ".join(affected)}</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="banner ok">✓ All nodes patched — no php2shell exposure detected.</div>',
                unsafe_allow_html=True)

# --- node cards -------------------------------------------------------------
st.markdown('<div class="sect">Fleet</div>', unsafe_allow_html=True)
cards = ""
pillmap = {"AFFECTED":("bad","AFFECTED"),"PATCHED":("ok","PATCHED"),"UNKNOWN":("warn","UNKNOWN")}
for n, d in enriched.items():
    pc, pl = pillmap[d["cls"]]
    iso_badge = '<span class="pill iso">🔒 isolated</span>' if d["iso"] else ''
    cards += (
        f'<div class="node {"vuln" if d["cls"]=="AFFECTED" else "good"}">'
        f'<div class="nm">{n} {iso_badge}</div>'
        f'<div class="svc">{SERVICE.get(n,"-")}</div>'
        f'<div class="ver">PHP {d["live"]}</div>'
        f'<div style="margin-top:8px"><span class="pill {pc}"><span class="dot"></span>{pl}</span></div>'
        f'<div class="meta">State: {d["state"]}<br>SG: {", ".join(d["sgs"])}<br>IP: {d["ip"] or "-"}</div>'
        f'</div>')
st.markdown(f'<div class="nodes">{cards}</div>', unsafe_allow_html=True)

# --- automation + evidence --------------------------------------------------
L, R = st.columns(2)
with L:
    st.markdown('<div class="sect">🤖 Automated response (6h)</div>', unsafe_allow_html=True)
    html = '<div class="panel">'
    try:
        ev = A["logs"].filter_log_events(
            logGroupName=f"/aws/lambda/{FLEET_TAG}-responder",
            startTime=int((datetime.datetime.now()-datetime.timedelta(hours=6)).timestamp()*1000),
            limit=200)
        found = []
        for e in ev.get("events", []):
            m = e["message"].strip()
            if m.startswith("{") and '"classification"' in m:
                try:
                    j = json.loads(m)
                    if j.get("action") in ("isolate","alert_only"):
                        found.append((datetime.datetime.fromtimestamp(e["timestamp"]/1000).strftime("%H:%M"),
                                      j.get("name","").replace(f"{FLEET_TAG}-",""), j.get("result","")))
                except Exception: pass
        if found:
            for t,nm,res in found[-8:]:
                html += f'<div class="row"><span class="muted">{t}</span><span>{nm}</span><span>{res}</span></div>'
        else:
            html += '<div class="row muted">No containment actions in the last 6h.</div>'
    except ClientError:
        html += '<div class="row muted">Lambda log group not found yet.</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

    # alert status
    try:
        arn = next((t["TopicArn"] for t in A["sns"].list_topics().get("Topics",[])
                    if t["TopicArn"].endswith(f"{FLEET_TAG}-alerts")), None)
        if arn:
            for s in A["sns"].list_subscriptions_by_topic(TopicArn=arn).get("Subscriptions",[]):
                ok = s.get("SubscriptionArn","").startswith("arn:")
                st.markdown(f'<div class="muted" style="font-size:12px;margin-top:8px">🔔 {s.get("Endpoint")} — '
                            f'{"confirmed" if ok else "pending confirmation"}</div>', unsafe_allow_html=True)
    except Exception: pass

with R:
    st.markdown('<div class="sect">🗄 Evidence (S3, encrypted)</div>', unsafe_allow_html=True)
    html = '<div class="panel">'
    try:
        acct = A["sts"].get_caller_identity()["Account"]
        objs = A["s3"].list_objects_v2(Bucket=f"{FLEET_TAG}-evidence-{acct}",
                                       Prefix="findings/", MaxKeys=12).get("Contents", [])
        if objs:
            for o in objs[-8:]:
                html += (f'<div class="row"><span>{o["Key"].split("/")[-1][:18]}…</span>'
                         f'<span class="muted">{o["LastModified"].strftime("%m-%d %H:%M")}</span></div>')
        else:
            html += '<div class="row muted">No evidence objects yet.</div>'
    except ClientError:
        html += '<div class="row muted">Evidence bucket not found yet.</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

# --- timeline ---------------------------------------------------------------
st.markdown('<div class="sect">📜 Operator action timeline</div>', unsafe_allow_html=True)
html = '<div class="panel">'
try:
    recs = [json.loads(l) for l in AUDIT_LOG.read_text(encoding="utf-8").strip().splitlines()[-10:]]
    for r in recs:
        html += (f'<div class="row"><span class="muted">{r["ts"][11:19]}</span>'
                 f'<span>{r["action"]} · {r["node"]}</span><span>{r["result"]}</span></div>')
    if not recs:
        html += '<div class="row muted">No operator actions logged yet.</div>'
except Exception:
    html += '<div class="row muted">No operator actions logged yet.</div>'
html += '</div>'
st.markdown(html, unsafe_allow_html=True)

# --- controls ---------------------------------------------------------------
st.markdown('<div class="sect">🎛 Response controls</div>', unsafe_allow_html=True)
st.caption("Destructive actions need a typed CONFIRM and re-check the result before reporting success.")
node = st.selectbox("Target", ["(all)"] + list(fleet.keys()))
target = None if node == "(all)" else node
c = st.columns(4)

def do_isolate(sel):
    q = sg_id("quarantine-sg"); tg = fleet if sel is None else {sel: fleet[sel]}
    for d in tg.values():
        d["inst"].modify_attribute(Groups=[q])
        A["ec2"].create_tags(Resources=[d["id"]], Tags=[{"Key":"Status","Value":"isolated"}])
    ref = get_fleet()
    return [n for n in tg if ref[n]["sgs"] == ["quarantine-sg"]]

def do_restore(sel):
    s = sg_id("sg"); tg = fleet if sel is None else {sel: fleet[sel]}
    for d in tg.values():
        d["inst"].modify_attribute(Groups=[s])
        A["ec2"].create_tags(Resources=[d["id"]], Tags=[{"Key":"Status","Value":"restored"}])
    return list(tg)

def do_power(sel, on):
    tg = fleet if sel is None else {sel: fleet[sel]}
    for d in tg.values(): d["inst"].start() if on else d["inst"].stop()
    return list(tg)

if c[0].button("🔒 Isolate", use_container_width=True): st.session_state["pending"]=("isolate",target)
if c[1].button("♻ Restore", use_container_width=True):
    st.success(f"Restored & verified: {', '.join(do_restore(target))}"); st.rerun()
if c[2].button("⏸ Stop", use_container_width=True): st.session_state["pending"]=("stop",target)
if c[3].button("▶ Start", use_container_width=True):
    st.success(f"Starting: {', '.join(do_power(target, True))}")

pending = st.session_state.get("pending")
if pending:
    act, sel = pending
    scope = "ALL nodes" if sel is None else sel
    st.warning(f"Confirm **{act}** on **{scope}**. Type CONFIRM to proceed.")
    typed = st.text_input("Type CONFIRM", key="cfm")
    cc = st.columns([1,1,4])
    if cc[0].button("Proceed", type="primary"):
        if typed.strip() == "CONFIRM":
            if act == "isolate": st.success(f"Isolated & verified: {', '.join(do_isolate(sel))}")
            elif act == "stop":  st.success(f"Stopping: {', '.join(do_power(sel, False))}")
            st.session_state["pending"]=None
        else: st.error("Type CONFIRM exactly.")
    if cc[1].button("Cancel"): st.session_state["pending"]=None; st.rerun()

st.caption("Patch & verify run over SSH via the CLI: "
           "`python fleet_control.py patch web-01` then `python fleet_control.py verify`.")
