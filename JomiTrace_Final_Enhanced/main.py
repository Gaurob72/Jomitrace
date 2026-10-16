"""JomiTrace - explainable land-record verification prototype.
All sample records are fictional. This is not an official land-ownership verification service.
"""
import os
import json
import hashlib
import hmac
import secrets
import sqlite3
from datetime import date, datetime
from html import escape
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, DictLoader
from starlette.middleware.sessions import SessionMiddleware

DB = os.getenv("JOMITRACE_DB", "jomitrace.db")
SECRET_KEY = os.getenv("JOMITRACE_SECRET", "change-this-demo-secret-before-deployment")
UNITS = {"decimal": 1, "katha": 1.65, "bigha": 33, "acre": 100}
RECORD_TYPES = ["deed", "khatian_cs", "khatian_sa", "khatian_rs", "khatian_bs"]
SOURCES = ["registration", "mutation"]


def dec(value, unit):
    return round(float(value) * UNITS[unit], 2)


def seal(case):
    return hashlib.sha256(json.dumps(case, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def parse_date(value):
    return date.fromisoformat(value)


def analyze(case):
    findings = []
    records, transfers = case.get("records", []), case.get("transfers", [])
    plots = {str(r.get("plot", "")).strip() for r in records}
    if len(plots) > 1:
        findings.append(("R1", "warning", "Plot number differs between supplied records.", sorted(plots)))

    areas = {
        f'{r.get("type", "record")}: {r.get("area", "?")} {r.get("unit", "decimal")}':
        dec(r.get("area", 0), r.get("unit", "decimal"))
        for r in records
    }
    if areas and max(areas.values()) - min(areas.values()) > 0.01 * max(max(areas.values()), 0.01):
        findings.append(("R2", "warning", "Land area differs between records after conversion to decimals.", areas))

    reg = sorted([t for t in transfers if t.get("source") == "registration"], key=lambda t: t.get("date", ""))
    for previous, current in zip(reg, reg[1:]):
        if previous.get("plot") == current.get("plot") and current.get("seller") != previous.get("buyer"):
            findings.append(("R3", "high",
                f'Ownership chain may be broken: {current.get("seller")} is listed as seller, but the previous recorded buyer was {previous.get("buyer")}.',
                [previous, current]))

    sales_by_seller_plot = {}
    for transaction in reg:
        key = (str(transaction.get("plot")), str(transaction.get("seller")))
        sales_by_seller_plot.setdefault(key, []).append(transaction)
    for (plot, seller), transactions in sales_by_seller_plot.items():
        if len(transactions) > 1:
            findings.append(("R4", "high",
                f"Plot {plot} appears in {len(transactions)} registration transactions with the same seller ({seller}); review for possible duplicate sale.",
                transactions))

    for index in range(max(0, len(reg) - 2)):
        if (parse_date(reg[index + 2]["date"]) - parse_date(reg[index]["date"])).days <= 365:
            findings.append(("R5", "warning", "Three or more recorded transfers occur within 12 months.", reg[index:index + 3]))
            break

    mutations = sorted([t for t in transfers if t.get("source") == "mutation"], key=lambda t: t.get("date", ""))
    if reg and mutations and reg[-1].get("buyer") != mutations[-1].get("buyer"):
        findings.append(("R6", "high",
            f'Registration record lists {reg[-1].get("buyer")} as latest buyer, while the latest supplied mutation record lists {mutations[-1].get("buyer")}.',
            [reg[-1], mutations[-1]]))

    survey_order = ["khatian_cs", "khatian_sa", "khatian_rs", "khatian_bs"]
    present = [i for i, kind in enumerate(survey_order) if any(r.get("type") == kind for r in records)]
    if present and any(i not in present for i in range(present[0], present[-1] + 1)):
        findings.append(("R7", "warning", "The supplied survey sequence has a missing survey type between available records.",
                         [survey_order[i] for i in present]))

    severities = {item[1] for item in findings}
    verdict = ("High-risk indicators: verify before proceeding" if "high" in severities else
               "Further verification recommended" if findings else
               "No inconsistencies found in supplied records")
    return verdict, findings


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 240_000)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def rec(kind, owner, plot, khatian, area, unit="decimal", dt="2020-01-01"):
    return dict(type=kind, owner=owner, plot=str(plot), khatian=khatian, area=float(area), unit=unit, date=dt)


def tr(seller, buyer, plot, dt, source="registration"):
    return dict(seller=seller, buyer=buyer, plot=str(plot), date=dt, source=source)


SEED = [
    dict(title="Case 1 - Clean (fictional)", district="Demo District",
         records=[rec("deed", "Rahim", "450", "K-12", 15), rec("khatian_rs", "Rahim", "450", "K-12", 15)],
         transfers=[tr("Abdul", "Rahim", "450", "2015-03-01"), tr("Abdul", "Rahim", "450", "2015-04-01", "mutation")]),
    dict(title="Case 2 - Area mismatch (fictional)", district="Demo District",
         records=[rec("deed", "Rahim", "450", "K-12", 15), rec("khatian_rs", "Rahim", "450", "K-12", 12)], transfers=[]),
    dict(title="Case 3 - Double sale + broken chain (fictional)", district="Demo District",
         records=[rec("deed", "Rahim", "450", "K-12", 15)],
         transfers=[tr("Rahim", "Karim", "450", "2021-02-10"), tr("Rahim", "Hasan", "450", "2022-06-05"), tr("Selim", "Jamal", "450", "2023-01-15")]),
    dict(title="Case 4 - Worst case (fictional)", district="Demo District",
         records=[rec("khatian_cs", "Nur", "77", "K-3", 1, "bigha"), rec("khatian_rs", "Nur", "78", "K-9", 30)],
         transfers=[tr("Nur", "Omar", "77", "2023-01-10"), tr("Omar", "Pial", "77", "2023-05-20"),
                    tr("Pial", "Qamar", "77", "2023-09-02"), tr("Nur", "Omar", "77", "2023-10-01", "mutation")]),
]


def con():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = con()
    db.execute("CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL, hash TEXT NOT NULL, owner TEXT DEFAULT 'demo')")
    columns = {row["name"] for row in db.execute("PRAGMA table_info(cases)").fetchall()}
    if "owner" not in columns:
        db.execute("ALTER TABLE cases ADD COLUMN owner TEXT DEFAULT 'demo'")
    db.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT NOT NULL,
        case_id INTEGER, created_at TEXT NOT NULL, detail TEXT)""")
    # Demo accounts; change these before any deployment. Passwords are hashed.
    if not db.execute("SELECT 1 FROM users WHERE username='buyer'").fetchone():
        db.execute("INSERT INTO users VALUES(?,?,?,?)",
                   ("buyer", hash_password("BuyerDemo123!"), "buyer", datetime.utcnow().isoformat()))
    if not db.execute("SELECT 1 FROM users WHERE username='officer'").fetchone():
        db.execute("INSERT INTO users VALUES(?,?,?,?)",
                   ("officer", hash_password("OfficerDemo123!"), "officer", datetime.utcnow().isoformat()))
    count = db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if count == 0:
        for sample in SEED:
            db.execute("INSERT INTO cases(data,hash,owner) VALUES(?,?,?)",
                       (json.dumps(sample, ensure_ascii=False), seal(sample), "demo"))
    db.commit()
    db.close()


def load_case(case_id):
    db = con()
    row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Case not found")
    return row["id"], json.loads(row["data"]), row["hash"], row["owner"]


def audit(username, action, case_id=None, detail=""):
    db = con()
    db.execute("INSERT INTO audit_log(username,action,case_id,created_at,detail) VALUES(?,?,?,?,?)",
               (username, action, case_id, datetime.utcnow().isoformat(timespec="seconds") + "Z", detail[:500]))
    db.commit()
    db.close()


BASE = r"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title or 'JomiTrace — Land Intelligence' }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#f4f7f3;--surface:#fff;--ink:#152b22;--muted:#6a7b72;--line:#e0e8e1;--green:#174c38;--green2:#236b4d;--mint:#e4f3e9;--red:#b8322a;--redbg:#fff0ee;--amber:#996000;--amberbg:#fff4dd;--shadow:0 10px 30px rgba(22,55,38,.06)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 'DM Sans',sans-serif}
a{color:var(--green2)}h1,h2,h3,h4{font-family:Manrope,'DM Sans',sans-serif;line-height:1.18;letter-spacing:-.025em}h1{font-size:clamp(2rem,4vw,3.15rem);margin:7px 0 12px;font-weight:800}h2{font-size:1.4rem;margin:26px 0 13px}h3{font-size:1.05rem;margin:7px 0}p{color:var(--muted);margin:7px 0 14px}
.demo{background:#123d2d;color:#dcefe3;text-align:center;padding:7px 14px;font-size:12px;letter-spacing:.02em}
.app-shell{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:calc(100vh - 32px)}
.sidebar{background:#fff;border-right:1px solid var(--line);padding:25px 16px;display:flex;flex-direction:column;gap:25px}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink);font:800 1.45rem Manrope,sans-serif;padding:0 12px}
.brand-mark{width:35px;height:35px;border-radius:11px;background:var(--green);color:white;display:grid;place-items:center;font-size:20px;box-shadow:0 5px 12px #174c3820}
.brand small{display:block;font:500 11px 'DM Sans',sans-serif;color:var(--muted);letter-spacing:.06em;text-transform:uppercase}
.nav-label{padding:0 13px;color:#91a096;text-transform:uppercase;letter-spacing:.12em;font-size:10px;font-weight:700;margin-bottom:5px}
.nav-list{display:grid;gap:5px}.nav-list a{display:flex;align-items:center;gap:12px;text-decoration:none;color:#52655b;padding:11px 13px;border-radius:10px;font-weight:600;transition:.15s}
.nav-list a:hover,.nav-list a.active{background:var(--mint);color:var(--green)}
.nav-icon{width:22px;text-align:center;font-size:17px}.sidebar-note{margin-top:auto;background:#f2f7f2;border:1px solid var(--line);border-radius:13px;padding:14px;font-size:12px;color:var(--muted)}
.sidebar-note strong{display:block;color:var(--green);margin-bottom:4px}
.main-area{min-width:0;padding:0 34px 45px}
.topbar{min-height:75px;display:flex;align-items:center;justify-content:space-between;gap:15px;border-bottom:1px solid var(--line);margin-bottom:28px}
.breadcrumb{font-size:13px;color:var(--muted)}.topbar-right{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.user-chip{display:flex;align-items:center;gap:9px;padding:7px 11px;border:1px solid var(--line);background:#fff;border-radius:99px;font-size:12px;font-weight:700}
.avatar{width:27px;height:27px;border-radius:50%;background:#d9eee0;color:var(--green);display:grid;place-items:center;font-weight:800}
.content{max-width:1250px;margin:0 auto}
.eyebrow{color:var(--green2);font-size:11px;font-weight:800;letter-spacing:.13em;text-transform:uppercase}
.hero-row{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin:8px 0 24px}.hero-copy{max-width:760px}.hero-copy p{font-size:16px;max-width:700px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--green);border-radius:9px;padding:10px 15px;background:var(--green);color:white;text-decoration:none;font:700 13px 'DM Sans',sans-serif;cursor:pointer;transition:transform .15s,background .15s;white-space:nowrap}
.btn:hover{background:#0f3928;transform:translateY(-1px);color:white}.btn.secondary{background:#fff;color:var(--green);border-color:var(--line)}.btn.secondary:hover{background:var(--mint)}.btn.danger{background:#fff;color:var(--red);border-color:#f0c5c1}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.card,.panel{background:var(--surface);border:1px solid var(--line);border-radius:15px;padding:20px;margin-bottom:15px;box-shadow:var(--shadow)}
.metric-card{position:relative;overflow:hidden}.metric-card:after{content:'';position:absolute;width:90px;height:90px;border-radius:50%;background:var(--mint);right:-26px;top:-26px;opacity:.9}.metric-top{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:13px;font-weight:600}.metric-symbol{position:relative;z-index:1;width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:var(--mint);color:var(--green);font-size:17px}.metric{font:800 2.25rem Manrope,sans-serif;letter-spacing:-.05em;margin:12px 0 2px}.metric-foot{font-size:12px;color:var(--muted)}
.case{display:flex;justify-content:space-between;gap:18px;align-items:center;border:1px solid var(--line);border-left:4px solid #d5e2d8;padding:19px 20px}.case.high{border-left-color:var(--red)}.case.warn{border-left-color:#c08720}.case.ok{border-left-color:#2d8b5b}.case-main{min-width:0}.case-meta{font-size:12px;color:var(--muted)}.case-actions{display:flex;align-items:center;gap:14px;flex-shrink:0}.case-title{font-size:17px;margin:5px 0}.case-description{margin:4px 0 8px}
.pill{display:inline-flex;align-items:center;gap:5px;border-radius:99px;padding:4px 10px;background:#e5f5e9;color:#247449;font-size:12px;font-weight:700}.pill.high{background:var(--redbg);color:var(--red)}.pill.warn{background:var(--amberbg);color:var(--amber)}
.section-heading{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:27px 0 12px}.section-heading h2{margin:0}.section-heading span{font-size:12px;color:var(--muted)}
.filter-panel{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(200px,1fr) auto;align-items:end;gap:12px;padding:16px}.filter-panel label{margin-top:0}
label{display:block;font-weight:700;font-size:13px;margin:12px 0 6px}input,select,textarea{width:100%;padding:11px 12px;border:1px solid #d4dfd6;border-radius:9px;background:#fff;color:var(--ink);font:14px 'DM Sans',sans-serif;outline:none;transition:border .15s,box-shadow .15s}input:focus,select:focus,textarea:focus{border-color:#5b9a75;box-shadow:0 0 0 3px #5b9a751a}textarea{min-height:90px}.formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
table{width:100%;border-collapse:collapse;min-width:600px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line)}th{background:#f5f8f4;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.tablewrap{overflow:auto}
.alert{padding:13px 15px;border-radius:10px;background:var(--amberbg);color:#765000;margin:12px 0}.alert.success{background:#e5f5e9;color:#21643b}.error{color:var(--red);font-weight:700}
.finding{border:1px solid var(--line);border-left:4px solid #c08720;padding:17px 18px;background:white;border-radius:12px;margin:12px 0;box-shadow:var(--shadow)}.finding.high{border-left-color:var(--red)}.finding.ok{border-left-color:#2d8b5b}
.hash{font:12px ui-monospace,monospace;overflow-wrap:anywhere;background:#f5f8f4;padding:9px;border-radius:7px}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.login-shell{max-width:500px;margin:38px auto}.login-card{padding:30px}.login-card h1{font-size:2.4rem}.login-brand{display:flex;justify-content:center;margin:24px 0 5px}
.footer{margin-top:35px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12px}
@media(max-width:900px){.app-shell{grid-template-columns:78px minmax(0,1fr)}.sidebar{padding:22px 10px}.brand{justify-content:center;padding:0}.brand-text,.nav-label,.nav-text,.sidebar-note{display:none}.nav-list a{justify-content:center;padding:12px 8px}.nav-icon{font-size:19px}.main-area{padding:0 20px 35px}.grid{gap:10px}.card{padding:16px}}
@media(max-width:650px){.app-shell{display:block}.sidebar{display:none}.main-area{padding:0 14px 28px}.topbar{min-height:62px;margin-bottom:20px}.hero-row{display:block}.hero-row>.btn{margin-top:8px}.grid{grid-template-columns:1fr}.filter-panel{grid-template-columns:1fr}.case{align-items:flex-start;flex-direction:column}.case-actions{width:100%;justify-content:space-between}.formgrid{grid-template-columns:1fr}.login-card{padding:22px}.topbar-right{gap:6px}}
@media print{.sidebar,.topbar,.demo,.noprint{display:none!important}.app-shell{display:block}.main-area{padding:0}body{background:white}.card,.panel,.finding{box-shadow:none}}
</style>
<body><div class="demo">● &nbsp; JomiTrace screening prototype &nbsp; · &nbsp; Synthetic demo data only &nbsp; · &nbsp; Not a legal conclusion</div>
{% if user %}
<div class="app-shell"><aside class="sidebar">
<a class="brand" href="/"><span class="brand-mark">⌁</span><span class="brand-text">JomiTrace<small>LAND INTELLIGENCE</small></span></a>
<div><div class="nav-label">Workspace</div><nav class="nav-list">
<a href="/" class="{{ 'active' if request.url.path == '/' else '' }}"><span class="nav-icon">▦</span><span class="nav-text">Dashboard</span></a>
<a href="/case/new" class="{{ 'active' if request.url.path == '/case/new' else '' }}"><span class="nav-icon">＋</span><span class="nav-text">New verification</span></a>
{% if user.role == 'officer' %}<a href="/audit" class="{{ 'active' if request.url.path == '/audit' else '' }}"><span class="nav-icon">◷</span><span class="nav-text">Audit log</span></a>{% endif %}
</nav></div>
<div><div class="nav-label">Information</div><nav class="nav-list"><a href="/#how-it-works"><span class="nav-icon">ⓘ</span><span class="nav-text">How it works</span></a></nav></div>
<div class="sidebar-note"><strong>Evidence first</strong>JomiTrace flags inconsistencies in supplied records. It does not prove fraud or legal ownership.</div>
</aside><main class="main-area"><div class="topbar"><div class="breadcrumb">Workspace <span style="padding:0 7px;color:#b0bcb3">/</span> {{ 'Dashboard' if request.url.path == '/' else ('New verification' if request.url.path == '/case/new' else 'Case analysis') }}</div><div class="topbar-right"><div class="user-chip"><span class="avatar">{{ user.username[:1]|upper }}</span><span>{{ user.username }} <span style="color:#849389">· {{ user.role }}</span></span></div><a class="btn secondary" href="/logout">Log out ↗</a></div></div><div class="content">
{% else %}
<div class="login-shell"><div class="login-brand"><a class="brand" href="/"><span class="brand-mark">⌁</span><span>JomiTrace<small style="text-align:center">LAND INTELLIGENCE</small></span></a></div><main class="content">
{% endif %}
{% if flash %}<div class="alert {{ 'success' if flash_type == 'success' else '' }}">{{ flash }}</div>{% endif %}
{% block body %}{% endblock %}
<div class="footer">JomiTrace is an educational screening prototype. It does not connect to official government records and cannot establish legal ownership. Do not enter real personal or land-record data.</div>
</div></main>{% if user %}</div>{% endif %}
</body></html>"""

LOGIN = r"""{% extends 'base' %}{% block body %}<section class="card login-card"><div class="eyebrow">SECURE DEMO ACCESS</div><h1>{{ heading }}</h1><p>{{ subtitle }}</p><form method="post" action="{{ action }}">
{% if register %}<label>Username</label><input name="username" required minlength="3" maxlength="40" autocomplete="username">{% else %}<label>Username</label><input name="username" required autocomplete="username">{% endif %}
<label>Password</label><input type="password" name="password" required minlength="8" autocomplete="{{ 'new-password' if register else 'current-password' }}">
{% if register %}<label>Demo role</label><select name="role"><option value="buyer">Buyer / Citizen</option><option value="officer">Officer / Reviewer</option></select><p class="muted">For this local prototype only. In a real system, privileged roles must be assigned by an administrator.</p>{% endif %}
<button class="btn" style="width:100%;margin-top:12px" type="submit">{{ 'Create account' if register else 'Log in' }} →</button></form>
{% if not register %}<div class="alert">Demo accounts: <b>buyer</b> / <b>BuyerDemo123!</b> and <b>officer</b> / <b>OfficerDemo123!</b></div><p><a href="/register">Create a demo account</a></p>{% else %}<p><a href="/login">Already registered? Log in</a></p>{% endif %}</section>{% endblock %}"""

HOME = r"""{% extends 'base' %}{% block body %}
<div class="hero-row"><div class="hero-copy"><div class="eyebrow">LAND RECORD SCREENING / OVERVIEW</div><h1>Land records,<br>checked with evidence.</h1><p>Compare supplied records, spot inconsistencies, and understand what needs further verification before a transaction proceeds.</p></div><a class="btn" href="/case/new">＋ Create verification case</a></div>
<div class="grid">
<div class="card metric-card"><div class="metric-top"><span>Cases visible to you</span><span class="metric-symbol">▦</span></div><div class="metric">{{ rows|length }}</div><div class="metric-foot">Cases in your workspace</div></div>
<div class="card metric-card"><div class="metric-top"><span>Need closer review</span><span class="metric-symbol">⌕</span></div><div class="metric">{{ flagged }}</div><div class="metric-foot">At least one finding to review</div></div>
<div class="card metric-card"><div class="metric-top"><span>High-risk indicators</span><span class="metric-symbol">⚑</span></div><div class="metric">{{ high }}</div><div class="metric-foot">Prioritize further verification</div></div>
</div>
<div class="section-heading"><h2>Verification cases</h2><span>{{ rows|length }} shown</span></div>
<form class="card filter-panel noprint" method="get" action="/">
<div><label>Search cases</label><input name="q" value="{{ q }}" placeholder="Case title, district or plot number"></div>
<div><label>Risk status</label><select name="status"><option value="">All statuses</option><option value="high" {{'selected' if status=='high' else ''}}>High-risk indicators</option><option value="warn" {{'selected' if status=='warn' else ''}}>Needs check</option><option value="ok" {{'selected' if status=='ok' else ''}}>Clear</option></select></div>
<div class="actions" style="margin-top:0"><button class="btn" type="submit">Apply filters</button><a class="btn secondary" href="/">Reset</a></div>
</form>
{% for r in rows %}<div class="card case {{r.level}}"><div class="case-main"><div class="case-meta">CASE #{{r.id}} &nbsp;·&nbsp; {{r.district}}</div><h3 class="case-title">{{r.title}}</h3><p class="case-description">{{r.verdict}}</p><span class="pill {{r.level}}">{% if r.level=='high' %}● High-risk indicators{% elif r.level=='warn' %}● Needs check{% else %}● Clear{% endif %}</span> <span class="case-meta">{{r.n}} finding(s)</span></div><div class="case-actions"><a class="btn" href="/case/{{r.id}}">Open analysis&nbsp; →</a></div></div>{% else %}<div class="card"><h3>No matching cases</h3><p>Try another search or create a new verification case.</p><a class="btn" href="/case/new">＋ Create case</a></div>{% endfor %}
<div class="card" id="how-it-works" style="margin-top:25px;background:#f8fbf7"><div class="eyebrow">HOW IT WORKS</div><h2 style="margin-top:8px">A clear path from records to review.</h2><div class="grid"><div><span class="metric-symbol">01</span><h3>Supply records</h3><p>Add fictional land records and transaction details.</p></div><div><span class="metric-symbol">02</span><h3>Compare evidence</h3><p>Rule-based checks look for mismatches and conflicting entries.</p></div><div><span class="metric-symbol">03</span><h3>Review findings</h3><p>Read the evidence and take issues to authorized professionals.</p></div></div></div>
{% endblock %}"""

NEW_CASE = r"""{% extends 'base' %}{% block body %}<a href="/" class="muted">← Dashboard</a><h1>Create a verification case</h1><p>Enter fictional demonstration data only. This form supports two records and up to three sale transactions to keep the prototype simple.</p>
<form method="post" action="/case/new" class="card">
<label>Case title</label><input name="title" required maxlength="100" placeholder="e.g. Plot 450 sample review">
<label>District / area label</label><input name="district" required maxlength="80" value="Demo District">
<h2>Record A</h2><div class="formgrid"><div><label>Record type</label><select name="type1">{% for t in record_types %}<option value="{{t}}">{{t}}</option>{% endfor %}</select></div><div><label>Recorded owner (fictional)</label><input name="owner1" required maxlength="80" value="Person A"></div><div><label>Plot number</label><input name="plot1" required maxlength="40" value="450"></div><div><label>Khatian number</label><input name="khatian1" required maxlength="40" value="K-12"></div><div><label>Land area</label><input type="number" name="area1" min="0.01" step="0.01" required value="15"></div><div><label>Area unit</label><select name="unit1">{% for u in units %}<option value="{{u}}">{{u}}</option>{% endfor %}</select></div></div>
<h2>Record B</h2><div class="formgrid"><div><label>Record type</label><select name="type2">{% for t in record_types %}<option value="{{t}}" {{'selected' if t=='khatian_rs' else ''}}>{{t}}</option>{% endfor %}</select></div><div><label>Recorded owner (fictional)</label><input name="owner2" required maxlength="80" value="Person A"></div><div><label>Plot number</label><input name="plot2" required maxlength="40" value="450"></div><div><label>Khatian number</label><input name="khatian2" required maxlength="40" value="K-12"></div><div><label>Land area</label><input type="number" name="area2" min="0.01" step="0.01" required value="15"></div><div><label>Area unit</label><select name="unit2">{% for u in units %}<option value="{{u}}">{{u}}</option>{% endfor %}</select></div></div>
<h2>Optional registration transactions</h2><p class="muted">Leave a seller or buyer blank to skip that transaction. Dates must be YYYY-MM-DD.</p>
{% for n in [1,2,3] %}<div class="panel"><b>Transaction {{n}}</b><div class="formgrid"><div><label>Seller</label><input name="seller{{n}}" maxlength="80" placeholder="e.g. Person A"></div><div><label>Buyer</label><input name="buyer{{n}}" maxlength="80" placeholder="e.g. Person B"></div><div><label>Plot</label><input name="tplot{{n}}" maxlength="40" value="450"></div><div><label>Date</label><input type="date" name="tdate{{n}}"></div></div></div>{% endfor %}
<div class="alert">This prototype uses assumed conversions: 1 katha = 1.65 decimals, 1 bigha = 33 decimals, 1 acre = 100 decimals. Actual measures can vary by region.</div>
<button class="btn" type="submit">Save and analyze</button> <a class="btn secondary" href="/">Cancel</a></form>{% endblock %}"""

CASE = r"""{% extends 'base' %}{% block body %}
<a href="/" class="muted noprint">← All cases</a>
<div class="hero-row"><div class="hero-copy"><div class="eyebrow">CASE REVIEW / EVIDENCE</div><h1>{{ c.title }}</h1><p>{{ c.district }} · Case #{{ id }} · Screening result only, not a legal determination.</p></div><a class="btn secondary noprint" href="/case/{{id}}/report">Download PDF report ↓</a></div>
<div class="grid">
 <div class="card metric-card"><div class="metric-top"><span>Assessment</span><span class="metric-symbol">◈</span></div><h3>{{ 'High-risk indicators' if F|selectattr('1','equalto','high')|list else ('Needs check' if F else 'Clear') }}</h3><div class="metric-foot">{{ F|length }} finding(s) from supplied records</div></div>
 <div class="card metric-card"><div class="metric-top"><span>Review status</span><span class="metric-symbol">✓</span></div><h3>{{ c.review.status if c.review else 'Pending Review' }}</h3><div class="metric-foot">Officer workflow status</div></div>
 <div class="card metric-card"><div class="metric-top"><span>Verification checklist</span><span class="metric-symbol">☷</span></div><h3>{{ checklist_done }} / {{ checklist_items|length }} complete</h3><div class="metric-foot">User checklist progress</div></div>
</div>
<div class="card"><b>Assessment:</b> {{ verdict }}<p>Findings are indicators for further review. A warning is not proof of fraud; a clear result does not prove legal ownership.</p><a class="btn secondary noprint" href="/case/{{id}}/report">Download PDF report</a> <button class="btn secondary noprint" onclick="window.print()">Print page</button></div>
<h2>Record comparison</h2><div class="tablewrap card"><table><tr><th>Field</th><th>Record A</th><th>Record B</th><th>Comparison</th></tr>
<tr><td>Record type</td><td>{{ c.records[0].type }}</td><td>{{ c.records[1].type }}</td><td>Reference types</td></tr>
<tr><td>Recorded owner</td><td>{{ c.records[0].owner }}</td><td>{{ c.records[1].owner }}</td><td>{{ 'Match' if c.records[0].owner|lower == c.records[1].owner|lower else 'Mismatch' }}</td></tr>
<tr><td>Plot number</td><td>{{ c.records[0].plot }}</td><td>{{ c.records[1].plot }}</td><td>{{ 'Match' if c.records[0].plot|string == c.records[1].plot|string else 'Mismatch' }}</td></tr>
<tr><td>Khatian number</td><td>{{ c.records[0].khatian }}</td><td>{{ c.records[1].khatian }}</td><td>{{ 'Match' if c.records[0].khatian|string == c.records[1].khatian|string else 'Mismatch' }}</td></tr>
<tr><td>Land area</td><td>{{ c.records[0].area }} {{ c.records[0].unit }}</td><td>{{ c.records[1].area }} {{ c.records[1].unit }}</td><td>{{ 'Compare units carefully' if c.records[0].unit != c.records[1].unit else ('Match' if c.records[0].area == c.records[1].area else 'Mismatch') }}</td></tr>
</table></div>
<h2>Findings and evidence</h2>
{% for f in F %}<div class="finding {{'high' if f[1]=='high' else ''}}"><b>{{f[0]}} · {{ rules[f[0]] }} · {{ 'High-risk indicator' if f[1]=='high' else 'Needs check' }}</b><p>{{f[2]}}</p><b>Evidence</b>
{% if f[3] is mapping %}<ul>{% for k,v in f[3].items() %}<li>{{k}}: {{v}}</li>{% endfor %}</ul>{% else %}<ul>{% for e in f[3] %}<li>{% if e is mapping %}{{e.seller}} → {{e.buyer}} · {{e.date}} · {{e.source}} · Plot {{e.plot}}{% else %}{{e}}{% endif %}</li>{% endfor %}</ul>{% endif %}</div>{% else %}<div class="finding ok">No rule flagged an inconsistency in the supplied records. This does not independently prove ownership or authenticity.</div>{% endfor %}
<h2>Ownership timeline (registration records)</h2>{% if reg %}<ol>{% for t in reg %}<li><b>{{t.seller}} → {{t.buyer}}</b> · {{t.date}} · Plot {{t.plot}}{% if loop.previtem and loop.previtem.buyer != t.seller %}<span class="error"> — possible chain break</span>{% endif %}</li>{% endfor %}</ol>{% else %}<p>No registration transfers were supplied.</p>{% endif %}
<h2>Verification checklist</h2><p>Mark each task only after you have actually completed it. This checklist is not legal certification.</p>
<form method="post" action="/case/{{id}}/checklist" class="card noprint">
{% for item in checklist_items %}<label style="display:flex;align-items:center;gap:10px;font-weight:500"><input style="width:auto" type="checkbox" name="completed" value="{{item.key}}" {{'checked' if item.key in checklist else ''}}> {{item.label}}</label>{% endfor %}
<div class="actions"><button class="btn" type="submit">Save checklist</button></div></form>
{% if user.role == 'officer' %}<h2>Officer review</h2><form method="post" action="/case/{{id}}/review" class="card noprint">
<label>Review status</label><select name="review_status">{% for s in review_statuses %}<option value="{{s}}" {{'selected' if c.review and c.review.status==s else ''}}>{{s}}</option>{% endfor %}</select>
<label>Officer note (fictional demo text only)</label><textarea name="review_note" maxlength="1000" placeholder="Explain what needs review or which documents are missing.">{{ c.review.note if c.review else '' }}</textarea>
<div class="actions"><button class="btn" type="submit">Save officer review</button></div></form>
{% else %}<div class="card"><h3>Officer review</h3><p><b>Status:</b> {{ c.review.status if c.review else 'Pending Review' }}</p><p><b>Note:</b> {{ c.review.note if c.review and c.review.note else 'No officer note yet.' }}</p></div>{% endif %}
<h2>Integrity seal</h2><div class="card"><b>{{'Hash matches stored record' if intact else 'Hash mismatch: stored data changed'}}</b><div class="muted">SHA-256 stored hash</div><div class="hash">{{stored}}</div><div class="muted">Recalculated hash</div><div class="hash">{{now}}</div>
{% if user.role == 'officer' %}<form method="post" action="/case/{{id}}/tamper" class="actions noprint"><button class="btn danger" onclick="return confirm('Run the demo-only tampering simulation?')">Simulate tampering (demo)</button></form><form method="post" action="/case/{{id}}/reset" class="actions noprint"><button class="btn secondary">Reset seeded case</button></form>{% endif %}</div>
<h2>Recommended next steps</h2><ul><li>Review the original documents.</li><li>Verify the ownership chain with authorized records.</li><li>Consult the appropriate land registration authority or a qualified legal professional.</li></ul>
{% endblock %}"""

AUDIT = r"""{% extends 'base' %}{% block body %}<h1>Audit log</h1><p>Recent actions recorded by this prototype.</p><div class="tablewrap card"><table><tr><th>When (UTC)</th><th>User</th><th>Action</th><th>Case</th><th>Details</th></tr>{% for a in rows %}<tr><td>{{a.created_at}}</td><td>{{a.username}}</td><td>{{a.action}}</td><td>{{a.case_id or '—'}}</td><td>{{a.detail}}</td></tr>{% endfor %}</table></div>{% endblock %}"""

env = Environment(loader=DictLoader({"base": BASE, "home": HOME, "login": LOGIN, "new_case": NEW_CASE, "case": CASE, "audit": AUDIT}), autoescape=True)
templates = Jinja2Templates(env=env)
app = FastAPI(title="JomiTrace")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)


@app.on_event("startup")
def startup():
    init_db()


def current_user(request: Request):
    username = request.session.get("username")
    if not username:
        return None
    db = con()
    row = db.execute("SELECT username,role FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    return dict(username=row["username"], role=row["role"]) if row else None


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in")
    return user


def can_view(user, owner):
    return user["role"] == "officer" or owner in (user["username"], "demo")


def render(request, template, context=None, status_code=200):
    user = current_user(request)
    context = context or {}
    context.update({"request": request, "user": user})
    flash = request.session.pop("flash", None)
    if flash:
        context["flash"], context["flash_type"] = flash
    return templates.TemplateResponse(request, template, context, status_code=status_code)


@app.get("/login")
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", 303)
    return render(request, "login", {"heading": "Welcome back", "subtitle": "Log in to your JomiTrace demo account.", "register": False, "action": "/login"})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    db = con()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    if not row or not verify_password(password, row["password_hash"]):
        return render(request, "login", {"heading": "Welcome back", "subtitle": "The username or password was not correct.", "register": False, "action": "/login", "flash": "Login failed. Check your credentials.", "flash_type": "error"}, 401)
    request.session.clear()
    request.session["username"] = username
    audit(username, "login")
    return RedirectResponse("/", 303)


@app.get("/register")
def register_page(request: Request):
    return render(request, "login", {"heading": "Create demo account", "subtitle": "Use fictional information only.", "register": True, "action": "/register"})


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("buyer")):
    username = username.strip().lower()
    if not username.replace("_", "").isalnum() or len(username) < 3 or len(username) > 40:
        return render(request, "login", {"heading": "Create demo account", "subtitle": "Choose a username with letters, numbers, or underscores.", "register": True, "action": "/register", "flash": "Invalid username.", "flash_type": "error"}, 400)
    if len(password) < 8:
        return render(request, "login", {"heading": "Create demo account", "subtitle": "Password must be at least 8 characters.", "register": True, "action": "/register", "flash": "Password must be at least 8 characters.", "flash_type": "error"}, 400)
    if role not in ("buyer", "officer"):
        role = "buyer"
    db = con()
    try:
        db.execute("INSERT INTO users VALUES(?,?,?,?)", (username, hash_password(password), role, datetime.utcnow().isoformat()))
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return render(request, "login", {"heading": "Create demo account", "subtitle": "That username is already taken.", "register": True, "action": "/register", "flash": "Username already exists.", "flash_type": "error"}, 400)
    db.close()
    request.session.clear()
    request.session["username"] = username
    audit(username, "register", detail=f"role={role}")
    return RedirectResponse("/", 303)


@app.get("/logout")
def logout(request: Request):
    user = current_user(request)
    if user:
        audit(user["username"], "logout")
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.get("/")
def home(request: Request, q: str = "", status: str = ""):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    db = con()
    rows = db.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    db.close()
    output = []
    for row in rows:
        if not can_view(user, row["owner"]):
            continue
        case_data = json.loads(row["data"])
        verdict, findings = analyze(case_data)
        level = "high" if any(f[1] == "high" for f in findings) else "warn" if findings else "ok"
        plot_text = " ".join(str(r.get("plot", "")) for r in case_data.get("records", []))
        haystack = f'{case_data.get("title","")} {case_data.get("district","")} {plot_text}'.lower()
        if q and q.lower() not in haystack:
            continue
        if status and status != level:
            continue
        output.append(dict(id=row["id"], title=case_data.get("title"), district=case_data.get("district", ""),
                           verdict=verdict, n=len(findings), level=level,
                           label={"high": "High-risk indicators", "warn": "Needs check", "ok": "Clear"}[level]))
    return render(request, "home", {"rows": output, "q": q, "status": status,
                                    "flagged": sum(1 for x in output if x["level"] != "ok"),
                                    "high": sum(1 for x in output if x["level"] == "high")})


@app.get("/case/new")
def new_case_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    return render(request, "new_case", {"record_types": RECORD_TYPES, "units": list(UNITS)})


@app.post("/case/new")
def create_case(
    request: Request,
    title: str = Form(...), district: str = Form(...),
    type1: str = Form(...), owner1: str = Form(...), plot1: str = Form(...), khatian1: str = Form(...), area1: float = Form(...), unit1: str = Form(...),
    type2: str = Form(...), owner2: str = Form(...), plot2: str = Form(...), khatian2: str = Form(...), area2: float = Form(...), unit2: str = Form(...),
    seller1: str = Form(""), buyer1: str = Form(""), tplot1: str = Form(""), tdate1: str = Form(""),
    seller2: str = Form(""), buyer2: str = Form(""), tplot2: str = Form(""), tdate2: str = Form(""),
    seller3: str = Form(""), buyer3: str = Form(""), tplot3: str = Form(""), tdate3: str = Form("")
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    if type1 not in RECORD_TYPES or type2 not in RECORD_TYPES or unit1 not in UNITS or unit2 not in UNITS:
        raise HTTPException(400, "Invalid record type or unit")
    if area1 <= 0 or area2 <= 0:
        raise HTTPException(400, "Area must be greater than zero")
    records = [
        rec(type1, owner1.strip(), plot1.strip(), khatian1.strip(), area1, unit1),
        rec(type2, owner2.strip(), plot2.strip(), khatian2.strip(), area2, unit2)
    ]
    transfers = []
    for seller, buyer, plot, dt in [(seller1, buyer1, tplot1, tdate1), (seller2, buyer2, tplot2, tdate2), (seller3, buyer3, tplot3, tdate3)]:
        if seller.strip() or buyer.strip() or dt.strip():
            if not (seller.strip() and buyer.strip() and plot.strip() and dt.strip()):
                raise HTTPException(400, "For each transaction, enter seller, buyer, plot and date, or leave all fields blank.")
            try:
                parse_date(dt)
            except ValueError:
                raise HTTPException(400, "Transaction date must be a valid date.")
            transfers.append(tr(seller.strip(), buyer.strip(), plot.strip(), dt, "registration"))
    data = {"title": title.strip()[:100] + " (fictional)", "district": district.strip()[:80],
            "records": records, "transfers": transfers, "checklist": [],
            "review": {"status": "Pending Review", "note": ""}}
    db = con()
    cur = db.execute("INSERT INTO cases(data,hash,owner) VALUES(?,?,?)",
                     (json.dumps(data, ensure_ascii=False), seal(data), user["username"]))
    case_id = cur.lastrowid
    db.commit()
    db.close()
    audit(user["username"], "create_case", case_id, "Created fictional verification case")
    return RedirectResponse(f"/case/{case_id}", 303)


RULE_NAMES = {"R1": "Plot number consistency", "R2": "Land area comparison", "R3": "Ownership chain", "R4": "Potential duplicate sale",
              "R5": "Rapid transfers", "R6": "Registration vs mutation", "R7": "Survey chain"}

CHECKLIST_ITEMS = [
    {"key": "documents_reviewed", "label": "Review the supplied deed and khatian details"},
    {"key": "plot_checked", "label": "Compare plot / dag numbers"},
    {"key": "area_checked", "label": "Compare land areas and units"},
    {"key": "ownership_checked", "label": "Review the supplied ownership-transfer timeline"},
    {"key": "official_verification", "label": "Verify documents with an authorized source or qualified professional"},
]
REVIEW_STATUSES = ["Pending Review", "Under Review", "More Documents Required", "Review Completed"]


@app.get("/case/{case_id}")
def case_page(request: Request, case_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    ident, data, stored_hash, owner = load_case(case_id)
    if not can_view(user, owner):
        raise HTTPException(403, "You cannot view this case.")
    verdict, findings = analyze(data)
    reg = sorted([t for t in data.get("transfers", []) if t.get("source") == "registration"], key=lambda t: t.get("date", ""))
    intact = stored_hash == seal(data)
    data.setdefault("checklist", [])
    data.setdefault("review", {"status": "Pending Review", "note": ""})
    audit(user["username"], "view_case", ident)
    return render(request, "case", {"id": ident, "c": data, "verdict": verdict, "F": findings, "reg": reg,
                                    "stored": stored_hash, "now": seal(data), "intact": intact, "rules": RULE_NAMES,
                                    "checklist_items": CHECKLIST_ITEMS, "checklist": data["checklist"],
                                    "checklist_done": len(set(data["checklist"]) & {x["key"] for x in CHECKLIST_ITEMS}),
                                    "review_statuses": REVIEW_STATUSES})


@app.post("/case/{case_id}/checklist")
def save_checklist(request: Request, case_id: int, completed: Optional[list[str]] = Form(None)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    ident, data, stored_hash, owner = load_case(case_id)
    if not can_view(user, owner):
        raise HTTPException(403, "You cannot update this case.")
    if stored_hash != seal(data):
        raise HTTPException(409, "Integrity hash mismatch. Ask an officer to reset this demo case before editing it.")
    allowed = {item["key"] for item in CHECKLIST_ITEMS}
    data["checklist"] = sorted(set(completed or []) & allowed)
    db = con()
    db.execute("UPDATE cases SET data=?, hash=? WHERE id=?",
               (json.dumps(data, ensure_ascii=False), seal(data), ident))
    db.commit()
    db.close()
    audit(user["username"], "update_checklist", ident, f"{len(data['checklist'])}/{len(CHECKLIST_ITEMS)} checklist items complete")
    request.session["flash"] = ("Verification checklist saved.", "success")
    return RedirectResponse(f"/case/{ident}", 303)


@app.post("/case/{case_id}/review")
def save_review(request: Request, case_id: int, review_status: str = Form(...), review_note: str = Form("")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    if user["role"] != "officer":
        raise HTTPException(403, "Officer role required.")
    if review_status not in REVIEW_STATUSES:
        raise HTTPException(400, "Invalid review status.")
    ident, data, stored_hash, owner = load_case(case_id)
    if not can_view(user, owner):
        raise HTTPException(403, "You cannot update this case.")
    if stored_hash != seal(data):
        raise HTTPException(409, "Integrity hash mismatch. Reset this demo case before changing its review.")
    data.setdefault("review", {})
    data["review"] = {"status": review_status, "note": review_note.strip()[:1000]}
    db = con()
    db.execute("UPDATE cases SET data=?, hash=? WHERE id=?",
               (json.dumps(data, ensure_ascii=False), seal(data), ident))
    db.commit()
    db.close()
    audit(user["username"], "officer_review", ident, f"status={review_status}; note saved")
    request.session["flash"] = ("Officer review saved.", "success")
    return RedirectResponse(f"/case/{ident}", 303)


@app.post("/case/{case_id}/tamper")
def tamper(request: Request, case_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    if user["role"] != "officer":
        raise HTTPException(403, "Officer role required for this demo action.")
    ident, data, stored_hash, owner = load_case(case_id)
    if not can_view(user, owner):
        raise HTTPException(403, "You cannot modify this case.")
    if data.get("records"):
        data["records"][0]["area"] = float(data["records"][0].get("area", 0)) + 3
    db = con()
    db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(data, ensure_ascii=False), ident))
    db.commit()
    db.close()
    audit(user["username"], "simulate_tampering", ident, "Changed data without updating stored hash")
    request.session["flash"] = ("Tampering simulation complete; open the case to see the hash mismatch.", "success")
    return RedirectResponse(f"/case/{ident}", 303)


@app.post("/case/{case_id}/reset")
def reset_case(request: Request, case_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    if user["role"] != "officer":
        raise HTTPException(403, "Officer role required for this demo action.")
    ident, data, stored_hash, owner = load_case(case_id)
    if not data.get("title", "").startswith("Case ") or owner != "demo":
        raise HTTPException(400, "Reset is available only for original demo cases.")
    seed_index = int(data["title"].split(" - ")[0].replace("Case ", "")) - 1
    if seed_index < 0 or seed_index >= len(SEED):
        raise HTTPException(400, "No matching demo case.")
    sample = SEED[seed_index]
    db = con()
    db.execute("UPDATE cases SET data=?,hash=? WHERE id=?", (json.dumps(sample), seal(sample), ident))
    db.commit()
    db.close()
    audit(user["username"], "reset_case", ident)
    return RedirectResponse(f"/case/{ident}", 303)


@app.get("/case/{case_id}/report")
def report(request: Request, case_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    ident, data, stored_hash, owner = load_case(case_id)
    if not can_view(user, owner):
        raise HTTPException(403, "You cannot view this case.")
    verdict, findings = analyze(data)
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from io import BytesIO
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=8, leading=11))
        story = [Paragraph("JomiTrace — Verification Screening Report", styles["Title"]),
                 Paragraph("PROTOTYPE ONLY • SYNTHETIC DATA • NOT A LEGAL DETERMINATION", styles["Heading3"]),
                 Spacer(1, 8), Paragraph(f"Case: {escape(data.get('title',''))}", styles["Heading2"]),
                 Paragraph(f"District label: {escape(data.get('district',''))}", styles["BodyText"]),
                 Paragraph(f"Case ID: {ident} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["BodyText"]),
                 Spacer(1, 8), Paragraph("Assessment", styles["Heading2"]), Paragraph(escape(verdict), styles["BodyText"]),
                 Spacer(1, 8), Paragraph("Findings and evidence", styles["Heading2"])]
        if not findings:
            story.append(Paragraph("No rule flagged an inconsistency in the supplied records. This does not prove ownership or authenticity.", styles["BodyText"]))
        for finding in findings:
            evidence = finding[3]
            if isinstance(evidence, dict):
                evidence_text = "; ".join(f"{k}: {v}" for k, v in evidence.items())
            else:
                evidence_text = "; ".join(
                    f"{e.get('seller')} -> {e.get('buyer')} ({e.get('date')}, plot {e.get('plot')})" if isinstance(e, dict) else str(e)
                    for e in evidence)
            story.append(Paragraph(f"<b>{finding[0]} — {escape(RULE_NAMES[finding[0]])} ({escape(finding[1])})</b>", styles["BodyText"]))
            story.append(Paragraph(escape(finding[2]), styles["SmallText"]))
            story.append(Paragraph("Evidence: " + escape(evidence_text), styles["SmallText"]))
            story.append(Spacer(1, 6))
        story += [Spacer(1, 8), Paragraph("Supplied records", styles["Heading2"])]
        table_data = [["Type", "Owner", "Plot", "Khatian", "Area"]]
        for record in data.get("records", []):
            table_data.append([str(record.get("type", "")), str(record.get("owner", "")), str(record.get("plot", "")),
                               str(record.get("khatian", "")), f"{record.get('area','')} {record.get('unit','')}"])
        table = Table(table_data, repeatRows=1, colWidths=[30*mm, 30*mm, 18*mm, 25*mm, 30*mm])
        table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e4eee7")),
                                   ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
                                   ("FONTSIZE", (0,0), (-1,-1), 8), ("VALIGN", (0,0), (-1,-1), "TOP")]))
        story.append(table)
        story += [Spacer(1, 10), Paragraph("Ownership timeline (supplied registration transactions)", styles["Heading2"])]
        registration_transfers = sorted([t for t in data.get("transfers", []) if t.get("source") == "registration"], key=lambda t: t.get("date", ""))
        if registration_transfers:
            for t in registration_transfers:
                story.append(Paragraph(escape(f"{t.get('seller','')} -> {t.get('buyer','')} | {t.get('date','')} | Plot {t.get('plot','')}"), styles["SmallText"]))
        else:
            story.append(Paragraph("No registration transactions supplied.", styles["SmallText"]))
        story += [Spacer(1, 8), Paragraph("Verification checklist", styles["Heading2"])]
        checklist = set(data.get("checklist", []))
        for item in CHECKLIST_ITEMS:
            story.append(Paragraph(("[x] " if item["key"] in checklist else "[ ] ") + escape(item["label"]), styles["SmallText"]))
        review = data.get("review", {"status": "Pending Review", "note": ""})
        story += [Spacer(1, 8), Paragraph("Officer review (not a legal approval)", styles["Heading2"]),
                  Paragraph("Status: " + escape(review.get("status", "Pending Review")), styles["SmallText"]),
                  Paragraph("Note: " + escape(review.get("note", "") or "No officer note supplied."), styles["SmallText"]),
                  Spacer(1, 10), Paragraph("Integrity seal (SHA-256)", styles["Heading2"]),
                  Paragraph(escape(stored_hash), styles["SmallText"]),
                  Spacer(1, 8), Paragraph("Recommended next steps", styles["Heading2"]),
                  Paragraph("Review original documents, verify the ownership chain using authorized records, and consult the relevant land authority or a qualified legal professional.", styles["BodyText"]),
                  Spacer(1, 8), Paragraph("Unit conversion assumptions may vary by region. This report is a screening aid only and does not confirm legal ownership.", styles["SmallText"])]
        doc.build(story)
        audit(user["username"], "download_report", ident, "PDF screening report generated")
        return Response(buffer.getvalue(), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="JomiTrace-case-{ident}-report.pdf"'})
    except ImportError:
        return HTMLResponse("PDF export requires ReportLab. Run: pip install reportlab", status_code=500)


@app.get("/audit")
def audit_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    if user["role"] != "officer":
        raise HTTPException(403, "Officer role required.")
    db = con()
    rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    db.close()
    return render(request, "audit", {"rows": rows})


@app.get("/health")
def health():
    return {"status": "ok", "app": "JomiTrace", "data": "synthetic prototype"}
