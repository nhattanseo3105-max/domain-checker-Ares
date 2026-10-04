import os
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout

from flask import Flask, render_template_string, request, jsonify
import requests
from requests.adapters import HTTPAdapter

try:
    import whois  # python-whois (fallback cuối cùng, chậm)
except Exception:  # pragma: no cover
    whois = None

app = Flask(__name__)

# ==========================================
# CẤU HÌNH
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")

UA = {
    "User-Agent": "Mozilla/5.0 (compatible; DomainChecker/3.0)",
    "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.5",
}

# Session dùng chung + connection pool lớn để tái sử dụng kết nối (nhanh hơn rất nhiều)
SESSION = requests.Session()
_adapter = HTTPAdapter(pool_connections=100, pool_maxsize=200, max_retries=0)
SESSION.mount("https://", _adapter)
SESSION.mount("http://", _adapter)
SESSION.headers.update(UA)

# Pool thread dùng chung cho mọi request
EXEC = ThreadPoolExecutor(max_workers=96)

OVERALL_TIMEOUT = 14  # giây tối đa cho 1 domain


def http_get_json(url, timeout=8, headers=None):
    """GET → (status_code, json | None). Không raise."""
    try:
        r = SESSION.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, None
    except Exception:
        return None, None


# ==========================================
# 1. TIỆN ÍCH XỬ LÝ DỮ LIỆU
# ==========================================
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def format_date_full(dt):
    """datetime / ISO string / list → DD/MM/YYYY"""
    if not dt:
        return None
    try:
        if isinstance(dt, (list, tuple)):
            dts = [format_date_full(x) for x in dt if x]
            dts = [d for d in dts if d]
            if not dts:
                return None
            # nếu có nhiều ngày, lấy ngày sớm nhất (ngày tạo)
            dts.sort(key=lambda s: (s[6:10], s[3:5], s[0:2]))
            return dts[0]
        if isinstance(dt, datetime):
            return dt.strftime("%d/%m/%Y")
        if isinstance(dt, str):
            m = _DATE_RE.search(dt)
            if m:
                y, mo, d = m.groups()
                return f"{d}/{mo}/{y}"
            for fmt in ("%d-%b-%Y", "%d/%m/%Y", "%Y/%m/%d", "%d.%m.%Y", "%Y.%m.%d"):
                try:
                    return datetime.strptime(dt.strip()[:11], fmt).strftime("%d/%m/%Y")
                except ValueError:
                    continue
    except Exception:
        pass
    return None


def _normalize_status(s):
    """Chỉ quan tâm 3 loại: serverHold, clientHold, transferLock"""
    s = str(s).lower().replace(" ", "").replace("_", "").replace("-", "")
    if "serverhold" in s:
        return "serverHold"
    if "clienthold" in s:
        return "clientHold"
    if "clienttransferprohibited" in s or "servertransferprohibited" in s:
        return "transferLock"
    return None


def format_status_display(status_set):
    labels = {
        "serverHold": ("serverHold", "badge-danger"),
        "clientHold": ("clientHold", "badge-danger"),
        "transferLock": ("Chặn Transfer", "badge-warning"),
    }
    badges = []
    for key in ("serverHold", "clientHold", "transferLock"):
        if key in status_set:
            text, cls = labels[key]
            badges.append(f"<span class='badge {cls}'>{text}</span>")
    if not badges:
        return "<span class='badge badge-success'>Bình thường</span>"
    return "<br>".join(badges)


def _vcard_fn(ent):
    vcard = ent.get("vcardArray", [])
    if len(vcard) > 1 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4 and prop[0] in ("fn", "org"):
                val = prop[3]
                if isinstance(val, list):
                    val = " ".join(str(v) for v in val if v)
                if val:
                    return str(val)
    return None


def _find_registrar(entities):
    for ent in entities or []:
        roles = [str(r).lower() for r in ent.get("roles", [])]
        if "registrar" in roles:
            name = _vcard_fn(ent)
            if not name:
                for pid in ent.get("publicIds", []) or []:
                    if pid.get("identifier"):
                        name = f"IANA ID {pid['identifier']}"
                        break
            if not name:
                name = ent.get("handle") or ent.get("name")
            if name:
                return str(name)
        # entity lồng nhau
        sub = _find_registrar(ent.get("entities", []))
        if sub:
            return sub
    return None


def _parse_rdap_json(data):
    """RDAP JSON → (status_set, registrar, created_str)"""
    status_found = set()
    for s in data.get("status", []) or []:
        k = _normalize_status(s)
        if k:
            status_found.add(k)
    registrar = _find_registrar(data.get("entities", []))
    created = None
    for ev in data.get("events", []) or []:
        action = str(ev.get("eventAction", "")).lower()
        if action in ("registration", "registered") and ev.get("eventDate"):
            created = format_date_full(ev["eventDate"])
            if created:
                break
    return status_found, registrar, created


def _parse_flat_json(data):
    """JSON phẳng (who-dat, rdap.cloud...) → (status_set, registrar, created, registered)"""
    status_found = set()
    registrar = None
    created = None
    registered = False
    if not isinstance(data, dict):
        return status_found, registrar, created, registered

    if data.get("isRegistered") is True or data.get("id"):
        registered = True

    reg_val = data.get("registrar")
    if isinstance(reg_val, str) and reg_val:
        registrar = reg_val
        registered = True
    elif isinstance(reg_val, dict):
        registrar = reg_val.get("name") or reg_val.get("organization") or reg_val.get("organisation")
        registered = True

    statuses = data.get("status") or data.get("statuses") or []
    if isinstance(statuses, str):
        statuses = [statuses]
    for s in statuses:
        k = _normalize_status(s)
        if k:
            status_found.add(k)

    for k in ("created", "creationDate", "creation_date", "createdDate", "registered", "registrationDate"):
        if data.get(k):
            created = format_date_full(data[k])
            if created:
                registered = True
                break

    # lồng RDAP
    for key in ("rdap", "data", "result"):
        sub = data.get(key)
        if isinstance(sub, dict) and ("events" in sub or "entities" in sub or "status" in sub):
            st, reg, cr = _parse_rdap_json(sub)
            status_found |= st
            registrar = registrar or reg
            created = created or cr
            registered = True
    if "events" in data or "entities" in data:
        st, reg, cr = _parse_rdap_json(data)
        status_found |= st
        registrar = registrar or reg
        created = created or cr
        registered = True
    return status_found, registrar, created, registered


def _is_restricted_404(data):
    if not isinstance(data, dict):
        return False
    desc = data.get("description") or []
    desc_text = " ".join(str(d) for d in desc) if isinstance(desc, list) else str(desc)
    full = (desc_text + " " + str(data.get("title", ""))).lower()
    return any(
        x in full
        for x in ("not available for registration", "restricted by registry policy", "registry policy", "prohibited")
    )


# ==========================================
# 2. CÁC NGUỒN DỮ LIỆU (chạy song song)
# ==========================================
_bootstrap = {"map": None}
_bootstrap_lock = threading.Lock()


def _load_bootstrap():
    if _bootstrap["map"] is not None:
        return _bootstrap["map"]
    with _bootstrap_lock:
        if _bootstrap["map"] is not None:
            return _bootstrap["map"]
        mp = {}
        code, data = http_get_json("https://data.iana.org/rdap/dns.json", timeout=10)
        if code == 200 and isinstance(data, dict):
            for tlds, urls in data.get("services", []):
                https = [u for u in urls if u.startswith("https")] or urls
                for t in tlds:
                    mp[t.lower()] = https[0] if https else None
        _bootstrap["map"] = mp  # kể cả rỗng để khỏi gọi lại liên tục
        return mp


def _empty():
    return {
        "registered": False, "not_found": False, "restricted": False,
        "status": set(), "registrar": None, "created": None,
        "auth": False, "has_status_src": False,
    }


def _from_rdap_response(code, data, auth=False):
    res = _empty()
    if code == 200 and isinstance(data, dict):
        st, reg, cr = _parse_rdap_json(data)
        res.update(registered=True, status=st, registrar=reg, created=cr, has_status_src=True, auth=auth)
        res["_links"] = data.get("links", [])
    elif code == 404:
        res["not_found"] = True
        res["auth"] = auth
        if _is_restricted_404(data):
            res["restricted"] = True
    return res


def src_registry_rdap(domain):
    """Nguồn 1: RDAP trực tiếp từ registry (IANA bootstrap) — chính xác & nhanh nhất."""
    tld = domain.rsplit(".", 1)[-1].lower()
    base = _load_bootstrap().get(tld)
    if not base:
        return _empty()
    code, data = http_get_json(base.rstrip("/") + "/domain/" + domain, timeout=8)
    res = _from_rdap_response(code, data, auth=True)

    # Backup: registry "thin" (vd .com) thiếu registrar → theo link related sang RDAP của registrar
    if res["registered"] and not res["registrar"]:
        for ln in res.get("_links", []) or []:
            if str(ln.get("rel", "")).lower() == "related" and ln.get("href", "").startswith("http"):
                c2, d2 = http_get_json(ln["href"], timeout=8)
                if c2 == 200 and isinstance(d2, dict):
                    st, reg, cr = _parse_rdap_json(d2)
                    res["status"] |= st
                    res["registrar"] = res["registrar"] or reg
                    res["created"] = res["created"] or cr
                    break
    return res


def src_rdap_org(domain):
    code, data = http_get_json("https://rdap.org/domain/" + domain, timeout=9)
    return _from_rdap_response(code, data)


def src_rdap_net(domain):
    code, data = http_get_json("https://www.rdap.net/domain/" + domain, timeout=9)
    return _from_rdap_response(code, data)


def _flat_source(url):
    def fn(domain):
        code, data = http_get_json(url.format(domain=domain), timeout=9)
        res = _empty()
        if code == 200 and isinstance(data, dict):
            st, reg, cr, registered = _parse_flat_json(data)
            res.update(registered=registered, status=st, registrar=reg, created=cr,
                       has_status_src=bool(st) or registered)
        return res
    return fn


src_whodat = _flat_source("https://who-dat.as93.net/{domain}")
src_rdapcloud = _flat_source("https://rdap.cloud/api/v1/{domain}")


def src_python_whois(domain):
    """Fallback cuối: WHOIS port 43 qua python-whois (chậm)."""
    res = _empty()
    if whois is None:
        return res
    try:
        w = whois.whois(domain)
        if w and w.domain_name:
            raw = w.status
            if isinstance(raw, str):
                raw = [raw]
            st = set()
            for s in raw or []:
                k = _normalize_status(s)
                if k:
                    st.add(k)
            reg = w.registrar
            if isinstance(reg, list):
                reg = reg[0] if reg else None
            res.update(
                registered=True, status=st, registrar=reg,
                created=format_date_full(getattr(w, "creation_date", None)),
                has_status_src=True,
            )
    except Exception:
        pass
    return res


FAST_SOURCES = [src_registry_rdap, src_rdap_org, src_rdap_net, src_whodat, src_rdapcloud]


def _merge(info, res):
    if res["registered"]:
        info["registered"] = True
    if res["not_found"]:
        info["not_found"] = True
        if res["auth"]:
            info["auth_not_found"] = True
    if res["restricted"]:
        info["restricted"] = True
    info["status"] |= res["status"]
    if res["has_status_src"]:
        info["has_status_src"] = True
    # Ưu tiên nguồn auth (registry) cho registrar / created
    if res["registrar"] and (not info["registrar"] or res["auth"]):
        info["registrar"] = str(res["registrar"]).strip()
    if res["created"] and (not info["created"] or res["auth"]):
        info["created"] = res["created"]


def _complete(info):
    return bool(info["registered"] and info["registrar"] and info["created"] and info["has_status_src"])


def get_domain_info(domain):
    """
    Trả về (status_html, registrar, created_dd/mm/yyyy, state)
    state: ok | unregistered | restricted
    Chạy song song 5 nguồn RDAP, dừng ngay khi đã đủ dữ liệu; thiếu mới gọi WHOIS 43.
    """
    info = {
        "registered": False, "not_found": False, "auth_not_found": False,
        "restricted": False, "status": set(), "registrar": None,
        "created": None, "has_status_src": False,
    }

    futs = {EXEC.submit(fn, domain): fn for fn in FAST_SOURCES}
    try:
        for fut in as_completed(futs, timeout=OVERALL_TIMEOUT):
            try:
                _merge(info, fut.result())
            except Exception:
                continue
            if info["restricted"]:
                break
            if info["auth_not_found"] and not info["registered"]:
                break
            if _complete(info):
                break
    except FutTimeout:
        pass
    for f in futs:
        f.cancel()

    if info["restricted"] and not info["registered"]:
        return (
            "<span class='badge badge-danger'>Không thể đăng ký</span><br>"
            "<span class='badge badge-warning'>Restricted by Registry Policy</span>",
            "Registry Policy", None, "restricted",
        )

    # Backup: thiếu registrar / ngày ĐK → WHOIS port 43
    need_backup = (not info["registered"] and not info["auth_not_found"]) or (
        info["registered"] and (not info["registrar"] or not info["created"])
    )
    if need_backup:
        try:
            _merge(info, EXEC.submit(src_python_whois, domain).result(timeout=12))
        except Exception:
            pass

    if not info["registered"]:
        return "Chưa đăng ký / Ẩn thông tin", "Không có dữ liệu", None, "unregistered"

    return (
        format_status_display(info["status"]),
        info["registrar"] or "Không xác định",
        info["created"],
        "ok",
    )


# ==========================================
# 3. NAMESERVER & CLOUDFLARE
# ==========================================
def get_nameservers(domain):
    def ask(url, headers=None):
        code, data = http_get_json(url, timeout=6, headers=headers)
        if code == 200 and isinstance(data, dict) and "Answer" in data:
            return [a["data"].rstrip(".") for a in data["Answer"] if a.get("type") == 2]
        return []

    futs = [
        EXEC.submit(ask, f"https://dns.google/resolve?name={domain}&type=NS"),
        EXEC.submit(ask, f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS",
                    {"accept": "application/dns-json"}),
    ]
    try:
        for f in as_completed(futs, timeout=8):
            try:
                r = f.result()
            except Exception:
                continue
            if r:
                return r
    except FutTimeout:
        pass
    return []


def check_cf_eligibility(domain):
    """Giả lập add domain vào CF để kiểm tra Banned."""
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        return "<span class='badge badge-muted'>Thiếu API CF</span>"
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    data = {"name": domain, "account": {"id": CF_ACCOUNT_ID}, "jump_start": False}
    try:
        r = SESSION.post(url, headers=headers, json=data, timeout=10)
        resp = r.json()
        if r.status_code == 200 and resp.get("success"):
            zone_id = resp["result"]["id"]
            # xóa zone ở nền, không bắt người dùng chờ
            EXEC.submit(lambda: SESSION.delete(f"{url}/{zone_id}", headers=headers, timeout=8))
            return "<span class='badge badge-success'>Sạch</span>"
        errors = resp.get("errors", [])
        if errors:
            code = errors[0].get("code")
            if code == 1049:
                return "<span class='badge badge-info'>Sạch (Chưa ĐK) - Mua Tốt</span>"
            if code == 1097:
                return "<span class='badge badge-danger'>BANNED</span>"
            if code == 1095:
                return "<span class='badge badge-danger'>Bị CF Chặn Add</span>"
            if code == 1116:
                return "<span class='badge badge-warning'>Đuôi TLD bị CF cấm</span>"
            if code == 1061:
                return "<span class='badge badge-success'>Sạch (Đã nằm trong CF khác)</span>"
            return f"<span class='badge badge-muted'>Lỗi CF: {code}</span>"
        return "<span class='badge badge-muted'>Không rõ trạng thái</span>"
    except Exception:
        return "<span class='badge badge-danger'>Lỗi Call API CF</span>"


# ==========================================
# 4. GIAO DIỆN WEB
# ==========================================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domain Checker — Ares</title>
<link rel="icon" type="image/png" href="https://cdn-icons-png.flaticon.com/512/15435/15435750.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#0b0f19;--bg-card:#111827;--bg-elevated:#1a2234;--border:#1e293b;--border-light:#334155;--text:#e2e8f0;--text-muted:#94a3b8;--text-dim:#64748b;--primary:#3b82f6;--radius:12px;--radius-sm:8px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;
background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(59,130,246,.15),transparent),radial-gradient(ellipse 60% 40% at 100% 100%,rgba(139,92,246,.08),transparent)}
.container{max-width:1300px;margin:0 auto;padding:32px 24px 60px}
.header{display:flex;align-items:center;margin-bottom:28px}
.logo{display:flex;align-items:center;gap:14px}
.logo-icon{width:44px;height:44px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 0 24px rgba(59,130,246,.35)}
.logo h1{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;background:linear-gradient(90deg,#e2e8f0,#94a3b8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo p{font-size:.8rem;color:var(--text-dim);margin-top:2px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:16px;box-shadow:0 4px 24px rgba(0,0,0,.25)}
textarea{width:100%;height:130px;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13.5px;resize:vertical}
textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,.2)}
textarea::placeholder{color:var(--text-dim)}
.action-bar{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px;align-items:center}
button{border:none;padding:10px 18px;font-size:14px;font-weight:600;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s;font-family:inherit;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;box-shadow:0 2px 12px rgba(59,130,246,.35)}
.btn-primary:hover:not(:disabled){transform:translateY(-1px)}
.btn-secondary{background:var(--bg-elevated);color:var(--text);border:1px solid var(--border-light)}
.btn-secondary:hover{background:#243044}
.btn-warning{background:linear-gradient(135deg,#f59e0b,#d97706);color:#111}
button:disabled{opacity:.45;cursor:not-allowed;transform:none!important}
.delay-box{display:flex;align-items:center;gap:8px;margin-left:auto;font-size:13px;color:var(--text-muted)}
.delay-box input{width:70px;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:'JetBrains Mono',monospace}
.progress{margin-top:14px;font-size:13.5px;color:var(--text-muted);font-weight:500;display:flex;align-items:center;gap:8px}
.progress-dot{width:8px;height:8px;border-radius:50%;background:var(--primary);animation:pulse 1.4s ease infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.85)}}
.legend{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:16px;display:none}
.legend.show{display:block}
.legend-title{font-size:11px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.07em;margin-bottom:12px}
.legend-groups{display:grid;grid-template-columns:1fr 1fr;gap:16px 28px}
.legend-group{display:none}.legend-group.show{display:block}
.legend-group-title{font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.legend-rows{display:flex;flex-direction:column;gap:6px}
.legend-row{display:none;align-items:center;gap:10px;font-size:12.5px;color:var(--text-muted)}
.legend-row.show{display:flex}
.legend-row .badge{flex-shrink:0;min-width:148px;text-align:center}
@media(max-width:780px){.legend-groups{grid-template-columns:1fr}}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11.5px;font-weight:600;white-space:nowrap}
.badge-success{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.25)}
.badge-danger{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.25)}
.badge-warning{background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.25)}
.badge-info{background:rgba(6,182,212,.15);color:#22d3ee;border:1px solid rgba(6,182,212,.25)}
.badge-muted{background:rgba(100,116,139,.15);color:#94a3b8;border:1px solid rgba(100,116,139,.25)}
.badge-cf-yes{background:rgba(246,130,31,.2);color:#fb923c;border:1px solid rgba(246,130,31,.3)}
.badge-cf-no{background:rgba(100,116,139,.15);color:#94a3b8;border:1px solid rgba(100,116,139,.25)}
.table-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.25)}
.table-wrapper{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px;min-width:860px}
th{background:var(--bg-elevated);color:var(--text-muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:14px 16px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:13px 16px;border-bottom:1px solid var(--border);vertical-align:middle;white-space:nowrap}
td.status-cell{white-space:normal;line-height:1.8}
tbody tr:hover{background:rgba(59,130,246,.04)}
tbody tr:last-child td{border-bottom:none}
.domain-cell{font-family:'JetBrains Mono',monospace;font-weight:500;font-size:13px;color:#93c5fd}
.date-cell{font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--text-muted)}
.ns-cell{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);max-width:280px;overflow:hidden;text-overflow:ellipsis;display:inline-block}
.skipped{color:var(--text-dim);font-style:italic;font-size:12.5px}
.error-cell{color:#f87171}
.modal{display:none;position:fixed;z-index:1000;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(6px);align-items:center;justify-content:center}
.modal.show{display:flex}
.modal-content{background:var(--bg-card);border:1px solid var(--border-light);padding:28px;border-radius:16px;width:400px;max-width:95vw;box-shadow:0 20px 50px rgba(0,0,0,.5)}
.modal-content h3{font-size:1.1rem;margin-bottom:20px}
.close-btn{float:right;font-size:22px;color:var(--text-dim);cursor:pointer;line-height:1}
.close-btn:hover{color:var(--text)}
.settings-item{display:flex;align-items:center;gap:12px;padding:10px 0;cursor:pointer;font-size:14px}
.settings-item input{width:17px;height:17px;accent-color:var(--primary);cursor:pointer}
.settings-item label{cursor:pointer;user-select:none}
.footer{text-align:center;margin-top:36px;font-size:13px;color:var(--text-dim)}
.footer span{background:linear-gradient(90deg,#3b82f6,#8b5cf6,#06b6d4,#3b82f6);background-size:300% 100%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;animation:gm 5s linear infinite}
@keyframes gm{0%{background-position:0% 50%}100%{background-position:300% 50%}}
</style>
</head>
<body>
<div class="container">
  <div class="header"><div class="logo"><div class="logo-icon">◈</div>
    <div><h1>Domain Checker</h1><p>Ares · Domain Intelligence</p></div></div></div>

  <div class="card">
    <textarea id="domainList" placeholder="Nhập domain (mỗi dòng 1 domain). Hỗ trợ dán kèm giá tiền / ký tự lạ — hệ thống tự lọc.&#10;google.com&#10;tk88b.net    14,99 USD&#10;fifasmx.com  12,99 USD"></textarea>
    <div class="action-bar">
      <button id="btnCheck" class="btn-primary" onclick="startCheck(false)">▶ Bắt đầu kiểm tra</button>
      <button id="btnRetry" class="btn-warning" onclick="startCheck(true)" disabled>↻ Retry lỗi</button>
      <button class="btn-secondary" onclick="openSettings()">⚙ Cài đặt</button>
      <div class="delay-box">
        <label for="threads">Luồng song song</label>
        <input type="number" id="threads" value="12" min="1" max="40" title="Số domain kiểm tra cùng lúc">
      </div>
    </div>
    <div class="progress" id="progressText">Sẵn sàng kiểm tra</div>
  </div>

  <div class="legend" id="legendBox">
    <div class="legend-title">◈ Chú thích trạng thái (chỉ hiện những trạng thái đang có trong kết quả)</div>
    <div class="legend-groups">
      <div class="legend-group" id="legendDomainGroup">
        <div class="legend-group-title">Trạng thái Domain</div>
        <div class="legend-rows">
          <div class="legend-row" data-key="normal"><span class="badge badge-success">Bình thường</span><span>Không bị hold / không khóa transfer</span></div>
          <div class="legend-row" data-key="serverHold"><span class="badge badge-danger">serverHold</span><span>Registry giữ · không resolve DNS</span></div>
          <div class="legend-row" data-key="clientHold"><span class="badge badge-danger">clientHold</span><span>Registrar giữ · không resolve DNS</span></div>
          <div class="legend-row" data-key="transferLock"><span class="badge badge-warning">Chặn Transfer</span><span>Không chuyển registrar được</span></div>
          <div class="legend-row" data-key="chuaDK"><span class="badge badge-muted">Chưa đăng ký / Ẩn thông tin</span><span>Domain chưa đăng ký hoặc WHOIS bị ẩn</span></div>
          <div class="legend-row" data-key="restricted"><span class="badge badge-danger">Không thể đăng ký</span><span>Bị Registry Policy cấm</span></div>
        </div>
      </div>
      <div class="legend-group" id="legendCfGroup">
        <div class="legend-group-title">Trạng thái Cloudflare</div>
        <div class="legend-rows">
          <div class="legend-row" data-key="cfSach"><span class="badge badge-success">Sạch</span><span>Có thể add vào Cloudflare</span></div>
          <div class="legend-row" data-key="cfBanned"><span class="badge badge-danger">BANNED</span><span>Bị Cloudflare cấm thêm</span></div>
          <div class="legend-row" data-key="cfChuaDK"><span class="badge badge-info">Sạch (Chưa ĐK)</span><span>Chưa đăng ký · nên mua</span></div>
          <div class="legend-row" data-key="cfTldCam"><span class="badge badge-warning">Đuôi TLD bị CF cấm</span><span>TLD không được CF hỗ trợ</span></div>
          <div class="legend-row" data-key="cfChanAdd"><span class="badge badge-danger">Bị CF Chặn Add</span><span>Cloudflare từ chối thêm domain</span></div>
          <div class="legend-row" data-key="cfOther"><span class="badge badge-muted">Lỗi CF / Không rõ</span><span>Lỗi API hoặc trạng thái không xác định</span></div>
        </div>
      </div>
    </div>
  </div>

  <div class="table-card"><div class="table-wrapper">
    <table><thead><tr id="tableHeader"></tr></thead><tbody id="resultBody"></tbody></table>
  </div></div>
  <div class="footer">DEV by <span>Ares</span></div>
</div>

<div id="settingsModal" class="modal"><div class="modal-content">
  <span class="close-btn" onclick="closeSettings()">&times;</span>
  <h3>⚙ Cài đặt kiểm tra</h3>
  <div class="settings-item"><input type="checkbox" id="chk_cf"><label for="chk_cf">Trạng thái CF (Có thể Add CF)</label></div>
  <div class="settings-item"><input type="checkbox" id="chk_registrar" checked><label for="chk_registrar">Nhà đăng ký (Registrar)</label></div>
  <div class="settings-item"><input type="checkbox" id="chk_hold" checked><label for="chk_hold">Trạng thái Hold / Chặn Transfer</label></div>
  <div class="settings-item"><input type="checkbox" id="chk_dates" checked><label for="chk_dates">Ngày đăng ký</label></div>
  <div class="settings-item"><input type="checkbox" id="chk_ns" checked><label for="chk_ns">Nameserver & Cloudflare NS</label></div>
  <button class="btn-primary" style="margin-top:22px;width:100%;justify-content:center" onclick="closeSettings()">Lưu cài đặt</button>
</div></div>

<script>
const modal = document.getElementById("settingsModal");
function openSettings(){ modal.classList.add("show"); }
function closeSettings(){ modal.classList.remove("show"); }
window.onclick = e => { if (e.target === modal) closeSettings(); };

let failedDomains = [];
let seenLegendKeys = new Set();

function getOptions(){
  return {
    check_cf: document.getElementById('chk_cf').checked,
    check_registrar: document.getElementById('chk_registrar').checked,
    check_hold: document.getElementById('chk_hold').checked,
    check_dates: document.getElementById('chk_dates').checked,
    check_ns: document.getElementById('chk_ns').checked
  };
}

function buildHeader(o){
  let h = '<th>Domain</th>';
  if (o.check_cf) h += '<th>Trạng thái CF</th>';
  if (o.check_registrar) h += '<th>Nhà đăng ký</th>';
  if (o.check_hold) h += '<th>Trạng thái Domain</th>';
  if (o.check_dates) h += '<th>Ngày đăng ký</th>';
  if (o.check_ns) h += '<th>CF NS</th><th>Nameservers</th>';
  document.getElementById('tableHeader').innerHTML = h;
}

function countCols(o){
  return 1 + (o.check_cf?1:0) + (o.check_registrar?1:0) + (o.check_hold?1:0) + (o.check_dates?1:0) + (o.check_ns?2:0);
}

function isFailed(d, o){
  if (!d) return true;
  if (d.state === "unregistered" || d.state === "restricted") return false; // kết quả hợp lệ, không cần retry
  if (d.state === "error") return true;
  if (o.check_registrar && (!d.registrar || d.registrar === "Không xác định")) return true;
  if (o.check_dates && !d.created) return true;
  if (d.cf_add_status && String(d.cf_add_status).toLowerCase().includes("lỗi")) return true;
  return false;
}

function collectLegend(d, o){
  if (o.check_hold && d.status){
    const st = d.status;
    if (st.includes("Bình thường")) seenLegendKeys.add("normal");
    if (st.includes("serverHold")) seenLegendKeys.add("serverHold");
    if (st.includes("clientHold")) seenLegendKeys.add("clientHold");
    if (st.includes("Chặn Transfer")) seenLegendKeys.add("transferLock");
    if (st.includes("Chưa đăng ký")) seenLegendKeys.add("chuaDK");
    if (st.includes("Không thể đăng ký")) seenLegendKeys.add("restricted");
  }
  if (o.check_cf && d.cf_add_status){
    const cf = d.cf_add_status;
    if (cf.includes("BANNED")) seenLegendKeys.add("cfBanned");
    else if (cf.includes("Sạch (Chưa ĐK)")) seenLegendKeys.add("cfChuaDK");
    else if (cf.includes("Sạch")) seenLegendKeys.add("cfSach");
    if (cf.includes("Đuôi TLD bị CF cấm")) seenLegendKeys.add("cfTldCam");
    if (cf.includes("Bị CF Chặn Add")) seenLegendKeys.add("cfChanAdd");
    if (cf.includes("Lỗi CF") || cf.includes("Không rõ") || cf.includes("Thiếu API") || cf.includes("Lỗi Call")) seenLegendKeys.add("cfOther");
  }
}

const DOMAIN_KEYS = ["normal","serverHold","clientHold","transferLock","chuaDK","restricted"];
function updateLegend(){
  const box = document.getElementById('legendBox');
  if (!seenLegendKeys.size){ box.classList.remove("show"); return; }
  box.classList.add("show");
  document.querySelectorAll(".legend-row,.legend-group").forEach(el => el.classList.remove("show"));
  let hasD = false, hasC = false;
  seenLegendKeys.forEach(k => {
    const row = document.querySelector(`.legend-row[data-key="${k}"]`);
    if (row){ row.classList.add("show"); DOMAIN_KEYS.includes(k) ? hasD = true : hasC = true; }
  });
  if (hasD) document.getElementById("legendDomainGroup").classList.add("show");
  if (hasC) document.getElementById("legendCfGroup").classList.add("show");
}

function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function renderRow(domain, d, o){
  let nsText;
  if (d.ns === "Bỏ qua") nsText = '<span class="skipped">Bỏ qua</span>';
  else if (Array.isArray(d.ns) && d.ns.length) nsText = `<span class="ns-cell" title="${esc(d.ns.join(', '))}">${esc(d.ns.join(', '))}</span>`;
  else nsText = '<span class="error-cell">Không có NS</span>';

  let cfBadge = '<span class="skipped">Bỏ qua</span>';
  if (d.is_cloudflare !== "Bỏ qua")
    cfBadge = d.is_cloudflare ? '<span class="badge badge-cf-yes">Đang dùng</span>' : '<span class="badge badge-cf-no">Không dùng</span>';

  let reg = d.registrar || "";
  if (["Không có dữ liệu","Không xác định","Bỏ qua"].includes(reg)) reg = `<span class="error-cell">${esc(reg)}</span>`;
  else reg = esc(reg);

  let dateText = '<span class="skipped">—</span>';
  if (d.created) dateText = `<span class="date-cell">${esc(d.created)}</span>`;
  else if (d.state === "unregistered") dateText = '<span class="skipped">Chưa ĐK</span>';
  else if (d.state === "restricted") dateText = '<span class="skipped">—</span>';
  else if (o.check_dates) dateText = '<span class="error-cell">Không lấy được</span>';

  let c = `<td class="domain-cell">${esc(domain)}</td>`;
  if (o.check_cf) c += `<td>${d.cf_add_status || ""}</td>`;
  if (o.check_registrar) c += `<td>${reg}</td>`;
  if (o.check_hold) c += `<td class="status-cell">${d.status || ""}</td>`;
  if (o.check_dates) c += `<td>${dateText}</td>`;
  if (o.check_ns) c += `<td>${cfBadge}</td><td>${nsText}</td>`;
  return c;
}

async function startCheck(isRetry = false){
  const btn = document.getElementById('btnCheck');
  const btnRetry = document.getElementById('btnRetry');
  const o = getOptions();
  const conc = Math.min(40, Math.max(1, parseInt(document.getElementById('threads').value) || 12));
  let domains = [];

  if (isRetry){
    domains = [...failedDomains];
    if (!domains.length){ alert("Không có domain lỗi để retry!"); return; }
  } else {
    const text = document.getElementById('domainList').value;
    const re = /(?:https?:\/\/)?(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/i;
    domains = text.replace(/\r/g, "").split("\n").map(line => {
      const cleaned = line.trim().toLowerCase();
      if (!cleaned) return null;
      const tok = cleaned.split(/[\s\t,;|]+/)[0];
      let m = tok.includes(".") ? tok.match(re) : null;
      if (!m) m = cleaned.match(re);
      return m ? m[1] : null;
    }).filter(d => d && d.includes(".") && d.length > 3);
    domains = [...new Set(domains)];
    if (!domains.length){ alert("Vui lòng nhập ít nhất 1 domain hợp lệ!"); return; }
    failedDomains = [];
    seenLegendKeys = new Set();
  }

  buildHeader(o);
  const tbody = document.getElementById('resultBody');
  if (!isRetry) tbody.innerHTML = '';
  btn.disabled = true; btnRetry.disabled = true;

  const total = domains.length;
  const colspan = countCols(o) - 1;
  const retryList = new Set();   // domain lỗi của lượt này
  let completed = 0, next = 0;

  // Tạo sẵn toàn bộ dòng theo thứ tự nhập
  for (const domain of domains){
    let row = document.getElementById(`row-${domain}`);
    if (!row){ row = document.createElement('tr'); row.id = `row-${domain}`; tbody.appendChild(row); }
    row.innerHTML = `<td class="domain-cell">${esc(domain)}</td><td colspan="${colspan}" class="skipped">Đang chờ…</td>`;
  }

  const t0 = performance.now();
  function setProgress(){
    const sec = ((performance.now() - t0) / 1000).toFixed(1);
    document.getElementById('progressText').innerHTML =
      `<span class="progress-dot"></span> Đã xong ${completed}/${total} · ${sec}s`;
  }

  async function processOne(domain){
    const row = document.getElementById(`row-${domain}`);
    row.innerHTML = `<td class="domain-cell">${esc(domain)}</td><td colspan="${colspan}" class="skipped">Đang quét dữ liệu…</td>`;
    try {
      const resp = await fetch('/api/check', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain, options: o})
      });
      if (!resp.ok) throw new Error("Server error");
      const d = await resp.json();
      collectLegend(d, o);
      row.innerHTML = renderRow(domain, d, o);
      if (isFailed(d, o)) retryList.add(domain);
    } catch (e){
      row.innerHTML = `<td class="domain-cell">${esc(domain)}</td><td colspan="${colspan}" class="error-cell">Lỗi network / quá tải — thử lại sau</td>`;
      retryList.add(domain);
    }
    completed++;
    setProgress();
    updateLegend();
  }

  async function worker(){
    while (true){
      const i = next++;
      if (i >= total) break;
      await processOne(domains[i]);
    }
  }

  setProgress();
  await Promise.all(Array.from({length: Math.min(conc, total)}, worker));

  if (isRetry){
    failedDomains = failedDomains.filter(d => !domains.includes(d)).concat([...retryList]);
  } else {
    failedDomains = [...retryList];
  }
  const sec = ((performance.now() - t0) / 1000).toFixed(1);
  document.getElementById('progressText').innerHTML =
    `✓ Hoàn thành ${completed}/${total} domain trong ${sec}s` +
    (failedDomains.length ? ` · <span style="color:#f87171">${failedDomains.length} lỗi</span>` : '');
  btn.disabled = false;
  btnRetry.disabled = failedDomains.length === 0;
  updateLegend();
}
</script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/check', methods=['POST'])
def api_check():
    domain = "Unknown"
    try:
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        options = data.get('options', {}) or {}
        if not domain:
            return jsonify({"status": "Lỗi", "state": "error", "ns": [], "registrar": "", "is_cloudflare": False}), 400

        want_ns = options.get('check_ns', True)
        want_info = (
            options.get('check_registrar', True)
            or options.get('check_hold', True)
            or options.get('check_dates', True)
        )
        want_cf = options.get('check_cf', False)

        # Chạy NS, WHOIS/RDAP, CF song song → tổng thời gian = nguồn chậm nhất
        f_ns = EXEC.submit(get_nameservers, domain) if want_ns else None
        f_info = EXEC.submit(get_domain_info, domain) if want_info else None
        f_cf = EXEC.submit(check_cf_eligibility, domain) if want_cf else None

        ns_list = "Bỏ qua"
        is_cloudflare = "Bỏ qua"
        if f_ns:
            ns_list = f_ns.result()
            is_cloudflare = any('cloudflare.com' in ns.lower() for ns in ns_list) if ns_list else False

        status, registrar, created, state = "Bỏ qua", "Bỏ qua", None, "ok"
        if f_info:
            status, registrar, created, state = f_info.result()
            if not options.get('check_registrar', True):
                registrar = "Bỏ qua"
            if not options.get('check_hold', True):
                status = "Bỏ qua"
            if not options.get('check_dates', True):
                created = None

        cf_add_status = f_cf.result() if f_cf else "Bỏ qua"

        return jsonify({
            "domain": domain,
            "cf_add_status": cf_add_status,
            "registrar": registrar,
            "status": status,
            "created": created,
            "state": state,
            "ns": ns_list,
            "is_cloudflare": is_cloudflare,
        })
    except Exception:
        return jsonify({
            "domain": domain, "cf_add_status": "Lỗi Backend", "registrar": "Lỗi",
            "status": "Lỗi", "created": None, "state": "error",
            "ns": [], "is_cloudflare": False,
        })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
