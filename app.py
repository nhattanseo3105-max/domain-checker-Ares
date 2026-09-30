import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
import requests
import whois

app = Flask(__name__)

# ==========================================
# CẤU HÌNH CLOUDFLARE API
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")

# ==========================================
# 1. CÁC HÀM KIỂM TRA & XỬ LÝ DỮ LIỆU
# ==========================================
def format_date_short(dt):
    """Chuyển datetime / ISO string → DD/MM/YY"""
    if not dt:
        return None
    try:
        if isinstance(dt, list):
            dt = dt[0]
        if isinstance(dt, str):
            dt = dt.replace("Z", "+00:00").split("+")[0].split(".")[0]
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(dt[:19] if "T" in dt else dt[:10], fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        if isinstance(dt, datetime):
            return dt.strftime("%d/%m/%y")
    except Exception:
        pass
    return None

def check_cf_eligibility(domain):
    """Giả lập add domain vào CF để check xem có bị Banned không"""
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        return "<span class='badge badge-muted'>Thiếu API CF</span>"
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "name": domain,
        "account": {"id": CF_ACCOUNT_ID},
        "jump_start": False
    }
    try:
        r = requests.post(url, headers=headers, json=data, timeout=10)
        resp = r.json()
        if r.status_code == 200 and resp.get("success"):
            zone_id = resp["result"]["id"]
            requests.delete(f"{url}/{zone_id}", headers=headers, timeout=5)
            return "<span class='badge badge-success'>Sạch</span>"
        errors = resp.get("errors", [])
        if errors:
            err_code = errors[0].get("code")
            if err_code == 1049:
                return "<span class='badge badge-info'>Sạch (Chưa ĐK) - Mua Tốt</span>"
            elif err_code == 1097:
                return "<span class='badge badge-danger'>BANNED</span>"
            elif err_code == 1095:
                return "<span class='badge badge-danger'>Bị CF Chặn Add</span>"
            elif err_code == 1116:
                return "<span class='badge badge-warning'>Đuôi TLD bị CF cấm</span>"
            elif err_code == 1061:
                return "<span class='badge badge-success'>Sạch (Đã nằm trong CF khác)</span>"
            else:
                return f"<span class='badge badge-muted'>Lỗi CF: {err_code}</span>"
        return "<span class='badge badge-muted'>Không rõ trạng thái</span>"
    except Exception:
        return "<span class='badge badge-danger'>Lỗi Call API CF</span>"

def get_nameservers(domain):
    ns_list = []
    try:
        url = f"https://dns.google/resolve?name={domain}&type=NS"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "Answer" in data:
                ns_list = [ans["data"].rstrip(".") for ans in data["Answer"] if ans.get("type") == 2]
                if ns_list:
                    return ns_list
    except Exception:
        pass
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS"
        headers = {"accept": "application/dns-json"}
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "Answer" in data:
                ns_list = [ans["data"].rstrip(".") for ans in data["Answer"] if ans.get("type") == 2]
                return ns_list
    except Exception:
        pass
    return ns_list

def _normalize_status(s):
    """Chuẩn hóa 1 status string → key chuẩn"""
    s = str(s).lower().replace(" ", "").replace("_", "").replace("-", "")
    mapping = {
        "serverhold": "serverHold",
        "clienthold": "clientHold",
        "clienttransferprohibited": "clientTransferProhibited",
        "servertransferprohibited": "serverTransferProhibited",
        "pendingtransfer": "pendingTransfer",
        "clientupdateprohibited": "clientUpdateProhibited",
        "serverupdateprohibited": "serverUpdateProhibited",
        "clientdeleteprohibited": "clientDeleteProhibited",
        "serverdeleteprohibited": "serverDeleteProhibited",
        "redemptionperiod": "redemptionPeriod",
        "pendingdelete": "pendingDelete",
        "ok": "ok",
        "active": "ok",
    }
    for k, v in mapping.items():
        if k in s:
            return v
    return None

def _parse_rdap_json(data):
    """Parse RDAP JSON → status set + registrar + dates"""
    status_found = set()
    registrar = None
    created = None
    expires = None
    statuses = data.get("status", [])
    for s in statuses:
        key = _normalize_status(s)
        if key:
            status_found.add(key)
    entities = data.get("entities", [])
    for ent in entities:
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                        registrar = prop[3]
                        break
            if not registrar:
                registrar = ent.get("handle") or ent.get("name")
    events = data.get("events", [])
    for ev in events:
        action = str(ev.get("eventAction", "")).lower()
        date_str = ev.get("eventDate")
        if not date_str:
            continue
        if action in ("registration", "registered"):
            created = format_date_short(date_str)
        elif action in ("expiration", "expiry", "expired", "registrar expiration"):
            expires = format_date_short(date_str)
    return status_found, registrar, created, expires

def format_status_display(status_set):
    """Chuyển set status → HTML badge đẹp, mỗi trạng thái 1 dòng"""
    if not status_set:
        return "<span class='badge badge-success'>Active / Không bị lock</span>"
    labels = {
        "serverHold": ("serverHold", "badge-danger"),
        "clientHold": ("clientHold", "badge-danger"),
        "clientTransferProhibited": ("Khóa Transfer (Client)", "badge-warning"),
        "serverTransferProhibited": ("Khóa Transfer (Server)", "badge-warning"),
        "pendingTransfer": ("Đang chuyển Registrar", "badge-orange"),
        "clientUpdateProhibited": ("Khóa Update", "badge-muted"),
        "serverUpdateProhibited": ("Khóa Update (Server)", "badge-muted"),
        "clientDeleteProhibited": ("Khóa Delete", "badge-muted"),
        "serverDeleteProhibited": ("Khóa Delete (Server)", "badge-muted"),
        "redemptionPeriod": ("Redemption Period", "badge-danger"),
        "pendingDelete": ("Pending Delete", "badge-danger"),
        "ok": ("Active", "badge-success"),
    }
    priority = [
        "serverHold", "clientHold", "pendingTransfer",
        "redemptionPeriod", "pendingDelete",
        "clientTransferProhibited", "serverTransferProhibited",
        "clientUpdateProhibited", "serverUpdateProhibited",
        "clientDeleteProhibited", "serverDeleteProhibited", "ok"
    ]
    badges = []
    for key in priority:
        if key in status_set:
            text, cls = labels.get(key, (key, "badge-muted"))
            badges.append(f"<span class='badge {cls}'>{text}</span>")
    for key in status_set:
        if key not in priority:
            badges.append(f"<span class='badge badge-muted'>{key}</span>")
    # Mỗi trạng thái nằm trên 1 dòng
    return "<br>".join(badges) if badges else "<span class='badge badge-success'>Active / Không bị lock</span>"

def get_domain_info(domain):
    """
    Lấy status (Hold + Transfer + Lock) + Registrar + ngày ĐK / hết hạn.
    """
    status_found = set()
    registrar = None
    created = None
    expires = None
    is_registered = False

    # ---------- 1. rdap.org ----------
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if r.status_code == 200:
            is_registered = True
            data = r.json()
            st, reg, cr, exp = _parse_rdap_json(data)
            status_found.update(st)
            if reg:
                registrar = reg
            if cr:
                created = cr
            if exp:
                expires = exp
    except Exception:
        pass

    # ---------- 2. who-dat.as93.net ----------
    if not registrar or not status_found or not created or not expires:
        try:
            r = requests.get(f"https://who-dat.as93.net/{domain}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                is_registered = True
                if "registrar" in data and data["registrar"]:
                    reg_val = data["registrar"]
                    if isinstance(reg_val, str):
                        registrar = registrar or reg_val
                    elif isinstance(reg_val, dict):
                        registrar = registrar or reg_val.get("name") or reg_val.get("organization")
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    key = _normalize_status(s)
                    if key:
                        status_found.add(key)
                for key_map in [
                    ("created", "creationDate", "creation_date", "registered"),
                    ("expires", "expirationDate", "expiration_date", "expiry"),
                ]:
                    for k in key_map:
                        if k in data and data[k]:
                            formatted = format_date_short(data[k])
                            if formatted:
                                if "creat" in k or "regist" in k:
                                    created = created or formatted
                                else:
                                    expires = expires or formatted
                            break
                if "rdap" in data and isinstance(data["rdap"], dict):
                    st, reg, cr, exp = _parse_rdap_json(data["rdap"])
                    status_found.update(st)
                    if reg and not registrar:
                        registrar = reg
                    if cr and not created:
                        created = cr
                    if exp and not expires:
                        expires = exp
        except Exception:
            pass

    # ---------- 3. rdap.cloud ----------
    if not registrar or not status_found or not created or not expires:
        try:
            r = requests.get(f"https://rdap.cloud/api/v1/{domain}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                is_registered = True
                if "registrar" in data:
                    reg_val = data["registrar"]
                    if isinstance(reg_val, str):
                        registrar = registrar or reg_val
                    elif isinstance(reg_val, dict):
                        registrar = registrar or reg_val.get("name") or reg_val.get("organization")
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    key = _normalize_status(s)
                    if key:
                        status_found.add(key)
                for key_map in [
                    ("created", "creationDate", "creation_date", "registered"),
                    ("expires", "expirationDate", "expiration_date", "expiry"),
                ]:
                    for k in key_map:
                        if k in data and data[k]:
                            formatted = format_date_short(data[k])
                            if formatted:
                                if "creat" in k or "regist" in k:
                                    created = created or formatted
                                else:
                                    expires = expires or formatted
                            break
                st, reg, cr, exp = _parse_rdap_json(data)
                status_found.update(st)
                if reg and not registrar:
                    registrar = reg
                if cr and not created:
                    created = cr
                if exp and not expires:
                    expires = exp
        except Exception:
            pass

    # ---------- 4. python-whois (fallback) ----------
    if not is_registered or not registrar or not status_found or not created or not expires:
        try:
            w = whois.whois(domain)
            if w.domain_name:
                is_registered = True
                raw_status = w.status
                if isinstance(raw_status, str):
                    raw_status = [raw_status]
                if raw_status:
                    for s in raw_status:
                        key = _normalize_status(s)
                        if key:
                            status_found.add(key)
                if w.registrar and not registrar:
                    registrar = w.registrar
                if not created and getattr(w, "creation_date", None):
                    created = format_date_short(w.creation_date)
                if not expires and getattr(w, "expiration_date", None):
                    expires = format_date_short(w.expiration_date)
        except Exception:
            pass

    if not is_registered:
        return "Chưa đăng ký / Ẩn thông tin", "Không có dữ liệu", None, None

    final_status = format_status_display(status_found)
    final_registrar = registrar if registrar else "Không xác định"
    return final_status, final_registrar, created, expires

# ==========================================
# 2. GIAO DIỆN WEB
# ==========================================
HTML_TEMPLATE = """
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
        :root {
            --bg: #0b0f19;
            --bg-card: #111827;
            --bg-elevated: #1a2234;
            --border: #1e293b;
            --border-light: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --success: #22c55e;
            --danger: #ef4444;
            --warning: #f59e0b;
            --orange: #f97316;
            --info: #06b6d4;
            --accent: #8b5cf6;
            --radius: 12px;
            --radius-sm: 8px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.5;
            background-image:
                radial-gradient(ellipse 80% 50% at 50% -20%, rgba(59, 130, 246, 0.15), transparent),
                radial-gradient(ellipse 60% 40% at 100% 100%, rgba(139, 92, 246, 0.08), transparent);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 32px 24px 60px;
        }
        /* Header */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .logo-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 24px rgba(59, 130, 246, 0.35);
        }
        .logo h1 {
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #e2e8f0, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .logo p {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 2px;
        }
        /* Input Card */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25);
        }
        textarea {
            width: 100%;
            height: 130px;
            padding: 14px 16px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13.5px;
            resize: vertical;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        textarea::placeholder { color: var(--text-dim); }
        .action-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 16px;
            align-items: center;
        }
        button {
            border: none;
            padding: 10px 18px;
            font-size: 14px;
            font-weight: 600;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: all 0.2s;
            font-family: inherit;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            box-shadow: 0 2px 12px rgba(59, 130, 246, 0.35);
        }
        .btn-primary:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(59, 130, 246, 0.45);
        }
        .btn-secondary {
            background: var(--bg-elevated);
            color: var(--text);
            border: 1px solid var(--border-light);
        }
        .btn-secondary:hover { background: #243044; }
        .btn-warning {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: #111;
        }
        .btn-warning:hover:not(:disabled) { transform: translateY(-1px); }
        button:disabled {
            opacity: 0.45;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none !important;
        }
        .delay-box {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: auto;
            font-size: 13px;
            color: var(--text-muted);
        }
        .delay-box input {
            width: 80px;
            padding: 8px 10px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 13px;
            font-family: 'JetBrains Mono', monospace;
        }
        .delay-box input:focus {
            outline: none;
            border-color: var(--primary);
        }
        .progress {
            margin-top: 14px;
            font-size: 13.5px;
            color: var(--text-muted);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .progress-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--primary);
            animation: pulse 1.4s ease infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }
        /* ========== LEGEND (động - chỉ hiện trạng thái xuất hiện) ========== */
        .legend {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px 20px;
            margin-bottom: 16px;
            display: none; /* Ẩn mặc định, hiện khi có kết quả */
        }
        .legend.show {
            display: block;
        }
        .legend-title {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.07em;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .legend-groups {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px 28px;
        }
        .legend-group {
            display: none;
        }
        .legend-group.show {
            display: block;
        }
        .legend-group-title {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 8px;
            padding-bottom: 4px;
            border-bottom: 1px solid var(--border);
        }
        .legend-rows {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .legend-row {
            display: none;
            align-items: center;
            gap: 10px;
            font-size: 12.5px;
            color: var(--text-muted);
            line-height: 1.35;
        }
        .legend-row.show {
            display: flex;
        }
        .legend-row .badge {
            flex-shrink: 0;
            min-width: 148px;
            text-align: center;
        }
        @media (max-width: 780px) {
            .legend-groups { grid-template-columns: 1fr; }
            .legend-row .badge { min-width: 130px; }
        }
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11.5px;
            font-weight: 600;
            letter-spacing: 0.01em;
            white-space: nowrap;
        }
        .badge-success { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.25); }
        .badge-danger  { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.25); }
        .badge-orange  { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.25); }
        .badge-info    { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.25); }
        .badge-muted   { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.25); }
        .badge-cf-yes  { background: rgba(246, 130, 31, 0.2); color: #fb923c; border: 1px solid rgba(246, 130, 31, 0.3); }
        .badge-cf-no   { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.25); }
        /* Table */
        .table-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25);
        }
        .table-wrapper { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
            min-width: 900px;
        }
        th {
            background: var(--bg-elevated);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        td {
            padding: 13px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
            white-space: nowrap;
        }
        td.status-cell {
            white-space: normal;
            line-height: 1.8;
        }
        tbody tr { transition: background 0.15s; }
        tbody tr:hover { background: rgba(59, 130, 246, 0.04); }
        tbody tr:last-child td { border-bottom: none; }
        .domain-cell {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            font-size: 13px;
            color: #93c5fd;
        }
        .date-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: var(--text-muted);
        }
        .ns-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-dim);
            max-width: 280px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .skipped { color: var(--text-dim); font-style: italic; font-size: 12.5px; }
        .error-cell { color: #f87171; }
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            inset: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(6px);
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.25s;
        }
        .modal.show {
            display: flex;
            opacity: 1;
        }
        .modal-content {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            padding: 28px;
            border-radius: 16px;
            width: 400px;
            max-width: 95vw;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            transform: translateY(12px);
            transition: transform 0.25s;
        }
        .modal.show .modal-content { transform: translateY(0); }
        .modal-content h3 {
            font-size: 1.1rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .close-btn {
            float: right;
            font-size: 22px;
            color: var(--text-dim);
            cursor: pointer;
            line-height: 1;
            margin-top: -4px;
            transition: color 0.15s;
        }
        .close-btn:hover { color: var(--text); }
        .settings-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0;
            cursor: pointer;
            font-size: 14px;
        }
        .settings-item input {
            width: 17px;
            height: 17px;
            accent-color: var(--primary);
            cursor: pointer;
        }
        .settings-item label { cursor: pointer; user-select: none; }
        /* Footer */
        .footer {
            text-align: center;
            margin-top: 36px;
            font-size: 13px;
            color: var(--text-dim);
        }
        .footer span {
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #06b6d4, #3b82f6);
            background-size: 300% 100%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
            animation: gradientMove 5s linear infinite;
        }
        @keyframes gradientMove {
            0% { background-position: 0% 50%; }
            100% { background-position: 300% 50%; }
        }
        @media (max-width: 640px) {
            .container { padding: 20px 14px 40px; }
            .delay-box { margin-left: 0; width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <div class="logo-icon">◈</div>
                <div>
                    <h1>Domain Checker</h1>
                    <p>Ares · Domain Intelligence</p>
                </div>
            </div>
        </div>

        <!-- Input -->
        <div class="card">
            <textarea id="domainList" placeholder="Nhập domain (mỗi dòng 1 domain). Hỗ trợ dán kèm giá tiền / ký tự lạ — hệ thống tự lọc.&#10;google.com&#10;tk88b.net    14,99 USD&#10;fifasmx.com  12,99 USD"></textarea>
            <div class="action-bar">
                <button id="btnCheck" class="btn-primary" onclick="startCheck(false)">▶ Bắt đầu kiểm tra</button>
                <button id="btnRetry" class="btn-warning" onclick="startCheck(true)" disabled>↻ Retry lỗi</button>
                <button class="btn-secondary" onclick="openSettings()">⚙ Cài đặt</button>
                <div class="delay-box">
                    <label for="delayMs">Delay</label>
                    <input type="number" id="delayMs" value="500" min="0" step="100" title="ms giữa mỗi domain">
                    <span>ms</span>
                </div>
            </div>
            <div class="progress" id="progressText">Sẵn sàng kiểm tra</div>
        </div>

        <!-- Legend - động, chỉ hiện trạng thái xuất hiện trong kết quả -->
        <div class="legend" id="legendBox">
            <div class="legend-title">◈ Chú thích trạng thái (chỉ hiện những trạng thái đang có trong kết quả)</div>
            <div class="legend-groups">
                <!-- Nhóm Domain -->
                <div class="legend-group" id="legendDomainGroup">
                    <div class="legend-group-title">Trạng thái Domain</div>
                    <div class="legend-rows">
                        <div class="legend-row" data-key="active">
                            <span class="badge badge-success">Active / Không bị lock</span>
                            <span>Hoạt động bình thường</span>
                        </div>
                        <div class="legend-row" data-key="serverHold">
                            <span class="badge badge-danger">serverHold</span>
                            <span>Bị tạm giữ · không resolve DNS</span>
                        </div>
                        <div class="legend-row" data-key="clientHold">
                            <span class="badge badge-danger">clientHold</span>
                            <span>Bị tạm giữ · không resolve DNS</span>
                        </div>
                        <div class="legend-row" data-key="transferLock">
                            <span class="badge badge-warning">Khóa Transfer</span>
                            <span>Không chuyển registrar được</span>
                        </div>
                        <div class="legend-row" data-key="pendingTransfer">
                            <span class="badge badge-orange">Đang chuyển Registrar</span>
                            <span>Đang trong quá trình transfer</span>
                        </div>
                        <div class="legend-row" data-key="updateLock">
                            <span class="badge badge-muted">Khóa Update / Delete</span>
                            <span>Không sửa WHOIS / xóa được</span>
                        </div>
                        <div class="legend-row" data-key="redemption">
                            <span class="badge badge-danger">Redemption / Pending Delete</span>
                            <span>Sắp xóa hoặc đang chuộc</span>
                        </div>
                        <div class="legend-row" data-key="chuaDK">
                            <span class="badge badge-muted">Chưa đăng ký / Ẩn thông tin</span>
                            <span>Domain chưa đăng ký hoặc WHOIS bị ẩn</span>
                        </div>
                    </div>
                </div>
                <!-- Nhóm Cloudflare -->
                <div class="legend-group" id="legendCfGroup">
                    <div class="legend-group-title">Trạng thái Cloudflare</div>
                    <div class="legend-rows">
                        <div class="legend-row" data-key="cfSach">
                            <span class="badge badge-success">Sạch</span>
                            <span>Có thể add vào Cloudflare</span>
                        </div>
                        <div class="legend-row" data-key="cfBanned">
                            <span class="badge badge-danger">BANNED</span>
                            <span>Bị Cloudflare cấm thêm</span>
                        </div>
                        <div class="legend-row" data-key="cfChuaDK">
                            <span class="badge badge-info">Sạch (Chưa ĐK)</span>
                            <span>Chưa đăng ký · nên mua</span>
                        </div>
                        <div class="legend-row" data-key="cfTldCam">
                            <span class="badge badge-warning">Đuôi TLD bị CF cấm</span>
                            <span>TLD không được CF hỗ trợ</span>
                        </div>
                        <div class="legend-row" data-key="cfChanAdd">
                            <span class="badge badge-danger">Bị CF Chặn Add</span>
                            <span>Cloudflare từ chối thêm domain</span>
                        </div>
                        <div class="legend-row" data-key="cfOther">
                            <span class="badge badge-muted">Lỗi CF / Không rõ</span>
                            <span>Lỗi API hoặc trạng thái không xác định</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Table -->
        <div class="table-card">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr id="tableHeader"></tr>
                    </thead>
                    <tbody id="resultBody"></tbody>
                </table>
            </div>
        </div>
        <div class="footer">
            DEV by <span>Ares</span>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeSettings()">&times;</span>
            <h3>⚙ Cài đặt kiểm tra</h3>
            <div class="settings-item">
                <input type="checkbox" id="chk_cf">
                <label for="chk_cf">Trạng thái CF (Có thể Add CF)</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_registrar" checked>
                <label for="chk_registrar">Nhà đăng ký (Registrar)</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_hold" checked>
                <label for="chk_hold">Trạng thái Hold / Lock / Transfer</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_dates" checked>
                <label for="chk_dates">Ngày đăng ký / Hết hạn</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_ns" checked>
                <label for="chk_ns">Nameserver & Cloudflare NS</label>
            </div>
            <button class="btn-primary" style="margin-top: 22px; width: 100%; justify-content: center;" onclick="closeSettings()">Lưu cài đặt</button>
        </div>
    </div>

    <script>
        const modal = document.getElementById("settingsModal");
        function openSettings() { modal.classList.add("show"); }
        function closeSettings() { modal.classList.remove("show"); }
        window.onclick = function(e) { if (e.target === modal) closeSettings(); };

        let failedDomains = [];
        // Tập hợp các key legend đã xuất hiện trong lần check hiện tại
        let seenLegendKeys = new Set();

        function getOptions() {
            return {
                check_cf: document.getElementById('chk_cf').checked,
                check_registrar: document.getElementById('chk_registrar').checked,
                check_hold: document.getElementById('chk_hold').checked,
                check_dates: document.getElementById('chk_dates').checked,
                check_ns: document.getElementById('chk_ns').checked
            };
        }

        function buildHeader(options) {
            const tr = document.getElementById('tableHeader');
            let html = '<th>Domain</th>';
            if (options.check_cf) html += '<th>Trạng thái CF</th>';
            if (options.check_registrar) html += '<th>Nhà đăng ký</th>';
            if (options.check_hold) html += '<th>Trạng thái Domain</th>';
            if (options.check_dates) html += '<th>Ngày ĐK → Hết hạn</th>';
            if (options.check_ns) {
                html += '<th>CF NS</th>';
                html += '<th>Nameservers</th>';
            }
            tr.innerHTML = html;
        }

        function countVisibleCols(options) {
            let n = 1;
            if (options.check_cf) n++;
            if (options.check_registrar) n++;
            if (options.check_hold) n++;
            if (options.check_dates) n++;
            if (options.check_ns) n += 2;
            return n;
        }

        function isFailedResult(data, options) {
            if (!data) return true;
            if (options.check_registrar) {
                const reg = (data.registrar || "").toString().toLowerCase();
                if (reg.includes("không có dữ liệu") || reg.includes("không xác định") || reg.includes("lỗi") || reg === "") return true;
            }
            if (options.check_hold) {
                const st = (data.status || "").toString().toLowerCase();
                if (st.includes("lỗi") || st.includes("chưa đăng ký")) return true;
            }
            if (data.cf_add_status && data.cf_add_status.toString().toLowerCase().includes("lỗi")) return true;
            return false;
        }

        // Phân tích HTML status / cf để đánh dấu key legend tương ứng
        function collectLegendKeysFromResult(data, options) {
            if (options.check_hold && data.status) {
                const st = data.status;
                if (st.includes("Active / Không bị lock") || st.includes(">Active<")) {
                    seenLegendKeys.add("active");
                }
                if (st.includes("serverHold")) seenLegendKeys.add("serverHold");
                if (st.includes("clientHold")) seenLegendKeys.add("clientHold");
                if (st.includes("Khóa Transfer")) seenLegendKeys.add("transferLock");
                if (st.includes("Đang chuyển Registrar")) seenLegendKeys.add("pendingTransfer");
                if (st.includes("Khóa Update") || st.includes("Khóa Delete")) seenLegendKeys.add("updateLock");
                if (st.includes("Redemption") || st.includes("Pending Delete")) seenLegendKeys.add("redemption");
                if (st.includes("Chưa đăng ký") || st.includes("Ẩn thông tin")) seenLegendKeys.add("chuaDK");
            }
            if (options.check_cf && data.cf_add_status) {
                const cf = data.cf_add_status;
                if (cf.includes("Sạch") && !cf.includes("Chưa ĐK") && !cf.includes("Đã nằm")) {
                    seenLegendKeys.add("cfSach");
                }
                if (cf.includes("Sạch (Đã nằm trong CF khác)")) seenLegendKeys.add("cfSach");
                if (cf.includes("BANNED")) seenLegendKeys.add("cfBanned");
                if (cf.includes("Sạch (Chưa ĐK)")) seenLegendKeys.add("cfChuaDK");
                if (cf.includes("Đuôi TLD bị CF cấm")) seenLegendKeys.add("cfTldCam");
                if (cf.includes("Bị CF Chặn Add")) seenLegendKeys.add("cfChanAdd");
                if (cf.includes("Lỗi CF") || cf.includes("Không rõ") || cf.includes("Thiếu API")) {
                    seenLegendKeys.add("cfOther");
                }
            }
        }

        function updateLegendVisibility() {
            const legendBox = document.getElementById('legendBox');
            if (seenLegendKeys.size === 0) {
                legendBox.classList.remove("show");
                return;
            }
            legendBox.classList.add("show");

            // Ẩn tất cả row trước
            document.querySelectorAll(".legend-row").forEach(row => {
                row.classList.remove("show");
            });
            document.querySelectorAll(".legend-group").forEach(g => {
                g.classList.remove("show");
            });

            // Hiện những row có key
            let hasDomain = false;
            let hasCf = false;
            seenLegendKeys.forEach(key => {
                const row = document.querySelector(`.legend-row[data-key="${key}"]`);
                if (row) {
                    row.classList.add("show");
                    if (["active","serverHold","clientHold","transferLock","pendingTransfer","updateLock","redemption","chuaDK"].includes(key)) {
                        hasDomain = true;
                    } else {
                        hasCf = true;
                    }
                }
            });
            if (hasDomain) document.getElementById("legendDomainGroup").classList.add("show");
            if (hasCf) document.getElementById("legendCfGroup").classList.add("show");
        }

        async function sleep(ms) {
            return new Promise(r => setTimeout(r, ms));
        }

        async function startCheck(isRetry = false) {
            const btn = document.getElementById('btnCheck');
            const btnRetry = document.getElementById('btnRetry');
            const options = getOptions();
            const delay = Math.max(0, parseInt(document.getElementById('delayMs').value) || 500);
            let domains = [];

            if (isRetry) {
                domains = [...failedDomains];
                if (!domains.length) { alert("Không có domain lỗi để retry!"); return; }
            } else {
                const text = document.getElementById('domainList').value;
                // Tự động chỉ lấy domain, bỏ giá tiền / ký tự lạ / tab
                const domainRegex = /(?:https?:\\/\\/)?(?:www\\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/i;
                domains = text.replace(/\\r/g, "").split("\\n")
                    .map(line => {
                        const cleaned = line.trim().toLowerCase();
                        if (!cleaned) return null;
                        const firstToken = cleaned.split(/[\\s\\t,;|]+/)[0];
                        if (domainRegex.test(firstToken) && firstToken.includes(".")) {
                            const m = firstToken.match(domainRegex);
                            return m ? m[1] : null;
                        }
                        const m = cleaned.match(domainRegex);
                        return m ? m[1] : null;
                    })
                    .filter(d => d && d.includes(".") && d.length > 3);
                domains = [...new Set(domains)];
                if (!domains.length) { alert("Vui lòng nhập ít nhất 1 domain hợp lệ!"); return; }
                failedDomains = [];
                seenLegendKeys = new Set(); // reset legend keys khi check mới
            }

            buildHeader(options);
            const tbody = document.getElementById('resultBody');
            if (!isRetry) tbody.innerHTML = '';

            btn.disabled = true;
            btnRetry.disabled = true;

            let completed = 0;
            const total = domains.length;
            const colspan = countVisibleCols(options) - 1;

            for (const domain of domains) {
                document.getElementById('progressText').innerHTML =
                    `<span class="progress-dot"></span> Đang xử lý ${completed + 1}/${total} — <b style="color:#93c5fd">${domain}</b>`;

                let row = document.getElementById(`row-${domain}`);
                if (!row) {
                    row = document.createElement('tr');
                    row.id = `row-${domain}`;
                    tbody.appendChild(row);
                }
                row.innerHTML = `<td class="domain-cell">${domain}</td><td colspan="${colspan}" class="skipped">Đang quét dữ liệu…</td>`;

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain, options })
                    });
                    if (!response.ok) throw new Error("Server error");
                    const data = await response.json();

                    // Thu thập key legend từ kết quả này
                    collectLegendKeysFromResult(data, options);

                    // NS
                    let nsText = "";
                    if (data.ns === "Bỏ qua") {
                        nsText = '<span class="skipped">Bỏ qua</span>';
                    } else if (Array.isArray(data.ns) && data.ns.length) {
                        nsText = `<span class="ns-cell" title="${data.ns.join(', ')}">${data.ns.join(', ')}</span>`;
                    } else {
                        nsText = '<span class="error-cell">Không có NS</span>';
                    }

                    // CF Badge
                    let cfBadge = '<span class="skipped">Bỏ qua</span>';
                    if (data.is_cloudflare !== "Bỏ qua") {
                        cfBadge = data.is_cloudflare
                            ? '<span class="badge badge-cf-yes">Đang dùng</span>'
                            : '<span class="badge badge-cf-no">Không dùng</span>';
                    }

                    // Registrar
                    let registrarText = data.registrar || "";
                    if (["Không có dữ liệu", "Không xác định", "Bỏ qua"].includes(registrarText)) {
                        registrarText = `<span class="error-cell">${registrarText}</span>`;
                    }

                    // Dates
                    let datesText = "—";
                    if (data.created || data.expires) {
                        datesText = `<span class="date-cell">${data.created || "—"} → ${data.expires || "—"}</span>`;
                    } else if ((data.status || "").includes("Chưa đăng ký")) {
                        datesText = '<span class="skipped">Chưa ĐK</span>';
                    }

                    // Build row
                    let cells = `<td class="domain-cell">${domain}</td>`;
                    if (options.check_cf) cells += `<td>${data.cf_add_status || ""}</td>`;
                    if (options.check_registrar) cells += `<td>${registrarText}</td>`;
                    if (options.check_hold) cells += `<td class="status-cell">${data.status || ""}</td>`;
                    if (options.check_dates) cells += `<td>${datesText}</td>`;
                    if (options.check_ns) {
                        cells += `<td>${cfBadge}</td>`;
                        cells += `<td>${nsText}</td>`;
                    }
                    row.innerHTML = cells;

                    if (isFailedResult(data, options)) {
                        if (!failedDomains.includes(domain)) failedDomains.push(domain);
                    } else {
                        failedDomains = failedDomains.filter(d => d !== domain);
                    }
                } catch (e) {
                    row.innerHTML = `
                        <td class="domain-cell">${domain}</td>
                        <td colspan="${colspan}" class="error-cell">Lỗi network / quá tải — thử lại sau</td>`;
                    if (!failedDomains.includes(domain)) failedDomains.push(domain);
                }

                completed++;
                // Cập nhật legend sau mỗi domain để người dùng thấy dần
                updateLegendVisibility();
                if (completed < total && delay > 0) await sleep(delay);
            }

            document.getElementById('progressText').innerHTML =
                `✓ Hoàn thành ${completed}/${total} domain` +
                (failedDomains.length ? ` · <span style="color:#f87171">${failedDomains.length} lỗi</span>` : '');
            btn.disabled = false;
            btnRetry.disabled = failedDomains.length === 0;
            updateLegendVisibility(); // lần cuối
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
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        options = data.get('options', {})
        if not domain:
            return jsonify({"status": "Lỗi", "ns": [], "registrar": "", "is_cloudflare": False}), 400

        ns_list = "Bỏ qua"
        status = "Bỏ qua"
        registrar = "Bỏ qua"
        created = None
        expires = None
        cf_add_status = "Bỏ qua"
        is_cloudflare = "Bỏ qua"

        need_whois = (
            options.get('check_registrar', True)
            or options.get('check_hold', True)
            or options.get('check_dates', True)
        )

        if options.get('check_ns', True):
            ns_list = get_nameservers(domain)
            is_cloudflare = False
            if ns_list:
                is_cloudflare = any('cloudflare.com' in ns.lower() for ns in ns_list)

        if need_whois:
            status, registrar, created, expires = get_domain_info(domain)
            if not options.get('check_registrar', True):
                registrar = "Bỏ qua"
            if not options.get('check_hold', True):
                status = "Bỏ qua"
            if not options.get('check_dates', True):
                created = None
                expires = None

        if options.get('check_cf', False):
            cf_add_status = check_cf_eligibility(domain)

        return jsonify({
            "domain": domain,
            "cf_add_status": cf_add_status,
            "registrar": registrar,
            "status": status,
            "created": created,
            "expires": expires,
            "ns": ns_list,
            "is_cloudflare": is_cloudflare
        })
    except Exception:
        return jsonify({
            "domain": domain if 'domain' in locals() else "Unknown",
            "cf_add_status": "Lỗi Backend",
            "registrar": "Lỗi",
            "status": "Lỗi",
            "created": None,
            "expires": None,
            "ns": [],
            "is_cloudflare": False
        })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
