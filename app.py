import os
from flask import Flask, render_template_string, request, jsonify
import requests
import whois

app = Flask(__name__)

# ==========================================
# CẤU HÌNH CLOUDFLARE API (Cần điền)
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")

# ==========================================
# 1. CÁC HÀM KIỂM TRA & XỬ LÝ DỮ LIỆU
# ==========================================
def check_cf_eligibility(domain):
    """Giả lập add domain vào CF để check xem có bị Banned không"""
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        return "<span style='color:gray'>Thiếu API CF</span>"
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
            requests.delete(f"{url}/{zone_id}", headers=headers)
            return "<span style='color:#28a745; font-weight:bold;'>Sạch (Add Thành Công)</span>"
        errors = resp.get("errors", [])
        if errors:
            err_code = errors[0].get("code")
            if err_code == 1049:
                return "<span style='color:#007bff; font-weight:bold;'>Sạch (Chưa Đăng Ký) - Mua Tốt</span>"
            elif err_code == 1097:
                return "<span style='color:red; font-weight:bold;'>BỊ BANNED BỞI CF (Không mua)</span>"
            elif err_code == 1095:
                return "<span style='color:red; font-weight:bold;'>Bị CF Chặn Add</span>"
            elif err_code == 1116:
                return "<span style='color:orange; font-weight:bold;'>Đuôi TLD bị CF cấm</span>"
            elif err_code == 1061:
                return "<span style='color:#28a745; font-weight:bold;'>Sạch (Đã nằm trong CF khác)</span>"
            else:
                return f"<span style='color:gray;'>Lỗi CF: {err_code}</span>"
        return "<span style='color:gray;'>Không rõ trạng thái</span>"
    except Exception:
        return "<span style='color:red;'>Lỗi Call API CF</span>"


def get_nameservers(domain):
    ns_list = []
    try:
        url = f"https://dns.google/resolve?name={domain}&type=NS"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if "Answer" in data:
                ns_list = [ans["data"].rstrip(".") for ans in data["Answer"] if ans["type"] == 2]
                if ns_list:
                    return ns_list
    except Exception:
        pass
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS"
        headers = {"accept": "application/dns-json"}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if "Answer" in data:
                ns_list = [ans["data"].rstrip(".") for ans in data["Answer"] if ans["type"] == 2]
                return ns_list
    except Exception:
        pass
    return ns_list


def _parse_rdap_json(data):
    """Parse RDAP JSON → status set + registrar"""
    status_found = set()
    registrar = None
    statuses = data.get("status", [])
    for s in statuses:
        s_lower = str(s).lower()
        if "server hold" in s_lower or "serverhold" in s_lower or "server update prohibited" in s_lower:
            status_found.add("serverHold")
        if "client hold" in s_lower or "clienthold" in s_lower:
            status_found.add("clientHold")
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
                # Một số RDAP trả tên trong publicIds hoặc handle
                registrar = ent.get("handle") or ent.get("name")
    return status_found, registrar


def get_domain_info(domain):
    """
    Lấy status Hold + Registrar.
    Thứ tự ưu tiên:
      1. RDAP qua rdap.org
      2. who-dat.as93.net (free no-key)
      3. rdap.cloud
      4. python-whois (fallback cuối)
    """
    status_found = set()
    registrar = None
    is_registered = False

    # ---------- 1. rdap.org ----------
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=12)
        if r.status_code == 200:
            is_registered = True
            data = r.json()
            st, reg = _parse_rdap_json(data)
            status_found.update(st)
            if reg:
                registrar = reg
    except Exception:
        pass

    # ---------- 2. who-dat.as93.net ----------
    if not registrar or not status_found:
        try:
            r = requests.get(f"https://who-dat.as93.net/{domain}", timeout=12)
            if r.status_code == 200:
                data = r.json()
                is_registered = True
                # who-dat có thể trả dạng normalized hoặc raw
                if "registrar" in data and data["registrar"]:
                    registrar = data["registrar"] if isinstance(data["registrar"], str) else data["registrar"].get("name") or data["registrar"].get("organization")
                # status
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    s_lower = str(s).lower()
                    if "serverhold" in s_lower or "server hold" in s_lower:
                        status_found.add("serverHold")
                    if "clienthold" in s_lower or "client hold" in s_lower:
                        status_found.add("clientHold")
                # nếu có raw RDAP
                if "rdap" in data and isinstance(data["rdap"], dict):
                    st, reg = _parse_rdap_json(data["rdap"])
                    status_found.update(st)
                    if reg and not registrar:
                        registrar = reg
        except Exception:
            pass

    # ---------- 3. rdap.cloud ----------
    if not registrar or not status_found:
        try:
            r = requests.get(f"https://rdap.cloud/api/v1/{domain}", timeout=12)
            if r.status_code == 200:
                data = r.json()
                is_registered = True
                # cấu trúc có thể khác nhau, cố gắng parse linh hoạt
                if "registrar" in data:
                    reg_val = data["registrar"]
                    if isinstance(reg_val, str):
                        registrar = reg_val
                    elif isinstance(reg_val, dict):
                        registrar = reg_val.get("name") or reg_val.get("organization")
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    s_lower = str(s).lower()
                    if "serverhold" in s_lower or "server hold" in s_lower:
                        status_found.add("serverHold")
                    if "clienthold" in s_lower or "client hold" in s_lower:
                        status_found.add("clientHold")
                # thử parse như RDAP chuẩn
                st, reg = _parse_rdap_json(data)
                status_found.update(st)
                if reg and not registrar:
                    registrar = reg
        except Exception:
            pass

    # ---------- 4. python-whois (fallback cuối) ----------
    if not is_registered or not registrar or not status_found:
        try:
            w = whois.whois(domain)
            if w.domain_name:
                is_registered = True
                raw_status = w.status
                if isinstance(raw_status, str):
                    raw_status = [raw_status]
                if raw_status:
                    for s in raw_status:
                        s_lower = str(s).lower()
                        if "serverhold" in s_lower or "server hold" in s_lower:
                            status_found.add("serverHold")
                        if "clienthold" in s_lower or "client hold" in s_lower:
                            status_found.add("clientHold")
                if w.registrar and not registrar:
                    registrar = w.registrar
        except Exception:
            pass

    if not is_registered:
        return "Chưa đăng ký / Ẩn thông tin", "Không có dữ liệu"

    final_status = " | ".join(sorted(status_found)) if status_found else "Không bị hold"
    final_registrar = registrar if registrar else "Không xác định"
    return final_status, final_registrar


# ==========================================
# 2. GIAO DIỆN WEB & API ROUTER
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Checker - Ares</title>
    <link rel="icon" type="image/png" href="https://cdn-icons-png.magnific.com/256/15435/15435750.png?semt=ais_white_label">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; padding: 20px; color: #333; transition: 0.3s; }
        .container { max-width: 1400px; margin: auto; background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 8px 16px rgba(0,0,0,0.08); }
        textarea { width: 100%; height: 150px; padding: 12px; box-sizing: border-box; border: 1px solid #ced4da; border-radius: 6px; margin-bottom: 15px; font-family: monospace; transition: border-color 0.2s; }
        textarea:focus { border-color: #007bff; outline: none; box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25); }

        .action-bar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; align-items: center; }
        button { border: none; padding: 10px 20px; font-size: 15px; border-radius: 6px; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; }
        .btn-primary { background: #007bff; color: white; box-shadow: 0 4px 6px rgba(0, 123, 255, 0.2); }
        .btn-primary:hover:not(:disabled) { background: #0056b3; transform: translateY(-1px); box-shadow: 0 6px 8px rgba(0, 123, 255, 0.3); }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; transform: translateY(-1px); }
        .btn-warning { background: #fd7e14; color: white; }
        .btn-warning:hover:not(:disabled) { background: #e8590c; transform: translateY(-1px); }
        button:disabled { background: #cccccc; cursor: not-allowed; transform: none; box-shadow: none; }

        .delay-box { display: flex; align-items: center; gap: 6px; margin-left: 8px; }
        .delay-box label { font-size: 14px; color: #555; white-space: nowrap; }
        .delay-box input { width: 90px; padding: 8px 10px; border: 1px solid #ced4da; border-radius: 6px; font-size: 14px; }

        .progress { margin-top: 10px; font-size: 14px; color: #555; font-weight: 500; }

        .table-wrapper { overflow-x: auto; margin-top: 20px; border-radius: 8px; box-shadow: 0 0 0 1px #dee2e6; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; min-width: 900px; background: #fff; }
        th, td { border-bottom: 1px solid #dee2e6; padding: 12px 15px; text-align: left; vertical-align: middle; white-space: nowrap; }
        th { background-color: #f8f9fa; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; }

        tbody tr { transition: background-color 0.2s ease; }
        tbody tr:hover { background-color: #f1f8ff; }

        .hold { color: #dc3545; font-weight: bold; }
        .ok { color: #28a745; font-weight: bold; }
        .badge-cf-yes { background: #f6821f; color: white; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; display: inline-block; box-shadow: 0 2px 4px rgba(246, 130, 31, 0.3); }
        .badge-cf-no { background: #6c757d; color: white; padding: 5px 12px; border-radius: 20px; font-size: 12px; display: inline-block; }
        .skipped { color: #adb5bd; font-style: italic; }
        .error-cell { color: #dc3545; }

        /* Modal */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); backdrop-filter: blur(4px); opacity: 0; transition: opacity 0.3s ease; }
        .modal.show { display: flex; align-items: center; justify-content: center; opacity: 1; }
        .modal-content { background-color: #fff; padding: 25px; border-radius: 12px; width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); transform: translateY(-20px); transition: transform 0.3s ease; }
        .modal.show .modal-content { transform: translateY(0); }
        .close-btn { color: #aaa; float: right; font-size: 24px; font-weight: bold; cursor: pointer; line-height: 1; margin-top: -5px; transition: color 0.2s; }
        .close-btn:hover { color: #333; }
        .settings-item { margin: 12px 0; display: flex; align-items: center; cursor: pointer; }
        .settings-item input { margin-right: 10px; width: 16px; height: 16px; cursor: pointer; }
        .settings-item label { cursor: pointer; font-size: 15px; user-select: none; }

        .footer { text-align: center; margin-top: 40px; font-weight: 800; font-size: 18px; letter-spacing: 1px; }
        .gradient-text {
            background: linear-gradient(270deg, #ff007f, #007bff, #00d2ff, #ff007f);
            background-size: 400% 400%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientShift 4s ease infinite;
        }
        @keyframes gradientShift {
            0% { background-position: 0% 50% }
            50% { background-position: 100% 50% }
            100% { background-position: 0% 50% }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Domain Checker - Ares</h2>
        <p style="color: #6c757d; margin-bottom: 20px;">Hỗ trợ kiểm tra hàng loạt trạng thái Hold, Nhà đăng ký, và danh sách đen của Cloudflare.</p>

        <textarea id="domainList" placeholder="Nhập domain vào đây (mỗi domain 1 dòng)...&#10;google.com&#10;dantri.com.vn"></textarea>

        <div class="action-bar">
            <button id="btnCheck" class="btn-primary" onclick="startCheck(false)">🚀 Bắt đầu kiểm tra</button>
            <button id="btnRetry" class="btn-warning" onclick="startCheck(true)" disabled>🔄 Retry domain lỗi</button>
            <button class="btn-secondary" onclick="openSettings()">⚙️ Cài đặt check</button>

            <div class="delay-box">
                <label for="delayMs">Delay (ms):</label>
                <input type="number" id="delayMs" value="1000" min="0" step="100" title="Thời gian chờ giữa mỗi domain (milliseconds)">
            </div>
        </div>

        <div class="progress" id="progressText">Sẵn sàng.</div>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr id="tableHeader">
                        <!-- Header được build động bằng JS -->
                    </tr>
                </thead>
                <tbody id="resultBody">
                </tbody>
            </table>
        </div>

        <div class="footer"><span class="gradient-text">DEV by Ares</span></div>
    </div>

    <!-- Modal Cài Đặt -->
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeSettings()">&times;</span>
            <h3 style="margin-top: 0; color: #333;">⚙️ Cài đặt kiểm tra</h3>

            <div class="settings-item">
                <input type="checkbox" id="chk_cf">
                <label for="chk_cf">Kiểm tra Trạng thái CF (Có thể Add CF)</label>
            </div>

            <div class="settings-item">
                <input type="checkbox" id="chk_whois" checked>
                <label for="chk_whois">Kiểm tra Nhà đăng ký & Trạng thái Hold</label>
            </div>

            <div class="settings-item">
                <input type="checkbox" id="chk_ns" checked>
                <label for="chk_ns">Kiểm tra Nameserver & Cloudflare NS</label>
            </div>

            <button class="btn-primary" style="margin-top: 20px; width: 100%;" onclick="closeSettings()">Lưu cài đặt</button>
        </div>
    </div>

    <script>
        const modal = document.getElementById("settingsModal");
        function openSettings() { modal.classList.add("show"); }
        function closeSettings() { modal.classList.remove("show"); }
        window.onclick = function(event) {
            if (event.target == modal) closeSettings();
        }

        // Lưu danh sách domain lỗi để Retry
        let failedDomains = [];

        function getOptions() {
            return {
                check_cf: document.getElementById('chk_cf').checked,
                check_whois: document.getElementById('chk_whois').checked,
                check_ns: document.getElementById('chk_ns').checked
            };
        }

        function buildHeader(options) {
            const tr = document.getElementById('tableHeader');
            let html = '<th width="15%">Domain</th>';
            if (options.check_cf) {
                html += '<th width="15%">Trạng thái CF</th>';
            }
            html += `
                <th width="20%">Nhà đăng ký (Registrar)</th>
                <th width="15%">Trạng thái Hold</th>
                <th width="10%">Cloudflare NS</th>
                <th width="25%">Nameservers Hiện tại</th>
            `;
            tr.innerHTML = html;
        }

        function isFailedResult(data) {
            // Coi là lỗi nếu:
            // - registrar là "Không có dữ liệu" / "Không xác định" / "Lỗi" / rỗng
            // - status chứa "Lỗi" hoặc "Chưa đăng ký / Ẩn thông tin" (có thể retry)
            // - có lỗi backend
            if (!data) return true;
            const reg = (data.registrar || "").toString().toLowerCase();
            const st = (data.status || "").toString().toLowerCase();
            if (reg.includes("không có dữ liệu") || reg.includes("không xác định") || reg.includes("lỗi") || reg === "") return true;
            if (st.includes("lỗi") || st.includes("chưa đăng ký")) return true;
            if (data.cf_add_status && data.cf_add_status.toString().toLowerCase().includes("lỗi")) return true;
            return false;
        }

        async function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        async function startCheck(isRetry = false) {
            const btn = document.getElementById('btnCheck');
            const btnRetry = document.getElementById('btnRetry');
            const options = getOptions();
            const delay = Math.max(0, parseInt(document.getElementById('delayMs').value) || 1000);

            let domains = [];
            if (isRetry) {
                domains = [...failedDomains];
                if (domains.length === 0) {
                    alert("Không có domain lỗi để retry!");
                    return;
                }
            } else {
                const text = document.getElementById('domainList').value;
                domains = text.split('\\n').map(d => d.trim().toLowerCase()).filter(d => d);
                if (domains.length === 0) {
                    alert("Vui lòng nhập ít nhất 1 domain!");
                    return;
                }
                failedDomains = []; // reset khi check mới
            }

            // Build header theo options (ẩn cột CF nếu không tick)
            buildHeader(options);

            const tbody = document.getElementById('resultBody');
            if (!isRetry) {
                tbody.innerHTML = '';
            }

            btn.disabled = true;
            btnRetry.disabled = true;

            let completed = 0;
            const total = domains.length;

            for (let domain of domains) {
                document.getElementById('progressText').innerText = `⏳ Đang xử lý: ${completed + 1}/${total} — ${domain}`;

                // Nếu là retry → tìm row cũ hoặc tạo mới
                let row = document.getElementById(`row-${domain}`);
                if (!row) {
                    row = document.createElement('tr');
                    row.id = `row-${domain}`;
                    tbody.appendChild(row);
                }
                row.innerHTML = `<td><b>${domain}</b></td><td colspan="5" style="color:#6c757d; font-style:italic;">Đang quét dữ liệu...</td>`;

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({domain: domain, options: options})
                    });

                    if (!response.ok) throw new Error("Lỗi Server");
                    const data = await response.json();

                    // Render Status Hold
                    let statusClass = "ok";
                    if (data.status.includes('Hold') || data.status.includes('Chưa đăng ký')) statusClass = 'hold';

                    // Render NS
                    let nsText = "";
                    if (data.ns === "Bỏ qua") {
                        nsText = '<span class="skipped">Bỏ qua</span>';
                    } else if (Array.isArray(data.ns) && data.ns.length > 0) {
                        nsText = data.ns.join(', ');
                    } else {
                        nsText = '<span style="color:red; font-weight:bold;">Không có NS</span>';
                    }

                    // Render Cloudflare Badge
                    let cfBadge = '<span class="skipped">Bỏ qua</span>';
                    if (data.is_cloudflare !== "Bỏ qua") {
                        cfBadge = data.is_cloudflare
                            ? '<span class="badge-cf-yes">Đang dùng</span>'
                            : '<span class="badge-cf-no">Không dùng</span>';
                    }

                    // Registrar
                    let registrarText = data.registrar;
                    if (registrarText === "Không có dữ liệu" || registrarText === "Không xác định") {
                        registrarText = `<span class="error-cell">${registrarText}</span>`;
                    }

                    // CF status cell (chỉ khi tick)
                    let cfCell = "";
                    if (options.check_cf) {
                        let cfAddStatus = data.cf_add_status || "";
                        cfCell = `<td>${cfAddStatus}</td>`;
                    }

                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        ${cfCell}
                        <td>${registrarText}</td>
                        <td class="${statusClass}">${data.status}</td>
                        <td>${cfBadge}</td>
                        <td>${nsText}</td>
                    `;

                    // Theo dõi domain lỗi
                    if (isFailedResult(data)) {
                        if (!failedDomains.includes(domain)) {
                            failedDomains.push(domain);
                        }
                    } else {
                        // Nếu retry thành công → bỏ khỏi danh sách lỗi
                        failedDomains = failedDomains.filter(d => d !== domain);
                    }

                } catch (e) {
                    let colspan = options.check_cf ? 5 : 4;
                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        <td colspan="${colspan}" style="color:red;">Lỗi quá tải / network, thử lại sau</td>
                    `;
                    if (!failedDomains.includes(domain)) {
                        failedDomains.push(domain);
                    }
                }

                completed++;
                // Delay giữa các domain (trừ domain cuối)
                if (completed < total && delay > 0) {
                    await sleep(delay);
                }
            }

            document.getElementById('progressText').innerText = `✅ Hoàn thành ${completed}/${total} domain! (Lỗi còn lại: ${failedDomains.length})`;
            btn.disabled = false;
            btnRetry.disabled = failedDomains.length === 0;
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
        cf_add_status = "Bỏ qua"
        is_cloudflare = "Bỏ qua"

        # 1. Nameserver
        if options.get('check_ns', True):
            ns_list = get_nameservers(domain)
            is_cloudflare = False
            if ns_list:
                is_cloudflare = any('cloudflare.com' in ns.lower() for ns in ns_list)

        # 2. WHOIS / Hold + Registrar (có nhiều backup)
        if options.get('check_whois', True):
            status, registrar = get_domain_info(domain)

        # 3. CF eligibility
        if options.get('check_cf', False):
            cf_add_status = check_cf_eligibility(domain)

        return jsonify({
            "domain": domain,
            "cf_add_status": cf_add_status,
            "registrar": registrar,
            "status": status,
            "ns": ns_list,
            "is_cloudflare": is_cloudflare
        })
    except Exception:
        return jsonify({
            "domain": domain if 'domain' in locals() else "Unknown",
            "cf_add_status": "Lỗi Backend",
            "registrar": "Lỗi",
            "status": "Lỗi",
            "ns": [],
            "is_cloudflare": False
        })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
