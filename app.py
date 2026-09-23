import os
from flask import Flask, render_template_string, request, jsonify
import requests
import whois

app = Flask(__name__)

# ==========================================
# CẤU HÌNH CLOUDFLARE API (Cần điền)
# ==========================================
# Bạn có thể điền cứng ở đây, hoặc thiết lập trong Environment của Render
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

        # Trường hợp 1: Domain add thành công (Đã có người đăng ký & không bị cấm)
        if r.status_code == 200 and resp.get("success"):
            # Xóa ngay lập tức để không làm rác tài khoản CF của bạn
            zone_id = resp["result"]["id"]
            requests.delete(f"{url}/{zone_id}", headers=headers)
            return "<span style='color:#28a745; font-weight:bold;'>Sạch (Add Thành Công)</span>"

        # Trường hợp 2: Bị vướng lỗi (Cấm, chưa mua, v.v...)
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
    except Exception as e:
        return "<span style='color:red;'>Lỗi Call API CF</span>"

def get_nameservers(domain):
    ns_list = []
    try:
        url = f"https://dns.google/resolve?name={domain}&type=NS"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if 'Answer' in data:
                ns_list = [ans['data'].rstrip('.') for ans in data['Answer'] if ans['type'] == 2]
                return ns_list
    except: pass

    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS"
        headers = {'accept': 'application/dns-json'}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if 'Answer' in data:
                ns_list = [ans['data'].rstrip('.') for ans in data['Answer'] if ans['type'] == 2]
                return ns_list
    except: pass
    return ns_list

def get_domain_info(domain):
    status_found = set()
    registrar = None
    is_registered = False

    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            is_registered = True
            data = r.json()
            statuses = data.get('status', [])
            for s in statuses:
                s_lower = s.lower()
                if 'server hold' in s_lower or 'serverhold' in s_lower or 'server update prohibited' in s_lower:
                    status_found.add('serverHold')
                if 'client hold' in s_lower or 'clienthold' in s_lower:
                    status_found.add('clientHold')
            entities = data.get('entities', [])
            for ent in entities:
                if 'registrar' in ent.get('roles', []):
                    vcard = ent.get('vcardArray', [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == 'fn':
                                registrar = prop[3]
                                break
    except: pass

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
                        s_lower = s.lower()
                        if 'serverhold' in s_lower or 'server hold' in s_lower:
                            status_found.add('serverHold')
                        if 'clienthold' in s_lower or 'client hold' in s_lower:
                            status_found.add('clientHold')
                if w.registrar and not registrar:
                    registrar = w.registrar
        except: pass

    if not is_registered:
        return "Chưa đăng ký / Ẩn thông tin", "Không có dữ liệu"

    final_status = " | ".join(list(status_found)) if status_found else "Active / OK"
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
    <title>Quản Lý Domain - dev by Ares</title>
    <link rel="icon" type="image/x-icon" href="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRRtG00dWfkGqx_XWIYqY09Yp_bIx0Oaj9y-9CDJET5Tg&s=10">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; padding: 20px; color: #333; }
        .container { max-width: 1400px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        textarea { width: 100%; height: 150px; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 10px; font-family: monospace; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; font-size: 16px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #cccccc; cursor: not-allowed; }
        .progress { margin-top: 10px; font-size: 14px; color: #555; }
        .table-wrapper { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; min-width: 1100px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: middle; white-space: nowrap; }
        th { background-color: #f8f9fa; }
        .hold { color: #dc3545; font-weight: bold; }
        .ok { color: #28a745; font-weight: bold; }
        .badge-cf-yes { background: #f6821f; color: white; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; display: inline-block; }
        .badge-cf-no { background: #6c757d; color: white; padding: 4px 10px; border-radius: 12px; font-size: 12px; display: inline-block; }
        .footer { text-align: center; margin-top: 30px; font-weight: bold; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Công cụ săn & kiểm tra Domain (Hold, Banned CF, NS)</h2>
        <p>Kiểm tra xem tên miền có bị Cloudflare ban trước khi mua hay không. Hỗ trợ check NS, Hold status.</p>
        <textarea id="domainList" placeholder="Nhập domain vào đây...&#10;google.com&#10;dantri.com.vn"></textarea>
        <button id="btnCheck" onclick="startCheck()">Bắt đầu kiểm tra</button>
        <div class="progress" id="progressText"></div>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th width="15%">Domain</th>
                        <th width="15%">Kiểm tra Add CF (Mua)</th>
                        <th width="20%">Nhà đăng ký (Registrar)</th>
                        <th width="15%">Trạng thái Hold</th>
                        <th width="10%">Cloudflare NS</th>
                        <th width="25%">Nameservers Hiện tại</th>
                    </tr>
                </thead>
                <tbody id="resultBody">
                </tbody>
            </table>
        </div>
        <div class="footer">dev by Ares</div>
    </div>

    <script>
        async function startCheck() {
            const btn = document.getElementById('btnCheck');
            const text = document.getElementById('domainList').value;
            const domains = text.split('\\n').map(d => d.trim().toLowerCase()).filter(d => d);
            
            if (domains.length === 0) {
                alert("Vui lòng nhập ít nhất 1 domain!");
                return;
            }

            const tbody = document.getElementById('resultBody');
            tbody.innerHTML = '';
            btn.disabled = true;

            let completed = 0;

            for (let domain of domains) {
                document.getElementById('progressText').innerText = `Đang xử lý: ${completed}/${domains.length} ...`;
                const row = document.createElement('tr');
                row.id = `row-${domain}`;
                row.innerHTML = `<td><b>${domain}</b></td><td colspan="5" style="color:gray;">Đang xử lý ngầm...</td>`;
                tbody.appendChild(row);

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({domain: domain})
                    });
                    
                    if (!response.ok) throw new Error("Lỗi Server");
                    
                    const data = await response.json();
                    
                    let statusClass = data.status.includes('Hold') ? 'hold' : 'ok';
                    if(data.status.includes('Chưa đăng ký')) statusClass = 'hold';

                    let nsText = data.ns.length > 0 ? 
                        data.ns.join(', ') : 
                        '<span style="color:red; font-weight:bold;">Không có NS</span>';

                    let cfBadge = data.is_cloudflare ? 
                        '<span class="badge-cf-yes">Đang dùng</span>' : 
                        '<span class="badge-cf-no">Không dùng</span>';

                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        <td>${data.cf_add_status}</td>
                        <td style="${data.registrar === 'Không có dữ liệu' ? 'color:red' : ''}">${data.registrar}</td>
                        <td class="${statusClass}">${data.status}</td>
                        <td>${cfBadge}</td>
                        <td>${nsText}</td>
                    `;
                } catch (e) {
                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        <td colspan="5" style="color:red;">Lỗi quá tải, thử lại sau</td>
                    `;
                }
                completed++;
            }
            document.getElementById('progressText').innerText = `Hoàn thành ${completed}/${domains.length} domain!`;
            btn.disabled = false;
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
        
        if not domain:
            return jsonify({"status": "Lỗi", "ns": [], "registrar": "", "is_cloudflare": False}), 400

        # Kiểm tra song song các thông tin
        ns_list = get_nameservers(domain)
        status, registrar = get_domain_info(domain)
        cf_add_status = check_cf_eligibility(domain)
        
        is_cloudflare = False
        if ns_list:
            is_cloudflare = any('cloudflare.com' in ns.lower() for ns in ns_list)
        
        return jsonify({
            "domain": domain,
            "cf_add_status": cf_add_status,
            "registrar": registrar,
            "status": status,
            "ns": ns_list,
            "is_cloudflare": is_cloudflare
        })
    except Exception as e:
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
