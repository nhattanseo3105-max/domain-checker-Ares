import os
from flask import Flask, render_template_string, request, jsonify
import requests
import whois

app = Flask(__name__)

# ==========================================
# 1. CÁC HÀM KIỂM TRA & XỬ LÝ DỮ LIỆU
# ==========================================

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
    except:
        pass

    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS"
        headers = {'accept': 'application/dns-json'}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if 'Answer' in data:
                ns_list = [ans['data'].rstrip('.') for ans in data['Answer'] if ans['type'] == 2]
                return ns_list
    except:
        pass

    return ns_list

def get_domain_info(domain):
    status_found = set()
    registrar = None
    is_registered = False

    # 1. Thử dùng RDAP API
    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=15) # Tăng timeout
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
    except:
        pass

    # 2. Nếu RDAP không được, dùng python-whois
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
        except:
            pass

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
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        textarea { width: 100%; height: 150px; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 10px; font-family: monospace; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; font-size: 16px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #cccccc; cursor: not-allowed; }
        .progress { margin-top: 10px; font-size: 14px; color: #555; }
        .table-wrapper { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; min-width: 900px; }
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
        <h2>Công cụ kiểm tra Hàng loạt Domain</h2>
        <p>Kiểm tra NS, Registrar, Cloudflare, trạng thái Hold. Không giới hạn số lượng.</p>
        <textarea id="domainList" placeholder="Nhập domain vào đây...&#10;google.com&#10;dantri.com.vn"></textarea>
        <button id="btnCheck" onclick="startCheck()">Bắt đầu kiểm tra</button>
        <div class="progress" id="progressText"></div>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th width="15%">Domain</th>
                        <th width="20%">Nhà đăng ký (Registrar)</th>
                        <th width="15%">Trạng thái</th>
                        <th width="15%">Cloudflare</th>
                        <th width="35%">Nameservers (NS)</th>
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
                row.innerHTML = `<td><b>${domain}</b></td><td colspan="4" style="color:gray;">Đang kiểm tra...</td>`;
                tbody.appendChild(row);

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({domain: domain})
                    });
                    
                    // Bắt lỗi HTTP status (500, 502, 504...)
                    if (!response.ok) {
                        throw new Error(`Server báo lỗi ${response.status}`);
                    }
                    
                    const data = await response.json();
                    
                    let statusClass = data.status.includes('Hold') ? 'hold' : 'ok';
                    if(data.status.includes('Chưa đăng ký')) statusClass = 'hold';

                    let nsText = data.ns.length > 0 ? 
                        data.ns.join(', ') : 
                        '<span style="color:red; font-weight:bold;">Không có Nameserver</span>';

                    let cfBadge = data.is_cloudflare ? 
                        '<span class="badge-cf-yes">Đang dùng</span>' : 
                        '<span class="badge-cf-no">Không dùng</span>';

                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        <td style="${data.registrar === 'Không có dữ liệu' || data.registrar === 'Lỗi Timeout Server' ? 'color:red' : ''}">${data.registrar}</td>
                        <td class="${statusClass}">${data.status}</td>
                        <td>${cfBadge}</td>
                        <td>${nsText}</td>
                    `;
                } catch (e) {
                    row.innerHTML = `
                        <td><b>${domain}</b></td>
                        <td style="color:red;">Lỗi Timeout / Proxy</td>
                        <td class="hold">Không tra cứu được</td>
                        <td><span class="badge-cf-no">Không rõ</span></td>
                        <td><span style="color:red;">Thử lại sau</span></td>
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
    # Bao bọc bằng Try...Except để luôn trả về JSON dù hệ thống bị quá tải
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({"status": "Lỗi", "ns": [], "registrar": "", "is_cloudflare": False}), 400

        ns_list = get_nameservers(domain)
        status, registrar = get_domain_info(domain)
        
        is_cloudflare = False
        if ns_list:
            is_cloudflare = any('cloudflare.com' in ns.lower() for ns in ns_list)
        
        return jsonify({
            "domain": domain,
            "registrar": registrar,
            "status": status,
            "ns": ns_list,
            "is_cloudflare": is_cloudflare
        })
    except Exception as e:
        # Nếu backend có văng lỗi, báo về UI dạng chuẩn JSON thay vì màn hình 500 HTML
        return jsonify({
            "domain": domain if 'domain' in locals() else "Unknown",
            "registrar": "Lỗi Backend Server",
            "status": "Lỗi hệ thống",
            "ns": [],
            "is_cloudflare": False
        })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
