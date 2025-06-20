# CyberSentry Pro+

🔍 **CyberSentry Pro+** is an advanced web vulnerability scanner built for ethical hackers and penetration testers. It performs deep analysis on websites to discover security misconfigurations and vulnerabilities.

---

## 🚀 Features

- ✅ 30+ vulnerability checks (XSS, SQLi, LFI, SSRF, IDOR, etc.)
- 🛡️ Security headers inspection
- 🌐 DNS & subdomain enumeration
- 📦 Compression and server fingerprinting
- 🔍 API & WebSocket endpoint detection
- 📑 Sensitive file & directory exposure detection
- 📊 JSON and HTML report generation
- 🧵 Multi-threaded scanning for better performance
- 🧠 Technology & CMS detection (WordPress, Laravel, etc.)

---

## ⚙️ Requirements

Install Python 3.7+ and the required packages.

### `requirements.txt`

| Package           | Purpose                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `requests`        | Sending HTTP/HTTPS requests                                             |
| `beautifulsoup4`  | HTML parsing for crawling and form extraction                           |
| `colorama`        | Terminal color formatting                                               |
| `dnspython`       | DNS queries (A, MX, TXT, CNAME, etc.)                                   |
| `pyjwt`           | JWT decoding and vulnerability checks                                   |
| `brotli`          | Brotli decompression for HTTP response compression                      |
| `zlib` (builtin)  | GZIP/Deflate decompression (standard Python library)                   |

### Install requirements:

```bash
pip install -r requirements.txt
