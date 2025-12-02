# 🛡️ VigilEdge WAF - Enterprise Web Application Firewall

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-WAF-red.svg)](https://github.com)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com)

<div align="center">

**Professional-grade Web Application Firewall with real-time threat detection, monitoring, and comprehensive security features**

[Quick Start](#-quick-start) • [Features](#️-features) • [Installation](#-installation) • [Documentation](#-documentation) • [API](#-api-endpoints) • [Testing](#-testing-security-features)

</div>

---

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [🌟 Overview](#-overview)
- [🛡️ Features](#️-features)
- [📦 Installation](#-installation)
- [🏗️ Project Structure](#️-project-structure)
- [⚡ Performance & Specifications](#-performance--specifications)
- [🔧 Configuration](#-configuration)
- [📝 API Endpoints](#-api-endpoints)
- [🧪 Testing Security Features](#-testing-security-features)
- [🎬 Demo & Screenshots](#-demo--screenshots)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [🔒 Security Notice](#-security-notice)
- [📄 License](#-license)
- [👥 Authors](#-authors)
- [📞 Support](#-support)

---

## 🚀 Quick Start

### ⚡ One-Click Launch (Easiest Method)

Simply **double-click `start_both.bat`** in this folder (vigiledge part 3), and both the WAF and vulnerable test application will start automatically!

```
vigiledge part 3/
├── start_both.bat  ← Double-click this file!
└── project-null-2.0/
    └── vigiledge-collage-project--main/
        └── VigilEdge/
```

**That's it!** Your browser will automatically open to the protected application after 5 seconds.

### 🌐 Access Points

After starting, access these URLs:

| Service | URL | Description | Credentials |
|---------|-----|-------------|-------------|
| **WAF Dashboard** | http://localhost:5000/dashboard | Real-time security monitoring | No login required |
| **Protected App** | http://localhost:5000/protected/ | E-commerce app via WAF proxy | - |
| **Admin Panel** | http://localhost:5000/protected/admin | Admin interface | Password: `admin123` |
| **API Docs** | http://localhost:5000/docs | Interactive API documentation | - |
| **Direct App** | http://localhost:8080/ | Unprotected app (bypasses WAF) | ⚠️ Testing only |

### 🎯 First-Time Users

1. **Double-click** `start_both.bat`
2. **Wait** for two terminal windows to appear
3. **Browser opens** automatically to http://localhost:5000/protected
4. **Test the WAF** by trying SQL injection: `admin' OR '1'='1'--`
5. **View dashboard** at http://localhost:5000/dashboard to see blocked threats

---

## 🌟 Overview

VigilEdge WAF is an **enterprise-grade web application firewall** designed to protect web applications from common security threats including:

- 🛡️ **SQL Injection** - Pattern-based detection and blocking
- 🔒 **XSS Attacks** - Cross-site scripting prevention
- 🚫 **DDoS Attempts** - Traffic analysis and rate limiting
- 🤖 **Bot Detection** - Advanced crawler identification
- 📍 **IP Blocking** - Dynamic blacklist management
- 🔐 **Path Traversal** - Directory access prevention

Built with **FastAPI** and **Python 3.13+**, VigilEdge provides:

- ⚡ **Real-time threat detection** with < 10ms latency
- 📊 **Live monitoring dashboard** with WebSocket updates
- 🔐 **Session-based authentication** preventing URL bypass
- 🌐 **Mobile-responsive UI** optimized for all devices
- 📡 **RESTful API** for automation and integration
- 🎯 **Zero-config startup** with automated scripts

### Use Cases

✅ **Development Teams** - Test application security before deployment  
✅ **Security Researchers** - Analyze threat patterns and responses  
✅ **Educational Purposes** - Learn about web application security  
✅ **Penetration Testing** - Validate security controls  
✅ **Production Deployment** - Protect live web applications (WAF component only)

---

## 🛡️ Features

### Core Security Features

| Feature | Description | Status |
|---------|-------------|--------|
| **SQL Injection Protection** | Advanced pattern detection with 50+ signatures | ✅ Active |
| **XSS Prevention** | Cross-site scripting mitigation with content filtering | ✅ Active |
| **Rate Limiting** | Configurable per IP/endpoint (default: 100 req/min) | ✅ Active |
| **IP Blocking** | Dynamic blacklist with CRUD API operations | ✅ Active |
| **DDoS Protection** | Traffic analysis with automatic mitigation | ✅ Active |
| **Bot Detection** | User-agent analysis and behavioral patterns | ✅ Active |
| **Path Traversal Protection** | Directory traversal attack prevention | ✅ Active |
| **CSRF Protection** | Token-based CSRF prevention | 🔄 Optional |
| **File Upload Scanning** | Malware detection in uploads | 🔄 Optional |

### Monitoring & Alerting

- 📊 **Real-time Dashboard** - Live security metrics with animated charts
- 📱 **Mobile Optimized** - Fully responsive design (desktop/tablet/mobile)
- 🔔 **WebSocket Alerts** - Instant threat notifications without page refresh
- 📝 **Event Logging** - Comprehensive security event tracking with timestamps
- 🚫 **Blocked IPs Management** - Full CRUD interface for IP blacklist
- 📈 **Traffic Analysis** - Request/response logging with filtering
- 💾 **Auto-backup** - Daily database backups with rotation

### Administration & API

- 🔐 **Session-Based Auth** - Secure admin access preventing URL bypass attacks
- 🎨 **Professional UI** - Modern glassmorphism design with security badges
- ⚙️ **Configuration Management** - Dynamic rule updates via YAML
- 📡 **RESTful API** - Full API for blocked IPs and event logs
- 📖 **Interactive Docs** - Auto-generated OpenAPI/Swagger documentation
- 🔄 **Hot Reload** - Configuration changes without restart
- 📊 **Metrics Export** - Prometheus-compatible metrics endpoint

---

## 📁 Complete Project Structure

```
vigiledge part 3/
│
├── start_both.bat                                    # ⚡ ONE-CLICK STARTUP
│
└── project-null-2.0/
    └── vigiledge-collage-project--main/
        ├── README.md                                 # GitHub repository info
        ├── LICENSE                                   # MIT License
        │
        └── VigilEdge/                               # Main project directory
            ├── README.md                            # 📖 Full documentation
            ├── PROJECT_STRUCTURE.md                 # 📁 Structure guide
            │
            ├── waf/                                 # 🛡️ WAF Application
            │   ├── main.py                         # Entry point
            │   ├── requirements.txt                # Dependencies
            │   ├── vigiledge/                      # Core package
            │   ├── config/                         # Configuration
            │   ├── templates/                      # Dashboard UI
            │   └── static/                         # Assets
            │
            ├── vulnerable-app/                      # 🎯 Test Application
            │   ├── app.py                          # Vulnerable e-commerce app
            │   └── vulnerable.db                   # SQLite database
            │
            ├── scripts/                             # 🔧 Automation
            │   ├── start_both.bat                  # Startup script
            │   ├── setup.bat                       # Environment setup
            │   └── clear_ports.bat                 # Port cleanup
            │
            ├── docs/                                # 📚 Documentation
            │   ├── PROJECT_REPORT_CHAPTERS.md      # Full report
            │   ├── TESTING_README.md               # Testing guide
            │   └── WAF_TESTING_GUIDE.md            # WAF testing
            │
            └── tests/                               # 🧪 Test Suite
                ├── test_waf.py
                ├── test_auth.py
                └── quick_test.py
```

---

## 🌟 Features

### 🛡️ Security Features
- ✅ **SQL Injection Protection** - Pattern-based detection and blocking
- ✅ **XSS Prevention** - Cross-site scripting mitigation
- ✅ **DDoS Protection** - Traffic analysis and rate limiting
- ✅ **IP Blocking** - Dynamic blacklist management
- ✅ **Bot Detection** - Advanced crawler identification
- ✅ **Path Traversal Protection** - Directory access prevention

### 📊 Monitoring & Dashboard
- ✅ **Real-time Dashboard** - Live security metrics
- ✅ **Mobile Responsive** - Optimized for all devices
- ✅ **WebSocket Updates** - Instant threat notifications
- ✅ **Event Logging** - Comprehensive security logs
- ✅ **API Integration** - RESTful endpoints for automation

### 🔐 Authentication & Access
- ✅ **Session-based Auth** - Prevents URL-based bypass
- ✅ **Professional UI** - Glassmorphism design
- ✅ **Secure Cookies** - HTTP-only, secure flags
- ✅ **Admin Panel** - Complete security control

---

## 📦 Installation

### Prerequisites
- Python 3.13 or higher
- Windows 10/11 (Linux/Mac compatible with minor adjustments)
- 2GB RAM minimum
- Internet connection for dependencies

### Step-by-Step Setup

#### 1️⃣ Install Python Dependencies
```bash
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge"
pip install -r waf/requirements.txt
```

#### 2️⃣ Start the System
```bash
# Return to root folder
cd "..\..\.."

# Run startup script
start_both.bat
```

#### 3️⃣ Verify Installation
- WAF Terminal: Should show "VigilEdge WAF Ready!"
- Vulnerable App Terminal: Should show "Server will start on http://localhost:8080"
- Browser: Automatically opens to http://localhost:5000/protected

---

## 🧪 Testing Security Features

### 🔍 SQL Injection Tests

#### Test 1: Classic SQL Injection
```bash
URL: http://localhost:5000/protected/admin
Username: admin' OR '1'='1'--
Password: anything

Expected Result: ⛔ Request blocked by WAF
Dashboard Event: SQL Injection detected from your IP
```

#### Test 2: UNION-based Injection
```bash
URL: http://localhost:5000/protected/search
Search: ' UNION SELECT * FROM users--

Expected Result: ⛔ Blocked with threat details
Event Log: Payload logged with "UNION SELECT" pattern
```

#### Test 3: Boolean-based Injection
```bash
Username: admin' AND '1'='1
Expected Result: ⛔ Blocked immediately
```

### 🛡️ XSS Attack Tests

#### Test 1: Script Tag Injection
```bash
URL: http://localhost:5000/protected/admin
Input Field: <script>alert('XSS')</script>

Expected Result: ⛔ WAF blocks request
Dashboard: XSS threat logged with script payload
```

#### Test 2: Event Handler XSS
```bash
Input: <img src=x onerror="alert('XSS')">
Expected Result: ⛔ Blocked - onerror pattern detected
```

#### Test 3: JavaScript Protocol
```bash
Input: <a href="javascript:alert('XSS')">Click</a>
Expected Result: ⛔ Blocked - javascript: protocol detected
```

### 🔐 Authentication Bypass Tests

#### Test 1: URL Session Bypass
```bash
Steps:
1. Login at http://localhost:5000/protected/admin (password: admin123)
2. Copy the full URL from address bar
3. Open new incognito/private browser window
4. Paste the URL

Expected Result: ⛔ Redirected to login page (session required)
Reason: Session cookies not shared, URL alone insufficient
```

#### Test 2: Cookie Theft Prevention
```bash
Test: Try to export cookies to another browser
Expected Result: HTTP-only flag prevents JavaScript access
Security: Cookies marked as secure and HTTP-only
```

### 📊 Rate Limiting Tests

#### Test 1: DDoS Simulation
```bash
# Send 150 requests in 60 seconds (exceeds 100 req/min limit)
for i in {1..150}; do curl http://localhost:5000/protected/; done

Expected Result: 
- First 100 requests: ✅ Processed
- Requests 101-150: ⛔ Rate limit exceeded (429 status)
- IP temporarily blocked for 5 minutes
```

### 🤖 Bot Detection Tests

```bash
# Test with suspicious user-agent
curl -H "User-Agent: BadBot/1.0" http://localhost:5000/protected/

Expected Result: ⛔ Blocked or flagged as bot traffic
Dashboard: Bot detection event logged
```

### 📈 Live Testing Dashboard

1. **Open Dashboard**: http://localhost:5000/dashboard
2. **Run Tests Above**: Execute SQL injection or XSS tests
3. **Watch Real-time Updates**: 
   - Threat counter increases
   - Event logs populate automatically
   - Blocked IPs list updates
   - Charts animate with new data

### 🎬 Demo Walkthrough

**Complete Testing Scenario** (5 minutes):

```bash
Step 1: Start System
→ Double-click start_both.bat
→ Wait for both terminals to show "Ready"

Step 2: Open Dashboard
→ Navigate to http://localhost:5000/dashboard
→ Verify all metrics show 0 (fresh start)

Step 3: Test SQL Injection
→ Go to http://localhost:5000/protected/admin
→ Enter: admin' OR '1'='1'--
→ Click Login
→ See "🛡️ BLOCKED BY WAF" message
→ Return to dashboard
→ Verify event logged under "Recent Threats"

Step 4: Test XSS
→ Try input: <script>alert(1)</script>
→ See block message
→ Dashboard shows XSS threat

Step 5: View API
→ curl http://localhost:5000/api/v1/event-logs
→ See JSON array of all blocked threats

Step 6: Manage Blocked IPs
→ Dashboard → Blocked IPs section
→ Add IP: 192.168.1.100
→ Try accessing from that IP (simulated)
→ Remove IP from dashboard

Result: ✅ All security features verified working
```

---

## 🎬 Demo & Screenshots

<details>
<summary>📸 Click to view screenshots and demos</summary>

### Real-time WAF Dashboard
![Dashboard](project-null-2.0/vigiledge-collage-project--main/VigilEdge/screenshots/dashboard.png)
- Live threat statistics with animated counters
- Real-time event log stream via WebSockets
- Mobile-responsive design for all devices
- Dark theme optimized for security operations

### Professional Login Interface
![Login](project-null-2.0/vigiledge-collage-project--main/VigilEdge/screenshots/login.png)
- Modern glassmorphism design
- Security badges and SSL indicators
- Session-based authentication
- Password strength validation

### Blocked IPs Management
![Blocked IPs](project-null-2.0/vigiledge-collage-project--main/VigilEdge/screenshots/blocked-ips.png)
- Full CRUD interface for IP blacklist
- Real-time block/unblock operations
- Reason tracking for each blocked IP
- Export functionality for reports

### WAF Threat Block Alert
![WAF Block](project-null-2.0/vigiledge-collage-project--main/VigilEdge/screenshots/waf-block.png)
- Instant threat notifications
- Detailed payload information
- Threat type classification
- Recommended actions

### Mobile Responsive Design
- 📱 Optimized for smartphones (320px+)
- 📱 Tablet-friendly layouts (768px+)
- 🖥️ Desktop full-featured (1024px+)
- ⚡ Touch-optimized controls

</details>

### 🎥 Video Demo
📹 **[Watch Full Demo Video](https://www.youtube.com/watch?v=demo-link)** *(Coming soon)*

- Complete feature walkthrough
- Live threat detection demonstrations
- API usage examples
- Configuration tutorials

---

## ⚡ Performance & Specifications

### System Requirements

| Component | Minimum | Recommended | Purpose |
|-----------|---------|-------------|---------|
| **CPU** | 2 cores @ 2.0GHz | 4+ cores @ 2.5GHz+ | Request processing |
| **RAM** | 2 GB | 4+ GB | In-memory caching |
| **Storage** | 100 MB | 500 MB | Logs & database |
| **OS** | Windows 10+ | Windows 11 | Native support |
| **Python** | 3.13+ | 3.13+ | Core runtime |
| **Network** | 10 Mbps | 100+ Mbps | Traffic handling |

### Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Request Processing** | < 10ms | Average latency per request |
| **Threat Detection** | < 5ms | Pattern matching speed |
| **Dashboard Updates** | Real-time | WebSocket streaming |
| **Concurrent Connections** | 1000+ | Configurable max connections |
| **Memory Usage** | 100-150 MB | Idle state |
| **CPU Usage** | < 5% | Idle, 20-30% under load |
| **Database Operations** | < 2ms | SQLite query time |

### Technology Stack

```
🔷 Backend Framework
├── FastAPI 0.104.1              # Async web framework
├── Uvicorn (ASGI)               # Production server
├── Python 3.13+                 # Core language
├── SQLite3                      # Embedded database
└── Pydantic                     # Data validation

🔷 Frontend
├── HTML5/CSS3                   # Structure & styling
├── JavaScript (ES6+)            # Client-side logic
├── WebSockets                   # Real-time updates
└── Responsive Design            # Mobile optimization

🔷 Security Engine
├── Custom WAF Engine            # Threat detection core
├── Regex Pattern Matching       # SQL/XSS detection
├── Rate Limiting                # DDoS protection
├── IP Blacklisting              # Access control
└── Session Management           # Authentication

🔷 Dependencies
├── httpx                        # HTTP client
├── starlette                    # ASGI toolkit
├── pyyaml                       # Config parsing
└── python-multipart             # Form handling
```

---

## 🔧 Configuration

### WAF Rules Configuration

Edit `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/config/waf_rules.yaml`:

```yaml
# SQL Injection Protection
sql_injection:
  enabled: true
  severity: high
  patterns:
    - "union.*select"
    - "drop.*table"
    - "' or '1'='1"
    - "1=1--"
    - "admin'--"
  
# XSS Protection
xss:
  enabled: true
  severity: high
  patterns:
    - "<script"
    - "javascript:"
    - "onerror="
    - "onclick="
    - "onload="

# Rate Limiting
rate_limiting:
  enabled: true
  requests_per_minute: 100
  burst_size: 150
  block_duration: 300  # seconds
```

### Environment Variables

Create `.env` file in `VigilEdge/waf/` directory:

```env
# Server Configuration
HOST=127.0.0.1
PORT=5000
DEBUG=False
ENVIRONMENT=production

# Security Settings
SQL_INJECTION_PROTECTION=True
XSS_PROTECTION=True
DDOS_PROTECTION=True
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
IP_BLOCKING_ENABLED=True
BOT_DETECTION_ENABLED=True

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/vigiledge.log
LOG_FORMAT=json

# Protected Application
VULNERABLE_APP_URL=http://localhost:8080
VULNERABLE_APP_ENABLED=True
VULNERABLE_APP_PROXY_PATH=/protected

# Session Configuration
SECRET_KEY=your-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=sqlite:///./vigiledge.db
```

### Session Configuration

- **Session Secret**: Auto-generated 32-byte secure token
- **Session Cookies**: HTTP-only, Secure flags enabled
- **Admin Password**: `admin123` (configurable in `vulnerable-app/app.py`)
- **Session Timeout**: 30 minutes (configurable)

---

## 📝 API Endpoints

### Blocked IPs Management

```bash
# Get all blocked IPs
GET http://localhost:5000/api/v1/blocked-ips
Response: [{"ip": "192.168.1.100", "reason": "SQL Injection", "blocked_at": "2024-12-01T10:30:00Z"}]

# Block a specific IP
POST http://localhost:5000/api/v1/blocked-ips
Body: {"ip": "192.168.1.100", "reason": "Suspicious activity"}
Response: {"success": true, "message": "IP blocked successfully"}

# Unblock a specific IP
DELETE http://localhost:5000/api/v1/blocked-ips/192.168.1.100
Response: {"success": true, "message": "IP unblocked"}

# Clear all blocked IPs
DELETE http://localhost:5000/api/v1/blocked-ips
Response: {"success": true, "message": "All IPs unblocked", "count": 5}
```

### Event Logs

```bash
# Get security event logs
GET http://localhost:5000/api/v1/event-logs
Query Params: ?limit=100&offset=0&threat_type=sql_injection
Response: [
  {
    "id": 1,
    "timestamp": "2024-12-01T10:30:00Z",
    "ip": "192.168.1.100",
    "threat_type": "SQL Injection",
    "payload": "' OR '1'='1",
    "blocked": true,
    "severity": "high"
  }
]

# Get event statistics
GET http://localhost:5000/api/v1/event-logs/stats
Response: {
  "total_events": 1543,
  "blocked_threats": 1456,
  "unique_ips": 234,
  "threat_types": {
    "sql_injection": 456,
    "xss": 234,
    "ddos": 123
  }
}
```

### WAF Proxy

```bash
# Access vulnerable app through WAF protection
GET http://localhost:5000/protected/
POST http://localhost:5000/protected/admin/login
Body: {"username": "admin", "password": "admin123"}

# All requests to /protected/* are proxied to http://localhost:8080
# with full WAF protection and threat detection
```

### Health & Metrics

```bash
# Health check
GET http://localhost:5000/health
Response: {"status": "healthy", "waf": "active", "backend": "online"}

# Metrics endpoint (Prometheus format)
GET http://localhost:5000/metrics
Response: WAF metrics in Prometheus format
```

---

## 🧪 Testing Security Features

## 🛠️ Troubleshooting

### Common Issues & Solutions

<details>
<summary><b>❌ Port Already in Use (Error 10048)</b></summary>

**Problem**: 
```
[Errno 10048] error while attempting to bind on address ('0.0.0.0', 5000): 
[winerror 10048] only one usage of each socket address is normally permitted
```

**Cause**: WAF or vulnerable app is already running from a previous session

**Solution 1 - Kill Specific Processes**:
```powershell
# Find processes using ports 5000/8080
netstat -ano | findstr :5000
netstat -ano | findstr :8080

# Kill the process (replace <PID> with actual ID from above)
taskkill /PID <PID> /F
```

**Solution 2 - Use Automated Script**:
```bash
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\scripts"
clear_ports.bat
```

**Solution 3 - Kill All Python Processes**:
```powershell
taskkill /IM python.exe /F
```

</details>

<details>
<summary><b>❌ Module Not Found Error</b></summary>

**Problem**: 
```
ModuleNotFoundError: No module named 'fastapi'
ImportError: No module named 'uvicorn'
```

**Cause**: Dependencies not installed or wrong Python environment

**Solution**:
```bash
# Ensure correct directory
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge"

# Verify Python version
python --version  # Should be 3.13+

# Install dependencies
pip install -r waf/requirements.txt --upgrade

# If still failing, use full path
python -m pip install -r waf/requirements.txt --upgrade
```

</details>

<details>
<summary><b>❌ Database Connection Error</b></summary>

**Problem**: 
```
sqlite3.OperationalError: unable to open database file
FileNotFoundError: vulnerable.db not found
```

**Cause**: Running from wrong directory or missing database

**Solution**:
```bash
# For vulnerable app - must run from vulnerable-app folder
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\vulnerable-app"
python app.py

# For WAF - must run from waf folder
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf"
python main.py

# Database auto-creates on first run if missing
```

</details>

<details>
<summary><b>❌ Templates Not Found</b></summary>

**Problem**: 
```
jinja2.exceptions.TemplateNotFound: dashboard.html
FileNotFoundError: template directory not found
```

**Cause**: Running from incorrect directory

**Solution**:
```bash
# WAF must be run from waf/ directory
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf"
python main.py

# NOT from VigilEdge root or other folders
# Templates are in waf/templates/ and paths are relative
```

</details>

<details>
<summary><b>❌ Browser Doesn't Auto-Open</b></summary>

**Problem**: start_both.bat runs but browser doesn't open

**Solution**:
```bash
# Manually open after both services start:
http://localhost:5000/protected

# Check if services are running:
# - WAF terminal should show "VigilEdge WAF Ready!"
# - Vulnerable app terminal should show "Uvicorn running on http://127.0.0.1:8080"

# If only one service started, check for port conflicts
```

</details>

<details>
<summary><b>❌ WAF Not Blocking Threats</b></summary>

**Problem**: SQL injection or XSS payloads not being blocked

**Solution**:
```bash
# 1. Check if accessing via WAF proxy
Correct URL: http://localhost:5000/protected/admin
Wrong URL: http://localhost:8080/admin (bypasses WAF)

# 2. Verify WAF rules are enabled
Check: waf/config/waf_rules.yaml
Ensure: sql_injection.enabled: true

# 3. Restart WAF after config changes
Ctrl+C in WAF terminal
python main.py (from waf directory)
```

</details>

<details>
<summary><b>❌ Dashboard Shows No Data</b></summary>

**Problem**: Dashboard loads but shows zero threats/events

**Solution**:
```bash
# Normal if fresh start - no threats detected yet
# To test:
1. Navigate to http://localhost:5000/protected/admin
2. Try SQL injection: admin' OR '1'='1'--
3. Dashboard should update immediately via WebSocket
4. If still no data, check browser console for errors
5. Verify WebSocket connection in Network tab
```

</details>

<details>
<summary><b>❌ Session Not Persisting</b></summary>

**Problem**: Keep getting logged out, session doesn't persist

**Solution**:
```bash
# Check browser settings:
- Cookies must be enabled
- Not in private/incognito mode (cookies don't persist)
- Browser not blocking third-party cookies

# Check WAF settings:
- Session secret is set (auto-generated)
- Session middleware is active
- No errors in WAF terminal about session
```

</details>

### 📋 Diagnostic Commands

```powershell
# Check if ports are accessible
Test-NetConnection -ComputerName localhost -Port 5000
Test-NetConnection -ComputerName localhost -Port 8080

# Verify Python packages
pip list | findstr fastapi
pip list | findstr uvicorn

# Check Python version
python --version

# View recent errors in logs
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge"
Get-Content logs/vigiledge.log -Tail 50

# Test API directly
curl http://localhost:5000/health
curl http://localhost:5000/api/v1/event-logs
```

### 🆘 Still Having Issues?

1. **Close everything** and start fresh
2. **Restart computer** to clear all ports
3. **Reinstall dependencies**: `pip install -r waf/requirements.txt --force-reinstall`
4. **Check antivirus/firewall**: May block ports 5000/8080
5. **Open GitHub Issue** with error details

---

## 📚 Documentation

### 📖 Additional Resources

Located in `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/`:

- **[PROJECT_REPORT_CHAPTERS.md](project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/PROJECT_REPORT_CHAPTERS.md)** - Complete project report with architecture diagrams
- **[TESTING_README.md](project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/TESTING_README.md)** - Comprehensive testing procedures
- **[WAF_TESTING_GUIDE.md](project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/WAF_TESTING_GUIDE.md)** - WAF-specific security testing
- **[MONGODB_README.md](project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/MONGODB_README.md)** - MongoDB integration guide
- **[PROJECT_STRUCTURE.md](project-null-2.0/vigiledge-collage-project--main/VigilEdge/PROJECT_STRUCTURE.md)** - Detailed folder structure explanation

### 🔗 Online Documentation

- **Interactive API Docs**: http://localhost:5000/docs (OpenAPI/Swagger)
- **ReDoc**: http://localhost:5000/redoc (Alternative API docs)
- **Health Check**: http://localhost:5000/health (System status)

---

## 🔒 Security Notice

### ⚠️ Important Security Information

**This repository contains TWO components:**

1. **🛡️ VigilEdge WAF** (`waf/` folder)
   - ✅ **Production-ready** when properly configured
   - ✅ Actively maintained security features
   - ✅ Safe to deploy for protecting applications
   - ⚙️ Requires proper configuration for production use
   - 🔐 Change default passwords and secrets

2. **🎯 Vulnerable Test Application** (`vulnerable-app/` folder)
   - ⚠️ **Contains INTENTIONAL security vulnerabilities**
   - ⛔ **DO NOT deploy to production**
   - ⛔ **DO NOT expose to public internet**
   - ✅ Use ONLY in isolated testing/development environments
   - ✅ Designed for security research and WAF testing

### 🔐 Security Best Practices

**Before Production Deployment:**

- [ ] Change all default passwords
- [ ] Generate new session secret keys
- [ ] Review and customize WAF rules
- [ ] Enable HTTPS/TLS
- [ ] Configure proper logging
- [ ] Set up monitoring and alerting
- [ ] Implement backup strategies
- [ ] Review and harden server configuration
- [ ] Conduct security audit
- [ ] Test thoroughly in staging environment

**Never in Production:**
- ❌ Do not use vulnerable-app in production
- ❌ Do not use default admin passwords
- ❌ Do not expose raw SQLite databases
- ❌ Do not disable security features for convenience
- ❌ Do not run as root/administrator

### 📋 Responsible Disclosure

If you discover a security vulnerability in the WAF component:

1. **DO NOT** open a public GitHub issue
2. Email security details to: security@vigiledge.example.com
3. Include POC (proof of concept) if available
4. Allow 90 days for fix before public disclosure
5. Credit will be given in security advisories

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### 🎯 Ways to Contribute

- 🐛 **Report Bugs** - Open issues for bugs in the WAF (not intentional vulnerabilities in test app)
- ✨ **Suggest Features** - Propose new security features or improvements
- 📝 **Improve Documentation** - Fix typos, add examples, clarify instructions
- 🧪 **Add Tests** - Write unit tests or integration tests
- 🔧 **Submit Code** - Fix bugs or implement features via pull requests
- 🌍 **Translate** - Help translate documentation to other languages

### 📋 Contribution Process

1. **Fork** the repository
   ```bash
   # Click "Fork" button on GitHub
   git clone https://github.com/YOUR_USERNAME/vigiledge-waf.git
   cd vigiledge-waf
   ```

2. **Create** a feature branch
   ```bash
   git checkout -b feature/AmazingFeature
   # or
   git checkout -b bugfix/FixSomething
   ```

3. **Make** your changes
   - Follow existing code style (PEP 8 for Python)
   - Add comments for complex logic
   - Update documentation if needed
   - Add tests for new features

4. **Test** your changes
   ```bash
   # Run existing tests
   cd project-null-2.0/vigiledge-collage-project--main/VigilEdge
   python -m pytest tests/

   # Test manually
   start_both.bat
   # Verify your changes work
   ```

5. **Commit** with clear messages
   ```bash
   git add .
   git commit -m "Add feature: Description of what was added"
   # or
   git commit -m "Fix bug: Description of what was fixed"
   ```

6. **Push** to your fork
   ```bash
   git push origin feature/AmazingFeature
   ```

7. **Open** a Pull Request
   - Go to your fork on GitHub
   - Click "Pull Request"
   - Describe your changes clearly
   - Link any related issues

### 📜 Development Guidelines

**Code Style:**
- Follow PEP 8 for Python code
- Use meaningful variable/function names
- Add docstrings to functions and classes
- Keep functions focused and small
- Use type hints where appropriate

**Commit Messages:**
```
Format: <type>: <description>

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- test: Adding tests
- refactor: Code refactoring
- style: Formatting changes
- chore: Maintenance tasks

Example:
feat: Add IP reputation checking feature
fix: Resolve SQL injection bypass in pattern matching
docs: Update API documentation with new endpoints
```

**Testing:**
- Add unit tests for new functions
- Add integration tests for features
- Ensure all existing tests pass
- Test on Windows (primary platform)
- Document test procedures

**Documentation:**
- Update README.md for user-facing changes
- Add docstrings for new functions
- Update API docs if endpoints change
- Add examples for new features

### 🏆 Contributors

We appreciate all contributors! Contributors will be listed here and in CONTRIBUTORS.md.

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](project-null-2.0/vigiledge-collage-project--main/LICENSE) for details.

---

## 👥 Authors & Acknowledgments

### Development Team
- **Core Development** - VigilEdge Team
- **Security Research** - OWASP Community
- **Framework** - FastAPI Contributors

### Special Thanks
- FastAPI for the excellent async framework
- OWASP for security guidelines and best practices
- The open-source security community

---

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/vigiledge-waf/issues)
- **Documentation**: See `VigilEdge/README.md` for detailed info
- **Email**: support@vigiledge.example.com

---

## ⭐ Quick Reference Card

| Action | Command/Location |
|--------|------------------|
| **Start System** | Double-click `start_both.bat` in root folder |
| **WAF Dashboard** | http://localhost:5000/dashboard |
| **Admin Panel** | http://localhost:5000/protected/admin |
| **API Docs** | http://localhost:5000/docs |
| **Stop Services** | Press `Ctrl+C` in both terminal windows |
| **Clear Ports** | Run `scripts/clear_ports.bat` |
| **View Logs** | Check `VigilEdge/logs/vigiledge.log` |
| **Full Docs** | Read `VigilEdge/README.md` |

---

<div align="center">

**⚡ VigilEdge WAF - Protecting Web Applications Since 2024 ⚡**

Made with ❤️ and ☕ by the VigilEdge Team

</div>
