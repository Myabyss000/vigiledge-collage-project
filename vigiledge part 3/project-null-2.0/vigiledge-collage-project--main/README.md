# VigilEdge WAF - Advanced Web Application Firewall

A professional-grade Web Application Firewall (WAF) with built-in threat detection, real-time alerting, and comprehensive security monitoring capabilities.

## 🛡️ Features

### Core Security Features
- **SQL Injection Protection**: Advanced pattern detection and blocking
- **XSS Prevention**: Cross-site scripting attack mitigation
- **Rate Limiting**: Configurable request rate limiting per IP/endpoint
- **IP Blocking**: Dynamic IP blacklisting with geo-location support
- **DDoS Protection**: Traffic analysis and automatic mitigation
- **Bot Detection**: Advanced bot and crawler identification

### Monitoring & Alerting
- **Real-time Dashboard**: Live security monitoring interface
- **WebSocket Alerts**: Instant threat notifications
- **Threat Intelligence**: IP reputation and geolocation data
- **Traffic Analysis**: Comprehensive request/response logging
- **Security Reports**: Automated security summaries

### Administration
- **JWT Authentication**: Secure admin access
- **Role-based Access**: Granular permission system
- **Configuration Management**: Dynamic rule updates
- **API Integration**: RESTful API for external integrations

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Redis (for caching and rate limiting)
- PostgreSQL (optional, uses SQLite by default)

### Installation

1. **Clone and Setup**
```bash
cd VigilEdge
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

2. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Database Setup**
```bash
alembic upgrade head
```

4. **Run the WAF**
```bash
python main.py
```

The WAF will start on `http://localhost:5000`

## 📊 Dashboard Access

- **Admin Dashboard**: http://localhost:5000/admin
- **API Documentation**: http://localhost:5000/docs
- **Health Check**: http://localhost:5000/health

Default admin credentials:
- Username: `admin`
- Password: `VigilEdge2025!`

## 🔧 Configuration

### Environment Variables
```env
# Application
APP_NAME=VigilEdge WAF
APP_VERSION=1.0.0
DEBUG=false
HOST=127.0.0.1
PORT=5000

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256

# Database
DATABASE_URL=sqlite:///./vigiledge.db
# DATABASE_URL=postgresql://user:pass@localhost/vigiledge

# Redis
REDIS_URL=redis://localhost:6379/0

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# GeoIP
GEOIP_DB_PATH=./data/GeoLite2-City.mmdb
```

### WAF Rules Configuration
```yaml
# config/waf_rules.yaml
sql_injection:
  enabled: true
  patterns:
    - "union.*select"
    - "drop.*table"
    - "exec.*sp_"
  
xss:
  enabled: true
  patterns:
    - "<script"
    - "javascript:"
    - "on(load|click|mouse)"

rate_limiting:
  default: 100  # requests per minute
  admin: 200
  api: 500
```

## 🏗️ Architecture

```
VigilEdge WAF
├── Core Engine (FastAPI + AsyncIO)
├── Security Modules
│   ├── SQL Injection Detection
│   ├── XSS Protection
│   ├── Rate Limiting
│   ├── IP Filtering
│   └── Bot Detection
├── Monitoring System
│   ├── Real-time Alerts
│   ├── Traffic Analysis
│   ├── Threat Intelligence
│   └── Reporting Engine
├── Storage Layer
│   ├── SQLite/PostgreSQL
│   ├── Redis Cache
│   └── Log Files
└── Admin Interface
    ├── Dashboard
    ├── Configuration
    └── Reports
```

## 📝 API Usage

### Protect Your Application
```python
import httpx

# Proxy requests through VigilEdge WAF
async def protected_request(url, method="GET", **kwargs):
    waf_url = f"http://localhost:5000/proxy?target={url}"
    async with httpx.AsyncClient() as client:
        response = await client.request(method, waf_url, **kwargs)
        return response
```

### Manual IP Blocking
```python
import httpx

async def block_ip(ip_address, reason="Manual block"):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:5000/api/v1/security/block-ip",
            json={"ip": ip_address, "reason": reason},
            headers={"Authorization": "Bearer YOUR_TOKEN"}
        )
        return response.json()
```

## 🔍 Monitoring

### Real-time Metrics
- Active connections
- Threat detection rate
- Blocked requests
- Response times
- Geographic distribution

### Alert Types
- **Critical**: SQL injection attempts, XSS attacks
- **High**: Rate limit exceeded, suspicious IPs
- **Medium**: Bot detection, unusual traffic patterns
- **Low**: Information gathering, port scans

## 🛠️ Development

### Running Tests
```bash
pytest tests/ -v --cov=vigiledge
```

### Code Quality
```bash
black vigiledge/
flake8 vigiledge/
mypy vigiledge/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the FAQ section

## 🔗 Related Projects

- [OWASP ModSecurity](https://github.com/SpiderLabs/ModSecurity)
- [Cloudflare WAF](https://developers.cloudflare.com/waf/)
- [AWS WAF](https://aws.amazon.com/waf/)

---

**⚡ VigilEdge - Advanced Web Application Firewall ⚡**
