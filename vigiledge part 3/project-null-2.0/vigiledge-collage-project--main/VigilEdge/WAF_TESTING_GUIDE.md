# VigilEdge WAF Testing Guide

## 🎯 Testing Environment Setup

This guide explains how to test your VigilEdge WAF using the vulnerable target application.

### Architecture Overview
```
[Attacker] → [VigilEdge WAF:5000] → [Vulnerable App:8080]
```

Your VigilEdge WAF acts as a reverse proxy, protecting the vulnerable application from attacks.

## 🚀 Quick Start

### 1. Start Both Applications
```bash
# Option 1: Use the batch script
run_testing_env.bat

# Option 2: Manual startup
# Terminal 1 - Start vulnerable target
python vulnerable_app.py

# Terminal 2 - Start WAF
python main.py
```

### 2. Access Points
- **WAF Dashboard**: http://localhost:5000
- **Vulnerable Target**: http://localhost:8080 (direct access)
- **Protected Target**: http://localhost:5000/test/* (through WAF)

## 🛡️ Testing Attack Scenarios

### SQL Injection Tests

**Target Endpoints:**
- `/products?id=1' OR 1=1--`
- `/login` (POST with malicious username)

**Attack Payloads:**
```sql
-- Basic SQLi
admin' OR '1'='1' --

-- Union-based SQLi
' UNION SELECT * FROM users --

-- Destructive SQLi (will be blocked)
admin'; DROP TABLE users; --

-- Information extraction
' UNION SELECT username, password FROM users --
```

**Testing Steps:**
1. Try direct access: `http://localhost:8080/products?id=1' OR 1=1--`
2. Try through WAF: `http://localhost:5000/api/v1/test/products?id=1' OR 1=1--`
3. Compare results - WAF should block the attack

### XSS (Cross-Site Scripting) Tests

**Target Endpoints:**
- `/?search=<script>alert('XSS')</script>`
- `/contact` (POST form)

**Attack Payloads:**
```html
<!-- Basic XSS -->
<script>alert('XSS')</script>

<!-- Event-based XSS -->
<img src=x onerror=alert('XSS')>

<!-- SVG XSS -->
<svg onload=alert('XSS')></svg>

<!-- Advanced XSS -->
<script>document.cookie='hacked=true'</script>
```

### File Upload Attacks

**Target**: `/upload`

**Malicious Files:**
```php
<?php system($_GET['cmd']); ?>  // Save as shell.php

<script>alert('XSS')</script>   // Save as malicious.html

#!/bin/bash
rm -rf /                        // Save as dangerous.sh
```

### Directory Traversal

**Target**: `/file?path=../../../etc/passwd`

**Payloads:**
```
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
```

### Authentication Bypass

**Target**: `/admin?token=admin123`

**Common Tokens to Try:**
```
admin123
password
123456
admin
root
```

## 📊 WAF Testing Workflow

### 1. Baseline Testing (Direct Access)
```bash
# Test vulnerable app directly
curl "http://localhost:8080/products?id=1' OR 1=1--"
curl -X POST "http://localhost:8080/login" -d "username=admin' OR '1'='1' --&password=anything"
```

### 2. Protection Testing (Through WAF)
```bash
# Same attacks through WAF - should be blocked
curl "http://localhost:5000/api/v1/test/products?id=1' OR 1=1--"
curl -X POST "http://localhost:5000/api/v1/test/login" -d "username=admin' OR '1'='1' --&password=anything"
```

### 3. Dashboard Monitoring
- Monitor real-time alerts on WAF dashboard
- Check blocked IPs list
- Review security events log
- Verify threat detection metrics

## 🔧 WAF Configuration for Testing

Add these routes to your `main.py` to proxy requests to the vulnerable app:

```python
@app.get("/api/v1/test/{path:path}")
async def test_proxy_get(path: str, request: Request):
    """Proxy GET requests to vulnerable app for testing"""
    target_url = f"http://localhost:8080/{path}"
    query_string = str(request.url.query)
    if query_string:
        target_url += f"?{query_string}"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(target_url, headers=dict(request.headers))
        return Response(content=response.content, status_code=response.status_code)

@app.post("/api/v1/test/{path:path}")
async def test_proxy_post(path: str, request: Request):
    """Proxy POST requests to vulnerable app for testing"""
    target_url = f"http://localhost:8080/{path}"
    body = await request.body()
    
    async with httpx.AsyncClient() as client:
        response = await client.post(target_url, content=body, headers=dict(request.headers))
        return Response(content=response.content, status_code=response.status_code)
```

## 📋 Expected WAF Behavior

### ✅ Should Block:
- SQL injection attempts
- XSS payloads
- Malicious file uploads
- Directory traversal attempts
- Rate limit violations
- Known malicious IPs

### ✅ Should Allow:
- Normal user requests
- Legitimate search queries
- Valid file uploads
- Proper authentication
- Regular browsing patterns

### ✅ Should Log:
- All blocked attacks
- Security events with details
- IP addresses and timestamps
- Attack patterns and severity

## 🎮 Interactive Testing Scenarios

### Scenario 1: E-commerce Attack Simulation
1. Browse the shop normally
2. Attempt to bypass login with SQL injection
3. Try to steal product data
4. Attempt XSS in search and contact forms

### Scenario 2: File System Attack
1. Upload legitimate files
2. Attempt malicious file uploads
3. Try directory traversal attacks
4. Attempt to access system files

### Scenario 3: Admin Panel Intrusion
1. Try to access admin panel
2. Attempt credential brute force
3. Try session hijacking
4. Test privilege escalation

## 📈 Performance Testing

### Load Testing
```bash
# Generate legitimate traffic
ab -n 1000 -c 10 http://localhost:5000/api/v1/test/

# Generate attack traffic
ab -n 100 -c 5 "http://localhost:5000/api/v1/test/products?id=1' OR 1=1--"
```

### Rate Limiting Tests
```bash
# Rapid requests to trigger rate limiting
for i in {1..50}; do
    curl "http://localhost:5000/api/v1/test/" &
done
```

## 🔍 Debugging and Analysis

### Log Analysis
- Check `logs/vigiledge.log` for security events
- Monitor WebSocket alerts in dashboard
- Review blocked IP statistics
- Analyze attack patterns

### Database Inspection
```bash
# Check vulnerable app database
sqlite3 vulnerable.db
.tables
SELECT * FROM users;
```

## ⚠️ Security Warnings

1. **Never use the vulnerable app in production**
2. **Only run on isolated test networks**
3. **Delete vulnerable app after testing**
4. **Monitor for real attacks during testing**
5. **Keep WAF logs for analysis**

## 🎯 Success Metrics

Your WAF is working correctly if:
- ✅ Direct attacks on vulnerable app succeed
- ✅ Same attacks through WAF are blocked
- ✅ Dashboard shows real-time alerts
- ✅ Security events are logged properly
- ✅ Legitimate traffic flows normally
- ✅ Performance remains acceptable

## 🚀 Advanced Testing

### Custom Attack Payloads
Create custom payloads to test specific WAF rules and bypass techniques.

### Automated Testing
Use tools like OWASP ZAP, Burp Suite, or custom scripts for automated security testing.

### Penetration Testing
Conduct comprehensive penetration testing to validate WAF effectiveness.

---

**Happy Testing! 🛡️**

Remember: The goal is to demonstrate how your VigilEdge WAF protects against real-world attacks!
