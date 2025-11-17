"""
Test suite for VigilEdge WAF
Tests security detection, blocking, and core functionality
"""

import pytest
import asyncio
import json
from datetime import datetime
from typing import Dict, Any

# Test the core WAF engine
class TestWAFEngine:
    """Test WAF engine functionality"""
    
    @pytest.fixture
    def waf_engine(self):
        """Create WAF engine instance for testing"""
        from vigiledge.core.waf_engine import WAFEngine
        return WAFEngine()
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, waf_engine):
        """Test SQL injection detection"""
        malicious_payloads = [
            "' UNION SELECT * FROM users--",
            "1; DROP TABLE users;",
            "admin' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'pass');--"
        ]
        
        for payload in malicious_payloads:
            allowed, event = await waf_engine.process_request(
                method="GET",
                url=f"http://example.com/search?q={payload}",
                headers={"User-Agent": "TestAgent"},
                body=None,
                client_ip="192.168.1.100"
            )
            
            assert not allowed, f"SQL injection not detected: {payload}"
            assert event.threat_type == "sql_injection"
            assert event.threat_level.value in ["high", "critical"]
    
    @pytest.mark.asyncio
    async def test_xss_detection(self, waf_engine):
        """Test XSS detection"""
        malicious_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for payload in malicious_payloads:
            allowed, event = await waf_engine.process_request(
                method="POST",
                url="http://example.com/comment",
                headers={"User-Agent": "TestAgent", "Content-Type": "application/json"},
                body=json.dumps({"content": payload}),
                client_ip="192.168.1.100"
            )
            
            assert not allowed, f"XSS not detected: {payload}"
            assert event.threat_type == "xss_attempt"
            assert event.threat_level.value in ["medium", "high"]
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, waf_engine):
        """Test rate limiting functionality"""
        client_ip = "192.168.1.200"
        
        # Send requests up to the limit
        for i in range(waf_engine.settings.rate_limit_requests):
            allowed, event = await waf_engine.process_request(
                method="GET",
                url="http://example.com/",
                headers={"User-Agent": "TestAgent"},
                body=None,
                client_ip=client_ip
            )
            
            if i < waf_engine.settings.rate_limit_requests - 1:
                assert allowed, f"Request {i} should be allowed"
        
        # Next request should be rate limited
        allowed, event = await waf_engine.process_request(
            method="GET",
            url="http://example.com/",
            headers={"User-Agent": "TestAgent"},
            body=None,
            client_ip=client_ip
        )
        
        assert not allowed, "Rate limit should be enforced"
        assert event.threat_type == "rate_limit_exceeded"
    
    @pytest.mark.asyncio
    async def test_bot_detection(self, waf_engine):
        """Test bot detection"""
        bot_user_agents = [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "Go-http-client/1.1"
        ]
        
        for user_agent in bot_user_agents:
            allowed, event = await waf_engine.process_request(
                method="GET",
                url="http://example.com/",
                headers={"User-Agent": user_agent},
                body=None,
                client_ip="192.168.1.100"
            )
            
            # Bots should be allowed but detected
            assert allowed, f"Bot should be allowed: {user_agent}"
            assert event.threat_type == "bot_detected"
    
    @pytest.mark.asyncio
    async def test_ip_blocking(self, waf_engine):
        """Test IP blocking functionality"""
        malicious_ip = "192.168.1.250"
        
        # Block the IP
        success = await waf_engine.block_ip(malicious_ip, "Test block")
        assert success, "IP should be blocked successfully"
        
        # Try to make a request from blocked IP
        allowed, event = await waf_engine.process_request(
            method="GET",
            url="http://example.com/",
            headers={"User-Agent": "TestAgent"},
            body=None,
            client_ip=malicious_ip
        )
        
        assert not allowed, "Blocked IP should not be allowed"
        assert event.threat_type == "blocked_ip"
        
        # Unblock the IP
        success = await waf_engine.unblock_ip(malicious_ip)
        assert success, "IP should be unblocked successfully"
        
        # Request should now be allowed
        allowed, event = await waf_engine.process_request(
            method="GET",
            url="http://example.com/",
            headers={"User-Agent": "TestAgent"},
            body=None,
            client_ip=malicious_ip
        )
        
        assert allowed, "Unblocked IP should be allowed"
    
    @pytest.mark.asyncio
    async def test_legitimate_requests(self, waf_engine):
        """Test that legitimate requests are allowed"""
        legitimate_requests = [
            {
                "method": "GET",
                "url": "http://example.com/",
                "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                "body": None
            },
            {
                "method": "POST",
                "url": "http://example.com/api/users",
                "headers": {"User-Agent": "MyApp/1.0", "Content-Type": "application/json"},
                "body": json.dumps({"name": "John Doe", "email": "john@example.com"})
            },
            {
                "method": "PUT",
                "url": "http://example.com/api/users/123",
                "headers": {"User-Agent": "MyApp/1.0", "Content-Type": "application/json"},
                "body": json.dumps({"name": "Jane Doe"})
            }
        ]
        
        for request_data in legitimate_requests:
            allowed, event = await waf_engine.process_request(
                method=request_data["method"],
                url=request_data["url"],
                headers=request_data["headers"],
                body=request_data["body"],
                client_ip="192.168.1.100"
            )
            
            assert allowed, f"Legitimate request should be allowed: {request_data['method']} {request_data['url']}"
            assert event.threat_type == "none" or event.threat_type == "bot_detected"


class TestSecurityManager:
    """Test security manager functionality"""
    
    @pytest.fixture
    def security_manager(self):
        """Create security manager instance for testing"""
        from vigiledge.core.security_manager import SecurityManager
        return SecurityManager()
    
    @pytest.mark.asyncio
    async def test_ip_reputation_check(self, security_manager):
        """Test IP reputation checking"""
        # Test unknown IP
        reputation = await security_manager.check_ip_reputation("8.8.8.8")
        assert reputation["status"] == "unknown"
        assert reputation["reputation_score"] == 0
        
        # Test whitelisted IP
        await security_manager.add_to_whitelist("1.1.1.1")
        reputation = await security_manager.check_ip_reputation("1.1.1.1")
        assert reputation["status"] == "whitelisted"
        assert reputation["reputation_score"] == 100
        
        # Test blacklisted IP
        await security_manager.add_to_blacklist("6.6.6.6")
        reputation = await security_manager.check_ip_reputation("6.6.6.6")
        assert reputation["status"] == "blacklisted"
        assert reputation["reputation_score"] == -100
    
    @pytest.mark.asyncio
    async def test_security_rules(self, security_manager):
        """Test security rule management"""
        from vigiledge.core.security_manager import SecurityRule
        
        # Create a test rule
        test_rule = SecurityRule(
            id="TEST_001",
            name="Test Rule",
            description="Test security rule",
            pattern="test_pattern",
            threat_type="test",
            severity="medium"
        )
        
        # Add the rule
        success = await security_manager.add_security_rule(test_rule)
        assert success, "Rule should be added successfully"
        
        # Test rule evaluation
        violations = await security_manager.evaluate_security_rules("This contains test_pattern in it")
        assert len(violations) > 0, "Rule should detect pattern"
        assert violations[0]["rule_id"] == "TEST_001"
        
        # Disable the rule
        success = await security_manager.disable_rule("TEST_001")
        assert success, "Rule should be disabled successfully"
        
        # Test should not trigger when disabled
        violations = await security_manager.evaluate_security_rules("This contains test_pattern in it")
        test_violations = [v for v in violations if v["rule_id"] == "TEST_001"]
        assert len(test_violations) == 0, "Disabled rule should not trigger"
        
        # Remove the rule
        success = await security_manager.remove_security_rule("TEST_001")
        assert success, "Rule should be removed successfully"


class TestConfiguration:
    """Test configuration loading and validation"""
    
    def test_settings_loading(self):
        """Test that settings load correctly"""
        from vigiledge.config import get_settings
        
        settings = get_settings()
        assert settings is not None
        assert settings.app_name == "VigilEdge WAF"
        assert settings.port == 5000
        assert isinstance(settings.rate_limit_requests, int)
        assert isinstance(settings.sql_injection_protection, bool)
    
    def test_security_config(self):
        """Test security configuration"""
        from vigiledge.config import get_security_config
        
        config = get_security_config()
        assert isinstance(config, dict)
        assert "sql_injection_protection" in config
        assert "xss_protection" in config
        assert "rate_limit_enabled" in config


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_request_processing(self):
        """Test complete request processing pipeline"""
        from vigiledge.core.waf_engine import WAFEngine
        
        waf = WAFEngine()
        
        # Test various attack scenarios
        attack_scenarios = [
            {
                "name": "SQL Injection",
                "method": "GET",
                "url": "http://test.com/search?q=' OR 1=1--",
                "expected_block": True,
                "expected_threat": "sql_injection"
            },
            {
                "name": "XSS Attack",
                "method": "POST",
                "url": "http://test.com/comment",
                "body": "<script>alert('XSS')</script>",
                "expected_block": True,
                "expected_threat": "xss_attempt"
            },
            {
                "name": "Legitimate Request",
                "method": "GET",
                "url": "http://test.com/api/data",
                "expected_block": False,
                "expected_threat": "none"
            }
        ]
        
        for scenario in attack_scenarios:
            allowed, event = await waf.process_request(
                method=scenario["method"],
                url=scenario["url"],
                headers={"User-Agent": "TestAgent"},
                body=scenario.get("body"),
                client_ip="192.168.1.100"
            )
            
            if scenario["expected_block"]:
                assert not allowed, f"Attack should be blocked: {scenario['name']}"
                assert event.threat_type == scenario["expected_threat"]
            else:
                assert allowed, f"Legitimate request should be allowed: {scenario['name']}"


# Test fixtures and utilities
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
