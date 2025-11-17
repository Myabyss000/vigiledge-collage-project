"""
Core WAF Engine - Main processing engine for the Web Application Firewall
Handles request/response processing, security checks, and threat detection
"""

import time
import asyncio
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import structlog

from ..config import get_settings
from .security_manager import SecurityManager


logger = structlog.get_logger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    """Actions that can be taken on requests"""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    id: str
    timestamp: datetime
    threat_type: str
    threat_level: ThreatLevel
    source_ip: str
    target_url: str
    user_agent: str
    action_taken: ActionType
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type,
            "threat_level": self.threat_level.value,
            "source_ip": self.source_ip,
            "target_url": self.target_url,
            "user_agent": self.user_agent,
            "action_taken": self.action_taken.value,
            "details": self.details,
            "blocked": self.blocked,
        }


@dataclass
class RequestMetrics:
    """Request processing metrics"""
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    threats_detected: int = 0
    avg_response_time: float = 0.0
    last_reset: datetime = field(default_factory=datetime.utcnow)
    
    def reset(self):
        """Reset metrics"""
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.threats_detected = 0
        self.avg_response_time = 0.0
        self.last_reset = datetime.utcnow()


class WAFEngine:
    """
    Main WAF Engine for processing HTTP requests and responses
    Implements security checks, threat detection, and request filtering
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.security_manager = SecurityManager()
        self.metrics = RequestMetrics()
        self.blocked_ips: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.security_events: List[SecurityEvent] = []
        self._init_security_patterns()
        
        logger.info("WAF Engine initialized", 
                   engine_version="1.0.0",
                   security_features_enabled=self._get_enabled_features())
    
    def _init_security_patterns(self):
        """Initialize security detection patterns"""
        self.sql_injection_patterns = [
            re.compile(r"union\s+select", re.IGNORECASE),
            re.compile(r"drop\s+table", re.IGNORECASE),
            re.compile(r"exec\s+sp_", re.IGNORECASE),
            re.compile(r"insert\s+into", re.IGNORECASE),
            re.compile(r"delete\s+from", re.IGNORECASE),
            re.compile(r"update\s+\w+\s+set", re.IGNORECASE),
            re.compile(r"script\s+", re.IGNORECASE),
            re.compile(r"(\'|\")(\s|%20)*(or|and)(\s|%20)*(\1|%27|%22)", re.IGNORECASE),
            re.compile(r"(\'|\")(\s|%20)*(\d+)(\s|%20)*=(\s|%20)*\3", re.IGNORECASE),
            # Additional SQL injection patterns
            re.compile(r"'\s+(or|and)\s+\d", re.IGNORECASE),  # ' OR 1=1
            re.compile(r"'\s+(or|and)\s+'", re.IGNORECASE),  # ' OR '
            re.compile(r"--", re.IGNORECASE),  # SQL comment
            re.compile(r"/\*.*\*/", re.IGNORECASE),  # SQL block comment
            re.compile(r";\s*drop", re.IGNORECASE),  # ; DROP
            re.compile(r";\s*delete", re.IGNORECASE),  # ; DELETE
        ]
        
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on(load|click|error|focus|blur|change|submit)", re.IGNORECASE),
            re.compile(r"<iframe[^>]*>", re.IGNORECASE),
            re.compile(r"<object[^>]*>", re.IGNORECASE),
            re.compile(r"<embed[^>]*>", re.IGNORECASE),
            re.compile(r"vbscript:", re.IGNORECASE),
            re.compile(r"expression\s*\(", re.IGNORECASE),
        ]
        
        self.bot_patterns = [
            re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
            re.compile(r"curl|wget|python|java", re.IGNORECASE),
            re.compile(r"automated|scanner|vulnerability", re.IGNORECASE),
        ]
    
    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled security features"""
        features = []
        if self.settings.sql_injection_protection:
            features.append("SQL Injection Protection")
        if self.settings.xss_protection:
            features.append("XSS Protection")
        if self.settings.ddos_protection:
            features.append("DDoS Protection")
        if self.settings.ip_blocking_enabled:
            features.append("IP Blocking")
        if self.settings.bot_detection_enabled:
            features.append("Bot Detection")
        if self.settings.rate_limit_enabled:
            features.append("Rate Limiting")
        return features
    
    async def process_request(self, 
                            method: str,
                            url: str, 
                            headers: Dict[str, str],
                            body: Optional[str] = None,
                            client_ip: str = "unknown") -> Tuple[bool, SecurityEvent]:
        """
        Process incoming HTTP request through WAF security checks
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: HTTP headers dictionary
            body: Request body content
            client_ip: Client IP address
            
        Returns:
            Tuple of (allow_request: bool, security_event: SecurityEvent)
        """
        start_time = time.time()
        self.metrics.total_requests += 1
        
        # Generate unique event ID
        event_id = f"WAF_{int(time.time())}_{len(self.security_events)}"
        
        # Basic request info
        user_agent = headers.get("User-Agent", "unknown")
        
        # Initialize security event
        security_event = SecurityEvent(
            id=event_id,
            timestamp=datetime.utcnow(),
            threat_type="none",
            threat_level=ThreatLevel.LOW,
            source_ip=client_ip,
            target_url=url,
            user_agent=user_agent,
            action_taken=ActionType.ALLOW,
            details={"method": method, "headers": dict(headers)}
        )
        
        try:
            # Check if IP is blocked
            if await self._is_ip_blocked(client_ip):
                security_event.threat_type = "blocked_ip"
                security_event.threat_level = ThreatLevel.HIGH
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["reason"] = "IP in blocklist"
                
                logger.warning("Blocked request from banned IP", 
                             client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.security_events.append(security_event)
                return False, security_event
            
            # Rate limiting check
            if self.settings.rate_limit_enabled:
                if not await self._check_rate_limit(client_ip):
                    security_event.threat_type = "rate_limit_exceeded"
                    security_event.threat_level = ThreatLevel.MEDIUM
                    security_event.action_taken = ActionType.RATE_LIMIT
                    security_event.blocked = True
                    security_event.details["rate_limit"] = {
                        "requests": self.settings.rate_limit_requests,
                        "window": self.settings.rate_limit_window
                    }
                    
                    logger.warning("Rate limit exceeded", 
                                 client_ip=client_ip, url=url)
                    
                    self.metrics.blocked_requests += 1
                    self.security_events.append(security_event)
                    return False, security_event
            
            # SQL Injection detection
            if self.settings.sql_injection_protection:
                sql_detected = await self._detect_sql_injection(url, body)
                if sql_detected:
                    security_event.threat_type = "sql_injection"
                    security_event.threat_level = ThreatLevel.CRITICAL
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = sql_detected
                    
                    logger.critical("SQL injection attempt detected", 
                                  client_ip=client_ip, url=url, 
                                  patterns=sql_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    
                    # Auto-block IP for SQL injection attempts
                    await self._auto_block_ip(client_ip, "SQL injection attempt")
                    
                    return False, security_event
            
            # XSS detection
            if self.settings.xss_protection:
                xss_detected = await self._detect_xss(url, body)
                if xss_detected:
                    security_event.threat_type = "xss_attempt"
                    security_event.threat_level = ThreatLevel.HIGH
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = xss_detected
                    
                    logger.error("XSS attempt detected", 
                               client_ip=client_ip, url=url,
                               patterns=xss_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    return False, security_event
            
            # Bot detection
            if self.settings.bot_detection_enabled:
                bot_detected = await self._detect_bot(user_agent)
                if bot_detected:
                    security_event.threat_type = "bot_detected"
                    security_event.threat_level = ThreatLevel.MEDIUM
                    security_event.action_taken = ActionType.LOG
                    security_event.details["bot_type"] = bot_detected
                    
                    logger.info("Bot detected", 
                              client_ip=client_ip, user_agent=user_agent,
                              bot_type=bot_detected)
            
            # Request allowed
            self.metrics.allowed_requests += 1
            self.security_events.append(security_event)
            
            # Update response time metrics
            processing_time = time.time() - start_time
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * (self.metrics.total_requests - 1) + processing_time)
                / self.metrics.total_requests
            )
            
            logger.info("Request processed successfully", 
                       client_ip=client_ip, url=url, 
                       processing_time=processing_time)
            
            return True, security_event
            
        except Exception as e:
            logger.error("Error processing request", 
                        client_ip=client_ip, url=url, error=str(e))
            
            security_event.threat_type = "processing_error"
            security_event.threat_level = ThreatLevel.LOW
            security_event.action_taken = ActionType.ALLOW
            security_event.details["error"] = str(e)
            
            self.security_events.append(security_event)
            return True, security_event
    
    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is in blocklist"""
        if ip in self.blocked_ips:
            block_time = self.blocked_ips[ip]
            # Check if block has expired (24 hours)
            if datetime.utcnow() - block_time > timedelta(hours=24):
                del self.blocked_ips[ip]
                return False
            return True
        return False
    
    async def _check_rate_limit(self, ip: str) -> bool:
        """Check if request is within rate limits"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.settings.rate_limit_window)
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        # Clean old requests outside the window
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip] 
            if req_time > window_start
        ]
        
        # Check if rate limit exceeded
        if len(self.rate_limits[ip]) >= self.settings.rate_limit_requests:
            return False
        
        # Add current request
        self.rate_limits[ip].append(now)
        return True
    
    async def _detect_sql_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect SQL injection patterns"""
        import urllib.parse
        detected_patterns = []
        
        # URL decode the content to detect encoded attacks (unquote_plus handles + as space)
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        content = f"{decoded_url} {decoded_body}"
        
        for pattern in self.sql_injection_patterns:
            if pattern.search(content):
                detected_patterns.append(pattern.pattern)
        
        return detected_patterns
    
    async def _detect_xss(self, url: str, body: Optional[str]) -> List[str]:
        """Detect XSS patterns"""
        import urllib.parse
        detected_patterns = []
        
        # URL decode the content to detect encoded attacks (unquote_plus handles + as space)
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        content = f"{decoded_url} {decoded_body}"
        
        for pattern in self.xss_patterns:
            if pattern.search(content):
                detected_patterns.append(pattern.pattern)
        
        return detected_patterns
    
    async def _detect_bot(self, user_agent: str) -> Optional[str]:
        """Detect bot/crawler patterns"""
        for pattern in self.bot_patterns:
            if pattern.search(user_agent):
                return pattern.pattern.split('|')[0]  # Return first matching pattern
        return None
    
    async def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP address"""
        # Don't auto-block localhost for testing purposes
        if ip in ["127.0.0.1", "localhost", "::1"]:
            logger.info("Skipping auto-block for localhost", ip=ip, reason=reason)
            return
        
        self.blocked_ips[ip] = datetime.utcnow()
        logger.warning("IP auto-blocked", ip=ip, reason=reason)
    
    # Management methods
    async def block_ip(self, ip: str, reason: str = "Manual block"):
        """Manually block an IP address"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.blocked_ips[ip] = datetime.utcnow()
            logger.info("IP manually blocked", ip=ip, reason=reason)
            return True
        except ValueError:
            logger.error("Invalid IP address", ip=ip)
            return False
    
    async def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            logger.info("IP unblocked", ip=ip)
            return True
        return False
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current WAF metrics"""
        return {
            "total_requests": self.metrics.total_requests,
            "blocked_requests": self.metrics.blocked_requests,
            "allowed_requests": self.metrics.allowed_requests,
            "threats_detected": self.metrics.threats_detected,
            "avg_response_time": round(self.metrics.avg_response_time, 3),
            "blocked_ips_count": len(self.blocked_ips),
            "active_rate_limits": len(self.rate_limits),
            "last_reset": self.metrics.last_reset.isoformat(),
            "uptime": str(datetime.utcnow() - self.metrics.last_reset),
        }
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events"""
        return [event.to_dict() for event in self.security_events[-limit:]]
    
    async def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IP addresses"""
        return [
            {
                "ip": ip,
                "blocked_at": block_time.isoformat(),
                "expires_at": (block_time + timedelta(hours=24)).isoformat()
            }
            for ip, block_time in self.blocked_ips.items()
        ]
    
    async def reset_metrics(self):
        """Reset WAF metrics"""
        self.metrics.reset()
        logger.info("WAF metrics reset")
    
    async def clear_events(self):
        """Clear security events history"""
        self.security_events.clear()
        logger.info("Security events cleared")
