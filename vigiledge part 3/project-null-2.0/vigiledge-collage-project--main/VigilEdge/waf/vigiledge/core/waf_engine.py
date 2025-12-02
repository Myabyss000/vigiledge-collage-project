"""
Core WAF Engine - Main processing engine for the Web Application Firewall
Handles request/response processing, security checks, and threat detection
"""

import time
import asyncio
import re
import sqlite3
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
    last_reset: datetime = field(default_factory=datetime.now)
    
    def reset(self):
        """Reset metrics"""
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.threats_detected = 0
        self.avg_response_time = 0.0
        self.last_reset = datetime.now()


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
        self.db_path = "vulnerable.db"
        
        # Advanced DDoS tracking
        self.connection_table: Dict[str, Dict[str, Any]] = {}  # IP -> connection data
        self.request_patterns: Dict[str, List[str]] = {}  # IP -> URL patterns
        self.user_agent_cache: Dict[str, int] = {}  # User-Agent -> count
        
        self._init_database()
        self._init_security_patterns()
        
        logger.info("WAF Engine initialized", 
                   engine_version="1.0.0",
                   security_features_enabled=self._get_enabled_features())
    
    def _init_security_patterns(self):
        """Initialize security detection patterns"""
        self.sql_injection_patterns = [
            # ============= BASIC SQL COMMANDS =============
            re.compile(r"union[\s\+\/\*!]*select", re.IGNORECASE),
            re.compile(r"union[\s\+\/\*!]*all[\s\+\/\*!]*select", re.IGNORECASE),
            re.compile(r"drop[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"drop[\s\+\/\*!]*database", re.IGNORECASE),
            re.compile(r"truncate[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"exec[\s\+\/\*!]*(sp_|xp_)", re.IGNORECASE),
            re.compile(r"insert[\s\+\/\*!]*into", re.IGNORECASE),
            re.compile(r"delete[\s\+\/\*!]*from", re.IGNORECASE),
            re.compile(r"update[\s\+\/\*!]*\w+[\s\+\/\*!]*set", re.IGNORECASE),
            re.compile(r"alter[\s\+\/\*!]*table", re.IGNORECASE),
            re.compile(r"create[\s\+\/\*!]*(table|database|procedure|function)", re.IGNORECASE),
            
            # ============= BOOLEAN-BASED BLIND INJECTION =============
            re.compile(r"(\'|\")(\s|%20|\/\*.*?\*\/)*(or|and)(\s|%20|\/\*.*?\*\/)*(\1|%27|%22)", re.IGNORECASE),
            re.compile(r"'\s*(or|and)\s*\d+\s*[=<>!]+\s*\d+", re.IGNORECASE),  # ' OR 1=1, ' AND 1<2
            re.compile(r"'\s*(or|and)\s*'[^']*'\s*[=<>!]+\s*'", re.IGNORECASE),  # ' OR 'a'='a
            re.compile(r"\d+\s*(or|and)\s*\d+\s*[=<>!]", re.IGNORECASE),  # 1 OR 1=1
            re.compile(r"'\s*(or|and)\s*'", re.IGNORECASE),  # ' OR '
            re.compile(r"'\s*(or|and)\s*true", re.IGNORECASE),  # ' OR true
            re.compile(r"'\s*(or|and)\s*false", re.IGNORECASE),  # ' AND false
            re.compile(r"'\s*(or|and)\s*not\s*", re.IGNORECASE),  # ' OR NOT
            re.compile(r"\d+\s*between\s*\d+\s*and\s*\d+", re.IGNORECASE),  # 1 BETWEEN 1 AND 10
            re.compile(r"'\s*is\s*(not\s*)?null", re.IGNORECASE),  # ' IS NULL, ' IS NOT NULL
            re.compile(r"null\s*is\s*(not\s*)?null", re.IGNORECASE),  # NULL IS NULL
            
            # ============= SQL COMMENTS & OBFUSCATION =============
            re.compile(r"--[+\-\s]*[^\r\n]*", re.IGNORECASE),  # SQL comment variations: --, --+, -- -
            re.compile(r"/\*[\s\S]*?\*/", re.IGNORECASE),  # SQL block comment
            re.compile(r"/\*![0-9]*", re.IGNORECASE),  # MySQL conditional comments /*! */
            re.compile(r"#[^\r\n]*", re.IGNORECASE),  # MySQL comment
            re.compile(r";%00", re.IGNORECASE),  # Null byte injection
            re.compile(r"%00", re.IGNORECASE),  # Null byte alone
            re.compile(r"[;'\"]\s*--", re.IGNORECASE),  # Quote/semicolon followed by comment
            re.compile(r"--\s*-", re.IGNORECASE),  # -- -
            re.compile(r"--\+", re.IGNORECASE),  # --+
            re.compile(r"--%20", re.IGNORECASE),  # -- with URL encoded space
            
            # ============= ADVANCED STACKED QUERIES =============
            re.compile(r";[\s\+\/\*!]*(drop|delete|truncate|alter|create|insert|update|exec)", re.IGNORECASE),
            re.compile(r"(union|select|insert|update|delete|drop|create|alter|exec|execute)[\s\+]*\/\*.*?\*\/[\s\+]*(select|from|where|union)", re.IGNORECASE),
            re.compile(r"(select|union)[\s\S]{0,100}?(from|into)", re.IGNORECASE),
            re.compile(r"(exec|execute)[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"(exec|execute)[\s\+\/\*!]*(xp_|sp_)", re.IGNORECASE),
            re.compile(r";\s*declare\s+", re.IGNORECASE),  # ; DECLARE
            
            # ============= TIME-BASED BLIND INJECTION =============
            re.compile(r"(sleep|benchmark|waitfor|pg_sleep|dbms_lock\.sleep)[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"waitfor[\s\+\/\*!]*delay", re.IGNORECASE),
            re.compile(r"benchmark[\s\+\/\*!]*\([\s\S]*?,[\s\S]*?\)", re.IGNORECASE),  # BENCHMARK(count, expr)
            re.compile(r"sleep[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # SLEEP(5)
            re.compile(r"pg_sleep[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # PG_SLEEP(5)
            
            # ============= STRING MANIPULATION & ENCODING =============
            re.compile(r"(concat|char|chr|substring|substr|mid|ascii|hex|unhex|bin|oct)[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"0x[0-9a-f]{2,}", re.IGNORECASE),  # Hex encoding (at least 2 chars)
            re.compile(r"char[\s\+\/\*!]*\([\s\S]*?[0-9]+", re.IGNORECASE),  # CHAR(65) etc
            re.compile(r"concat[\s\+\/\*!]*\(", re.IGNORECASE),
            re.compile(r"concat_ws[\s\+\/\*!]*\(", re.IGNORECASE),  # CONCAT_WS
            re.compile(r"group_concat[\s\+\/\*!]*\(", re.IGNORECASE),  # GROUP_CONCAT
            re.compile(r"make_set[\s\+\/\*!]*\(", re.IGNORECASE),  # MAKE_SET
            re.compile(r"\|\|", re.IGNORECASE),  # String concatenation operator
            
            # ============= DATABASE FINGERPRINTING =============
            re.compile(r"@@(version|servername|hostname|datadir|basedir)", re.IGNORECASE),
            re.compile(r"(version|database|user|current_user|session_user|system_user)[\s\+\/\*!]*\(\)", re.IGNORECASE),
            re.compile(r"information_schema\.", re.IGNORECASE),
            re.compile(r"(pg_|mysql\.|msdb\.|sys\.|sysobjects|syscolumns)", re.IGNORECASE),
            re.compile(r"sqlite_(version|master)", re.IGNORECASE),
            re.compile(r"(master|tempdb|model|msdb)\.", re.IGNORECASE),  # SQL Server databases
            re.compile(r"dual[\s\+]*from", re.IGNORECASE),  # Oracle DUAL table
            re.compile(r"all_tables|all_users|dba_", re.IGNORECASE),  # Oracle system views
            
            # ============= SUBQUERIES & NESTED QUERIES =============
            re.compile(r"\([\s\+\/\*!]*select[\s\S]{0,200}?from", re.IGNORECASE),
            re.compile(r"exists[\s\+\/\*!]*\([\s\+\/\*!]*select", re.IGNORECASE),  # EXISTS (SELECT
            re.compile(r"(any|all|some)[\s\+\/\*!]*\([\s\+\/\*!]*select", re.IGNORECASE),  # ANY (SELECT
            
            # ============= UNION-BASED WITH EVASION =============
            re.compile(r"union[\s\+\/\*!]{1,}(all[\s\+\/\*!]{1,})?select[\s\S]{0,100}?(null|[0-9])", re.IGNORECASE),
            re.compile(r"union[\s\+\/\*!]{1,}select[\s\+\/\*!]{1,}(null|[0-9])", re.IGNORECASE),
            re.compile(r"-[0-9]+[\s\+]*union[\s\+]*select", re.IGNORECASE),  # -1 UNION SELECT
            re.compile(r"order[\s\+\/\*!]*by[\s\+\/\*!]*[0-9]+[\s\+]*--", re.IGNORECASE),  # Column enumeration
            
            # ============= SQL OPERATORS & COMPARISONS =============
            re.compile(r"(&&|\|\||xor)", re.IGNORECASE),  # Logical operators
            re.compile(r"'\s*(=|<|>|!=|<>|<=|>=|like|rlike|regexp)\s*'", re.IGNORECASE),
            re.compile(r"[0-9]+\s*(=|<|>|!=|<>)\s*[0-9]+", re.IGNORECASE),  # Numeric comparisons
            re.compile(r"(div|mod)[\s\+\/\*!]+[0-9]", re.IGNORECASE),  # DIV, MOD operators
            
            # CASE WHEN statements (for blind injection)
            re.compile(r"case\s+when", re.IGNORECASE),
            
            # SQL wildcards and LIKE operators
            re.compile(r"'\s*like\s*'", re.IGNORECASE),
            re.compile(r"%'\s*(or|and)", re.IGNORECASE),
            
            # Backtick injection (MySQL identifier quotes)
            re.compile(r"`", re.IGNORECASE),  # Any backtick is suspicious in user input
            re.compile(r"``", re.IGNORECASE),  # Double backticks
            re.compile(r"`.*?`", re.IGNORECASE),  # Backtick-quoted identifiers
            
            # Quote variations and empty quotes
            re.compile(r"''", re.IGNORECASE),  # Empty single quotes
            re.compile(r'""', re.IGNORECASE),  # Empty double quotes
            
            # Multiple quotes (often used in injection)
            re.compile(r"'{2,}", re.IGNORECASE),  # Multiple single quotes
            re.compile(r'"{2,}', re.IGNORECASE),  # Multiple double quotes
            
            # ORDER BY clause (used for column enumeration)
            re.compile(r"order\s+by\s+\d+", re.IGNORECASE),  # ORDER BY 1, ORDER BY 28, etc.
            re.compile(r"order\s+by\s+[a-z_]+", re.IGNORECASE),  # ORDER BY column_name
            
            # Common SQL comment patterns with various formats
            re.compile(r"--\s*-", re.IGNORECASE),  # -- -
            re.compile(r"--\s*$", re.IGNORECASE),  # -- at end
            re.compile(r"--\+", re.IGNORECASE),  # --+
            re.compile(r"--%20", re.IGNORECASE),  # -- with space encoded
            
            # Quote followed by OR with various spacing
            re.compile(r"'\s*or\s*'", re.IGNORECASE),  # ' or '
            re.compile(r'"\s*or\s*"', re.IGNORECASE),  # " or "
            re.compile(r"'\s+or\s+\d+\s*--", re.IGNORECASE),  # ' OR 1 --
            re.compile(r"'\s+or\s+\d+\s*#", re.IGNORECASE),  # ' OR 1 #
            
            # Space variations with OR/AND
            re.compile(r"'\s+(or|and)\s+", re.IGNORECASE),  # ' OR, ' AND with spaces
            re.compile(r'"\s+(or|and)\s+', re.IGNORECASE),  # " OR, " AND with spaces
            
            # Advanced SQL injection techniques
            re.compile(r"group\s+by\s+", re.IGNORECASE),  # GROUP BY
            re.compile(r"having\s+", re.IGNORECASE),  # HAVING clause
            re.compile(r"limit\s+\d+", re.IGNORECASE),  # LIMIT clause
            re.compile(r"offset\s+\d+", re.IGNORECASE),  # OFFSET clause
            re.compile(r"procedure\s+", re.IGNORECASE),  # PROCEDURE
            re.compile(r"handler\s+", re.IGNORECASE),  # HANDLER
            re.compile(r"declare\s+", re.IGNORECASE),  # DECLARE
            re.compile(r"cursor\s+", re.IGNORECASE),  # CURSOR
            re.compile(r"fetch\s+", re.IGNORECASE),  # FETCH
            re.compile(r"open\s+", re.IGNORECASE),  # OPEN cursor
            re.compile(r"prepare\s+", re.IGNORECASE),  # PREPARE statement
            re.compile(r"execute\s+immediate", re.IGNORECASE),  # EXECUTE IMMEDIATE
            
            # Boolean-based blind variations
            re.compile(r"\d+\s*=\s*\d+", re.IGNORECASE),  # 1=1, 0=0
            re.compile(r"true|false", re.IGNORECASE),  # Boolean literals
            re.compile(r"null\s+is\s+null", re.IGNORECASE),  # NULL IS NULL
            
            # String manipulation functions
            re.compile(r"cast\s*\(", re.IGNORECASE),  # CAST()
            re.compile(r"convert\s*\(", re.IGNORECASE),  # CONVERT()
            re.compile(r"substr\s*\(", re.IGNORECASE),  # SUBSTR()
            re.compile(r"length\s*\(", re.IGNORECASE),  # LENGTH()
            re.compile(r"replace\s*\(", re.IGNORECASE),  # REPLACE()
            re.compile(r"reverse\s*\(", re.IGNORECASE),  # REVERSE()
            re.compile(r"lower\s*\(", re.IGNORECASE),  # LOWER()
            re.compile(r"upper\s*\(", re.IGNORECASE),  # UPPER()
            
            # Database fingerprinting
            re.compile(r"sqlite_version", re.IGNORECASE),  # SQLite version
            re.compile(r"mysql\.", re.IGNORECASE),  # MySQL tables
            re.compile(r"pg_catalog", re.IGNORECASE),  # PostgreSQL catalog
            re.compile(r"sys\.", re.IGNORECASE),  # System tables
            re.compile(r"master\.", re.IGNORECASE),  # SQL Server master db
            
            # Out-of-band techniques
            re.compile(r"load_file\s*\(", re.IGNORECASE),  # LOAD_FILE()
            re.compile(r"into\s+outfile", re.IGNORECASE),  # INTO OUTFILE
            re.compile(r"into\s+dumpfile", re.IGNORECASE),  # INTO DUMPFILE
            re.compile(r"xp_cmdshell", re.IGNORECASE),  # SQL Server command execution
            
            # Second-order injection patterns
            re.compile(r"insert\s+.*?values\s*\(", re.IGNORECASE),  # INSERT with VALUES
            re.compile(r"update\s+.*?set\s+", re.IGNORECASE),  # UPDATE with SET
            
            # NoSQL injection patterns
            re.compile(r"\$ne\s*:", re.IGNORECASE),  # MongoDB $ne
            re.compile(r"\$gt\s*:", re.IGNORECASE),  # MongoDB $gt
            re.compile(r"\$lt\s*:", re.IGNORECASE),  # MongoDB $lt
            
            # ============= WAF BYPASS & EVASION TECHNIQUES =============
            re.compile(r"un(io|on)n[\s\+\/\*!]*(se|le)lect", re.IGNORECASE),  # UNiON SeLECT variations
            re.compile(r"[uU]%6e[iI]%6f[nN]", re.IGNORECASE),  # URL encoded UNION
            re.compile(r"[sS]%65[lL]%65[cC]%74", re.IGNORECASE),  # URL encoded SELECT
            re.compile(r"&#[xX]?[0-9a-fA-F]+;", re.IGNORECASE),  # HTML entity encoding
            re.compile(r"\\u00[0-9a-fA-F]{2}", re.IGNORECASE),  # Unicode escape sequences
            re.compile(r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", re.IGNORECASE),  # Double URL encoding
            re.compile(r"[\+\s]{2,}(union|select|from|where)", re.IGNORECASE),  # Multiple spaces
            
            # ============= ADVANCED ERROR-BASED INJECTION =============
            re.compile(r"extractvalue[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL EXTRACTVALUE()
            re.compile(r"updatexml[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL UPDATEXML()
            re.compile(r"exp[\s\+\/\*!]*\(~[\s\+]*\(", re.IGNORECASE),  # MySQL EXP overflow
            re.compile(r"polygon[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL POLYGON()
            re.compile(r"multipoint[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTIPOINT()
            re.compile(r"geometrycollection[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL GEOMETRYCOLLECTION()
            re.compile(r"linestring[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL LINESTRING()
            re.compile(r"multilinestring[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTILINESTRING()
            re.compile(r"multipolygon[\s\+\/\*!]*\(", re.IGNORECASE),  # MySQL MULTIPOLYGON()
            re.compile(r"convert[\s\+]*\([\s\S]*?,[\s\S]*?\)", re.IGNORECASE),  # CONVERT with type conversion
            
            # ============= POSTGRESQL SPECIFIC =============
            re.compile(r"pg_(sleep|stat|table|database|user)", re.IGNORECASE),
            re.compile(r"pg_read_file[\s\+\/\*!]*\(", re.IGNORECASE),  # File read
            re.compile(r"copy[\s\+]*[\s\S]*?from[\s\+]*program", re.IGNORECASE),  # Command execution
            re.compile(r"::(int|text|char|varchar)", re.IGNORECASE),  # PostgreSQL type casting
            re.compile(r"chr[\s\+\/\*!]*\([0-9]+\)", re.IGNORECASE),  # CHR() function
            re.compile(r"current_setting[\s\+\/\*!]*\(", re.IGNORECASE),  # PostgreSQL settings
            
            # ============= ORACLE SPECIFIC =============
            re.compile(r"utl_http\.request", re.IGNORECASE),  # Oracle UTL_HTTP
            re.compile(r"dbms_(pipe|sql|xmlgen|crypto|random|lob)", re.IGNORECASE),  # Oracle DBMS packages
            re.compile(r"utl_(file|tcp|smtp|inaddr)", re.IGNORECASE),  # Oracle UTL packages
            re.compile(r"from[\s\+]*dual", re.IGNORECASE),  # Oracle DUAL table
            re.compile(r"rownum", re.IGNORECASE),  # Oracle ROWNUM
            
            # ============= MSSQL SPECIFIC =============
            re.compile(r"xp_(cmdshell|regread|regwrite|dirtree|enumgroups)", re.IGNORECASE),  # SQL Server extended procs
            re.compile(r"sp_(executesql|makewebtask|addextendedproc)", re.IGNORECASE),  # SQL Server stored procs
            re.compile(r"openrowset[\s\+\/\*!]*\(", re.IGNORECASE),  # OPENROWSET
            re.compile(r"opendatasource[\s\+\/\*!]*\(", re.IGNORECASE),  # OPENDATASOURCE
            re.compile(r"fn_(virtualfilestats|trace_gettable)", re.IGNORECASE),  # SQL Server functions
            
            # ============= ADVANCED BLIND TECHNIQUES =============
            re.compile(r"if[\s\+\/\*!]*\([\s\S]*?,[\s\S]*?,", re.IGNORECASE),  # IF(condition, true_val, false_val)
            re.compile(r"case[\s\+\/\*!]*when[\s\S]*?then[\s\S]*?else", re.IGNORECASE),  # CASE WHEN
            re.compile(r"iif[\s\+\/\*!]*\(", re.IGNORECASE),  # IIF() function
            re.compile(r"nullif[\s\+\/\*!]*\(", re.IGNORECASE),  # NULLIF()
            re.compile(r"ifnull[\s\+\/\*!]*\(", re.IGNORECASE),  # IFNULL()
            re.compile(r"coalesce[\s\+\/\*!]*\(", re.IGNORECASE),  # COALESCE()
            
            # ============= POLYGLOT INJECTIONS =============
            re.compile(r"sleep\([0-9]+\).*?benchmark", re.IGNORECASE),  # Multi-DB time functions
            re.compile(r"'\+[\s\+]*'", re.IGNORECASE),  # String concatenation '+'
            re.compile(r"'[\s\+]*\|\|[\s\+]*'", re.IGNORECASE),  # String concatenation '||'
            re.compile(r"0x[0-9a-f]+[\s\+]*union", re.IGNORECASE),  # Hex + UNION
            
            # ============= JSON/XML SQL INJECTION =============
            re.compile(r"\{[\s\S]*?(\$ne|\$gt|\$where|\$regex)[\s\S]*?\}", re.IGNORECASE),  # JSON injection
            re.compile(r"<(select|union|insert|delete)", re.IGNORECASE),  # XML injection
            re.compile(r"extractvalue[\s\+]*\(", re.IGNORECASE),
            re.compile(r"xmltype[\s\+]*\(", re.IGNORECASE),  # Oracle XMLType
            
            # ============= BYPASS QUOTES & STRING DELIMITERS =============
            re.compile(r"char[\s\+\/\*!]*\([0-9,\s]+\)", re.IGNORECASE),  # CHAR bypassing quotes
            re.compile(r"0x[0-9a-f]+[\s\+]*(=|<|>|like)", re.IGNORECASE),  # Hex comparison
            re.compile(r"binary[\s\+]*'", re.IGNORECASE),  # BINARY keyword
            re.compile(r"_binary[\s\+]*'", re.IGNORECASE),  # _binary modifier
            
            # ============= SECOND-ORDER & STORED INJECTION =============
            re.compile(r"call[\s\+\/\*!]*\w+[\s\+]*\(", re.IGNORECASE),  # CALL procedure
            re.compile(r"procedure[\s\+]*\w+", re.IGNORECASE),
            re.compile(r"trigger[\s\+]*(on|for|after|before)", re.IGNORECASE),
            
            # ============= OUT-OF-BAND & DNS EXFILTRATION =============
            re.compile(r"load_file[\s\+\/\*!]*\(['\"]\\\\\\\\", re.IGNORECASE),  # UNC path injection
            re.compile(r"select[\s\S]*?into[\s\+]*(outfile|dumpfile)", re.IGNORECASE),
            re.compile(r"bulk[\s\+]*insert", re.IGNORECASE),  # SQL Server BULK INSERT
            
            # ============= MYSQL SPECIFIC ADVANCED =============
            re.compile(r"information_schema\.(tables|columns|schemata)", re.IGNORECASE),
            re.compile(r"mysql\.(user|db|tables_priv|columns_priv)", re.IGNORECASE),
            re.compile(r"show[\s\+]*(databases|tables|columns|processlist)", re.IGNORECASE),
            re.compile(r"load[\s\+]*data[\s\+]*infile", re.IGNORECASE),
            
            # ============= EXTREMELY RARE BUT DANGEROUS =============
            re.compile(r"into[\s\+]*@", re.IGNORECASE),  # Variable injection
            re.compile(r"set[\s\+]*@[\w]+[\s\+]*=", re.IGNORECASE),  # SET @var
            re.compile(r"prepare[\s\+]*[\w]+[\s\+]*from", re.IGNORECASE),  # Prepared statements
            re.compile(r"execute[\s\+]*[\w]+[\s\+]*(using|into)", re.IGNORECASE),
            re.compile(r"\$or\s*:", re.IGNORECASE),  # MongoDB $or
            re.compile(r"\$and\s*:", re.IGNORECASE),  # MongoDB $and
            re.compile(r"\$where\s*:", re.IGNORECASE),  # MongoDB $where
            re.compile(r"\$regex\s*:", re.IGNORECASE),  # MongoDB $regex
        ]
        
        self.xss_patterns = [
            # Basic XSS patterns
            re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE),
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            re.compile(r"</script>", re.IGNORECASE),
            
            # JavaScript protocols
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"vbscript\s*:", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?text/html", re.IGNORECASE),
            re.compile(r"data\s*:[\s\S]*?base64", re.IGNORECASE),
            
            # Event handlers (comprehensive list)
            re.compile(r"on(load|click|error|focus|blur|change|submit|mouseover|mouseout|keydown|keyup|keypress)", re.IGNORECASE),
            re.compile(r"on(dblclick|mousedown|mouseup|mousemove|contextmenu|wheel)", re.IGNORECASE),
            re.compile(r"on(drag|dragstart|dragend|dragover|dragenter|dragleave|drop)", re.IGNORECASE),
            re.compile(r"on(scroll|resize|select|input|invalid|search)", re.IGNORECASE),
            re.compile(r"on(copy|cut|paste|abort|canplay|canplaythrough|durationchange)", re.IGNORECASE),
            re.compile(r"on(ended|loadeddata|loadedmetadata|loadstart|pause|play|playing)", re.IGNORECASE),
            re.compile(r"on(progress|ratechange|seeked|seeking|stalled|suspend|timeupdate)", re.IGNORECASE),
            re.compile(r"on(volumechange|waiting|animationstart|animationend|animationiteration)", re.IGNORECASE),
            re.compile(r"on(transitionend|message|open|show|toggle)", re.IGNORECASE),
            
            # Dangerous HTML tags
            re.compile(r"<iframe[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<object[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<embed[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<applet[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<meta[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<link[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<base[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<form[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<input[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<button[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<svg[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<math[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<marquee[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<audio[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<video[\s\S]*?>", re.IGNORECASE),
            re.compile(r"<style[\s\S]*?>", re.IGNORECASE),
            
            # CSS-based XSS
            re.compile(r"expression\s*\(", re.IGNORECASE),
            re.compile(r"behavior\s*:", re.IGNORECASE),
            re.compile(r"-moz-binding\s*:", re.IGNORECASE),
            re.compile(r"@import", re.IGNORECASE),
            re.compile(r"url\s*\(\s*['\"]?\s*javascript:", re.IGNORECASE),
            
            # HTML entities and encoding bypass
            re.compile(r"&[#x]?[0-9a-f]+;?", re.IGNORECASE),  # HTML entities
            re.compile(r"&#x[0-9a-f]+", re.IGNORECASE),  # Hex entities
            re.compile(r"&#\d+", re.IGNORECASE),  # Decimal entities
            
            # Attribute-based XSS
            re.compile(r"src\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"href\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"data\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"action\s*=[\s\S]*?javascript:", re.IGNORECASE),
            re.compile(r"formaction\s*=[\s\S]*?javascript:", re.IGNORECASE),
            
            # Obfuscation techniques
            re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex escaping
            re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),  # Unicode escaping
            re.compile(r"\\[0-7]{1,3}", re.IGNORECASE),  # Octal escaping
            
            # String concatenation
            re.compile(r"String\.fromCharCode", re.IGNORECASE),
            re.compile(r"eval\s*\(", re.IGNORECASE),
            re.compile(r"setTimeout\s*\(", re.IGNORECASE),
            re.compile(r"setInterval\s*\(", re.IGNORECASE),
            re.compile(r"Function\s*\(", re.IGNORECASE),
            
            # DOM-based XSS
            re.compile(r"document\.(write|writeln|cookie|location|domain)", re.IGNORECASE),
            re.compile(r"window\.(location|name|open)", re.IGNORECASE),
            re.compile(r"innerHTML|outerHTML", re.IGNORECASE),
            
            # Template injection patterns
            re.compile(r"\{\{[\s\S]*?\}\}", re.IGNORECASE),  # Angular/Vue
            re.compile(r"\${[\s\S]*?}", re.IGNORECASE),  # ES6 templates
            
            # Alert/Prompt/Confirm
            re.compile(r"(alert|prompt|confirm)\s*\(", re.IGNORECASE),
            
            # Advanced XSS evasion techniques
            re.compile(r"<\s*script", re.IGNORECASE),  # < script with space
            re.compile(r"script\s*>", re.IGNORECASE),  # script > with space
            re.compile(r"</\s*script\s*>", re.IGNORECASE),  # </ script >
            
            # HTML5 new tags and attributes
            re.compile(r"<\s*img[\s\S]*?src", re.IGNORECASE),  # IMG with src
            re.compile(r"<\s*body[\s\S]*?onload", re.IGNORECASE),  # BODY onload
            re.compile(r"<\s*img[\s\S]*?onerror", re.IGNORECASE),  # IMG onerror
            re.compile(r"<\s*input[\s\S]*?onfocus", re.IGNORECASE),  # INPUT onfocus
            
            # SVG-based XSS
            re.compile(r"<svg[\s\S]*?onload", re.IGNORECASE),  # SVG onload
            re.compile(r"<animatetransform", re.IGNORECASE),  # SVG animate
            re.compile(r"<set[\s\S]*?attributename", re.IGNORECASE),  # SVG set
            re.compile(r"<animate[\s\S]*?onbegin", re.IGNORECASE),  # SVG animate events
            
            # XML/XSLT injection
            re.compile(r"<\?xml", re.IGNORECASE),  # XML declaration
            re.compile(r"<\!DOCTYPE", re.IGNORECASE),  # DOCTYPE
            re.compile(r"<\!ENTITY", re.IGNORECASE),  # ENTITY declaration
            re.compile(r"<\!\[CDATA\[", re.IGNORECASE),  # CDATA section
            
            # JavaScript execution contexts
            re.compile(r"constructor", re.IGNORECASE),  # Constructor property
            re.compile(r"__proto__", re.IGNORECASE),  # Prototype pollution
            re.compile(r"prototype", re.IGNORECASE),  # Prototype chain
            
            # Event handler variations
            re.compile(r"onwheel\s*=", re.IGNORECASE),  # onwheel
            re.compile(r"onpointerover\s*=", re.IGNORECASE),  # onpointerover
            re.compile(r"onpointerenter\s*=", re.IGNORECASE),  # onpointerenter
            re.compile(r"onbeforescriptexecute\s*=", re.IGNORECASE),  # Firefox specific
            re.compile(r"onafterscriptexecute\s*=", re.IGNORECASE),  # Firefox specific
            
            # Filter bypass techniques
            re.compile(r"&#", re.IGNORECASE),  # HTML entities
            re.compile(r"%3C", re.IGNORECASE),  # < URL encoded
            re.compile(r"%3E", re.IGNORECASE),  # > URL encoded
            re.compile(r"\\x3c", re.IGNORECASE),  # < hex encoded
            re.compile(r"\\x3e", re.IGNORECASE),  # > hex encoded
            re.compile(r"\\u003c", re.IGNORECASE),  # < unicode
            re.compile(r"\\u003e", re.IGNORECASE),  # > unicode
            
            # Data exfiltration
            re.compile(r"fetch\s*\(", re.IGNORECASE),  # Fetch API
            re.compile(r"XMLHttpRequest", re.IGNORECASE),  # XHR
            re.compile(r"\.send\s*\(", re.IGNORECASE),  # XHR send
            re.compile(r"navigator\.", re.IGNORECASE),  # Navigator object
            re.compile(r"location\s*=", re.IGNORECASE),  # Location redirect
            re.compile(r"window\.location", re.IGNORECASE),  # Window location
            
            # WebSocket and event source
            re.compile(r"WebSocket\s*\(", re.IGNORECASE),  # WebSocket
            re.compile(r"EventSource\s*\(", re.IGNORECASE),  # Server-sent events
            
            # AngularJS specific
            re.compile(r"ng-", re.IGNORECASE),  # Angular directives
            re.compile(r"\{\{.*?\}\}", re.IGNORECASE),  # Angular expressions
            
            # React/JSX patterns
            re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),  # React XSS vector
            
            # MIME type confusion
            re.compile(r"text/html", re.IGNORECASE),  # HTML MIME type in data URLs
            re.compile(r"application/javascript", re.IGNORECASE),  # JS MIME type
        ]
        
        self.path_traversal_patterns = [
            # Basic directory traversal patterns - STRICT
            re.compile(r"\.\.[/\\]", re.IGNORECASE),  # ../ or ..\
            re.compile(r"\.\.$", re.IGNORECASE),  # .. at end
            re.compile(r"/\.\./", re.IGNORECASE),  # /../ anywhere
            re.compile(r"\\\.\.", re.IGNORECASE),  # \..
            re.compile(r"\.\./", re.IGNORECASE),  # ../
            re.compile(r"\.\.\\", re.IGNORECASE),  # ..\
            
            # URL encoded variants (single encoding)
            re.compile(r"%2e%2e[/\\]", re.IGNORECASE),  # %2e%2e/
            re.compile(r"%2e%2e%2f", re.IGNORECASE),  # %2e%2e%2f
            re.compile(r"%2e%2e%5c", re.IGNORECASE),  # %2e%2e%5c
            re.compile(r"\.\.%2f", re.IGNORECASE),  # ..%2f
            re.compile(r"\.\.%5c", re.IGNORECASE),  # ..%5c
            re.compile(r"%2e\.%2f", re.IGNORECASE),  # Mixed encoding
            re.compile(r"%2e\.%5c", re.IGNORECASE),  # Mixed encoding
            
            # Double URL encoded
            re.compile(r"%252e%252e[/\\]", re.IGNORECASE),
            re.compile(r"%252e%252e%252f", re.IGNORECASE),
            re.compile(r"%252e%252e%255c", re.IGNORECASE),
            re.compile(r"\.\.%252f", re.IGNORECASE),
            
            # Triple URL encoded
            re.compile(r"%25252e%25252e", re.IGNORECASE),
            
            # Unicode/UTF-8 encoding
            re.compile(r"%c0%ae%c0%ae[/\\]", re.IGNORECASE),
            re.compile(r"%c0%ae%c0%ae%c0%af", re.IGNORECASE),
            re.compile(r"%c0%ae%c0%ae%c1%9c", re.IGNORECASE),
            re.compile(r"%c0%2e%c0%2e[/\\]", re.IGNORECASE),
            re.compile(r"\.\xc0\xaf", re.IGNORECASE),
            re.compile(r"\xc0\xae\xc0\xae", re.IGNORECASE),
            
            # 16-bit Unicode encoding
            re.compile(r"%u002e%u002e[/\\]", re.IGNORECASE),
            re.compile(r"%%32%65%%32%65[/\\]", re.IGNORECASE),
            
            # Backslash and forward slash combinations
            re.compile(r"\.\.[/\\]+", re.IGNORECASE),
            re.compile(r"\.\.[\\/]+", re.IGNORECASE),
            re.compile(r"[/\\]+\.\.[/\\]+", re.IGNORECASE),
            
            # Null byte injection
            re.compile(r"\.\./+%00", re.IGNORECASE),
            re.compile(r"\.\.\\+%00", re.IGNORECASE),
            re.compile(r"%00", re.IGNORECASE),
            
            # Common sensitive file paths (Unix/Linux)
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"/etc/shadow", re.IGNORECASE),
            re.compile(r"/etc/hosts", re.IGNORECASE),
            re.compile(r"/etc/hostname", re.IGNORECASE),
            re.compile(r"/etc/group", re.IGNORECASE),
            re.compile(r"/etc/issue", re.IGNORECASE),
            re.compile(r"/etc/motd", re.IGNORECASE),
            re.compile(r"/etc/mysql/my\.cnf", re.IGNORECASE),
            re.compile(r"/etc/ssh/sshd_config", re.IGNORECASE),
            re.compile(r"/proc/self/environ", re.IGNORECASE),
            re.compile(r"/proc/self/cmdline", re.IGNORECASE),
            re.compile(r"/proc/self/status", re.IGNORECASE),
            re.compile(r"/proc/self/fd/", re.IGNORECASE),
            re.compile(r"/proc/version", re.IGNORECASE),
            re.compile(r"/proc/cpuinfo", re.IGNORECASE),
            re.compile(r"/var/log/", re.IGNORECASE),
            re.compile(r"/var/mail/", re.IGNORECASE),
            re.compile(r"/var/www/", re.IGNORECASE),
            re.compile(r"/usr/local/", re.IGNORECASE),
            re.compile(r"/home/[^/]+/\.ssh", re.IGNORECASE),
            re.compile(r"\.bash_history", re.IGNORECASE),
            re.compile(r"\.ssh/id_rsa", re.IGNORECASE),
            re.compile(r"\.ssh/authorized_keys", re.IGNORECASE),
            
            # Common sensitive file paths (Windows)
            re.compile(r"c:[/\\]+windows[/\\]+system32", re.IGNORECASE),
            re.compile(r"c:[/\\]+windows[/\\]+win\.ini", re.IGNORECASE),
            re.compile(r"c:[/\\]+windows[/\\]+system\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+system32", re.IGNORECASE),
            re.compile(r"boot\.ini", re.IGNORECASE),
            re.compile(r"win\.ini", re.IGNORECASE),
            re.compile(r"system\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+sam", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+system", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+software", re.IGNORECASE),
            re.compile(r"[/\\]+windows[/\\]+repair[/\\]+security", re.IGNORECASE),
            re.compile(r"[/\\]+winnt[/\\]+system32", re.IGNORECASE),
            re.compile(r"[/\\]+inetpub[/\\]+wwwroot", re.IGNORECASE),
            re.compile(r"[/\\]+boot\.ini", re.IGNORECASE),
            re.compile(r"[/\\]+autoexec\.bat", re.IGNORECASE),
            re.compile(r"[/\\]+config\.sys", re.IGNORECASE),
            
            # Absolute path attempts
            re.compile(r"^[/\\]+etc[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+proc[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+var[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+usr[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+home[/\\]", re.IGNORECASE),
            re.compile(r"^[/\\]+root[/\\]", re.IGNORECASE),
            re.compile(r"^c:[/\\]", re.IGNORECASE),
            re.compile(r"^[a-z]:[/\\]", re.IGNORECASE),
            
            # Web application specific paths
            re.compile(r"web\.config", re.IGNORECASE),
            re.compile(r"\.htaccess", re.IGNORECASE),
            re.compile(r"\.htpasswd", re.IGNORECASE),
            re.compile(r"\.env", re.IGNORECASE),
            re.compile(r"\.git[/\\]", re.IGNORECASE),
            re.compile(r"\.svn[/\\]", re.IGNORECASE),
            re.compile(r"\.DS_Store", re.IGNORECASE),
            re.compile(r"\.bash_profile", re.IGNORECASE),
            re.compile(r"\.bashrc", re.IGNORECASE),
            re.compile(r"\.profile", re.IGNORECASE),
            
            # Application config files
            re.compile(r"config\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"database\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"settings\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
            re.compile(r"app\.(php|inc|conf|cfg|xml|json|yml|yaml)", re.IGNORECASE),
        ]
        
        self.bot_patterns = [
            re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
            re.compile(r"curl|wget|python|java", re.IGNORECASE),
            re.compile(r"automated|scanner|vulnerability", re.IGNORECASE),
        ]
        
        # Command Injection patterns
        self.command_injection_patterns = [
            # Unix/Linux commands
            re.compile(r";|\||&|`|\$\(|\$\{", re.IGNORECASE),  # Command separators
            re.compile(r"cat\s+/", re.IGNORECASE),  # cat command
            re.compile(r"ls\s+", re.IGNORECASE),  # ls command
            re.compile(r"pwd", re.IGNORECASE),  # pwd command
            re.compile(r"whoami", re.IGNORECASE),  # whoami command
            re.compile(r"id\s*$", re.IGNORECASE),  # id command
            re.compile(r"uname\s*", re.IGNORECASE),  # uname command
            re.compile(r"chmod\s+", re.IGNORECASE),  # chmod command
            re.compile(r"chown\s+", re.IGNORECASE),  # chown command
            re.compile(r"wget\s+", re.IGNORECASE),  # wget command
            re.compile(r"curl\s+", re.IGNORECASE),  # curl command
            re.compile(r"nc\s+", re.IGNORECASE),  # netcat command
            re.compile(r"bash\s+", re.IGNORECASE),  # bash command
            re.compile(r"sh\s+", re.IGNORECASE),  # sh command
            re.compile(r"/bin/", re.IGNORECASE),  # Binary paths
            re.compile(r"cmd\.exe", re.IGNORECASE),  # Windows cmd
            re.compile(r"powershell", re.IGNORECASE),  # PowerShell
            re.compile(r"system\s*\(", re.IGNORECASE),  # system() call
            re.compile(r"exec\s*\(", re.IGNORECASE),  # exec() call
            re.compile(r"passthru\s*\(", re.IGNORECASE),  # PHP passthru
            re.compile(r"shell_exec\s*\(", re.IGNORECASE),  # PHP shell_exec
            re.compile(r"proc_open\s*\(", re.IGNORECASE),  # PHP proc_open
            re.compile(r"popen\s*\(", re.IGNORECASE),  # popen
            
            # Command chaining
            re.compile(r"&&", re.IGNORECASE),  # AND operator
            re.compile(r"\|\|", re.IGNORECASE),  # OR operator
            re.compile(r";\s*\w+", re.IGNORECASE),  # Semicolon separator
            
            # Redirection operators
            re.compile(r">\s*/", re.IGNORECASE),  # Output redirection
            re.compile(r"<\s*/", re.IGNORECASE),  # Input redirection
            re.compile(r">>", re.IGNORECASE),  # Append redirection
        ]
        
        # LDAP Injection patterns
        self.ldap_injection_patterns = [
            re.compile(r"\*\)", re.IGNORECASE),  # LDAP wildcard
            re.compile(r"\(\|", re.IGNORECASE),  # LDAP OR
            re.compile(r"\(&", re.IGNORECASE),  # LDAP AND
            re.compile(r"\(!", re.IGNORECASE),  # LDAP NOT
            re.compile(r"admin\)", re.IGNORECASE),  # Common LDAP injection
            re.compile(r"\)\(", re.IGNORECASE),  # Filter bypass
            re.compile(r"objectClass=\*", re.IGNORECASE),  # LDAP enumeration
        ]
        
        # XML/XXE Injection patterns
        self.xml_injection_patterns = [
            re.compile(r"<!ENTITY", re.IGNORECASE),  # Entity declaration
            re.compile(r"<!DOCTYPE", re.IGNORECASE),  # DOCTYPE declaration
            re.compile(r"SYSTEM\s+['\"]", re.IGNORECASE),  # External entity
            re.compile(r"PUBLIC\s+['\"]", re.IGNORECASE),  # Public entity
            re.compile(r"file://", re.IGNORECASE),  # File protocol
            re.compile(r"php://", re.IGNORECASE),  # PHP wrapper
            re.compile(r"expect://", re.IGNORECASE),  # Expect wrapper
            re.compile(r"data://", re.IGNORECASE),  # Data protocol
            re.compile(r"gopher://", re.IGNORECASE),  # Gopher protocol
        ]
        
        # SSRF (Server-Side Request Forgery) patterns
        self.ssrf_patterns = [
            re.compile(r"localhost", re.IGNORECASE),  # Localhost
            re.compile(r"127\.0\.0\.1", re.IGNORECASE),  # Loopback IP
            re.compile(r"0\.0\.0\.0", re.IGNORECASE),  # All interfaces
            re.compile(r"169\.254\.", re.IGNORECASE),  # Link-local
            re.compile(r"192\.168\.", re.IGNORECASE),  # Private network
            re.compile(r"10\.\d+\.\d+\.\d+", re.IGNORECASE),  # Private network
            re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", re.IGNORECASE),  # Private network
            re.compile(r"file://", re.IGNORECASE),  # File protocol
            re.compile(r"dict://", re.IGNORECASE),  # Dict protocol
            re.compile(r"ftp://", re.IGNORECASE),  # FTP protocol
            re.compile(r"gopher://", re.IGNORECASE),  # Gopher protocol
            re.compile(r"ldap://", re.IGNORECASE),  # LDAP protocol
            re.compile(r"tftp://", re.IGNORECASE),  # TFTP protocol
        ]
        
        # Template Injection patterns
        self.template_injection_patterns = [
            re.compile(r"\{\{.*?\}\}", re.IGNORECASE),  # Jinja2/Angular
            re.compile(r"\{%.*?%\}", re.IGNORECASE),  # Jinja2 statements
            re.compile(r"\$\{.*?\}", re.IGNORECASE),  # EL/OGNL
            re.compile(r"<%.*?%>", re.IGNORECASE),  # JSP/ASP
            re.compile(r"@\{.*?\}", re.IGNORECASE),  # Thymeleaf
            re.compile(r"#\{.*?\}", re.IGNORECASE),  # SpEL
        ]
        
        # RCE (Remote Code Execution) patterns
        self.rce_patterns = [
            re.compile(r"__import__", re.IGNORECASE),  # Python import
            re.compile(r"eval\s*\(", re.IGNORECASE),  # Eval function
            re.compile(r"exec\s*\(", re.IGNORECASE),  # Exec function
            re.compile(r"compile\s*\(", re.IGNORECASE),  # Compile function
            re.compile(r"os\.system", re.IGNORECASE),  # OS system
            re.compile(r"subprocess", re.IGNORECASE),  # Subprocess
            re.compile(r"Runtime\.getRuntime", re.IGNORECASE),  # Java Runtime
            re.compile(r"ProcessBuilder", re.IGNORECASE),  # Java ProcessBuilder
            re.compile(r"deserialize", re.IGNORECASE),  # Deserialization
            re.compile(r"unserialize", re.IGNORECASE),  # PHP unserialize
            re.compile(r"pickle\.loads", re.IGNORECASE),  # Python pickle
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
        features.append("Path Traversal Protection")  # Always enabled
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
        
        # Whitelist API endpoints from WAF checks to prevent self-blocking
        whitelisted_paths = [
            '/api/v1/rules/toggle',
            '/api/v1/rules/status',
            '/api/v1/statistics',
            '/api/v1/connections/active',
            '/api/v1/connections/logs',
            '/api/v1/ips/activity',
            '/api/v1/system/uptime',
            '/api/v1/blocked-ips',
            '/api/v1/event-logs',
            # '/admin/login' - REMOVED from whitelist to demonstrate WAF blocking XSS/SQL injection in login form
            '/admin/logout',     # Whitelist admin logout endpoint
            '/health',
            '/static/',
            '/favicon.ico'
        ]
        
        # Extract path from URL for whitelisting check
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_path = parsed_url.path
        
        # Check if URL path matches any whitelisted path
        for whitelisted_path in whitelisted_paths:
            if url_path.startswith(whitelisted_path) or whitelisted_path in url_path:
                # Create a simple allow event
                event_id = f"WAF_{int(time.time())}_{len(self.security_events)}"
                security_event = SecurityEvent(
                    id=event_id,
                    timestamp=datetime.now(),
                    threat_type="none",
                    threat_level=ThreatLevel.LOW,
                    source_ip=client_ip,
                    target_url=url,
                    user_agent=headers.get("User-Agent", "unknown"),
                    action_taken=ActionType.ALLOW,
                    details={"whitelisted": True, "reason": "API endpoint"}
                )
                return True, security_event
        
        # Generate unique event ID
        event_id = f"WAF_{int(time.time())}_{len(self.security_events)}"
        
        # Basic request info
        user_agent = headers.get("User-Agent", "unknown")
        
        # DDoS detection - check for suspicious patterns (only if enabled)
        ddos_indicators = {"score": 0, "indicators": []}
        if self.settings.ddos_protection:
            ddos_indicators = await self._detect_ddos_patterns(method, url, headers, user_agent, client_ip)
            # Log DDoS score for debugging
            if ddos_indicators["score"] > 0:
                print(f"🛡️ DDoS Score: {ddos_indicators['score']} for IP {client_ip} (threshold: 5)")
                print(f"   Indicators: {', '.join(ddos_indicators['indicators'])}")
        
        # Initialize security event
        security_event = SecurityEvent(
            id=event_id,
            timestamp=datetime.now(),
            threat_type="none",
            threat_level=ThreatLevel.LOW,
            source_ip=client_ip,
            target_url=url,
            user_agent=user_agent,
            action_taken=ActionType.ALLOW,
            details={"method": method, "headers": dict(headers), "ddos_score": ddos_indicators["score"]}
        )
        
        # Block if DDoS score is high (threshold: 5 to reduce false positives)
        if self.settings.ddos_protection and ddos_indicators["score"] >= 5:
            security_event.threat_type = "ddos_attack"
            security_event.threat_level = ThreatLevel.CRITICAL
            security_event.action_taken = ActionType.BLOCK
            security_event.blocked = True
            security_event.details["ddos_indicators"] = ddos_indicators["indicators"]
            
            logger.critical("DDoS attack detected", 
                          client_ip=client_ip, 
                          score=ddos_indicators["score"],
                          indicators=ddos_indicators["indicators"])
            
            self.metrics.blocked_requests += 1
            self.metrics.threats_detected += 1
            self.security_events.append(security_event)
            self._log_event_to_db(security_event)
            await self._auto_block_ip(client_ip, "DDoS attack pattern detected")
            return False, security_event
        
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
                self._log_event_to_db(security_event)
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
                    self._log_event_to_db(security_event)
                    return False, security_event
            
            # XSS detection - CHECK FIRST (more specific patterns than SQL)
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
                    self._log_event_to_db(security_event)
                    return False, security_event
            else:
                # XSS protection is disabled - log and allow
                print(f"✓ XSS Protection DISABLED - allowing request from {client_ip}")
            
            # SQL Injection detection - CHECK AFTER XSS to avoid false positives
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
                    self._log_event_to_db(security_event)
                    
                    # Auto-block IP for SQL injection attempts
                    await self._auto_block_ip(client_ip, "SQL injection attempt")
                    
                    return False, security_event
            
            # Path Traversal detection
            if self.settings.path_traversal_protection:
                path_traversal_detected = await self._detect_path_traversal(url, body)
                if path_traversal_detected:
                    security_event.threat_type = "path_traversal"
                    security_event.threat_level = ThreatLevel.CRITICAL
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = path_traversal_detected
                    
                    logger.critical("Path traversal attempt detected", 
                                  client_ip=client_ip, url=url,
                                  patterns=path_traversal_detected)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    
                    # Auto-block IP for path traversal attempts
                    await self._auto_block_ip(client_ip, "Path traversal attempt")
                    
                    return False, security_event
            
            # Authentication Bypass detection
            auth_bypass_detected = await self._detect_auth_bypass(url, body)
            if auth_bypass_detected:
                security_event.threat_type = "auth_bypass_attempt"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = auth_bypass_detected
                
                logger.critical("Authentication bypass attempt detected", 
                              client_ip=client_ip, url=url,
                              patterns=auth_bypass_detected)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                
                # Auto-block IP for auth bypass attempts
                await self._auto_block_ip(client_ip, "Authentication bypass attempt")
                
                return False, security_event
            
            # Command Injection detection
            command_injection_detected = await self._detect_command_injection(url, body)
            if command_injection_detected:
                security_event.threat_type = "command_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = command_injection_detected
                
                logger.critical("Command injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "Command injection attempt")
                return False, security_event
            
            # LDAP Injection detection
            ldap_injection_detected = await self._detect_ldap_injection(url, body)
            if ldap_injection_detected:
                security_event.threat_type = "ldap_injection"
                security_event.threat_level = ThreatLevel.HIGH
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = ldap_injection_detected
                
                logger.error("LDAP injection attempt detected", 
                           client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                return False, security_event
            
            # XML/XXE Injection detection
            xml_injection_detected = await self._detect_xml_injection(url, body)
            if xml_injection_detected:
                security_event.threat_type = "xml_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = xml_injection_detected
                
                logger.critical("XML/XXE injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "XML injection attempt")
                return False, security_event
            
            # SSRF detection (exempt internal API calls from localhost)
            is_localhost = client_ip in ['127.0.0.1', 'localhost', '::1']
            is_api_route = url.startswith('/api/v1/')
            
            if not (is_localhost and is_api_route):
                ssrf_detected = await self._detect_ssrf(url, body)
                if ssrf_detected:
                    security_event.threat_type = "ssrf_attempt"
                    security_event.threat_level = ThreatLevel.HIGH
                    security_event.action_taken = ActionType.BLOCK
                    security_event.blocked = True
                    security_event.details["detected_patterns"] = ssrf_detected
                    
                    logger.error("SSRF attempt detected", 
                               client_ip=client_ip, url=url)
                    
                    self.metrics.blocked_requests += 1
                    self.metrics.threats_detected += 1
                    self.security_events.append(security_event)
                    self._log_event_to_db(security_event)
                    return False, security_event
            
            # Template Injection detection
            template_injection_detected = await self._detect_template_injection(url, body)
            if template_injection_detected:
                security_event.threat_type = "template_injection"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = template_injection_detected
                
                logger.critical("Template injection attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "Template injection attempt")
                return False, security_event
            
            # RCE detection
            rce_detected = await self._detect_rce(url, body)
            if rce_detected:
                security_event.threat_type = "rce_attempt"
                security_event.threat_level = ThreatLevel.CRITICAL
                security_event.action_taken = ActionType.BLOCK
                security_event.blocked = True
                security_event.details["detected_patterns"] = rce_detected
                
                logger.critical("Remote Code Execution attempt detected", 
                              client_ip=client_ip, url=url)
                
                self.metrics.blocked_requests += 1
                self.metrics.threats_detected += 1
                self.security_events.append(security_event)
                self._log_event_to_db(security_event)
                await self._auto_block_ip(client_ip, "RCE attempt")
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
            self._log_event_to_db(security_event)
            
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
            block_data = self.blocked_ips[ip]
            # Handle both old datetime format and new dict format
            if isinstance(block_data, dict):
                block_time = block_data.get('blocked_at', datetime.now())
            else:
                block_time = block_data
            
            # Check if block has expired (24 hours)
            if datetime.now() - block_time > timedelta(hours=24):
                del self.blocked_ips[ip]
                return False
            return True
        return False
    
    async def _check_rate_limit(self, ip: str) -> bool:
        """Advanced rate limiting with burst detection and adaptive throttling"""
        now = datetime.now()
        window_start = now - timedelta(seconds=self.settings.rate_limit_window)
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        # Clean old requests outside the window
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip] 
            if req_time > window_start
        ]
        
        current_request_count = len(self.rate_limits[ip])
        
        # Burst detection - check for sudden spikes
        recent_window = now - timedelta(seconds=5)  # Last 5 seconds
        recent_requests = [req for req in self.rate_limits[ip] if req > recent_window]
        burst_threshold = self.settings.rate_limit_requests // 2  # 50% of limit in 5 seconds
        
        if len(recent_requests) >= burst_threshold:
            logger.warning(f"Burst attack detected from {ip}: {len(recent_requests)} requests in 5 seconds")
            # Temporarily block aggressive bursts
            await self._auto_block_ip(ip, "Burst attack - rapid request spike")
            return False
        
        # Progressive rate limiting - stricter limits as request count increases
        if current_request_count >= self.settings.rate_limit_requests:
            return False
        elif current_request_count >= (self.settings.rate_limit_requests * 0.8):
            # 80% threshold - start applying delays
            logger.info(f"IP {ip} approaching rate limit: {current_request_count}/{self.settings.rate_limit_requests}")
        
        # Distributed attack detection - check for coordinated attacks
        await self._detect_distributed_attack()
        
        # Add current request
        self.rate_limits[ip].append(now)
        return True
    
    async def _detect_distributed_attack(self):
        """Detect distributed DDoS attacks from multiple IPs"""
        now = datetime.now()
        recent_window = now - timedelta(seconds=10)
        
        # Count total requests across all IPs in last 10 seconds
        total_recent_requests = 0
        active_ips = 0
        
        for ip, requests in self.rate_limits.items():
            recent = [req for req in requests if req > recent_window]
            if recent:
                total_recent_requests += len(recent)
                active_ips += 1
        
        # DDoS threshold: 500+ requests from 10+ IPs in 10 seconds
        if total_recent_requests > 500 and active_ips >= 10:
            logger.critical(f"Distributed DDoS attack detected! {total_recent_requests} requests from {active_ips} IPs")
            # Trigger emergency mode (could notify admins, enable CAPTCHA, etc.)
            self.metrics.threats_detected += 1
        
        # Slowloris detection - many IPs with persistent connections
        if active_ips > 50:
            logger.warning(f"Potential Slowloris attack: {active_ips} concurrent connections")
    
    async def _detect_sql_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect SQL injection patterns with multiple decoding passes"""
        import urllib.parse
        import html
        detected_patterns = []
        
        # Multiple decoding passes to catch nested encoding
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode (for extreme cases)
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: HTML entity decode
        html_decoded_url = html.unescape(triple_decoded_url)
        html_decoded_body = html.unescape(triple_decoded_body)
        contents.append(f"{html_decoded_url} {html_decoded_body}")
        
        # Normalize whitespace and remove SQL comments
        for i, content in enumerate(contents):
            # Remove multiple spaces
            content = re.sub(r'\s+', ' ', content)
            # Remove SQL block comments
            content = re.sub(r'/\*.*?\*/', ' ', content)
            # Remove SQL line comments
            content = re.sub(r'--[^\n]*', ' ', content)
            # Remove null bytes
            content = content.replace('\x00', '')
            # Lowercase for case-insensitive matching
            contents[i] = content.lower()
        
        # Check all decoded versions against patterns
        for content in contents:
            for pattern in self.sql_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_xss(self, url: str, body: Optional[str]) -> List[str]:
        """Detect XSS patterns with multiple decoding passes"""
        import urllib.parse
        import html
        detected_patterns = []
        
        # Multiple decoding passes
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: HTML entity decode
        html_decoded_url = html.unescape(triple_decoded_url)
        html_decoded_body = html.unescape(triple_decoded_body)
        contents.append(f"{html_decoded_url} {html_decoded_body}")
        
        # Pass 6: Remove spaces between tags and attributes (common obfuscation)
        for i, content in enumerate(contents):
            # Normalize whitespace
            content = re.sub(r'\s+', ' ', content)
            # Remove null bytes
            content = content.replace('\x00', '')
            # Remove Unicode zero-width characters
            content = content.replace('\u200b', '').replace('\ufeff', '')
            # Lowercase for better matching
            contents[i] = content.lower()
        
        # Check all decoded versions
        for content in contents:
            for pattern in self.xss_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_path_traversal(self, url: str, body: Optional[str]) -> List[str]:
        """Detect path traversal patterns with aggressive decoding"""
        import urllib.parse
        detected_patterns = []
        
        # Multiple decoding passes for path traversal
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2: Single URL decode
        decoded_url = urllib.parse.unquote_plus(url)
        decoded_body = urllib.parse.unquote_plus(body) if body else ''
        contents.append(f"{decoded_url} {decoded_body}")
        
        # Pass 3: Double URL decode
        double_decoded_url = urllib.parse.unquote_plus(decoded_url)
        double_decoded_body = urllib.parse.unquote_plus(decoded_body)
        contents.append(f"{double_decoded_url} {double_decoded_body}")
        
        # Pass 4: Triple URL decode (path traversal often heavily encoded)
        triple_decoded_url = urllib.parse.unquote_plus(double_decoded_url)
        triple_decoded_body = urllib.parse.unquote_plus(double_decoded_body)
        contents.append(f"{triple_decoded_url} {triple_decoded_body}")
        
        # Pass 5: Quadruple decode (extreme cases)
        quad_decoded_url = urllib.parse.unquote_plus(triple_decoded_url)
        quad_decoded_body = urllib.parse.unquote_plus(triple_decoded_body)
        contents.append(f"{quad_decoded_url} {quad_decoded_body}")
        
        # Normalize paths
        for i, content in enumerate(contents):
            # Normalize slashes
            content = content.replace('\\', '/')
            # Remove null bytes
            content = content.replace('\x00', '')
            # Remove duplicate slashes
            content = re.sub(r'/+', '/', content)
            # Normalize backslashes to forward slashes for consistent matching
            content = content.replace('\\\\', '/')
            contents[i] = content.lower()
        
        # Check all decoded versions
        for content in contents:
            for pattern in self.path_traversal_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_bot(self, user_agent: str) -> Optional[str]:
        """Detect bot/crawler patterns"""
        for pattern in self.bot_patterns:
            if pattern.search(user_agent):
                return pattern.pattern.split('|')[0]  # Return first matching pattern
        return None
    
    async def _detect_command_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect command injection patterns with multi-pass decoding"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.command_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_auth_bypass(self, url: str, body: Optional[str]) -> List[str]:
        """Detect authentication bypass attempts in URL parameters"""
        import urllib.parse
        detected_patterns = []
        
        # Authentication bypass patterns (case-insensitive)
        auth_bypass_patterns = [
            re.compile(r'[?&](token|auth|api_key|apikey|key|access_token|session|sess)=', re.IGNORECASE),
            re.compile(r'[?&](password|passwd|pwd|pass)=', re.IGNORECASE),
            re.compile(r'[?&](admin|is_admin|isadmin|role|user_role|privilege)=', re.IGNORECASE),
            re.compile(r'[?&](PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sessionid)=', re.IGNORECASE),
            re.compile(r'[?&](jwt|bearer|authorization)=', re.IGNORECASE),
        ]
        
        # Check URL for authentication parameters
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in auth_bypass_patterns:
                try:
                    if pattern.search(content):
                        match = pattern.search(content)
                        if match:
                            detected_patterns.append(f"Suspicious auth parameter: {match.group(0)}")
                except Exception:
                    continue
        
        return detected_patterns
    
    async def _detect_ldap_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect LDAP injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.ldap_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_xml_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect XML/XXE injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.xml_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_ssrf(self, url: str, body: Optional[str]) -> List[str]:
        """Detect SSRF patterns - only check query parameters and body, not the URL path"""
        import urllib.parse
        detected_patterns = []
        
        # Parse URL to extract only query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_string = parsed_url.query
        
        # Only check query parameters and body content, not the path or host
        # This prevents false positives when accessing localhost:5000/protected
        contents_to_check = []
        
        if query_string:
            contents_to_check.extend(self._multi_decode(query_string, None))
        
        if body:
            contents_to_check.extend(self._multi_decode("", body))
        
        # Check for SSRF patterns only in query params and body
        for content in contents_to_check:
            for pattern in self.ssrf_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_template_injection(self, url: str, body: Optional[str]) -> List[str]:
        """Detect template injection patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.template_injection_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    async def _detect_rce(self, url: str, body: Optional[str]) -> List[str]:
        """Detect RCE patterns"""
        import urllib.parse
        detected_patterns = []
        contents = self._multi_decode(url, body)
        
        for content in contents:
            for pattern in self.rce_patterns:
                try:
                    if pattern.search(content) and pattern.pattern not in detected_patterns:
                        detected_patterns.append(pattern.pattern)
                except Exception:
                    continue
        return detected_patterns
    
    def _multi_decode(self, url: str, body: Optional[str]) -> List[str]:
        """Helper method for multiple decoding passes"""
        import urllib.parse
        import html
        contents = []
        
        # Pass 1: Original
        contents.append(f"{url} {body or ''}")
        
        # Pass 2-5: Progressive URL decoding
        decoded = f"{url} {body or ''}"
        for _ in range(4):
            decoded_url = urllib.parse.unquote_plus(decoded.split(' ')[0])
            decoded_body = urllib.parse.unquote_plus(' '.join(decoded.split(' ')[1:]))
            decoded = f"{decoded_url} {decoded_body}"
            contents.append(decoded)
        
        # Pass 6: HTML entity decode
        html_decoded = html.unescape(decoded)
        contents.append(html_decoded)
        
        # Normalize
        normalized = []
        for content in contents:
            content = re.sub(r'\s+', ' ', content)
            content = content.replace('\x00', '')
            content = content.replace('\u200b', '').replace('\ufeff', '')
            normalized.append(content.lower())
        
        return normalized
    
    async def _detect_ddos_patterns(self, method: str, url: str, headers: Dict[str, str], 
                                   user_agent: str, ip: str) -> Dict[str, Any]:
        """
        Advanced DDoS detection with multiple indicators
        Returns: {"score": int, "indicators": List[str]}
        Score >= 5 indicates likely DDoS attack
        """
        score = 0
        indicators = []
        now = datetime.now()
        
        # Whitelist localhost/loopback IPs from DDoS checks
        if ip in ['127.0.0.1', 'localhost', '::1', '0.0.0.0']:
            return {"score": 0, "indicators": ["Localhost whitelisted"]}
        
        # Initialize connection tracking for this IP
        if ip not in self.connection_table:
            self.connection_table[ip] = {
                "first_seen": now,
                "request_count": 0,
                "methods": set(),
                "unique_urls": set(),
                "user_agents": set()
            }
        
        conn = self.connection_table[ip]
        conn["request_count"] += 1
        conn["methods"].add(method)
        conn["unique_urls"].add(url)
        conn["user_agents"].add(user_agent)
        
        # 1. Empty or suspicious User-Agent (but allow legitimate browsers)
        if not user_agent or user_agent == "unknown" or user_agent == "-":
            score += 1
            indicators.append("Missing/empty User-Agent")
        elif user_agent and len(user_agent) < 10 and "Mozilla" not in user_agent:
            # Very short UA without browser signature
            score += 1
            indicators.append("Suspicious short User-Agent")
        
        # 2. Same User-Agent from many requests (botnet signature)
        if user_agent in self.user_agent_cache:
            self.user_agent_cache[user_agent] += 1
            if self.user_agent_cache[user_agent] > 100:  # Same UA 100+ times
                score += 1
                indicators.append(f"Repeated User-Agent ({self.user_agent_cache[user_agent]} times)")
        else:
            self.user_agent_cache[user_agent] = 1
        
        # 3. Suspicious request patterns
        # Same URL repeatedly (resource exhaustion)
        if ip in self.request_patterns:
            self.request_patterns[ip].append(url)
            # Keep only last 20 requests
            self.request_patterns[ip] = self.request_patterns[ip][-20:]
            
            # Check if hammering same endpoint
            if len(self.request_patterns[ip]) >= 10:
                unique_urls = len(set(self.request_patterns[ip]))
                if unique_urls <= 2:  # 10+ requests to same 1-2 URLs
                    score += 2
                    indicators.append(f"URL hammering: {unique_urls} unique URLs in {len(self.request_patterns[ip])} requests")
        else:
            self.request_patterns[ip] = [url]
        
        # 4. HTTP method flooding
        if len(conn["methods"]) > 1 and conn["request_count"] > 20:
            # Mixed methods in rapid succession (attack tool signature)
            score += 1
            indicators.append(f"Method variety: {len(conn['methods'])} different methods")
        
        # 5. Missing common headers (bot signature)
        suspicious_headers = 0
        if "accept" not in headers:
            suspicious_headers += 1
        if "accept-language" not in headers:
            suspicious_headers += 1
        if "accept-encoding" not in headers:
            suspicious_headers += 1
        
        if suspicious_headers >= 2:
            score += 1
            indicators.append(f"Missing {suspicious_headers} common headers")
        
        # 6. Unusual request frequency
        time_since_first = (now - conn["first_seen"]).total_seconds()
        if time_since_first > 0:
            requests_per_second = conn["request_count"] / time_since_first
            if requests_per_second > 10:  # More than 10 req/sec from single IP
                score += 2
                indicators.append(f"High frequency: {requests_per_second:.1f} req/sec")
        
        # 7. Slowloris detection - incomplete requests
        content_length = headers.get("content-length", "0")
        if method in ["POST", "PUT"] and content_length == "0":
            score += 1
            indicators.append("Incomplete POST/PUT request")
        
        # 8. Suspicious query strings (amplification attacks)
        if "?" in url:
            query_length = len(url.split("?", 1)[1])
            if query_length > 500:  # Very long query string
                score += 1
                indicators.append(f"Excessive query string length: {query_length} chars")
        
        # 9. Known attack tool signatures in User-Agent
        attack_tools = ["hping", "slowloris", "hulk", "rudy", "loic", "hoic", 
                       "slowhttptest", "torshammer", "pyloris", "thc-ssl-dos"]
        ua_lower = user_agent.lower()
        for tool in attack_tools:
            if tool in ua_lower:
                score += 3
                indicators.append(f"Attack tool detected: {tool}")
                break
        
        # 10. Connection header anomalies
        connection_header = headers.get("connection", "").lower()
        if "keep-alive" in connection_header and conn["request_count"] > 50:
            # Persistent connection with many requests (slow attack)
            score += 1
            indicators.append("Suspicious persistent connection pattern")
        
        # Clean up old connection data (keep last hour only)
        if (now - conn["first_seen"]).total_seconds() > 3600:
            self.connection_table[ip] = {
                "first_seen": now,
                "request_count": 1,
                "methods": {method},
                "unique_urls": {url},
                "user_agents": {user_agent}
            }
        
        return {"score": score, "indicators": indicators}
    
    async def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP address"""
        # Don't auto-block localhost for testing purposes
        if ip in ["127.0.0.1", "localhost", "::1"]:
            logger.info("Skipping auto-block for localhost", ip=ip, reason=reason)
            return
        
        self.blocked_ips[ip] = {
            'blocked_at': datetime.now(),
            'reason': reason,
            'reason_type': 'malicious',
            'attempts': 1
        }
        logger.warning("IP auto-blocked", ip=ip, reason=reason)
    
    # Management methods
    async def block_ip(self, ip: str, reason: str = "Manual block", reason_type: str = "manual"):
        """Manually block an IP address with full details"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.blocked_ips[ip] = {
                'blocked_at': datetime.now(),
                'reason': reason,
                'reason_type': reason_type,
                'attempts': 1
            }
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
            "uptime": str(datetime.now() - self.metrics.last_reset),
        }
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_id, timestamp, threat_type, threat_level, ip, 
                       url, user_agent, action, blocked, details
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            import json
            events = []
            for row in rows:
                events.append({
                    "event_id": row[0],
                    "timestamp": row[1],
                    "threat_type": row[2],
                    "threat_level": row[3],
                    "ip": row[4] or "",
                    "url": row[5],
                    "user_agent": row[6],
                    "action": row[7],
                    "blocked": bool(row[8]),
                    "details": json.loads(row[9]) if row[9] else {}
                })
            
            return events
        except Exception as e:
            logger.error("Failed to fetch events from database", error=str(e))
            # Fallback to in-memory events
            return [event.to_dict() for event in self.security_events[-limit:]]
    
    async def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IP addresses with full details"""
        blocked_list = []
        for ip, block_data in self.blocked_ips.items():
            # Handle both datetime objects and dicts
            if isinstance(block_data, dict):
                block_time = block_data.get('blocked_at', datetime.now())
                reason = block_data.get('reason', 'Unknown')
                reason_type = block_data.get('reason_type', 'manual')
                attempts = block_data.get('attempts', 1)
            else:
                # Old format: block_data is datetime
                block_time = block_data
                reason = 'Blocked'
                reason_type = 'manual'
                attempts = 1
            
            # Calculate if blocked today
            today = datetime.now().date()
            blocked_date = block_time.date() if isinstance(block_time, datetime) else today
            is_today = blocked_date == today
            
            blocked_list.append({
                "ip": ip,
                "reason": reason,
                "reason_type": reason_type,
                "blocked_at": block_time.isoformat() if isinstance(block_time, datetime) else str(block_time),
                "expires_at": (block_time + timedelta(hours=24)).isoformat() if isinstance(block_time, datetime) else "",
                "attempts": attempts,
                "country": "🌍 Unknown",
                "is_today": is_today
            })
        
        return blocked_list
    
    async def clear_all_blocked_ips(self) -> bool:
        """Clear all blocked IP addresses"""
        try:
            self.blocked_ips.clear()
            logger.info("All blocked IPs cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear blocked IPs: {e}")
            return False
    
    async def reset_metrics(self):
        """Reset WAF metrics"""
        self.metrics.reset()
        logger.info("WAF metrics reset")
    
    async def clear_events(self):
        """Clear security events history"""
        self.security_events.clear()
        self.connection_table.clear()
        self.request_patterns.clear()
        self.user_agent_cache.clear()
        logger.info("Security events and DDoS tracking data cleared")
    
    def _init_database(self):
        """Initialize database and create security_events table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create security_events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    ip TEXT,
                    url TEXT,
                    user_agent TEXT,
                    action TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    details TEXT
                )
            ''')
            
            # Create index on timestamp for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON security_events(timestamp DESC)
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully", db_path=self.db_path)
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
    
    def _log_event_to_db(self, security_event: SecurityEvent):
        """Log security event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            import json
            cursor.execute('''
                INSERT INTO security_events 
                (event_id, timestamp, threat_type, threat_level, ip, url, 
                 user_agent, action, blocked, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                security_event.id,
                security_event.timestamp.isoformat(),
                security_event.threat_type,
                security_event.threat_level.value,
                security_event.source_ip,
                security_event.target_url,
                security_event.user_agent,
                security_event.action_taken.value,
                1 if security_event.blocked else 0,
                json.dumps(security_event.details)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to log event to database", error=str(e), event_id=security_event.id)
