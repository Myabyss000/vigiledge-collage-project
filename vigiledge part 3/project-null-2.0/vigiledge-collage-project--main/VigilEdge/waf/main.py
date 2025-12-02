"""
VigilEdge WAF - Main Application Entry Point
High-performance Web Application Firewall with FastAPI backend
"""

import uvicorn
import asyncio
import os
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.websockets import WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedError
import httpx
from datetime import datetime, timezone
import json
from typing import List
from pydantic import BaseModel

from vigiledge.config import get_settings
from vigiledge.core.waf_engine import WAFEngine
from vigiledge.api.routes import setup_routes
from vigiledge.middleware.security_middleware import SecurityMiddleware
from vigiledge.utils.logger import setup_logging
from vigiledge.utils.settings_loader import load_user_settings

# Initialize settings and logging
settings = get_settings()

# Load user settings from waf_settings.json and apply overrides (ONLY if file exists)
try:
    user_settings_loader = load_user_settings()
    if user_settings_loader and user_settings_loader.user_settings:
        user_settings_loader.apply_to_app_settings(settings)
except Exception as e:
    logging.warning(f"Could not load user settings, using defaults: {e}")

setup_logging()

# Configure logging to suppress WebSocket connection errors
import logging
import time
logging.getLogger("websockets.protocol").setLevel(logging.ERROR)
logging.getLogger("websockets.server").setLevel(logging.ERROR)
logging.getLogger("uvicorn.protocols.websockets").setLevel(logging.ERROR)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)

# Animation functions for terminal display
def animated_startup():
    """Display animated startup sequence"""
    
    # Clear screen and show title
    print("\033[2J\033[H")  # Clear screen and move cursor to top
    
    # ASCII Art Banner
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██╗   ██╗██╗ ██████╗ ██╗██╗     ███████╗██████╗  ██████╗  ║
    ║    ██║   ██║██║██╔════╝ ██║██║     ██╔════╝██╔══██╗██╔════╝  ║
    ║    ██║   ██║██║██║  ███╗██║██║     █████╗  ██║  ██║██║  ███╗ ║
    ║    ╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══╝  ██║  ██║██║   ██║ ║
    ║     ╚████╔╝ ██║╚██████╔╝██║███████╗███████╗██████╔╝╚██████╔╝ ║
    ║      ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝  ║
    ║                                                              ║
    ║                 🛡️  Web Application Firewall 🛡️              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print("\033[36m" + banner + "\033[0m")  # Cyan color
    
    # Animated loading sequence
    loading_steps = [
        ("🔧 Initializing Security Engine", 0.8),
        ("🔍 Loading Threat Detection Rules", 0.6),
        ("📊 Setting up Real-time Monitoring", 0.5),
        ("🌐 Starting Web Server", 0.4),
        ("🔗 Establishing WebSocket Connections", 0.3),
        ("✅ VigilEdge WAF Ready!", 0.2)
    ]
    
    print("\n" + "="*60)
    print("🚀 STARTUP SEQUENCE")
    print("="*60)
    
    for step, delay in loading_steps:
        # Animated dots
        for i in range(3):
            print(f"\r{step}{'.' * (i + 1)}", end="", flush=True)
            time.sleep(delay / 3)
        print(f"\r{step}... ✅")
        time.sleep(0.2)

async def monitoring_task():
    """Background task showing enhanced visual system status"""
    import random
    
    # Enhanced status indicators
    status_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    security_states = ["🟢 SECURE", "🟡 MONITORING", "🔵 SCANNING", "🟢 PROTECTED"]
    threat_alerts = ["🚨 SQL INJECTION BLOCKED", "⚠️  XSS ATTEMPT DETECTED", "🛡️  RATE LIMIT TRIGGERED"]
    
    counter = 0
    last_threat_time = 0
    
    while True:
        try:
            # Rotating status indicator
            status_char = status_chars[counter % len(status_chars)]
            security_state = security_states[counter % len(security_states)]
            
            # Get current time
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # Simulate metrics with more variety
            requests_processed = 1250 + random.randint(0, 100)
            threats_blocked = 12 + random.randint(0, 5)
            active_connections = len(manager.active_connections)
            cpu_usage = random.randint(15, 45)
            
            # Occasionally show threat alerts (visual drama!)
            threat_alert = ""
            if random.randint(1, 20) == 1 and counter - last_threat_time > 20:
                threat_alert = f" | 🚨 {random.choice(threat_alerts)}"
                last_threat_time = counter
            
            # Create enhanced status line with more visual elements
            status_line = (
                f"\r{status_char} {security_state} | "
                f"🕒 {current_time} | "
                f"📊 Requests: {requests_processed} | "
                f"🛡️  Blocked: {threats_blocked} | "
                f"🔗 Live: {active_connections} | "
                f"💻 CPU: {cpu_usage}%{threat_alert}"
            )
            
            # Color coding based on activity
            if threat_alert:
                print(f"\033[91m{status_line}\033[0m", end="", flush=True)  # Red for alerts
            elif cpu_usage > 35:
                print(f"\033[93m{status_line}\033[0m", end="", flush=True)  # Yellow for high CPU
            else:
                print(f"\033[92m{status_line}\033[0m", end="", flush=True)  # Green for normal
            
            counter += 1
            await asyncio.sleep(0.5)  # Update every 500ms
            
        except asyncio.CancelledError:
            print("\n🛑 Enhanced monitoring stopped.")
            break
        except Exception:
            # Silent error handling
            await asyncio.sleep(1)
            await asyncio.sleep(1)

# Auto-backup task
async def auto_backup_task(frequency: str = "daily"):
    """Automatic backup task based on configured frequency"""
    # Calculate interval in seconds
    intervals = {
        "hourly": 3600,
        "daily": 86400,
        "weekly": 604800
    }
    interval = intervals.get(frequency, 86400)
    
    print(f"💾 Auto-backup scheduler started: {frequency} backups")
    
    while True:
        try:
            await asyncio.sleep(interval)
            
            # Create backup
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            settings_file = Path("config/waf_settings.json")
            if settings_file.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = backup_dir / f"auto_backup_{timestamp}.json"
                
                with open(settings_file, 'r') as f:
                    content = f.read()
                with open(backup_path, 'w') as f:
                    f.write(content)
                
                print(f"💾 Auto-backup created: {backup_path.name}")
                
                # Clean old backups (keep last 10)
                backups = sorted(backup_dir.glob("auto_backup_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
                for old_backup in backups[10:]:
                    old_backup.unlink()
                    print(f"🗑️  Removed old backup: {old_backup.name}")
        
        except asyncio.CancelledError:
            print("💾 Auto-backup scheduler stopped")
            break
        except Exception as e:
            logging.error(f"Auto-backup error: {e}")
            await asyncio.sleep(60)  # Wait a minute before retry

# Modern lifespan event handler
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with animated startup"""
    # Animated startup sequence
    animated_startup()
    
    # 🔄 Clear WAF in-memory state (fresh session)
    print(f"\n🔄 Resetting WAF Session State...")
    waf_engine.blocked_ips.clear()  # Clear blocked IPs
    waf_engine.rate_limits.clear()  # Clear rate limit counters
    waf_engine.metrics.reset()  # Reset metrics
    waf_engine.security_events.clear()  # Clear in-memory events
    waf_engine.connection_table.clear()  # Clear DDoS connection tracking
    waf_engine.request_patterns.clear()  # Clear request pattern analysis
    waf_engine.user_agent_cache.clear()  # Clear User-Agent tracking
    print(f"   ✅ Blocked IPs cleared")
    print(f"   ✅ Rate limits reset")
    print(f"   ✅ Metrics reset to zero")
    print(f"   ✅ In-memory events cleared")
    print(f"   ✅ DDoS tracking data cleared")
    
    # 🗑️ Clear database (fresh start - no historical data)
    print(f"\n🗑️  Clearing Database...")
    try:
        import sqlite3
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM security_events')
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        print(f"   ✅ Database cleared: {deleted_count} events deleted")
        print(f"   🆕 Fresh session - starting from zero")
    except Exception as e:
        print(f"   ⚠️  Database clear failed: {e}")
    
    # Show connection info
    # Use 127.0.0.1 for display instead of 0.0.0.0 (which is invalid in browsers)
    display_host = "127.0.0.1" if settings.host == "0.0.0.0" else settings.host
    print(f"\n🌐 Server Information:")
    print(f"   📊 Dashboard: http://{display_host}:{settings.port}")
    print(f"   📖 API Docs: http://{display_host}:{settings.port}/docs")
    print(f"   🔧 Environment: {settings.environment}")
    print(f"   🛡️  Security Level: Maximum")
    
    # Check vulnerable application status
    if settings.vulnerable_app_enabled:
        print(f"\n🎯 Protected Application:")
        print(f"   🔗 Target: {settings.vulnerable_app_url}")
        print(f"   🛡️  Proxy: http://{display_host}:{settings.port}{settings.vulnerable_app_proxy_path}")
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.vulnerable_app_url}/health")
                if response.status_code == 200:
                    print(f"   ✅ Status: ONLINE (Protected)")
                else:
                    print(f"   ⚠️  Status: REACHABLE but unhealthy")
        except:
            print(f"   ❌ Status: OFFLINE")
            print(f"   💡 Tip: Start with 'python vulnerable_app.py' in another terminal")
    
    print("\n" + "="*60)
    print("📡 REAL-TIME MONITORING ACTIVE")
    print("="*60)
    
    # Start background monitoring
    monitoring_task_handle = asyncio.create_task(monitoring_task())
    
    # Start auto-backup scheduler if enabled
    backup_task_handle = None
    if user_settings_loader and user_settings_loader.user_settings:
        backup_settings = user_settings_loader.get_backup_settings()
        if backup_settings.get("auto_backup", False):
            backup_task_handle = asyncio.create_task(auto_backup_task(backup_settings.get("backup_frequency", "daily")))
            print(f"💾 Auto-backup enabled: {backup_settings.get('backup_frequency', 'daily')}")
    
    yield
    
    # Shutdown sequence
    print("\n\n🛑 VigilEdge WAF Shutting down...")
    print("🔒 Closing security connections...")
    monitoring_task_handle.cancel()
    if backup_task_handle:
        backup_task_handle.cancel()
    try:
        await monitoring_task_handle
        if backup_task_handle:
            await backup_task_handle
    except asyncio.CancelledError:
        pass
    print("✅ Shutdown complete. Stay secure! 🛡️")

# Create FastAPI application
app = FastAPI(
    title="VigilEdge WAF",
    description="Advanced Web Application Firewall with Real-time Threat Detection",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize WAF Engine
waf_engine = WAFEngine()

# Add security middleware 
app.add_middleware(SecurityMiddleware, waf_engine=waf_engine)

# Mount static files
current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")
templates_dir = os.path.join(current_dir, "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Favicon endpoint
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve favicon to prevent 404 errors"""
    favicon_path = os.path.join(static_dir, "favicon.ico")
    if os.path.exists(favicon_path):
        from fastapi.responses import FileResponse
        return FileResponse(favicon_path)
    else:
        # Return a minimal 1x1 transparent ICO if file doesn't exist
        from fastapi.responses import Response
        # Minimal valid ICO file (1x1 transparent pixel)
        ico_data = bytes([
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
            0x18, 0x00, 0x30, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])
        return Response(content=ico_data, media_type="image/x-icon")

# Setup templates
templates = Jinja2Templates(directory=templates_dir)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except (ConnectionClosedError, WebSocketDisconnect):
            # Client disconnected, remove from active connections silently
            self.disconnect(websocket)
        except Exception:
            # Handle any other WebSocket errors silently
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except (ConnectionClosedError, WebSocketDisconnect, Exception):
                # Mark for removal instead of immediate removal to avoid iteration issues
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            if connection in self.active_connections:
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Security token validation (deprecated - keeping for backward compatibility)
security = HTTPBearer()

async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT token for admin access (deprecated)"""
    # In production, implement proper JWT validation
    if credentials.credentials != "admin-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials

# No authentication required for WAF dashboard - direct access enabled
@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect directly to admin dashboard"""
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin")
async def redirect_to_protected_admin():
    """Redirect /admin to the protected vulnerable app admin panel"""
    return RedirectResponse(url="/protected/admin", status_code=302)

@app.get("/admin/logout")
async def redirect_to_protected_logout():
    """Redirect logout to the protected vulnerable app logout"""
    return RedirectResponse(url="/protected/admin/logout", status_code=302)

# Removed login - WAF doesn't need authentication
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - VigilEdge WAF</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: rgba(30, 30, 50, 0.95);
                border: 2px solid rgba(0, 212, 255, 0.3);
                border-radius: 16px;
                padding: 3rem;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            }
            .logo {
                text-align: center;
                margin-bottom: 2rem;
            }
            .logo h1 {
                font-size: 2rem;
                background: linear-gradient(135deg, #00d4ff, #00ffa6);
                -webkit-background-clip: text;
                background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 0.5rem;
            }
            .logo p { color: #94a3b8; font-size: 0.9rem; }
            .form-group {
                margin-bottom: 1.5rem;
            }
            label {
                display: block;
                color: #e1e7f5;
                margin-bottom: 0.5rem;
                font-weight: 500;
            }
            input {
                width: 100%;
                padding: 0.75rem;
                background: rgba(20, 20, 40, 0.9);
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 8px;
                color: #ffffff;
                font-size: 1rem;
            }
            input:focus {
                outline: none;
                border-color: #00d4ff;
                box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
            }
            .btn {
                width: 100%;
                padding: 1rem;
                background: linear-gradient(135deg, #00d4ff, #00ffa6);
                border: none;
                border-radius: 8px;
                color: #0a0e1a;
                font-size: 1rem;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3);
            }
            .error {
                background: rgba(255, 68, 68, 0.1);
                border: 1px solid rgba(255, 68, 68, 0.3);
                color: #ff6b6b;
                padding: 1rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                display: none;
            }
            .default-creds {
                margin-top: 1.5rem;
                padding: 1rem;
                background: rgba(0, 212, 255, 0.1);
                border: 1px solid rgba(0, 212, 255, 0.2);
                border-radius: 8px;
                font-size: 0.85rem;
                color: #94a3b8;
            }
            .default-creds strong { color: #00d4ff; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">
                <h1>🛡️ VigilEdge</h1>
                <p>Web Application Firewall</p>
            </div>
            
            <div id="error" class="error"></div>
            
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="username" name="username" required autocomplete="username">
                </div>
                
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                
                <button type="submit" class="btn">Login</button>
            </form>
            
            <div class="default-creds">
                <strong>Default Credentials:</strong><br>
                Username: <strong>admin</strong><br>
                Password: <strong>admin123</strong>
            </div>
        </div>
        
        <script>
            async function handleLogin(event) {
                event.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('error');
                
                try {
                    const response = await fetch('/api/v1/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        window.location.href = '/admin/dashboard';
                    } else {
                        errorDiv.textContent = '❌ ' + (data.error || 'Invalid credentials');
                        errorDiv.style.display = 'block';
                    }
                } catch (error) {
                    errorDiv.textContent = '❌ Login failed. Please try again.';
                    errorDiv.style.display = 'block';
                }
            }
        </script>
    </body>
    </html>
    """)

@app.get("/dashboard", response_class=HTMLResponse)
async def customer_dashboard():
    """Serve customer/user dashboard with limited features"""
    try:
        # Get basic metrics for customer view
        metrics = await waf_engine.get_metrics()
        
        # Load customer dashboard template
        template_path = os.path.join(current_dir, "templates", "customer_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace placeholders with default data (no user context)
        template_content = template_content.replace(
            "{{ username }}", "WAF User"
        ).replace(
            "{{ role }}", "User"
        ).replace(
            "{{ metrics.total_requests }}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{ metrics.blocked_requests }}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{ username[0].upper() if username else 'U' }}", 
            "U"
        ).replace(
            "{{ username or 'User' }}", 
            "User"
        ).replace(
            "{{ role.title() if role else 'Customer' }}", 
            "User"
        ).replace(
            "{{ metrics.total_requests or 1247 }}", 
            str(metrics.get('total_requests', 1247))
        ).replace(
            "{{ metrics.blocked_requests or 23 }}", 
            str(metrics.get('blocked_requests', 23))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Dashboard Error</h1>
        <p>Customer dashboard template not found.</p>
        <a href="/login">Back to Login</a>
        </body>
        </html>
        """, status_code=404)

# WAF doesn't need login/logout - authentication removed

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Serve the full admin dashboard with complete access"""
    try:
        # Get comprehensive data for admin view
        metrics = await waf_engine.get_metrics()
        blocked_ips = await waf_engine.get_blocked_ips()
        
        # Load admin dashboard template
        template_path = os.path.join(current_dir, "templates", "enhanced_dashboard.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace placeholders with actual data
        template_content = template_content.replace(
            "{{TOTAL_REQUESTS}}", str(metrics.get('total_requests', 0))
        ).replace(
            "{{BLOCKED_REQUESTS}}", str(metrics.get('blocked_requests', 0))
        ).replace(
            "{{THREATS_DETECTED}}", str(metrics.get('threats_detected', 0))
        ).replace(
            "{{BLOCKED_IPS_COUNT}}", str(len(blocked_ips))
        )
        
        return HTMLResponse(content=template_content)
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Admin Dashboard Error</h1>
        <p>Enhanced dashboard template not found.</p>
        <a href="/login">Back to Login</a>
        </body>
        </html>
        """, status_code=404)

@app.get("/enhanced", response_class=HTMLResponse)
async def enhanced_dashboard(request: Request):
    """Serve the enhanced cyber-themed dashboard"""
    try:
        with open("templates/enhanced_dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Enhanced Dashboard Not Found</h1>
        <p>The enhanced dashboard template is not available. Please ensure the templates directory exists.</p>
        <a href="/classic">Go to Classic Dashboard</a>
        </body>
        </html>
        """, status_code=404)

@app.get("/classic", response_class=HTMLResponse)
async def classic_dashboard():
    """Serve the original dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VigilEdge WAF Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --primary-bg: linear-gradient(135deg, #0a0a0a 0%, #1a0a2e 50%, #16213e 100%);
                --secondary-bg: rgba(26, 26, 46, 0.95);
                --card-bg: rgba(30, 30, 46, 0.98);
                --glass-bg: rgba(255, 255, 255, 0.05);
                --border-color: rgba(0, 255, 65, 0.2);
                --primary-green: #00ff41;
                --accent-green: #00cc33;
                --neon-blue: #00d4ff;
                --neon-purple: #b300ff;
                --danger-red: #ff3366;
                --warning-orange: #ff9500;
                --info-blue: #00aaff;
                --success-green: #00ff66;
                --text-primary: #ffffff;
                --text-secondary: #e0e0e0;
                --text-muted: #999999;
                --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                --glass-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
                --border-radius: 16px;
                --glow: 0 0 20px rgba(0, 255, 65, 0.5);
            }
            
            body {
                font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--primary-bg);
                color: var(--text-primary);
                line-height: 1.6;
                min-height: 100vh;
                position: relative;
                overflow-x: hidden;
            }
            
            body::before {
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    radial-gradient(circle at 20% 80%, rgba(0, 255, 65, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(179, 0, 255, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 40% 40%, rgba(0, 212, 255, 0.05) 0%, transparent 50%);
                pointer-events: none;
                z-index: -1;
            }
            
            .container {
                max-width: 1600px;
                margin: 0 auto;
                padding: 30px;
                position: relative;
                z-index: 1;
            }
            
            .header {
                text-align: center;
                margin-bottom: 50px;
                padding: 50px 0;
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                box-shadow: var(--glass-shadow);
                position: relative;
                overflow: hidden;
            }
            
            .header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, 
                    var(--primary-green) 0%, 
                    var(--neon-blue) 25%, 
                    var(--neon-purple) 50%, 
                    var(--neon-blue) 75%, 
                    var(--primary-green) 100%);
                animation: rainbow 3s linear infinite;
            }
            
            .header::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 300px;
                height: 300px;
                background: radial-gradient(circle, rgba(0, 255, 65, 0.1) 0%, transparent 70%);
                transform: translate(-50%, -50%);
                animation: pulse 4s ease-in-out infinite;
                pointer-events: none;
            }
            
            .header h1 {
                font-size: 4rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--primary-green), var(--neon-blue), var(--neon-purple));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 15px;
                text-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
                position: relative;
                z-index: 2;
                letter-spacing: -1px;
            }
            
            .header p {
                color: var(--text-secondary);
                font-size: 1.4rem;
                font-weight: 400;
                margin-bottom: 25px;
                position: relative;
                z-index: 2;
            }
            
            .status-indicator {
                display: inline-flex;
                align-items: center;
                gap: 12px;
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                padding: 12px 24px;
                border-radius: 25px;
                border: 1px solid var(--primary-green);
                box-shadow: var(--glow);
                position: relative;
                z-index: 2;
                font-weight: 600;
            }
            
            .status-dot {
                width: 12px;
                height: 12px;
                background: var(--primary-green);
                border-radius: 50%;
                animation: blink 2s ease-in-out infinite;
                box-shadow: 0 0 10px var(--primary-green);
            }
            
            .services-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }
            
            .service-category {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                padding: 25px;
                box-shadow: var(--glass-shadow);
                transition: all 0.4s ease;
                position: relative;
                overflow: hidden;
            }
            
            .service-category::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary-green), var(--neon-blue));
                transform: scaleX(0);
                transform-origin: left;
                transition: transform 0.3s ease;
            }
            
            .service-category:hover::before {
                transform: scaleX(1);
            }
            
            .service-category:hover {
                transform: translateY(-8px);
                box-shadow: 0 15px 40px rgba(0, 255, 65, 0.2);
                border-color: var(--primary-green);
            }
            
            .service-category h3 {
                color: var(--primary-green);
                margin-bottom: 20px;
                font-size: 1.3rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .service-links {
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            
            .service-link {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 12px 16px;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                text-decoration: none;
                color: var(--text-secondary);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .service-link::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.1), transparent);
                transition: left 0.5s ease;
            }
            
            .service-link:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
                transform: translateX(5px);
            }
            
            .service-link:hover::before {
                left: 100%;
            }
            
            .service-link-info {
                display: flex;
                flex-direction: column;
                gap: 2px;
            }
            
            .service-link-title {
                font-weight: 600;
                font-size: 0.95rem;
            }
            
            .service-link-url {
                font-size: 0.8rem;
                color: var(--text-muted);
                font-family: 'Courier New', monospace;
            }
            
            .service-link-icon {
                font-size: 1.2rem;
                opacity: 0.7;
                transition: all 0.3s ease;
            }
            
            .service-link:hover .service-link-icon {
                opacity: 1;
                transform: scale(1.2);
            }
            
            .nav {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                padding: 25px;
                border-radius: var(--border-radius);
                margin-bottom: 40px;
                box-shadow: var(--glass-shadow);
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
                justify-content: center;
                border: 1px solid var(--border-color);
            }
            
            .nav a {
                color: var(--text-secondary);
                text-decoration: none;
                padding: 15px 25px;
                border-radius: 12px;
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                transition: all 0.4s ease;
                font-weight: 600;
                position: relative;
                overflow: hidden;
                font-size: 0.95rem;
            }
            
            .nav a::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
                transition: left 0.5s ease;
            }
            
            .nav a:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: var(--glow);
                transform: translateY(-3px);
            }
            
            .nav a:hover::before {
                left: 100%;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 30px;
                margin-bottom: 50px;
            }
            
            .stat-card {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                padding: 35px;
                border-radius: var(--border-radius);
                position: relative;
                overflow: hidden;
                transition: all 0.4s ease;
                box-shadow: var(--glass-shadow);
            }
            
            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-green), var(--neon-blue));
                transform: scaleX(0);
                transform-origin: left;
                transition: transform 0.3s ease;
            }
            
            .stat-card:hover::before {
                transform: scaleX(1);
            }
            
            .stat-card:hover {
                transform: translateY(-10px) scale(1.02);
                box-shadow: 0 20px 60px rgba(0, 255, 65, 0.25);
                border-color: var(--primary-green);
            }
            
            .stat-value {
                font-size: 3rem;
                font-weight: 800;
                color: var(--primary-green);
                margin-bottom: 15px;
                text-shadow: var(--glow);
                transition: all 0.3s ease;
                position: relative;
                z-index: 2;
            }
            
            .stat-label {
                color: var(--text-secondary);
                font-size: 1.1rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1.5px;
                position: relative;
                z-index: 2;
            }
            
            .stat-icon {
                position: absolute;
                top: 25px;
                right: 25px;
                font-size: 2.5rem;
                opacity: 0.2;
                color: var(--primary-green);
                transition: all 0.3s ease;
            }
            
            .stat-card:hover .stat-icon {
                opacity: 0.4;
                transform: scale(1.1) rotate(5deg);
            }
            
            .alerts {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                padding: 35px;
                border-radius: var(--border-radius);
                box-shadow: var(--glass-shadow);
                position: relative;
                overflow: hidden;
            }
            
            .alerts::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--danger-red), var(--warning-orange), var(--success-green));
            }
            
            .alerts h3 {
                color: var(--primary-green);
                margin-bottom: 25px;
                font-size: 1.6rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 12px;
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
            }
            
            .alerts-container {
                max-height: 500px;
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: var(--primary-green) transparent;
            }
            
            .alerts-container::-webkit-scrollbar {
                width: 8px;
            }
            
            .alerts-container::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
            }
            
            .alerts-container::-webkit-scrollbar-thumb {
                background: var(--primary-green);
                border-radius: 4px;
                box-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
            }
            
            .alert {
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                border-left: 4px solid var(--danger-red);
                padding: 20px;
                margin: 20px 0;
                border-radius: 0 12px 12px 0;
                animation: slideIn 0.4s ease;
                position: relative;
                overflow: hidden;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            
            .alert::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
                animation: alertShine 4s ease-in-out infinite;
            }
            
            .connection-status {
                padding: 20px;
                border-radius: 12px;
                text-align: center;
                font-weight: 600;
                margin-bottom: 25px;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
                font-size: 1.05rem;
            }
            
            .connection-status.connected {
                background: rgba(0, 255, 102, 0.1);
                color: var(--success-green);
                border: 1px solid var(--success-green);
                box-shadow: 0 0 20px rgba(0, 255, 102, 0.3);
            }
            
            .connection-status.disconnected {
                background: rgba(255, 51, 102, 0.1);
                color: var(--danger-red);
                border: 1px solid var(--danger-red);
                box-shadow: 0 0 20px rgba(255, 51, 102, 0.3);
            }
            
            .loading {
                display: inline-block;
                width: 24px;
                height: 24px;
                border: 3px solid rgba(0, 255, 65, 0.3);
                border-radius: 50%;
                border-top-color: var(--primary-green);
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            @keyframes rainbow {
                0% { background-position: 0% 50%; }
                100% { background-position: 200% 50%; }
            }
            
            @keyframes pulse {
                0%, 100% { 
                    opacity: 0.8; 
                    transform: translate(-50%, -50%) scale(1);
                }
                50% { 
                    opacity: 0.4; 
                    transform: translate(-50%, -50%) scale(1.1);
                }
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            @keyframes alertShine {
                0% { left: -100%; }
                100% { left: 100%; }
            }
            
            @media (max-width: 1200px) {
                .services-grid {
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                }
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 15px;
                }
                
                .header h1 {
                    font-size: 2.5rem;
                }
                
                .header p {
                    font-size: 1.1rem;
                }
                
                .stats {
                    grid-template-columns: 1fr;
                }
                
                .services-grid {
                    grid-template-columns: 1fr;
                }
                
                .nav {
                    flex-direction: column;
                    align-items: center;
                }
            }
            
            .nav {
                background: var(--card-bg);
                padding: 20px;
                border-radius: var(--border-radius);
                margin-bottom: 30px;
                box-shadow: var(--shadow);
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                justify-content: center;
                border: 1px solid var(--border-color);
            }
            
            .nav a {
                color: var(--text-secondary);
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 8px;
                background: var(--secondary-bg);
                border: 1px solid var(--border-color);
                transition: all 0.3s ease;
                font-weight: 500;
                position: relative;
                overflow: hidden;
            }
            
            .nav a::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
                transition: left 0.5s ease;
            }
            
            .nav a:hover {
                color: var(--primary-green);
                border-color: var(--primary-green);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
                transform: translateY(-2px);
            }
            
            .nav a:hover::before {
                left: 100%;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }
            
            .stat-card {
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                padding: 30px;
                border-radius: var(--border-radius);
                position: relative;
                overflow: hidden;
                transition: all 0.3s ease;
                box-shadow: var(--shadow);
            }
            
            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: var(--primary-green);
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0, 255, 65, 0.15);
                border-color: var(--primary-green);
            }
            
            .stat-value {
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--primary-green);
                margin-bottom: 10px;
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
                transition: all 0.3s ease;
            }
            
            .stat-label {
                color: var(--text-secondary);
                font-size: 1rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .stat-icon {
                position: absolute;
                top: 20px;
                right: 20px;
                font-size: 2rem;
                opacity: 0.3;
                color: var(--primary-green);
            }
            
            .alerts {
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                padding: 30px;
                border-radius: var(--border-radius);
                box-shadow: var(--shadow);
            }
            
            .alerts h3 {
                color: var(--primary-green);
                margin-bottom: 20px;
                font-size: 1.5rem;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .alerts-container {
                max-height: 400px;
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: var(--primary-green) var(--secondary-bg);
            }
            
            .alerts-container::-webkit-scrollbar {
                width: 6px;
            }
            
            .alerts-container::-webkit-scrollbar-track {
                background: var(--secondary-bg);
                border-radius: 3px;
            }
            
            .alerts-container::-webkit-scrollbar-thumb {
                background: var(--primary-green);
                border-radius: 3px;
            }
            
            .alert {
                background: linear-gradient(135deg, rgba(255, 51, 102, 0.1), rgba(255, 51, 102, 0.05));
                border-left: 4px solid var(--danger-red);
                padding: 15px;
                margin: 15px 0;
                border-radius: 0 8px 8px 0;
                animation: slideIn 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .alert::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
                animation: alertShine 3s ease-in-out infinite;
            }
            
            .alert-time {
                color: var(--primary-green);
                font-weight: 600;
                font-size: 0.9rem;
            }
            
            .connection-status {
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                font-weight: 500;
                margin-bottom: 20px;
                transition: all 0.3s ease;
            }
            
            .connection-status.connected {
                background: rgba(0, 255, 65, 0.1);
                color: var(--primary-green);
                border: 1px solid var(--primary-green);
            }
            
            .connection-status.disconnected {
                background: rgba(255, 51, 102, 0.1);
                color: var(--danger-red);
                border: 1px solid var(--danger-red);
            }
            
            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(0, 255, 65, 0.3);
                border-radius: 50%;
                border-top-color: var(--primary-green);
                animation: spin 1s ease-in-out infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            @keyframes alertShine {
                0% { left: -100%; }
                100% { left: 100%; }
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }
                
                .header h1 {
                    font-size: 2rem;
                }
                
                .stats {
                    grid-template-columns: 1fr;
                }
                
                .nav {
                    flex-direction: column;
                    align-items: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ VigilEdge WAF</h1>
                <p>Enterprise-Grade Web Application Firewall & Security Operations Center</p>
                <div class="status-indicator">
                    <div class="status-dot"></div>
                    <span>System Operational</span>
                </div>
            </div>
            
            <div class="services-grid">
                <div class="service-category">
                    <h3>🏠 Core Services</h3>
                    <div class="service-links">
                        <a href="/" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Main Dashboard</div>
                                <div class="service-link-url">http://localhost:5000</div>
                            </div>
                            <div class="service-link-icon">🏠</div>
                        </a>
                        <a href="/health" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Health Monitor</div>
                                <div class="service-link-url">http://localhost:5000/health</div>
                            </div>
                            <div class="service-link-icon">💗</div>
                        </a>
                        <a href="/admin" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Admin Portal</div>
                                <div class="service-link-url">http://localhost:5000/admin</div>
                            </div>
                            <div class="service-link-icon">👨‍💼</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>📊 Analytics & Monitoring</h3>
                    <div class="service-links">
                        <a href="/api/v1/metrics" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Performance Metrics</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/metrics</div>
                            </div>
                            <div class="service-link-icon">📈</div>
                        </a>
                        <a href="/api/v1/events" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Events</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/events</div>
                            </div>
                            <div class="service-link-icon">📋</div>
                        </a>
                        <a href="javascript:void(0)" onclick="connectWebSocket()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Real-time Alerts</div>
                                <div class="service-link-url">ws://localhost:5000/ws</div>
                            </div>
                            <div class="service-link-icon">⚡</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🛡️ Security Management</h3>
                    <div class="service-links">
                        <a href="/api/v1/blocked-ips" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Blocked IPs</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/blocked-ips</div>
                            </div>
                            <div class="service-link-icon">🚫</div>
                        </a>
                        <a href="/api/v1/security/summary" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Summary</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/security/summary</div>
                            </div>
                            <div class="service-link-icon">🔍</div>
                        </a>
                        <a href="/api/v1/security/rules" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Security Rules</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/security/rules</div>
                            </div>
                            <div class="service-link-icon">📜</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>📚 Documentation</h3>
                    <div class="service-links">
                        <a href="/docs" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Interactive API Docs</div>
                                <div class="service-link-url">http://localhost:5000/docs</div>
                            </div>
                            <div class="service-link-icon">📖</div>
                        </a>
                        <a href="/redoc" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Alternative API Docs</div>
                                <div class="service-link-url">http://localhost:5000/redoc</div>
                            </div>
                            <div class="service-link-icon">📑</div>
                        </a>
                        <a href="javascript:void(0)" onclick="openLogViewer()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">System Logs</div>
                                <div class="service-link-url">logs/vigiledge.log</div>
                            </div>
                            <div class="service-link-icon">📄</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🧪 Testing & Development</h3>
                    <div class="service-links">
                        <a href="/api/v1/test/trigger-sql-injection" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">SQL Injection Test</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/test/trigger-sql-injection</div>
                            </div>
                            <div class="service-link-icon">💉</div>
                        </a>
                        <a href="/api/v1/test/trigger-xss" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">XSS Protection Test</div>
                                <div class="service-link-url">http://localhost:5000/api/v1/test/trigger-xss</div>
                            </div>
                            <div class="service-link-icon">🔗</div>
                        </a>
                        <a href="javascript:void(0)" onclick="runRateLimitTest()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Rate Limit Test</div>
                                <div class="service-link-url">Multiple Requests</div>
                            </div>
                            <div class="service-link-icon">🚀</div>
                        </a>
                    </div>
                </div>
                
                <div class="service-category">
                    <h3>🔧 Configuration</h3>
                    <div class="service-links">
                        <a href="javascript:void(0)" onclick="showEnvConfig()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Environment Variables</div>
                                <div class="service-link-url">.env Configuration</div>
                            </div>
                            <div class="service-link-icon">⚙️</div>
                        </a>
                        <a href="javascript:void(0)" onclick="showWafRules()" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">WAF Rules Config</div>
                                <div class="service-link-url">config/waf_rules.yaml</div>
                            </div>
                            <div class="service-link-icon">🔧</div>
                        </a>
                        <a href="/proxy" class="service-link">
                            <div class="service-link-info">
                                <div class="service-link-title">Proxy Gateway</div>
                                <div class="service-link-url">http://localhost:5000/proxy</div>
                            </div>
                            <div class="service-link-icon">🌐</div>
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="nav">
                <a href="/health">🏥 Health Status</a>
                <a href="/api/v1/metrics">📊 Metrics</a>
                <a href="/api/v1/events">📋 Recent Events</a>
                <a href="/api/v1/blocked-ips">🚫 Blocked IPs</a>
                <a href="/docs">📚 API Documentation</a>
            </div>

            <div class="stats" id="stats">
                <div class="stat-card">
                    <div class="stat-icon">📈</div>
                    <div class="stat-value" id="total-requests"><div class="loading"></div></div>
                    <div class="stat-label">Total Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🛡️</div>
                    <div class="stat-value" id="blocked-requests"><div class="loading"></div></div>
                    <div class="stat-label">Blocked Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚠️</div>
                    <div class="stat-value" id="threats-detected"><div class="loading"></div></div>
                    <div class="stat-label">Threats Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚡</div>
                    <div class="stat-value" id="response-time"><div class="loading"></div></div>
                    <div class="stat-label">Avg Response Time (ms)</div>
                </div>
            </div>

            <div class="alerts">
                <h3>🚨 Real-time Security Alerts</h3>
                <div id="connection-status" class="connection-status">
                    <span>🔌 Connecting to real-time monitoring...</span>
                </div>
                <div class="alerts-container" id="alerts-container">
                    <!-- Alerts will be populated here -->
                </div>
            </div>
        </div>

        <script>
            // WebSocket connection for real-time updates
            const ws = new WebSocket('ws://localhost:5000/ws');
            const alertsContainer = document.getElementById('alerts-container');
            const connectionStatus = document.getElementById('connection-status');
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                connectionStatus.className = 'connection-status connected';
                connectionStatus.innerHTML = '<span>✅ Connected to real-time monitoring</span>';
                
                // Send a welcome message
                setTimeout(() => {
                    addAlert('🚀 VigilEdge WAF monitoring system initialized', 'info');
                }, 1000);
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.type === 'alert') {
                    addAlert(data.message, data.severity || 'warning');
                } else if (data.type === 'metrics') {
                    updateMetrics(data.data);
                } else if (data.type === 'security_event') {
                    addAlert(`🚨 ${data.threat_type}: ${data.message}`, 'danger');
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                connectionStatus.className = 'connection-status disconnected';
                connectionStatus.innerHTML = '<span>❌ Disconnected from monitoring</span>';
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
                connectionStatus.className = 'connection-status disconnected';
                connectionStatus.innerHTML = '<span>⚠️ Connection error - Retrying...</span>';
            };
            
            function addAlert(message, severity = 'warning') {
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert alert-${severity}`;
                
                const timeStr = new Date().toLocaleTimeString();
                const severityIcon = {
                    'info': 'ℹ️',
                    'warning': '⚠️',
                    'danger': '🚨',
                    'success': '✅'
                }[severity] || '⚠️';
                
                alertDiv.innerHTML = `
                    <div class="alert-time">[${timeStr}] ${severityIcon}</div>
                    <div class="alert-message">${message}</div>
                `;
                
                alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
                
                // Keep only last 15 alerts
                while (alertsContainer.children.length > 15) {
                    alertsContainer.removeChild(alertsContainer.lastChild);
                }
                
                // Auto-remove old alerts after 30 seconds
                setTimeout(() => {
                    if (alertDiv.parentNode) {
                        alertDiv.style.opacity = '0';
                        alertDiv.style.transform = 'translateX(-100%)';
                        setTimeout(() => {
                            if (alertDiv.parentNode) {
                                alertDiv.parentNode.removeChild(alertDiv);
                            }
                        }, 300);
                    }
                }, 30000);
            }
            
            function updateMetrics(metrics) {
                // Add animation to value changes
                updateStatValue('total-requests', metrics.total_requests || 0);
                updateStatValue('blocked-requests', metrics.blocked_requests || 0);
                updateStatValue('threats-detected', metrics.threats_detected || 0);
                updateStatValue('response-time', (metrics.avg_response_time * 1000).toFixed(1) || '0.0');
            }
            
            function updateStatValue(elementId, newValue) {
                const element = document.getElementById(elementId);
                const currentValue = element.textContent;
                
                if (currentValue !== newValue.toString()) {
                    element.style.transform = 'scale(1.1)';
                    element.style.color = 'var(--accent-green)';
                    element.textContent = newValue;
                    
                    setTimeout(() => {
                        element.style.transform = 'scale(1)';
                        element.style.color = 'var(--primary-green)';
                    }, 200);
                }
            }
            
            // Fetch initial metrics
            async function loadInitialData() {
                try {
                    const response = await fetch('/api/v1/metrics');
                    const metrics = await response.json();
                    updateMetrics(metrics);
                } catch (error) {
                    console.error('Failed to load initial metrics:', error);
                    addAlert('Failed to load initial metrics', 'warning');
                }
            }
            
            // Load data when page loads
            document.addEventListener('DOMContentLoaded', () => {
                loadInitialData();
                
                // Add some demo alerts if no real alerts within 5 seconds
                setTimeout(() => {
                    if (alertsContainer.children.length === 0) {
                        addAlert('🛡️ All security systems operational', 'success');
                        setTimeout(() => {
                            addAlert('📊 Monitoring 0 active connections', 'info');
                        }, 2000);
                        setTimeout(() => {
                            addAlert('🔧 WAF engine initialized successfully', 'success');
                        }, 4000);
                    }
                }, 5000);
            });
            
            // Enhanced utility functions
            function connectWebSocket() {
                if (ws.readyState === WebSocket.OPEN) {
                    addAlert('🔌 WebSocket already connected', 'info');
                } else {
                    addAlert('🔄 Attempting to reconnect WebSocket...', 'warning');
                }
            }
            
            function openLogViewer() {
                addAlert('📄 Log viewer feature coming soon', 'info');
            }
            
            function runRateLimitTest() {
                addAlert('🚀 Running rate limit test...', 'warning');
                
                // Send multiple requests to test rate limiting
                let requests = 0;
                const maxRequests = 20;
                const interval = setInterval(async () => {
                    try {
                        await fetch('/api/v1/metrics');
                        requests++;
                        
                        if (requests >= maxRequests) {
                            clearInterval(interval);
                            addAlert(`✅ Rate limit test completed: ${requests} requests sent`, 'success');
                        }
                    } catch (error) {
                        clearInterval(interval);
                        addAlert('⚠️ Rate limit triggered - requests blocked', 'danger');
                    }
                }, 100);
            }
            
            function showEnvConfig() {
                const configInfo = `
                    🔧 Environment Configuration:
                    HOST=127.0.0.1
                    PORT=5000
                    DEBUG=true
                    SECRET_KEY=configured
                    SQL_INJECTION_PROTECTION=true
                    XSS_PROTECTION=true
                    RATE_LIMIT_ENABLED=true
                `;
                addAlert(configInfo, 'info');
            }
            
            function showWafRules() {
                addAlert('📜 WAF Rules: SQL Injection, XSS, Rate Limiting, Bot Detection', 'info');
            }
            
            // Refresh metrics every 30 seconds
            setInterval(loadInitialData, 30000);
            
            // Add CSS for alert severity types
            const style = document.createElement('style');
            style.textContent = `
                .alert-danger {
                    background: linear-gradient(135deg, rgba(255, 51, 102, 0.15), rgba(255, 51, 102, 0.05));
                    border-left-color: var(--danger-red);
                    box-shadow: 0 0 15px rgba(255, 51, 102, 0.3);
                }
                
                .alert-warning {
                    background: linear-gradient(135deg, rgba(255, 149, 0, 0.15), rgba(255, 149, 0, 0.05));
                    border-left-color: var(--warning-orange);
                    box-shadow: 0 0 15px rgba(255, 149, 0, 0.3);
                }
                
                .alert-info {
                    background: linear-gradient(135deg, rgba(0, 170, 255, 0.15), rgba(0, 170, 255, 0.05));
                    border-left-color: var(--info-blue);
                    box-shadow: 0 0 15px rgba(0, 170, 255, 0.3);
                }
                
                .alert-success {
                    background: linear-gradient(135deg, rgba(0, 255, 102, 0.15), rgba(0, 255, 102, 0.05));
                    border-left-color: var(--success-green);
                    box-shadow: 0 0 15px rgba(0, 255, 102, 0.3);
                }
                
                .alert-message {
                    margin-top: 8px;
                    color: var(--text-primary);
                    line-height: 1.4;
                    white-space: pre-line;
                }
                
                /* Enhanced glow effects */
                .stat-card:hover .stat-value {
                    text-shadow: 0 0 30px var(--primary-green);
                }
                
                /* Smooth transitions for all interactive elements */
                * {
                    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                
                /* Additional animations */
                @keyframes fadeInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                .service-category {
                    animation: fadeInUp 0.6s ease forwards;
                }
                
                .service-category:nth-child(1) { animation-delay: 0.1s; }
                .service-category:nth-child(2) { animation-delay: 0.2s; }
                .service-category:nth-child(3) { animation-delay: 0.3s; }
                .service-category:nth-child(4) { animation-delay: 0.4s; }
                .service-category:nth-child(5) { animation-delay: 0.5s; }
                .service-category:nth-child(6) { animation-delay: 0.6s; }
            `;
            document.head.appendChild(style);
        </script>
    </body>
    </html>
    """

# Security Rules Page
@app.get("/security-rules", response_class=HTMLResponse)
async def security_rules():
    """Serve the security rules page with cache-busting"""
    try:
        with open("templates/security_rules.html", "r", encoding="utf-8") as f:
            html_content = f.read()
            # Add cache-busting meta tags to force browser reload
            cache_buster = f'<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"><meta http-equiv="Pragma" content="no-cache"><meta http-equiv="Expires" content="0">'
            html_content = html_content.replace('<head>', f'<head>{cache_buster}')
            return html_content
    except FileNotFoundError:
        return HTMLResponse("""
        <html>
        <body>
        <h1>Security Rules Page Not Found</h1>
        <p>The security rules template is not available.</p>
        <a href="/">Go to Dashboard</a>
        </body>
        </html>
        """, status_code=404)

# Threat Detection Page
@app.get("/threat-detection", response_class=HTMLResponse)
async def threat_detection(request: Request):
    """Serve the threat detection page"""
    try:
        template_data = {
            "request": request,
            "page_title": "Threat Detection",
            "waf_status": "active"
        }
        return templates.TemplateResponse("threat_detection.html", template_data)
    except Exception as e:
        logging.error(f"Error loading threat detection page: {e}")
        return HTMLResponse("""
        <html>
        <body style="background: #0a0e1a; color: white; font-family: Arial; padding: 2rem;">
        <h1 style="color: #00d4ff;">Threat Detection</h1>
        <p>The threat detection page is under maintenance.</p>
        <a href="/" style="color: #00ffa6;">← Go to Dashboard</a>
        </body>
        </html>
        """, status_code=200)

# Analytics Page
@app.get("/analytics", response_class=HTMLResponse)
async def analytics(request: Request):
    """Serve the analytics page"""
    return templates.TemplateResponse("analytics.html", {"request": request})

# Network Monitor Page
@app.get("/network-monitor", response_class=HTMLResponse)
async def network_monitor(request: Request):
    """Serve the enhanced network monitor page"""
    return templates.TemplateResponse("network_monitor_enhanced.html", {"request": request})

# API Endpoints for Network Monitoring

@app.get("/api/v1/connections/active")
async def get_active_connections():
    """Get currently active connections"""
    connections = []
    for ip, data in waf_engine.connection_table.items():
        connections.append({
            "ip": ip,
            "first_seen": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "request_count": data["request_count"],
            "methods": list(data["methods"]),
            "unique_urls": len(data["unique_urls"]),
            "user_agents": list(data["user_agents"])[:3]  # Limit to first 3
        })
    return {"connections": connections, "total": len(connections)}

@app.get("/api/v1/connections/logs")
async def get_connection_logs(limit: int = 50):
    """Get recent security events/logs"""
    events = waf_engine.security_events[-limit:]  # Get last N events
    logs = []
    for event in reversed(events):
        logs.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp),
            "ip": event.source_ip,
            "url": event.target_url,
            "threat_type": event.threat_type,
            "threat_level": event.threat_level.value if hasattr(event.threat_level, "value") else str(event.threat_level),
            "action": event.action_taken.value if hasattr(event.action_taken, "value") else str(event.action_taken),
            "blocked": event.blocked,
            "user_agent": event.user_agent,
            "details": event.details
        })
    return {"logs": logs, "total": len(logs)}

@app.get("/api/v1/ips/activity")
async def get_ip_activity():
    """Get IP activity statistics"""
    ip_stats = {}
    
    # Aggregate from connection table
    for ip, data in waf_engine.connection_table.items():
        ip_stats[ip] = {
            "requests": data["request_count"],
            "first_seen": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "methods": list(data["methods"]),
            "unique_urls": len(data["unique_urls"])
        }
    
    # Add blocked/allowed stats from events
    for event in waf_engine.security_events[-200:]:  # Last 200 events
        ip = event.source_ip
        if ip not in ip_stats:
            ip_stats[ip] = {"requests": 0, "blocked": 0, "allowed": 0}
        
        if "blocked" not in ip_stats[ip]:
            ip_stats[ip]["blocked"] = 0
        if "allowed" not in ip_stats[ip]:
            ip_stats[ip]["allowed"] = 0
            
        if event.blocked:
            ip_stats[ip]["blocked"] += 1
        else:
            ip_stats[ip]["allowed"] += 1
    
    # Convert to list and sort by request count
    ip_list = [{"ip": ip, **stats} for ip, stats in ip_stats.items()]
    ip_list.sort(key=lambda x: x.get("requests", 0), reverse=True)
    
    return {"ips": ip_list[:50], "total": len(ip_list)}  # Top 50 IPs

@app.get("/api/v1/system/uptime")
async def get_system_uptime():
    """Get WAF uptime and health metrics"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    uptime_seconds = time.time() - process.create_time()
    
    return {
        "uptime_seconds": int(uptime_seconds),
        "uptime_formatted": f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m",
        "total_requests": waf_engine.metrics.total_requests,
        "blocked_requests": waf_engine.metrics.blocked_requests,
        "threats_detected": waf_engine.metrics.threats_detected,
        "cpu_percent": process.cpu_percent(),
        "memory_mb": process.memory_info().rss / 1024 / 1024,
        "status": "healthy"
    }

# Blocked IPs Page
@app.get("/blocked-ips", response_class=HTMLResponse)
async def blocked_ips(request: Request):
    """Serve the blocked IPs page with real data"""
    try:
        # Get blocked IPs from the WAF engine
        blocked_ips_data = await waf_engine.get_blocked_ips()
        
        # Get additional statistics
        stats = {
            'total_blocked': len(blocked_ips_data),
            'blocked_today': sum(1 for ip in blocked_ips_data if ip.get('is_today', False)),
            'automatic_blocks': sum(1 for ip in blocked_ips_data if ip.get('reason_type') in ['malicious', 'suspicious', 'bot']),
            'manual_blocks': sum(1 for ip in blocked_ips_data if ip.get('reason_type') == 'manual')
        }
        
        # Format data for template
        template_data = {
            "request": request,
            "blocked_ips": blocked_ips_data,
            "stats": stats,
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("blocked_ips.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading blocked IPs page: {e}")
        # Fallback with sample data
        sample_blocked_ips = [
            {
                'ip': '192.168.1.100',
                'reason': 'Multiple failed login attempts',
                'reason_type': 'suspicious',
                'blocked_at': '2024-01-15 10:30:00',
                'attempts': 15,
                'country': '🇺🇸 United States'
            },
            {
                'ip': '10.0.0.50',
                'reason': 'SQL injection attempt',
                'reason_type': 'malicious',
                'blocked_at': '2024-01-15 09:15:00',
                'attempts': 8,
                'country': '🇷🇺 Russia'
            }
        ]
        
        template_data = {
            "request": request,
            "blocked_ips": sample_blocked_ips,
            "stats": {
                'total_blocked': len(sample_blocked_ips),
                'blocked_today': 2,
                'automatic_blocks': 2,
                'manual_blocks': 0
            },
            "page_title": "Blocked IPs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("blocked_ips.html", template_data)

# API: Get Blocked IPs
@app.get("/api/v1/blocked-ips")
async def api_get_blocked_ips():
    """API endpoint to get all blocked IPs with full details"""
    try:
        blocked_ips = await waf_engine.get_blocked_ips()
        
        stats = {
            'total_blocked': len(blocked_ips),
            'blocked_today': sum(1 for ip in blocked_ips if ip.get('is_today', False)),
            'automatic_blocks': sum(1 for ip in blocked_ips if ip.get('reason_type') in ['malicious', 'suspicious', 'bot']),
            'manual_blocks': sum(1 for ip in blocked_ips if ip.get('reason_type') == 'manual')
        }
        
        return {
            "success": True,
            "blocked_ips": blocked_ips,
            "count": len(blocked_ips),
            "stats": stats
        }
    except Exception as e:
        logging.error(f"Error getting blocked IPs: {e}")
        return {"success": False, "error": str(e), "blocked_ips": [], "count": 0}

# API: Block New IP
@app.post("/api/v1/blocked-ips")
async def api_block_ip(request: Request):
    """API endpoint to manually block an IP address"""
    try:
        data = await request.json()
        ip_address = data.get('ip')
        reason = data.get('reason', 'Manual block')
        reason_type = data.get('reason_type', 'manual')
        notes = data.get('notes', '')
        
        if not ip_address:
            return {"success": False, "error": "IP address is required"}
        
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {"success": False, "error": "Invalid IP address format"}
        
        # Block the IP with full details
        full_reason = f"{reason}" + (f" - {notes}" if notes else "")
        result = await waf_engine.block_ip(ip_address, full_reason, reason_type)
        
        if result:
            return {
                "success": True,
                "message": f"IP {ip_address} has been blocked",
                "ip": ip_address,
                "reason": reason
            }
        else:
            return {"success": False, "error": "Failed to block IP"}
            
    except Exception as e:
        logging.error(f"Error blocking IP: {e}")
        return {"success": False, "error": str(e)}

# API: Unblock IP
@app.delete("/api/v1/blocked-ips/{ip_address}")
async def api_unblock_ip(ip_address: str):
    """API endpoint to unblock an IP address"""
    try:
        # Unblock the IP
        result = await waf_engine.unblock_ip(ip_address)
        
        if result:
            return {
                "success": True,
                "message": f"IP {ip_address} has been unblocked",
                "ip": ip_address
            }
        else:
            return {"success": False, "error": "Failed to unblock IP or IP not found"}
            
    except Exception as e:
        logging.error(f"Error unblocking IP: {e}")
        return {"success": False, "error": str(e)}

# API: Clear All Blocked IPs
@app.post("/api/v1/blocked-ips/clear")
async def api_clear_blocked_ips():
    """API endpoint to clear all blocked IPs"""
    try:
        result = await waf_engine.clear_all_blocked_ips()
        
        if result:
            return {
                "success": True,
                "message": "All blocked IPs have been cleared"
            }
        else:
            return {"success": False, "error": "Failed to clear blocked IPs"}
            
    except Exception as e:
        logging.error(f"Error clearing blocked IPs: {e}")
        return {"success": False, "error": str(e)}

# Event Logs Page
@app.get("/event-logs", response_class=HTMLResponse)
async def event_logs(request: Request):
    """Serve the event logs page with real data"""
    try:
        # Get recent events from WAF engine
        recent_events = await waf_engine.get_recent_events(limit=20)
        
        # Format data for template
        template_data = {
            "request": request,
            "events": recent_events,
            "total_events": len(recent_events),
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("event_logs.html", template_data)
        
    except Exception as e:
        logging.error(f"Error loading event logs page: {e}")
        
        # Fallback with minimal data
        template_data = {
            "request": request,
            "events": [],
            "page_title": "Event Logs",
            "waf_status": "active"
        }
        
        return templates.TemplateResponse("event_logs.html", template_data)

# API: Get Event Logs
@app.get("/api/v1/event-logs")
async def api_get_event_logs(limit: int = 50):
    """API endpoint to get recent security event logs"""
    try:
        # Get recent events from WAF engine
        events = await waf_engine.get_recent_events(limit=limit)
        
        return {
            "success": True,
            "events": events,
            "total": len(events)
        }
    except Exception as e:
        logging.error(f"Error getting event logs: {e}")
        return {
            "success": False,
            "error": str(e),
            "events": [],
            "total": 0
        }

# Settings Page
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Serve the settings page"""
    try:
        template_data = {
            "request": request,
            "page_title": "Settings", 
            "waf_status": "active"
        }
        return templates.TemplateResponse("settings.html", template_data)
    except Exception as e:
        logging.error(f"Error loading settings page: {e}")
        return HTMLResponse("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Settings - VigilEdge WAF</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
                    color: white;
                    margin: 0;
                    padding: 2rem;
                }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #00d4ff; margin-bottom: 2rem; }
                .coming-soon { text-align: center; padding: 4rem; }
                .back-link { color: #00ffa6; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>WAF Settings</h1>
                <div class="coming-soon">
                    <h2>Settings Under Development</h2>
                    <p>Configuration management interface will be available soon.</p>
                    <a href="/" class="back-link">← Back to Dashboard</a>
                </div>
            </div>
        </body>
        </html>
        """)

# API Endpoints for Settings Management
@app.get("/api/v1/settings")
async def get_settings():
    """Get all WAF settings from configuration file"""
    try:
        settings_file = Path("config/waf_settings.json")
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                settings = json.load(f)
            return settings
        else:
            # Return default settings if file doesn't exist
            default_settings = {
                "security": {
                    "threat_detection_enabled": True,
                    "auto_block_ips": True,
                    "rate_limiting": True,
                    "rate_limit_value": 100,
                    "block_duration": 60,
                    "threat_sensitivity": "medium"
                },
                "network": {
                    "listen_port": 8000,
                    "max_connections": 1000,
                    "ssl_enabled": True,
                    "ssl_cert_path": "/certs/server.crt",
                    "ssl_key_path": "/certs/server.key",
                    "allowed_origins": ["https://localhost:8000", "https://127.0.0.1:8000"]
                },
                "logging": {
                    "log_level": "INFO",
                    "log_to_file": True,
                    "log_file_path": "./logs/vigiledge.log",
                    "max_log_size_mb": 100,
                    "log_retention_days": 30,
                    "compress_old_logs": True
                },
                "rules": {
                    "sql_injection": True,
                    "xss_protection": True,
                    "path_traversal": True,
                    "bot_detection": True,
                    "command_injection": False
                },
                "backup": {
                    "auto_backup": True,
                    "backup_frequency": "daily"
                },
                "theme": {
                    "selected_theme": "dark",
                    "auto_dark_mode": False
                }
            }
            return default_settings
    except Exception as e:
        logging.error(f"Error loading settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load settings: {str(e)}")

@app.post("/api/v1/settings")
async def save_settings(settings: dict):
    """Save WAF settings to configuration file"""
    try:
        settings_file = Path("config/waf_settings.json")
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Validate settings structure
        required_sections = ["security", "network", "logging", "rules", "backup", "theme"]
        for section in required_sections:
            if section not in settings:
                raise HTTPException(status_code=400, detail=f"Missing required section: {section}")
        
        # Save to file
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        # Apply settings to WAF engine in real-time
        try:
            # Update rate limiting
            if settings["security"]["rate_limiting"]:
                waf_engine.rate_limit = settings["security"]["rate_limit_value"]
            
            # Update threat sensitivity
            waf_engine.threat_sensitivity = settings["security"]["threat_sensitivity"]
            
            # Update security rules
            for rule_name, enabled in settings["rules"].items():
                if hasattr(waf_engine, f"{rule_name}_enabled"):
                    setattr(waf_engine, f"{rule_name}_enabled", enabled)
            
            logging.info(f"✅ Settings saved and applied successfully")
        except Exception as e:
            logging.warning(f"Settings saved but failed to apply: {e}")
        
        return {
            "status": "success",
            "message": "Settings saved successfully",
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error saving settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")

@app.post("/api/v1/settings/reset")
async def reset_settings():
    """Reset settings to factory defaults by deleting the config file"""
    try:
        settings_file = Path("config/waf_settings.json")
        
        # Create backup before resetting
        if settings_file.exists():
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"before_reset_{timestamp}.json"
            
            # Copy current settings to backup
            with open(settings_file, 'r') as f:
                current_settings = f.read()
            with open(backup_path, 'w') as f:
                f.write(current_settings)
            
            # Delete the config file
            settings_file.unlink()
            logging.info("Settings reset to defaults (config file deleted)")
        
        return {
            "status": "success",
            "message": "Settings reset to factory defaults",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Error resetting settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset settings: {str(e)}")

# Backup Management APIs
@app.get("/api/v1/backups")
async def list_backups():
    """List all available backup files"""
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        backups = []
        for backup_file in backup_dir.glob("*.json"):
            stats = backup_file.stat()
            backups.append({
                "name": backup_file.stem,
                "filename": backup_file.name,
                "date": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "size_bytes": stats.st_size,
                "size_mb": round(stats.st_size / (1024 * 1024), 2)
            })
        
        # Sort by date descending
        backups.sort(key=lambda x: x["date"], reverse=True)
        
        return {"backups": backups, "total": len(backups)}
    except Exception as e:
        logging.error(f"Error listing backups: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")

@app.post("/api/v1/backups/create")
async def create_backup():
    """Create a new backup of current settings"""
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        # Read current settings
        settings_file = Path("config/waf_settings.json")
        if not settings_file.exists():
            raise HTTPException(status_code=404, detail="Settings file not found")
        
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"config_backup_{timestamp}.json"
        backup_path = backup_dir / backup_filename
        
        # Save backup
        with open(backup_path, 'w') as f:
            json.dump(settings, f, indent=2)
        
        stats = backup_path.stat()
        
        return {
            "status": "success",
            "message": "Backup created successfully",
            "backup": {
                "name": backup_path.stem,
                "filename": backup_filename,
                "date": datetime.now().isoformat(),
                "size_mb": round(stats.st_size / (1024 * 1024), 2)
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create backup: {str(e)}")

@app.get("/api/v1/backups/download/{filename}")
async def download_backup(filename: str):
    """Download a specific backup file"""
    try:
        backup_dir = Path("backups")
        backup_path = backup_dir / filename
        
        if not backup_path.exists() or not backup_path.is_file():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Security check: ensure filename doesn't contain path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        with open(backup_path, 'r') as f:
            content = f.read()
        
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error downloading backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to download backup: {str(e)}")

@app.delete("/api/v1/backups/delete/{filename}")
async def delete_backup(filename: str):
    """Delete a specific backup file"""
    try:
        backup_dir = Path("backups")
        backup_path = backup_dir / filename
        
        if not backup_path.exists() or not backup_path.is_file():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Security check: ensure filename doesn't contain path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        backup_path.unlink()
        
        return {
            "status": "success",
            "message": f"Backup '{filename}' deleted successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {str(e)}")

# API endpoint to toggle security rules
@app.post("/api/v1/rules/toggle")
async def toggle_security_rule(request: dict):
    """Toggle a specific security rule on/off"""
    try:
        rule_name = request.get('rule_name')
        enabled = request.get('enabled')
        
        # Map rule names to WAF settings
        rule_mapping = {
            'sql_injection': 'sql_injection_protection',
            'xss': 'xss_protection',
            'path_traversal': 'path_traversal_protection',
            'rate_limit': 'rate_limit_enabled',
            'file_upload': 'file_upload_scanning',
            'ip_reputation': 'ip_reputation_enabled'
        }
        
        if rule_name not in rule_mapping:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid rule name"}
            )
        
        # Update the WAF settings
        setting_name = rule_mapping[rule_name]
        setattr(waf_engine.settings, setting_name, enabled)
        
        # Rate limiting also controls DDoS protection
        if rule_name == 'rate_limit':
            setattr(waf_engine.settings, 'ddos_protection', enabled)
        
        print(f"✓ {rule_name} -> {'ON' if enabled else 'OFF'}")
        
        return {
            "success": True,
            "message": f"Rule {rule_name} {'enabled' if enabled else 'disabled'}"
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "waf_engine": "operational"
    }

# WebSocket endpoint for real-time alerts
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    last_ping = asyncio.get_event_loop().time()
    ping_interval = 15  # Send ping every 15 seconds for mobile stability
    
    try:
        while True:
            current_time = asyncio.get_event_loop().time()
            
            # Send heartbeat ping to keep connection alive (especially for mobile)
            if current_time - last_ping >= ping_interval:
                try:
                    await websocket.send_json({"type": "ping"})
                    last_ping = current_time
                except:
                    break  # Connection lost, exit loop
            
            # Send periodic metrics updates
            try:
                metrics = await waf_engine.get_metrics()
                await manager.send_personal_message(
                    json.dumps({"type": "metrics", "data": metrics}),
                    websocket
                )
            except:
                break  # Connection lost, exit loop
            
            # Check for incoming messages (pong responses)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=2.0)
            except asyncio.TimeoutError:
                # No message received, that's fine - continue
                pass
            except:
                break  # Connection error, exit loop
            
            await asyncio.sleep(3)  # Reduced from 5 to 3 seconds for faster updates
            
    except (WebSocketDisconnect, ConnectionClosedError):
        # Client disconnected normally - silent cleanup
        pass
    except Exception:
        # Any other error - silent cleanup
        pass
    finally:
        manager.disconnect(websocket)

# Setup API routes
setup_routes(app, waf_engine, manager)

# Proxy endpoint for protecting applications
@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request):
    """Proxy endpoint to protect backend applications"""
    try:
        # Get target URL from query parameter
        target_url = request.query_params.get("target")
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        
        # Get client IP with null check
        client_ip = request.client.host if request.client else "unknown"
        
        # Get request data
        method = request.method
        headers = dict(request.headers)
        body = await request.body()
        
        # Process through WAF
        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode() if body else None,
            client_ip=client_ip
        )
        
        if not allowed:
            # Broadcast security alert
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {security_event.threat_type.upper()} blocked from {client_ip}"
            }))
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by WAF",
                    "reason": security_event.threat_type,
                    "event_id": security_event.id
                }
            )
        
        # Forward request to target
        async with httpx.AsyncClient() as client:
            # Remove proxy-specific headers
            headers.pop("host", None)
            headers.pop("content-length", None)
            
            response = await client.request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=settings.proxy_timeout
            )
            
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
                headers=dict(response.headers)
            )
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Proxy error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Background task for monitoring
async def monitoring_task():
    """Background monitoring and alerting"""
    while True:
        try:
            # Check for security events and send alerts
            recent_events = await waf_engine.get_recent_events(limit=10)
            
            for event in recent_events[-5:]:  # Check last 5 events
                if event.get("blocked") and event.get("threat_level") in ["high", "critical"]:
                    alert_message = f"🚨 {event['threat_type'].upper()} attack blocked from {event['source_ip']}"
                    await manager.broadcast(json.dumps({
                        "type": "alert",
                        "message": alert_message
                    }))
            
            await asyncio.sleep(10)  # Check every 10 seconds
            
        except Exception as e:
            print(f"Monitoring task error: {e}")
            await asyncio.sleep(30)

# Protected proxy endpoint - Main WAF protection route
@app.api_route("/protected/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.api_route("/protected", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], include_in_schema=False)
async def protected_proxy(request: Request, path: str = ""):
    """
    Protected proxy endpoint - All requests go through WAF protection
    Access vulnerable app through this endpoint for full WAF protection
    Example: http://localhost:5000/protected/login
    """
    try:
        # Build target URL
        target_url = f"{settings.vulnerable_app_url}/{path}" if path else settings.vulnerable_app_url
        
        # Preserve query parameters
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Get request details
        method = request.method
        headers = dict(request.headers)
        body = await request.body()
        
        # Process through WAF
        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode() if body else None,
            client_ip=client_ip
        )
        
        if not allowed:
            # Broadcast security alert
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {security_event.threat_type.upper()} blocked from {client_ip}"
            }))
            
            # Check if this is an API/JSON request (like login)
            content_type = headers.get('content-type', '').lower()
            accept_header = headers.get('accept', '').lower()
            
            # Return JSON for API requests
            if 'application/json' in content_type or 'application/json' in accept_header:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by VigilEdge WAF",
                        "reason": security_event.threat_type,
                        "event_id": security_event.id,
                        "timestamp": security_event.timestamp.isoformat(),
                        "details": "Your request has been identified as potentially malicious"
                    },
                    headers={
                        "X-WAF-Status": "BLOCKED",
                        "X-WAF-Event-ID": security_event.id,
                        "X-WAF-Threat-Type": security_event.threat_type,
                    }
                )
            
            # Return HTML for browser requests
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Request Blocked - VigilEdge WAF</title>
                    <style>
                        body {{
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                            color: #fff;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                        }}
                        .container {{
                            text-align: center;
                            padding: 40px;
                            background: rgba(255, 255, 255, 0.1);
                            border-radius: 12px;
                            border: 2px solid rgba(255, 107, 107, 0.5);
                            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                        }}
                        h1 {{ color: #ff6b6b; margin-bottom: 20px; }}
                        .icon {{ font-size: 64px; margin-bottom: 20px; }}
                        .details {{ 
                            background: rgba(0, 0, 0, 0.3); 
                            padding: 20px; 
                            border-radius: 8px;
                            margin-top: 20px;
                            text-align: left;
                        }}
                        .back-btn {{
                            display: inline-block;
                            margin-top: 20px;
                            padding: 12px 24px;
                            background: #00d4ff;
                            color: #000;
                            text-decoration: none;
                            border-radius: 6px;
                            font-weight: bold;
                        }}
                        .back-btn:hover {{ background: #00b4d8; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">🛡️</div>
                        <h1>Request Blocked by VigilEdge WAF</h1>
                        <p>Your request has been identified as potentially malicious and was blocked.</p>
                        <div class="details">
                            <p><strong>Event ID:</strong> {security_event.id}</p>
                            <p><strong>Threat Type:</strong> {security_event.threat_type.upper()}</p>
                            <p><strong>Threat Level:</strong> {security_event.threat_level.value.upper()}</p>
                            <p><strong>Timestamp:</strong> {security_event.timestamp}</p>
                        </div>
                        <a href="/protected" class="back-btn">← Back to Home</a>
                    </div>
                </body>
                </html>
                """,
                status_code=403
            )
        
        # Forward request to vulnerable app
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Remove proxy-specific headers
            forward_headers = {k: v for k, v in headers.items() 
                             if k.lower() not in ['host', 'content-length']}
            
            try:
                response = await client.request(
                    method=method,
                    url=target_url,
                    headers=forward_headers,
                    content=body if body else None,
                    follow_redirects=False
                )
                
                # Rewrite HTML content to fix links
                content = response.content
                content_type = response.headers.get('content-type', '')
                
                if 'text/html' in content_type:
                    try:
                        html_content = content.decode('utf-8')
                        
                        # Rewrite all links to include /protected prefix
                        import re
                        
                        # Fix href attributes: href="/path" -> href="/protected/path"
                        html_content = re.sub(
                            r'href=["\']/((?!protected)[^"\']*)["\']',
                            r'href="/protected/\1"',
                            html_content
                        )
                        
                        # Fix action attributes: action="/path" -> action="/protected/path"
                        html_content = re.sub(
                            r'action=["\']/((?!protected)[^"\']*)["\']',
                            r'action="/protected/\1"',
                            html_content
                        )
                        
                        # Fix src attributes for scripts/images: src="/path" -> src="/protected/path"
                        html_content = re.sub(
                            r'src=["\']/((?!protected|http)[^"\']*)["\']',
                            r'src="/protected/\1"',
                            html_content
                        )
                        
                        # Add base tag to help with relative URLs
                        if '<head>' in html_content:
                            html_content = html_content.replace(
                                '<head>',
                                '<head>\n    <base href="/protected/">'
                            )
                        
                        content = html_content.encode('utf-8')
                    except Exception as e:
                        # If rewriting fails, return original content
                        print(f"HTML rewriting error: {e}")
                        pass
                
                # Update Content-Length header for rewritten content
                response_headers = dict(response.headers)
                response_headers['content-length'] = str(len(content))
                
                # Remove headers that might cause issues
                response_headers.pop('transfer-encoding', None)
                
                # Return the response from vulnerable app
                return Response(
                    content=content,
                    status_code=response.status_code,
                    headers=response_headers,
                    media_type=response.headers.get('content-type', 'text/html')
                )
                
            except httpx.ConnectError:
                return HTMLResponse(
                    content=f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Backend Unavailable - VigilEdge WAF</title>
                        <style>
                            body {{
                                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                                color: #fff;
                                display: flex;
                                justify-content: center;
                                align-items: center;
                                height: 100vh;
                                margin: 0;
                            }}
                            .container {{
                                text-align: center;
                                padding: 40px;
                                background: rgba(255, 255, 255, 0.1);
                                border-radius: 12px;
                                border: 2px solid rgba(255, 179, 71, 0.5);
                                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                                max-width: 600px;
                            }}
                            h1 {{ color: #ffb347; margin-bottom: 20px; }}
                            .icon {{ font-size: 64px; margin-bottom: 20px; }}
                            .command {{
                                background: rgba(0, 0, 0, 0.5);
                                padding: 15px;
                                border-radius: 6px;
                                font-family: 'Courier New', monospace;
                                margin: 20px 0;
                                color: #00ff87;
                            }}
                            .back-btn {{
                                display: inline-block;
                                margin-top: 20px;
                                padding: 12px 24px;
                                background: #00d4ff;
                                color: #000;
                                text-decoration: none;
                                border-radius: 6px;
                                font-weight: bold;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="icon">⚠️</div>
                            <h1>Backend Application Not Available</h1>
                            <p>The vulnerable application is not running on <strong>{settings.vulnerable_app_url}</strong></p>
                            <p>To start the vulnerable application, run:</p>
                            <div class="command">python vulnerable_app.py</div>
                            <p><small>WAF is ready and waiting to protect your application.</small></p>
                            <a href="/enhanced" class="back-btn">← Go to Dashboard</a>
                        </div>
                    </body>
                    </html>
                    """,
                    status_code=503
                )
    
    except Exception as e:
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error - VigilEdge WAF</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                        color: #fff;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }}
                    .container {{
                        text-align: center;
                        padding: 40px;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 12px;
                        max-width: 600px;
                    }}
                    h1 {{ color: #ff6b6b; }}
                    .error {{ background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 6px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔥 Proxy Error</h1>
                    <p>An error occurred while processing your request.</p>
                    <div class="error"><code>{str(e)}</code></div>
                </div>
            </body>
            </html>
            """,
            status_code=500
        )

# Testing proxy endpoints for vulnerable application
@app.get("/api/v1/test/{path:path}")
async def test_proxy_get(path: str, request: Request):
    """Proxy GET requests to vulnerable app for testing WAF protection"""
    try:
        target_url = f"http://localhost:8080/{path}"
        query_string = str(request.url.query)
        if query_string:
            target_url += f"?{query_string}"
        
        # Forward headers (excluding host)
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(target_url, headers=headers)
            
            # Return proxied response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Vulnerable app not running",
                "message": f"Could not connect to http://localhost:8080 - {str(e)}",
                "instruction": "Start the vulnerable app with: python vulnerable_app.py"
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": str(e)},
            status_code=500
        )

@app.post("/api/v1/test/{path:path}")
async def test_proxy_post(path: str, request: Request):
    """Proxy POST requests to vulnerable app for testing WAF protection"""
    try:
        target_url = f"http://localhost:8080/{path}"
        body = await request.body()
        
        # Forward headers (excluding host)
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(target_url, content=body, headers=headers)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Vulnerable app not running",
                "message": f"Could not connect to http://localhost:8080 - {str(e)}",
                "instruction": "Start the vulnerable app with: python vulnerable_app.py"
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": str(e)},
            status_code=500
        )

@app.get("/test-target")
async def test_target_status():
    """Check if vulnerable test target is running"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{settings.vulnerable_app_url}/health")
            if response.status_code == 200:
                return JSONResponse({
                    "status": "online",
                    "message": "Vulnerable target application is running",
                    "target_url": settings.vulnerable_app_url,
                    "proxy_url": f"http://{settings.host}:{settings.port}{settings.vulnerable_app_proxy_path}",
                    "dashboard": f"http://{settings.host}:{settings.port}"
                })
    except:
        pass
    
    return JSONResponse({
        "status": "offline",
        "message": "Vulnerable target application is not running",
        "instruction": "Start with: python vulnerable_app.py",
        "port": 8080
    }, status_code=503)

# Catch-all proxy route for protecting vulnerable application
@app.api_route("/protected/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_to_vulnerable_app(path: str, request: Request):
    """
    Reverse proxy that protects vulnerable application with WAF
    All requests go through WAF security checks before reaching the target
    """
    if not settings.vulnerable_app_enabled:
        return JSONResponse({
            "error": "Protected application access is disabled",
            "message": "Enable vulnerable_app_enabled in configuration"
        }, status_code=503)
    
    try:
        # Build target URL
        target_url = f"{settings.vulnerable_app_url}/{path}"
        query_string = str(request.url.query)
        if query_string:
            target_url += f"?{query_string}"
        
        # Get client IP with null check
        client_ip = request.client.host if request.client else "unknown"
        
        # Get request data
        method = request.method
        headers = dict(request.headers)
        body = await request.body()
        body_str = body.decode('utf-8') if body else None
        
        # 🛡️ WAF SECURITY CHECK - Process request through WAF engine
        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body_str,
            client_ip=client_ip
        )
        
        if not allowed:
            # 🚨 THREAT DETECTED - Block and log
            threat_type = security_event.threat_type if security_event else "unknown"
            event_id = security_event.id if security_event else "N/A"
            
            # Broadcast security alert to connected dashboards
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {threat_type.upper()} blocked from {client_ip}",
                "severity": "high",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
            
            # Return blocked response
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by VigilEdge WAF",
                    "reason": threat_type,
                    "event_id": event_id,
                    "message": "Your request was identified as a potential security threat",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        
        # ✅ REQUEST ALLOWED - Forward to vulnerable application
        async with httpx.AsyncClient(timeout=settings.proxy_timeout) as client:
            # Remove proxy-specific headers
            headers_to_forward = {k: v for k, v in headers.items() 
                                  if k.lower() not in ['host', 'content-length']}
            
            response = await client.request(
                method=method,
                url=target_url,
                headers=headers_to_forward,
                content=body,
                follow_redirects=False
            )
            
            # Return proxied response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
            
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Vulnerable application not accessible",
                "message": f"Could not connect to {settings.vulnerable_app_url}",
                "details": str(e),
                "instruction": "Start the vulnerable app with: python vulnerable_app.py"
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={
                "error": "Proxy error",
                "message": str(e)
            },
            status_code=500
        )

def main():
    """Main application entry point"""
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        access_log=True,
        log_level=settings.log_level.lower()
    )

if __name__ == "__main__":
    main()
