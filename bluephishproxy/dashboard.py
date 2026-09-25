"""Operator dashboard — real-time monitoring UI.

A single-page dashboard that connects to the SSE feed and displays live
visit events, campaign stats, and detection analytics. Served at
/api/operator/dashboard.
"""

from __future__ import annotations

from .config import Config


def dashboard_html(cfg: Config) -> str:
    token_param = f"?token={cfg.operator_token}" if cfg.operator_token else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BluePhishProxy — Operator Dashboard</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-dim: #8b949e; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --green: #3fb950;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); font-size: 14px;
  }}
  .header {{
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 16px 24px; display: flex; align-items: center;
    justify-content: space-between;
  }}
  .header h1 {{ font-size: 18px; font-weight: 600 }}
  .header h1 span {{ color: var(--accent) }}
  .status {{ display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-dim) }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--red) }}
  .dot.connected {{ background: var(--green); animation: pulse 2s infinite }}
  @keyframes pulse {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:.4 }} }}

  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 20px 24px }}
  .stat {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px 20px;
  }}
  .stat .label {{ font-size: 12px; color: var(--text-dim); margin-bottom: 4px }}
  .stat .value {{ font-size: 28px; font-weight: 700 }}
  .stat .value.bot {{ color: var(--red) }}
  .stat .value.suspicious {{ color: var(--orange) }}
  .stat .value.clean {{ color: var(--green) }}

  .panels {{ display: grid; grid-template-columns: 1fr 340px; gap: 16px; padding: 0 24px 24px }}

  .feed {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; overflow: hidden;
  }}
  .feed-header {{
    padding: 12px 16px; border-bottom: 1px solid var(--border);
    font-weight: 600; font-size: 13px; display: flex;
    justify-content: space-between; align-items: center;
  }}
  .feed-body {{ max-height: 520px; overflow-y: auto }}
  .event {{
    padding: 10px 16px; border-bottom: 1px solid var(--border);
    font-size: 13px; display: grid;
    grid-template-columns: 80px 1fr 100px 60px;
    gap: 8px; align-items: center;
    animation: slideIn .3s ease;
  }}
  @keyframes slideIn {{ from {{ opacity:0; transform: translateY(-8px) }} }}
  .event:hover {{ background: rgba(88,166,255,.05) }}
  .event .time {{ color: var(--text-dim); font-size: 11px; font-family: monospace }}
  .event .info {{ overflow: hidden }}
  .event .ip {{ font-weight: 600; font-family: monospace }}
  .event .org {{ color: var(--text-dim); font-size: 12px; white-space: nowrap;
    overflow: hidden; text-overflow: ellipsis }}
  .event .vendor {{ font-size: 11px; color: var(--accent) }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
  }}
  .badge.bot {{ background: rgba(248,81,73,.15); color: var(--red) }}
  .badge.suspicious {{ background: rgba(210,153,34,.15); color: var(--orange) }}
  .badge.clean {{ background: rgba(63,185,80,.15); color: var(--green) }}

  .sidebar {{ display: flex; flex-direction: column; gap: 16px }}
  .panel {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }}
  .panel h3 {{ font-size: 13px; font-weight: 600; margin-bottom: 12px; color: var(--text-dim) }}
  .vendor-list {{ list-style: none }}
  .vendor-list li {{
    display: flex; justify-content: space-between; padding: 4px 0;
    font-size: 13px; border-bottom: 1px solid var(--border);
  }}
  .vendor-list li:last-child {{ border: none }}
  .vendor-count {{ font-weight: 600; color: var(--accent) }}

  .campaigns-list {{ list-style: none }}
  .campaigns-list li {{
    padding: 8px 0; border-bottom: 1px solid var(--border);
    font-size: 13px;
  }}
  .campaigns-list li:last-child {{ border: none }}
  .campaign-name {{ font-weight: 600 }}
  .campaign-meta {{ font-size: 11px; color: var(--text-dim) }}

  @media (max-width: 900px) {{
    .grid {{ grid-template-columns: repeat(2, 1fr) }}
    .panels {{ grid-template-columns: 1fr }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1><span>Blue</span>PhishProxy <span style="font-weight:400;font-size:13px;color:var(--text-dim)">Operator Dashboard</span></h1>
  <div class="status">
    <div class="dot" id="statusDot"></div>
    <span id="statusText">Connecting...</span>
  </div>
</div>

<div class="grid">
  <div class="stat"><div class="label">Total Visits</div><div class="value" id="totalVisits">0</div></div>
  <div class="stat"><div class="label">Bots Detected</div><div class="value bot" id="totalBots">0</div></div>
  <div class="stat"><div class="label">Suspicious</div><div class="value suspicious" id="totalSuspicious">0</div></div>
  <div class="stat"><div class="label">Clean</div><div class="value clean" id="totalClean">0</div></div>
</div>

<div class="panels">
  <div class="feed">
    <div class="feed-header">
      <span>Live Feed</span>
      <span style="font-size:11px;color:var(--text-dim)" id="eventCount">0 events</span>
    </div>
    <div class="feed-body" id="feedBody"></div>
  </div>

  <div class="sidebar">
    <div class="panel">
      <h3>Security Vendors Detected</h3>
      <ul class="vendor-list" id="vendorList">
        <li style="color:var(--text-dim)">Waiting for data...</li>
      </ul>
    </div>
    <div class="panel">
      <h3>Active Campaigns</h3>
      <ul class="campaigns-list" id="campaignsList">
        <li style="color:var(--text-dim)">Loading...</li>
      </ul>
    </div>
  </div>
</div>

<script>
(function() {{
  var stats = {{ total: 0, bot: 0, suspicious: 0, clean: 0 }};
  var vendors = {{}};
  var events = 0;
  var feedBody = document.getElementById("feedBody");

  function loadCampaigns() {{
    fetch("/api/operator/campaigns{token_param}")
      .then(function(r) {{ return r.json() }})
      .then(function(data) {{
        var list = document.getElementById("campaignsList");
        if (!data.length) {{ list.innerHTML = '<li style="color:var(--text-dim)">No campaigns</li>'; return }}
        list.innerHTML = data.map(function(c) {{
          return '<li><div class="campaign-name">' + c.name + '</div>' +
                 '<div class="campaign-meta">' + c.template + ' &middot; /c/' + c.id + '/ &middot; ' +
                 (c.active ? 'Active' : 'Paused') + '</div></li>';
        }}).join("");
      }})
      .catch(function() {{}});
  }}

  function loadInitialData() {{
    fetch("/api/operator/visits{token_param}&limit=20".replace("&","?",1))
      .then(function(r) {{ return r.json() }})
      .then(function(data) {{
        data.reverse().forEach(function(v) {{ addEvent(v, true) }});
      }})
      .catch(function() {{}});
  }}

  function updateStats() {{
    document.getElementById("totalVisits").textContent = stats.total;
    document.getElementById("totalBots").textContent = stats.bot;
    document.getElementById("totalSuspicious").textContent = stats.suspicious;
    document.getElementById("totalClean").textContent = stats.clean;
    document.getElementById("eventCount").textContent = events + " events";
  }}

  function updateVendors() {{
    var list = document.getElementById("vendorList");
    var sorted = Object.entries(vendors).sort(function(a,b) {{ return b[1] - a[1] }});
    if (!sorted.length) {{ list.innerHTML = '<li style="color:var(--text-dim)">None yet</li>'; return }}
    list.innerHTML = sorted.map(function(v) {{
      return '<li><span>' + v[0] + '</span><span class="vendor-count">' + v[1] + '</span></li>';
    }}).join("");
  }}

  function addEvent(v, initial) {{
    events++;
    var cls = v.classification || "clean";
    stats.total++;
    if (cls === "bot") stats.bot++;
    else if (cls === "suspicious") stats.suspicious++;
    else stats.clean++;

    if (v.vendor) {{
      vendors[v.vendor] = (vendors[v.vendor] || 0) + 1;
      updateVendors();
    }}

    var time = "";
    try {{ time = new Date(v.timestamp).toLocaleTimeString() }} catch(e) {{}}

    var row = document.createElement("div");
    row.className = "event";
    row.innerHTML =
      '<div class="time">' + time + '</div>' +
      '<div class="info"><div class="ip">' + (v.ip || "?") + '</div>' +
      '<div class="org">' + (v.org || "?") + ' &middot; ' + (v.country || "?") + '</div>' +
      (v.vendor ? '<div class="vendor">' + v.vendor + '</div>' : '') +
      '</div>' +
      '<div><span class="badge ' + cls + '">' + cls + '</span></div>' +
      '<div style="font-size:12px;font-weight:600">' + (v.score || 0) + '</div>';

    if (initial) {{
      feedBody.appendChild(row);
    }} else {{
      feedBody.insertBefore(row, feedBody.firstChild);
    }}

    while (feedBody.children.length > 200) feedBody.removeChild(feedBody.lastChild);
    updateStats();
  }}

  function connectSSE() {{
    var es = new EventSource("/api/operator/feed{token_param}");
    es.onopen = function() {{
      document.getElementById("statusDot").classList.add("connected");
      document.getElementById("statusText").textContent = "Connected — Live";
    }};
    es.onmessage = function(e) {{
      try {{
        var data = JSON.parse(e.data);
        if (data.event === "visit") addEvent(data);
      }} catch(ex) {{}}
    }};
    es.onerror = function() {{
      document.getElementById("statusDot").classList.remove("connected");
      document.getElementById("statusText").textContent = "Reconnecting...";
    }};
  }}

  loadCampaigns();
  loadInitialData();
  connectSSE();
  setInterval(loadCampaigns, 30000);
}})();
</script>
</body>
</html>"""
