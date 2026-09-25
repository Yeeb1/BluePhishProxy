"""BluePhishProxy - red-team pre-staging reconnaissance proxy.

BluePhishProxy stands up a decoy "link protection / safe links" page that is
designed to be probed by a target organisation's defensive infrastructure
(secure email gateways, URL sandboxes, click-time scanners and Blue Team
manual inspection). Every visitor is fingerprinted with a multi-signal
detection engine so that an authorised engagement can learn which security
systems inspect its links before any real content is delivered.

Modules:

    config       - runtime configuration (env-driven)
    vendors      - known security-vendor / hosting fingerprint data
    fingerprint  - individual detection signal producers
    detection    - scoring engine that turns signals into a verdict
    storage      - visit logging + daily analytics
    reporting    - engagement report generation (Markdown / HTML)
    templates    - decoy scan page + JS fingerprint collector
    app          - Flask application factory and routes
"""

from __future__ import annotations

__version__ = "2.0.0"
__all__ = ["__version__"]
