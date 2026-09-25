"""Tests for the Jinja2 template registry."""

from __future__ import annotations

from bluephishproxy.lures import LURE_REGISTRY, list_templates, render_lure, reload_templates


class TestRegistry:
    def test_builtin_templates_discovered(self):
        assert len(LURE_REGISTRY) >= 8
        assert "safelinks" in LURE_REGISTRY
        assert "clickfix" in LURE_REGISTRY
        assert "captcha" in LURE_REGISTRY
        assert "oauth" in LURE_REGISTRY
        assert "mfa" in LURE_REGISTRY
        assert "docviewer" in LURE_REGISTRY
        assert "voicemail" in LURE_REGISTRY
        assert "sharepoint" in LURE_REGISTRY

    def test_partials_excluded(self):
        assert "_fingerprint" not in LURE_REGISTRY

    def test_metadata_parsed(self):
        info = LURE_REGISTRY["safelinks"]
        assert info["name"] == "Microsoft Safe Links"
        assert info["description"]

    def test_list_templates_format(self):
        templates = list_templates()
        assert isinstance(templates, list)
        for t in templates:
            assert "id" in t
            assert "name" in t
            assert "description" in t

    def test_reload_templates(self):
        reload_templates()
        assert len(LURE_REGISTRY) >= 8


class TestRendering:
    def test_safelinks_default(self):
        html = render_lure("safelinks")
        assert "Microsoft" in html
        assert "__bpp_send" in html

    def test_custom_brand(self):
        html = render_lure("safelinks", {"brand": "Contoso"})
        assert "Contoso" in html

    def test_oauth_permissions_list(self):
        html = render_lure("oauth", {"permissions": "Read mail,Send mail,Access calendar"})
        assert "Read mail" in html
        assert "Send mail" in html
        assert "Access calendar" in html

    def test_oauth_permissions_string_split(self):
        html = render_lure("oauth", {"permissions": "Read,Write"})
        assert "Read" in html
        assert "Write" in html

    def test_sharepoint_variables(self):
        html = render_lure("sharepoint", {
            "sender": "Jane Doe",
            "file_name": "secret.docx",
            "org_name": "ACME Corp",
        })
        assert "Jane Doe" in html
        assert "secret.docx" in html
        assert "ACME Corp" in html

    def test_unknown_template_fallback(self):
        html = render_lure("nonexistent_garbage_template")
        assert len(html) > 100
        assert "__bpp_send" in html

    def test_all_templates_render(self):
        for template_id in LURE_REGISTRY:
            html = render_lure(template_id)
            assert len(html) > 100, f"{template_id} rendered empty"
            assert "__bpp_send" in html, f"{template_id} missing fingerprint JS"

    def test_fingerprint_include(self):
        html = render_lure("captcha")
        assert "canvasHash" in html
        assert "webglRenderer" in html
        assert "mousePattern" in html
