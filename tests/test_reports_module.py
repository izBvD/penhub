"""Reports module: registration + lazy UI fragment; ALL CREDS moved out of NXC toolbar."""

from pathlib import Path


def test_sbnavigate_activates_reports():
    # Sidebar click → sbNavigate('reports') must explicitly activate the module;
    # without a case it falls through to `default` (route-only) and does nothing.
    js = Path("static/shell-nxc-shell.js").read_text(encoding="utf-8")
    assert "case 'reports':" in js
    assert "Shell.activate('reports')" in js


def test_sbisactive_recognizes_reports():
    # _sbIsActive must return true for reports when active; otherwise the sidebar
    # tile never gets `.active` (no active styling, no collapsed vertical unfold).
    js = Path("static/shell-nxc-shell.js").read_text(encoding="utf-8")
    assert "case 'reports':" in js and "return Shell.isActive('reports')" in js


def test_reports_deeplink_activation():
    # ?module=reports must activate the module on load (both ws-known and post-login paths).
    js = Path("static/shell-projects.js").read_text(encoding="utf-8")
    assert js.count("modParam === 'reports'") >= 2


def test_reports_registered():
    from penhub.shell.registry import shell_registry
    m = shell_registry.get_module("reports")
    assert m is not None
    assert m.name == "Reports"
    assert m.icon == "\U0001F4C4"   # 📄
    assert m.order == 40
    assert m.lazy is True


def test_reports_fragment_has_blocks(auth_client):
    r = auth_client.get("/api/shell/module/reports/ui")
    assert r.status_code == 200
    html = r.text
    assert "TIMELINE" in html
    assert "ALL CREDS" in html
    assert "ALL VULNS" in html
    assert "RPModule.exportAllCreds()" in html
    assert "RPModule.exportAllVulns()" in html


def test_shell_has_reports_container(auth_client):
    html = auth_client.get("/").text
    assert 'id="mod-reports"' in html
    # RPModule JS must be injected, else the export buttons do nothing.
    assert "modules/reports/module.js" in html


def test_allcred_button_removed_from_nxc_toolbar(auth_client):
    html = auth_client.get("/").text
    assert 'class="btn allcred"' not in html
    assert 'exportAllCred()' not in html
