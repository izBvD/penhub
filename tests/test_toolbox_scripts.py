"""
Test that the operator-scripts download ZIP bundles all client scripts,
including dicgenerat.py (needed by `nxc_collector --install`).
"""

import io
import zipfile


def test_scripts_zip_includes_dicgenerat(auth_client):
    r = auth_client.get("/api/toolbox/scripts")
    assert r.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "dicgenerat.py" in names
    # existing scripts still bundled
    for n in ["nxc_collector", "nxce.py", "nxc_updater.py"]:
        assert n in names
