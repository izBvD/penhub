"""Timeline (Reports module): migration, service, sync hook, API, download."""

import collector.db as db


def test_timeline_nodes_table_and_canonical_unique(auth_client):
    with db.db_cursor() as cur:
        cols = {r["name"] for r in cur.execute("PRAGMA table_info(timeline_nodes)")}
    assert {"id", "workspace_id", "kind", "label", "ts", "detail", "created_at"} <= cols


def test_canonical_unique_index_blocks_second_override(workspace_id):
    import sqlite3
    with db.db_cursor() as cur:
        cur.execute(
            "INSERT INTO timeline_nodes(workspace_id,kind,ts,created_at) VALUES(?,?,?,?)",
            (workspace_id, "first_sync", "2026-07-01T00:00:00Z", "2026-07-01T00:00:00Z"),
        )
    try:
        with db.db_cursor() as cur:
            cur.execute(
                "INSERT INTO timeline_nodes(workspace_id,kind,ts,created_at) VALUES(?,?,?,?)",
                (workspace_id, "first_sync", "2026-07-02T00:00:00Z", "2026-07-02T00:00:00Z"),
            )
        assert False, "expected UNIQUE violation on second canonical override"
    except sqlite3.IntegrityError:
        pass
    # custom rows are NOT restricted
    with db.db_cursor() as cur:
        for _ in range(2):
            cur.execute(
                "INSERT INTO timeline_nodes(workspace_id,kind,label,ts,created_at) VALUES(?,?,?,?,?)",
                (workspace_id, "custom", "n", "2026-07-03T00:00:00Z", "2026-07-03T00:00:00Z"),
            )


def test_fmt_elapsed():
    from collector.services.timeline_service import fmt_elapsed
    assert fmt_elapsed(0)                 == "00:00:00"
    assert fmt_elapsed(9390)              == "02:36:30"          # 2h36m30s, 0 days
    assert fmt_elapsed(86400 + 26400)     == "1 day 07:20:00"
    assert fmt_elapsed(2 * 86400 + 22080) == "2 days 06:08:00"
    assert fmt_elapsed(5 * 86400 + 50590) == "5 days 14:03:10"
    assert fmt_elapsed(21 * 86400)        == "21 days 00:00:00"
    assert fmt_elapsed(-5)                == "00:00:00"


def _seed_ws_creds_notifs(cur, wid):
    cur.execute("INSERT INTO credentials(workspace_id,proto,domain,username,password,credtype,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (wid, "SMB", "CORP", "jdoe", "P@ss1", "plaintext", "2026-07-01T11:48:30Z"))
    cur.execute("INSERT INTO notifications(workspace_id,type,title,created_at) VALUES(?,?,?,?)",
                (wid, "pwn3d", "DC01 (corp.local)", "2026-07-03T15:20:00Z"))
    cur.execute("INSERT INTO notifications(workspace_id,type,title,created_at) VALUES(?,?,?,?)",
                (wid, "domain_admin", "CORP\\admin", "2026-07-04T10:00:00Z"))
    cur.execute("INSERT INTO workspace_config(workspace_id,key,value) VALUES(?,?,?)",
                (wid, "timeline_first_sync", "2026-07-01T09:12:00Z"))
    cur.execute("INSERT INTO workspace_config(workspace_id,key,value) VALUES(?,?,?)",
                (wid, "timeline_first_sync_op", "alice"))


def test_build_timeline_auto_and_order(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-auto')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-auto'").fetchone()["id"]
        _seed_ws_creds_notifs(cur, wid)
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    assert [n["label"] for n in tl["nodes"]] == \
        ["First sync", "First captured account", "First PWNED", "First Domain Admin"]
    assert tl["nodes"][0]["elapsed_str"] == ""
    assert tl["nodes"][1]["elapsed_str"] == "02:36:30"
    assert tl["nodes"][2]["detail"] == "DC01 (corp.local)"
    assert tl["nodes"][1]["detail"] == "CORP\\jdoe:P@ss1"   # first account + secret
    assert tl["pending"] == []
    assert tl["total_str"] == "3 days 00:48:00"


def test_first_account_detail_has_plaintext_secret(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-acct')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-acct'").fetchone()["id"]
        cur.execute("INSERT INTO credentials(workspace_id,proto,domain,username,password,credtype,updated_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (wid, "SMB", "CORP", "jdoe", "P@ss1", "plaintext", "2026-07-01T10:00:00Z"))
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    acct = [n for n in tl["nodes"] if n["kind"] == "first_account"][0]
    assert acct["detail"] == "CORP\\jdoe:P@ss1"


def test_first_account_detail_hash_when_no_plaintext(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-acct-h')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-acct-h'").fetchone()["id"]
        cur.execute("INSERT INTO credentials(workspace_id,proto,domain,username,password,credtype,updated_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (wid, "SMB", "CORP", "jdoe", "NTHASHVAL", "hash", "2026-07-01T10:00:00Z"))
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    acct = [n for n in tl["nodes"] if n["kind"] == "first_account"][0]
    assert acct["detail"] == "CORP\\jdoe:NTHASHVAL"


def test_first_da_detail_has_secret(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-da')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-da'").fetchone()["id"]
        cur.execute("INSERT INTO credentials(workspace_id,proto,domain,username,password,credtype,updated_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (wid, "SMB", "CORP", "dadmin", "DaPass1", "plaintext", "2026-07-04T10:00:00Z"))
        cur.execute("INSERT INTO notifications(workspace_id,type,ref_domain,ref_username,title,created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (wid, "domain_admin", "CORP", "dadmin", "CORP\\dadmin", "2026-07-04T10:00:00Z"))
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    da = [n for n in tl["nodes"] if n["kind"] == "first_da"][0]
    assert da["detail"] == "CORP\\dadmin:DaPass1"


def test_first_pwned_detail_includes_cred(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-pwn')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-pwn'").fetchone()["id"]
        cur.execute("INSERT INTO hosts(workspace_id,ip,hostname,domain) VALUES(?,?,?,?)",
                    (wid, "10.0.0.5", "DC01", "corp.local"))
        hid = cur.execute("SELECT id FROM hosts WHERE workspace_id=? AND ip='10.0.0.5'",
                          (wid,)).fetchone()["id"]
        cur.execute("INSERT INTO credentials(workspace_id,proto,domain,username,password,credtype)"
                    " VALUES(?,?,?,?,?,?)", (wid, "SMB", "CORP", "jdoe", "nthash", "hash"))
        cid = cur.execute("SELECT id FROM credentials WHERE workspace_id=? AND username='jdoe'",
                          (wid,)).fetchone()["id"]
        cur.execute("INSERT INTO auth_relations(workspace_id,proto,credential_id,host_id,relation_type)"
                    " VALUES(?,?,?,?,?)", (wid, "SMB", cid, hid, "admin"))
        cur.execute("INSERT INTO notifications(workspace_id,type,ref_host_id,title,created_at)"
                    " VALUES(?,?,?,?,?)", (wid, "pwn3d", hid, "DC01 (corp.local)", "2026-07-03T15:20:00Z"))
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    pwn = [n for n in tl["nodes"] if n["kind"] == "first_pwned"][0]
    assert "DC01 (corp.local)" in pwn["detail"]
    assert "CORP\\jdoe:nthash" in pwn["detail"]   # account + secret (hash here)


def test_build_timeline_override_and_pending(auth_client):
    with db.db_cursor() as cur:
        cur.execute("INSERT INTO workspaces(name) VALUES('tl-ovr')")
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-ovr'").fetchone()["id"]
        cur.execute("INSERT INTO timeline_nodes(workspace_id,kind,label,ts,detail,created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (wid, "first_pwned", None, "2026-07-05T00:00:00Z", "manual-host", "x"))
    from collector.services.timeline_service import build_timeline
    with db.db_cursor() as cur:
        tl = build_timeline(cur, wid)
    assert [n["label"] for n in tl["nodes"]] == ["First PWNED"]
    assert tl["nodes"][0]["is_override"] is True
    assert set(tl["pending"]) == {"First sync", "First captured account", "First Domain Admin"}


def _sync(auth_client, ws, operator="op1"):
    return auth_client.post("/api/sync", json={
        "workspace": ws, "operator": operator, "data": {}})


def test_first_sync_hook_sets_once_even_empty(auth_client):
    r = _sync(auth_client, "tl-sync")          # empty payload
    assert r.status_code == 200
    with db.db_cursor() as cur:
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-sync'").fetchone()["id"]
        v1 = cur.execute("SELECT value FROM workspace_config"
                         " WHERE workspace_id=? AND key='timeline_first_sync'", (wid,)).fetchone()
    assert v1 is not None                       # empty sync still captured
    _sync(auth_client, "tl-sync", operator="op2")   # second sync
    with db.db_cursor() as cur:
        v2 = cur.execute("SELECT value FROM workspace_config"
                         " WHERE workspace_id=? AND key='timeline_first_sync'", (wid,)).fetchone()
        op = cur.execute("SELECT value FROM workspace_config"
                         " WHERE workspace_id=? AND key='timeline_first_sync_op'", (wid,)).fetchone()
    assert v2["value"] == v1["value"]           # not overwritten
    assert op["value"] == "op1"                 # first operator preserved


def test_timeline_api_crud(auth_client):
    auth_client.post("/api/workspaces", json={"name": "tl-api"})
    with db.db_cursor() as cur:
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-api'").fetchone()["id"]

    # GET on empty ws → all pending, no nodes
    r = auth_client.get(f"/api/timeline?workspace_id={wid}")
    assert r.status_code == 200
    assert r.json()["nodes"] == []
    assert len(r.json()["pending"]) == 4

    # canonical override
    r = auth_client.put("/api/timeline/canonical", json={
        "workspace_id": wid, "kind": "first_pwned",
        "ts": "2026-07-05T00:00:00Z", "detail": "DC01"})
    assert r.status_code == 200
    r = auth_client.get(f"/api/timeline?workspace_id={wid}")
    assert [n["kind"] for n in r.json()["nodes"]] == ["first_pwned"]
    assert r.json()["nodes"][0]["is_override"] is True

    # update the same override (upsert, no duplicate)
    r = auth_client.put("/api/timeline/canonical", json={
        "workspace_id": wid, "kind": "first_pwned",
        "ts": "2026-07-06T00:00:00Z", "detail": "DC02"})
    assert r.status_code == 200
    nodes = auth_client.get(f"/api/timeline?workspace_id={wid}").json()["nodes"]
    assert len(nodes) == 1 and nodes[0]["detail"] == "DC02"

    # reset override → back to pending
    r = auth_client.delete(f"/api/timeline/canonical?workspace_id={wid}&kind=first_pwned")
    assert r.status_code == 200
    assert auth_client.get(f"/api/timeline?workspace_id={wid}").json()["nodes"] == []

    # custom add / edit / delete
    r = auth_client.post("/api/timeline/custom", json={
        "workspace_id": wid, "label": "VPN", "ts": "2026-07-02T08:00:00Z", "detail": ""})
    nid = r.json()["id"]
    assert auth_client.put(f"/api/timeline/custom/{nid}", json={
        "label": "VPN access", "ts": "2026-07-02T08:00:00Z", "detail": "x"}).status_code == 200
    got = auth_client.get(f"/api/timeline?workspace_id={wid}").json()["nodes"]
    assert got and got[0]["label"] == "VPN access" and got[0]["detail"] == "x"
    assert auth_client.delete(f"/api/timeline/custom/{nid}").status_code == 200
    assert auth_client.get(f"/api/timeline?workspace_id={wid}").json()["nodes"] == []


def test_timeline_ts_normalized(auth_client):
    auth_client.post("/api/workspaces", json={"name": "tl-ts"})
    with db.db_cursor() as cur:
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-ts'").fetchone()["id"]
    # accept 'YYYY-MM-DD HH:MM:SS' (space separator, no Z) → stored canonical
    auth_client.post("/api/timeline/custom", json={
        "workspace_id": wid, "label": "n", "ts": "2026-07-02 08:00:00", "detail": ""})
    ts = auth_client.get(f"/api/timeline?workspace_id={wid}").json()["nodes"][0]["ts"]
    assert ts == "2026-07-02T08:00:00Z"


def test_timeline_download(auth_client):
    auth_client.post("/api/workspaces", json={"name": "tl-dl"})
    with db.db_cursor() as cur:
        wid = cur.execute("SELECT id FROM workspaces WHERE name='tl-dl'").fetchone()["id"]
        cur.execute("INSERT INTO workspace_config(workspace_id,key,value) VALUES(?,?,?)",
                    (wid, "timeline_first_sync", "2026-07-01T09:12:00Z"))
        cur.execute("INSERT INTO timeline_nodes(workspace_id,kind,label,ts,detail,created_at)"
                    " VALUES(?,?,?,?,?,?)", (wid, "custom", "VPN", "2026-07-03T09:12:00Z", "", "x"))
    r = auth_client.get(f"/api/timeline/download?workspace_id={wid}")
    assert r.status_code == 200
    assert "tl-dl_timeline.txt" in r.headers["content-disposition"]
    body = r.content.decode("utf-8")
    assert "TIMELINE — tl-dl" in body
    assert "1. First sync — 2026-07-01 09:12:00 UTC" in body
    assert "Elapsed from point 1: 2 days 00:00:00" in body
    assert "Total (point 1 → 2): 2 days 00:00:00" in body
    assert "Not reached:" in body
    assert "- First captured account" in body


def test_timeline_block_rendered(auth_client):
    html = auth_client.get("/api/shell/module/reports/ui").text
    assert 'id="rpTimeline"' in html
    assert "RPModule.downloadTimeline()" in html
    assert "RPModule.addCustomNode()" in html
    assert "Coming soon" not in html


def test_reports_module_css_served(auth_client):
    html = auth_client.get("/").text
    assert "modules/reports/module.css" in html


def test_timeline_editor_is_a_form_not_prompt(auth_client):
    from pathlib import Path
    html = auth_client.get("/api/shell/module/reports/ui").text
    assert 'id="rpNodeModal"' in html          # modal container present
    assert 'type="datetime-local"' in html     # native date/time picker
    # no prompt()/window.prompt editors left in the module JS
    js = Path("static/modules/reports/module.js").read_text(encoding="utf-8")
    assert "prompt(" not in js
