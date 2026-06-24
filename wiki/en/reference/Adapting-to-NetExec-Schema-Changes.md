# Adapting to NetExec Schema Changes

PenHub reads NetExec's databases, which nxc places per-protocol within the workspace. NetExec developers occasionally **rename columns or tables** in their databases during updates. To prevent this from breaking sync, the reader on the operator side goes through a JSON map: **`nxc_schema.json`**.

---

## How the mapping works

Every read in `nxc_updater.py` essentially:

```
SELECT * FROM <table>      →  dict(row)      →  value = _col(row, proto, table, "password")
```

- `_col(...)` resolves an **internal key** (`password`) to the **actual column name** via `nxc_schema.json[proto][table][key]`. If there is no mapping — falls back to the key itself.
- The **table** name is resolved by `_table(proto, table)` via the reserved key `__table__` (fallback — the key name itself).
- Since the reader does `SELECT *`, all columns are already in the dict — so adapting to a new name is **just editing JSON**, no code changes needed.

```json
// nxc_schema.json (shape)
{
  "smb": {
    "users": {
      "username": "username",
      "password": "password",
      "__table__": "users"
    }
  }
}
```

---

## What to do when nxc changes the schema

### A column was renamed (e.g. `password` → `secret`)
Update the mapping value for the relevant `{proto}.{table}` key:
```json
"password": "secret"
```
No code changes needed.

### A table was renamed (e.g. `users` → `accounts`)
Add the `__table__` key to that table's map:
```json
"__table__": "accounts"
```
The name must be a simple SQL identifier; if not, `_table` discards it (with an error) and falls back to the key name.

### The JSON is broken (won't parse)
The entire map falls back to "names = keys" — i.e. behaves exactly as before the mapping existed. Always validate the JSON after editing.

---

## How to detect that columns have been renamed

At the start of each key table, `nxc_updater` checks the **required identifying columns** (ip / host / username / password / conf-check name, …) against what nxc returned. Example of a discrepancy:

```
[schema] smb.users: missing column(s) password — update nxc_schema.json
```

in `~/.nxc-collector.log`. This is **log only** — sync continues with available columns, so the service doesn't crash; edit the JSON when you see this in the log. Optional fields (vulnerability flags, banners) are intentionally **not** checked to avoid false positives on older nxc versions.

---

## When code changes are needed

The JSON remaps **names** of existing columns and tables. It does **not**:

- **Add a new entity** — reading a new table that appeared in nxc requires a code change.
- **Remove a gone entity** — unflagging a "required" nxc table that was removed requires a code change.
- **Touch PenHub's own schemas** (intentionally outside the map): `collector_vulns` (written by *our* nxc modules), the local merged DB (`_init_local_db`), and `meta`. nxc does not control those.

**Renamed column/table → edit `nxc_schema.json`. New or removed data → edit code.**
