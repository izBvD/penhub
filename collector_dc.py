# collector DC module — saves pentest results to nxc-vulns.db (independent of NXC DB schema)
# Checks: noPac (CVE-2021-42278/42287), Zerologon (CVE-2020-1472)
# Credits: @exploitph @Evi1cg @mpgn_x64 @dirkjanm

import sqlite3
import threading
from datetime import datetime
from os.path import join
from binascii import unhexlify

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

from nxc.helpers.misc import CATEGORY
from nxc.paths import WORKSPACE_DIR


_db_lock = threading.Lock()

MAX_ZEROLOGON_ATTEMPTS = 2000  # false negative chance ~0.04% at 2000 attempts

_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS collector_vulns (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol      TEXT    NOT NULL,
        port          INTEGER,
        ip            TEXT    NOT NULL,
        hostname      TEXT,
        domain        TEXT,
        username      TEXT,
        password      TEXT,
        lmhash        TEXT,
        nthash        TEXT,
        vuln_name     TEXT    NOT NULL,
        is_vulnerable INTEGER,
        details       TEXT,
        timestamp     TEXT    NOT NULL
    )
"""

_INSERT = """
    INSERT INTO collector_vulns
        (protocol, port, ip, hostname, domain,
         username, password, lmhash, nthash,
         vuln_name, is_vulnerable, details, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _collector_db_path(context):
    workspace = context.conf.get("nxc", "workspace", fallback="default")
    return join(WORKSPACE_DIR, workspace, "nxc-vulns.db")


def _save(db_path, protocol, port, ip, hostname, domain,
          username, password, lmhash, nthash,
          vuln_name, is_vulnerable, details):
    # Tri-state: 1=vulnerable, 0=checked-clean, None=could-not-check (stored NULL).
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    iv = None if is_vulnerable is None else int(is_vulnerable)
    row = (protocol, port, ip, hostname, domain,
           username, password, lmhash, nthash,
           vuln_name, iv, details, timestamp)
    with _db_lock:
        with sqlite3.connect(db_path) as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_INSERT, row)


def _try_zero_authenticate(rpc_con, dc_handle, target_computer):
    plaintext = b"\x00" * 8
    ciphertext = b"\x00" * 8
    flags = 0x212FFFFF
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + "\x00", target_computer + "\x00", plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con,
            dc_handle + "\x00",
            target_computer + "$\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + "\x00",
            ciphertext,
            flags,
        )
        assert server_auth["ErrorCode"] == 0
        return True
    except nrpc.DCERPCSessionError as ex:
        if ex.get_error_code() == 0xC0000022:
            return None
        raise


class NXCModule:
    name = "collector_dc"
    description = "collector DC checks (noPac CVE-2021-42278/42287, Zerologon CVE-2020-1472) — results saved to nxc-vulns.db"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        self.context = context
        for check in (self._check_zerologon, self._check_nopac):
            try:
                check(context, connection)
            except Exception as ex:
                context.log.debug(f"[collector_dc] {check.__name__} unhandled: {ex}")

    # -------------------------------------------------------------------------

    def _check_zerologon(self, context, connection):
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the check cannot run
        details = ""

        try:
            target_computer = connection.hostname or connection.host
            dc_handle = "\\\\" + target_computer
            binding = epm.hept_map(connection.host, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.setRemoteHost(connection.host)
            rpctransport.set_credentials("", "", "", "", "", "")
            rpctransport.set_kerberos(False, None)
            rpc_con = rpctransport.get_dce_rpc()
            rpc_con.connect()
            rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
            for _ in range(MAX_ZEROLOGON_ATTEMPTS):
                result = _try_zero_authenticate(rpc_con, dc_handle, target_computer)
                if result:
                    is_vulnerable = True
                    break
            else:
                is_vulnerable = False  # completed all attempts → checked-clean
                details = "Not vulnerable (patched)"
                context.log.highlight("[Zerologon] Not vulnerable (patched)")

        except DCERPCException:
            details = "DCERPCException — likely not a DC or port closed"
            context.log.fail(f"[Zerologon] {details}")
        except Exception as ex:
            details = f"Unexpected error: {ex}"
            context.log.debug(f"[Zerologon] {details}")

        if is_vulnerable:
            details = "Zero-authentication succeeded against Netlogon"
            context.log.highlight("[Zerologon] VULNERABLE")
            context.log.highlight("[Zerologon] Next step: https://github.com/dirkjanm/CVE-2020-1472")

        _save(
            db_path,
            protocol="smb",
            port=getattr(connection, "port", 445),
            ip=connection.host,
            hostname=getattr(connection, "hostname", None),
            domain=getattr(connection, "domain", None),
            username=None,
            password=None,
            lmhash=None,
            nthash=None,
            vuln_name="Zerologon (CVE-2020-1472)",
            is_vulnerable=is_vulnerable,
            details=details,
        )

    def _check_nopac(self, context, connection):
        if not connection.username:
            context.log.fail("[noPac] Module requires a username")
            return

        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the check cannot run
        details = ""
        user_name = Principal(connection.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        lmhash = unhexlify(connection.lmhash or "")
        nthash = unhexlify(connection.nthash or "")
        try:
            tgt_with_pac, _, _, _ = getKerberosTGT(
                user_name,
                connection.password or "",
                connection.domain,
                lmhash,
                nthash,
                connection.aesKey or "",
                connection.host,
                requestPAC=True,
            )
            context.log.highlight(f"[noPac] TGT with PAC size {len(tgt_with_pac)}")

            tgt_no_pac, _, _, _ = getKerberosTGT(
                user_name,
                connection.password or "",
                connection.domain,
                lmhash,
                nthash,
                connection.aesKey or "",
                connection.host,
                requestPAC=False,
            )
            context.log.highlight(f"[noPac] TGT without PAC size {len(tgt_no_pac)}")

            is_vulnerable = len(tgt_no_pac) < len(tgt_with_pac)
            details = f"TGT with PAC: {len(tgt_with_pac)} B, TGT without PAC: {len(tgt_no_pac)} B"

            if is_vulnerable:
                context.log.highlight("[noPac] VULNERABLE")
                context.log.highlight("[noPac] Next step: https://github.com/Ridter/noPac")

        except OSError:
            details = f"Kerberos unreachable (port 88) on {connection.host}"
            context.log.debug(f"[noPac] {details}")
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[noPac] {details}")

        _save(
            db_path,
            protocol="smb",
            port=getattr(connection, "port", 445),
            ip=connection.host,
            hostname=getattr(connection, "hostname", None),
            domain=connection.domain,
            username=connection.username,
            password=connection.password,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            vuln_name="noPac (CVE-2021-42278/42287)",
            is_vulnerable=is_vulnerable,
            details=details,
        )
