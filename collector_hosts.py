# collector Hosts module — saves pentest results to nxc-vulns.db (independent of NXC DB schema)
# General Windows host checks (non DC-specific)
# Credits: ms17-010 @d4t4s3c @mpgn_x64 | smbghost @ly4k_ @r4vanan | coerce_plus @mpgn_x64

import contextlib
import socket
import sqlite3
import struct
import threading
from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64
from datetime import datetime
from os.path import join

from impacket import system_errors
from impacket.dcerpc.v5 import transport, epm, rprn, rrp
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUNION, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.rprn import STRING_HANDLE, checkNullString
from impacket.examples.secretsdump import RemoteOperations
from impacket.uuid import uuidtup_to_bin

from impacket import nt_errors
from impacket.nmb import NetBIOSError
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError

from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from nxc.paths import WORKSPACE_DIR
from nxc.protocols.smb.remotefile import RemoteFile


# (name, pipe, uuid_tuple, set_pkt_privacy)
# Detection: bind success = service running + interface registered.
# DFSCoerce/PrinterBug/ShadowCoerce: service disabled = patch → bind fails → reliable.
# PetitPotam: efsrpc pipe is specific to EFS; lsarpc hosts many interfaces so checked second.
#   After KB5014754 the EFS methods are blocked but efsrpc bind may still succeed on patched hosts.
# MSEven excluded: eventlog always runs on every Windows host → 100% false positive with bind-only.
_COERCE_CHECKS = [
    ("DFSCoerce",    r"\PIPE\netdfs",       ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0"), False),
    ("ShadowCoerce", r"\PIPE\Fssagentrpc",  ("a8e0653c-2744-4389-a61d-7373df8b2292", "3.0"), True),
    ("PrinterBug",   r"\PIPE\spoolss",      ("12345678-1234-abcd-ef00-0123456789ab", "1.0"), True),
    # PetitPotam: efsrpc is most specific; samr/lsass/netlogon host the same EFSR interface as lsarpc
    ("PetitPotam",   r"\PIPE\efsrpc",       ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"), True),
    ("PetitPotam",   r"\PIPE\lsarpc",       ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"), True),
    ("PetitPotam",   r"\PIPE\samr",         ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"), True),
    ("PetitPotam",   r"\PIPE\lsass",        ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"), True),
    ("PetitPotam",   r"\PIPE\netlogon",     ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"), True),
]


def _rpc_bind(target, pipe, uuid_tuple, set_pkt_privacy,
              username, password, domain, lmhash, nthash, aesKey,
              doKerberos, dcHost):
    """Try to connect and bind to an RPC endpoint. Returns dce on success, None on failure."""
    string_binding = rf"ncacn_np:{target}[{pipe}]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_dport(445)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)
    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
    rpctransport.setRemoteHost(target)
    dce = rpctransport.get_dce_rpc()
    if doKerberos:
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    if set_pkt_privacy:
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(uuidtup_to_bin(uuid_tuple))
    return dce


# PrinterBug (MS-RPRN) interface — probed both over the spoolss named pipe and over its
# dynamic ncacn_ip_tcp endpoint (mirrors coerce_plus): the dynamic path catches PrinterBug
# when the named pipe is filtered but the RPRN interface is reachable via its RPC port.
_RPRN_UUID = ("12345678-1234-abcd-ef00-0123456789ab", "1.0")


def _get_dynamic_endpoint(interface, target, timeout=5):
    """Resolve an interface to its dynamic ncacn_ip_tcp endpoint via the EPM (port 135)."""
    string_binding = rf"ncacn_ip_tcp:{target}[135]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    return epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)


def _rpc_bind_dynamic(string_binding, target, uuid_tuple,
                      username, password, domain, lmhash, nthash, aesKey,
                      doKerberos, dcHost):
    """Bind to an already-resolved dynamic endpoint (PKT_PRIVACY). Returns dce on success, raises on failure."""
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)
    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
    rpctransport.setRemoteHost(target)
    dce = rpctransport.get_dce_rpc()
    if doKerberos:
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(uuidtup_to_bin(uuid_tuple))
    return dce


_db_lock = threading.Lock()

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

# SMBGhost negotiate packet (SMB 3.1.1 with compression capability)
_SMBGHOST_PKT = (
    b"\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02\"\x02$\x02\x00\x03\x02"
    b"\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00"
    b"\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
)


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


# PrintNightmare constants
_APD_COPY_ALL_FILES      = 0x00000004
_APD_COPY_FROM_DIRECTORY = 0x00000010
_APD_INSTALL_WARNED_DRIVER = 0x00008000
_RPC_E_ACCESS_DENIED     = 0x8001011B
system_errors.ERROR_MESSAGES[_RPC_E_ACCESS_DENIED] = ("RPC_E_ACCESS_DENIED", "Access is denied.")


class _DriverInfo2(NDRSTRUCT):
    structure = (
        ("cVersion",     DWORD),
        ("pName",        LPWSTR),
        ("pEnvironment", LPWSTR),
        ("pDriverPath",  LPWSTR),
        ("pDataFile",    LPWSTR),
        ("pConfigFile",  LPWSTR),
    )


class _PDriverInfo2(NDRPOINTER):
    referent = (("Data", _DriverInfo2),)


class _DriverInfo1(NDRSTRUCT):
    structure = (("pName", STRING_HANDLE),)


class _PDriverInfo1(NDRPOINTER):
    referent = (("Data", _DriverInfo1),)


class _DriverInfoUnion(NDRUNION):
    commonHdr = (("tag", ULONG),)
    union = {1: ("pNotUsed", _PDriverInfo1), 2: ("Level2", _PDriverInfo2)}


class _DriverContainer(NDRSTRUCT):
    structure = (("Level", DWORD), ("DriverInfo", _DriverInfoUnion))


class _RpcAddPrinterDriverEx(NDRCALL):
    opnum = 89
    structure = (
        ("pName",            STRING_HANDLE),
        ("pDriverContainer", _DriverContainer),
        ("dwFileCopyFlags",  DWORD),
    )


class _RpcAddPrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class _SmbHeader(Structure):
    _pack_ = 1
    _fields_ = [
        ("server_component", c_uint32),
        ("smb_command",      c_uint8),
        ("error_class",      c_uint8),
        ("reserved1",        c_uint8),
        ("error_code",       c_uint16),
        ("flags",            c_uint8),
        ("flags2",           c_uint16),
        ("process_id_high",  c_uint16),
        ("signature",        c_uint64),
        ("reserved2",        c_uint16),
        ("tree_id",          c_uint16),
        ("process_id",       c_uint16),
        ("user_id",          c_uint16),
        ("multiplex_id",     c_uint16),
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer):
        pass


class NXCModule:
    name = "collector_hosts"
    description = "collector host checks (MS17-010, SMBGhost, Coerce, WebDAV, PrintNightmare, WDigest, NTLMv1, RunAsPPL, UAC) — results saved to nxc-vulns.db"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        self.context = context
        for check in (self._check_ms17010, self._check_smbghost,
                      self._check_coerce, self._check_webdav,
                      self._check_printnightmare):
            try:
                check(context, connection)
            except Exception as ex:
                context.log.debug(f"[collector_hosts] {check.__name__} unhandled: {ex}")

    def on_admin_login(self, context, connection):
        self.context = context
        for check in (self._check_wdigest, self._check_ntlmv1_runasppl, self._check_uac):
            try:
                check(context, connection)
            except Exception as ex:
                context.log.debug(f"[collector_hosts] {check.__name__} unhandled: {ex}")

    # -------------------------------------------------------------------------

    def _check_smbghost(self, context, connection):
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the check cannot complete
        details = ""

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((connection.host, 445))
                sock.send(_SMBGHOST_PKT)
                nb_data = sock.recv(4)
                if len(nb_data) < 4:
                    details = "Connection closed unexpectedly"  # couldn't determine → None
                else:
                    nb, = struct.unpack(">I", nb_data)
                    res = sock.recv(nb)
                    if res[68:70] == b"\x11\x03" and res[70:72] == b"\x02\x00":
                        is_vulnerable = True
                        details = "SMB 3.1.1 with compression capability detected"
                    else:
                        is_vulnerable = False  # full response parsed, no compression → clean
                        details = "Not vulnerable"
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[SMBGhost] {details}")

        if is_vulnerable:
            context.log.highlight("[SMBGhost] VULNERABLE (CVE-2020-0796)")

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
            vuln_name="SMBGhost (CVE-2020-0796)",
            is_vulnerable=is_vulnerable,
            details=details,
        )

    def _check_ms17010(self, context, connection):
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the probe cannot complete
        details = ""

        try:
            is_vulnerable, details = self._ms17010_probe(connection.host)
        except ConnectionResetError:
            details = "Connection reset"
            context.log.debug(f"[MS17-010] Connection reset on {connection.host}")
        except ValueError as ex:
            details = f"Unexpected response: {ex}"
            context.log.debug(f"[MS17-010] {details}")
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[MS17-010] {details}")

        if is_vulnerable:
            context.log.highlight(f"[MS17-010] VULNERABLE — {details}")
            context.log.highlight("[MS17-010] Next step: https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/")
        elif details:
            context.log.debug(f"[MS17-010] {details}")

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
            vuln_name="MS17-010 EternalBlue",
            is_vulnerable=is_vulnerable,
            details=details,
        )

    def _ms17010_probe(self, ip, port=445):
        """Returns (is_vulnerable, details). Raises on socket errors."""
        bufsize = 1024
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        client.connect((ip, port))

        client.send(self._negotiate_proto_request())
        client.recv(bufsize)

        client.send(self._session_setup_andx_request())
        tcp_response = client.recv(bufsize)

        smb = _SmbHeader(tcp_response[4:36])
        user_id = struct.pack("<H", smb.user_id)
        native_os = tcp_response[45:].split(b"\x00")[0].decode(errors="replace")

        client.send(self._tree_connect_andx_request(ip, user_id))
        tcp_response = client.recv(bufsize)

        smb = _SmbHeader(tcp_response[4:36])
        tree_id     = struct.pack("<H", smb.tree_id)
        process_id  = struct.pack("<H", smb.process_id)
        user_id     = struct.pack("<H", smb.user_id)
        multiplex_id = struct.pack("<H", smb.multiplex_id)

        client.send(self._peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id))
        tcp_response = client.recv(bufsize)

        smb = _SmbHeader(tcp_response[4:36])
        nt_status = struct.pack("BBH", smb.error_class, smb.reserved1, smb.error_code)

        # STATUS_INSUFF_SERVER_RESOURCES → vulnerable
        if nt_status == b"\x05\x02\x00\xc0":
            details = f"OS: {native_os}"
            # check DoublePulsar backdoor
            client.send(self._trans2_request(tree_id, process_id, user_id, multiplex_id))
            tcp_response = client.recv(bufsize)
            smb = _SmbHeader(tcp_response[4:36])
            if smb.multiplex_id == 0x0051:
                key = (2 * smb.signature ^ (
                    ((smb.signature & 0xff00 | (smb.signature << 16)) << 8) |
                    (((smb.signature >> 16) | smb.signature & 0xff0000) >> 8)
                )) & 0xffffffff
                details += f"; DoublePulsar INFECTED (XOR key: {key:#010x})"
            client.close()
            return True, details

        client.close()

        if nt_status in (b"\x08\x00\x00\xc0", b"\x22\x00\x00\xc0"):
            return False, "Not vulnerable"
        return False, f"Unable to determine (NT status: {nt_status.hex()})"

    def _check_coerce(self, context, connection):
        db_path = _collector_db_path(context)
        target = connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}"
        creds = dict(
            username=connection.username or "",
            password=connection.password or "",
            domain=connection.domain or "",
            lmhash=connection.lmhash or "",
            nthash=connection.nthash or "",
            aesKey=connection.aesKey or "",
            doKerberos=connection.kerberos,
            dcHost=connection.kdcHost,
        )

        # PetitPotam: activate EFS before probing (same as original coerce_plus)
        with contextlib.suppress(Exception):
            epm.hept_map(target, uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "0.0")),
                         protocol="ncacn_ip_tcp")

        # Accumulate best result per name before saving.
        # PetitPotam has two pipes — if lsarpc fails but efsrpc succeeds,
        # we must not save a False record for lsarpc and then a True for efsrpc.
        results = {}  # name → (is_vulnerable, details)
        for name, pipe, uuid_tuple, pkt_privacy in _COERCE_CHECKS:
            if results.get(name, (False,))[0]:  # already confirmed vulnerable
                continue
            is_vulnerable = False
            details = ""
            try:
                dce = _rpc_bind(target, pipe, uuid_tuple, pkt_privacy, **creds)
                is_vulnerable = True
                details = f"Pipe: {pipe}"
                with contextlib.suppress(Exception):
                    dce.disconnect()
            except Exception as ex:
                details = f"Not vulnerable ({ex})"
                context.log.debug(f"[Coerce/{name}] {details}")

            if is_vulnerable or name not in results:
                results[name] = (is_vulnerable, details)

        # Dynamic fallback for PrinterBug — mirrors coerce_plus [dcerpc] path.
        # Catches PrinterBug when the spoolss named pipe is filtered but RPRN is
        # reachable via its dynamic TCP endpoint.
        if not results.get("PrinterBug", (False,))[0]:
            try:
                string_binding = _get_dynamic_endpoint(
                    uuidtup_to_bin(_RPRN_UUID), target, timeout=3
                )
                dce = _rpc_bind_dynamic(string_binding, target, _RPRN_UUID, **creds)
                results["PrinterBug"] = (True, "Dynamic endpoint (dcerpc)")
                with contextlib.suppress(Exception):
                    dce.disconnect()
            except Exception as ex:
                if "PrinterBug" not in results:
                    results["PrinterBug"] = (False, f"Not vulnerable ({ex})")

        for name, (is_vulnerable, details) in results.items():
            if is_vulnerable:
                context.log.highlight(f"[Coerce] VULNERABLE — {name}")
            _save(
                db_path,
                protocol="smb",
                port=getattr(connection, "port", 445),
                ip=connection.host,
                hostname=getattr(connection, "hostname", None),
                domain=getattr(connection, "domain", None),
                username=connection.username,
                password=None,
                lmhash=None,
                nthash=None,
                vuln_name=f"Coerce/{name}",
                is_vulnerable=is_vulnerable,
                details=details,
            )

    def _check_webdav(self, context, connection):
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the check cannot complete
        details = ""
        remote_file = None
        try:
            remote_file = RemoteFile(connection.conn, "DAV RPC Service", "IPC$", access=FILE_READ_DATA)
            remote_file.open_file()
            is_vulnerable = True
            details = "DAV RPC Service pipe found"
        except SessionError as ex:
            if ex.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                is_vulnerable = False  # pipe confirmed absent → clean
                details = "WebClient not running"
            else:
                details = f"SessionError: {ex}"  # couldn't determine → None
                context.log.debug(f"[WebDAV] {details}")
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as ex:
            details = f"Transport error: {ex.__class__.__name__}"  # → None
            context.log.debug(f"[WebDAV] {details}")
        finally:
            if remote_file is not None:
                with contextlib.suppress(Exception):
                    remote_file.close()

        if is_vulnerable:
            context.log.highlight("[WebDAV] WebClient service is running")

        _save(
            db_path,
            protocol="smb",
            port=getattr(connection, "port", 445),
            ip=connection.host,
            hostname=getattr(connection, "hostname", None),
            domain=getattr(connection, "domain", None),
            username=connection.username,
            password=None,
            lmhash=None,
            nthash=None,
            vuln_name="WebDAV",
            is_vulnerable=is_vulnerable,
            details=details,
        )

    def _check_printnightmare(self, context, connection):
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if the check cannot complete
        details = ""
        try:
            rpctransport = transport.SMBTransport(
                connection.conn.getRemoteHost(),
                filename=r"\spoolss",
                smb_connection=connection.conn,
            )
            dce = rpctransport.get_dce_rpc()
            if connection.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as ex:
            details = f"Spooler bind failed: {ex}"  # couldn't test (spooler unreachable) → None
            context.log.debug(f"[PrintNightmare] {details}")
            _save(db_path, "smb", getattr(connection, "port", 445),
                  connection.host, getattr(connection, "hostname", None),
                  getattr(connection, "domain", None),
                  connection.username, None, None, None,
                  "PrintNightmare (CVE-2021-1675)", None, details)
            return

        container = _DriverContainer()
        container["Level"] = 2
        container["DriverInfo"]["tag"] = 2
        for field in ("cVersion", "pName", "pEnvironment", "pDriverPath", "pDataFile", "pConfigFile"):
            container["DriverInfo"]["Level2"][field] = 0 if field == "cVersion" else NULL

        try:
            req = _RpcAddPrinterDriverEx()
            req["pName"] = checkNullString(NULL)
            req["pDriverContainer"] = container
            req["dwFileCopyFlags"] = _APD_COPY_ALL_FILES | _APD_COPY_FROM_DIRECTORY | _APD_INSTALL_WARNED_DRIVER
            dce.request(req)
            # no exception at all → also vulnerable
            is_vulnerable = True
            details = "RpcAddPrinterDriverEx succeeded"
        except DCERPCException as ex:
            code = ex.error_code
            if code == system_errors.ERROR_INVALID_PARAMETER:
                is_vulnerable = True
                details = "ERROR_INVALID_PARAMETER (parameter check reached → not patched)"
            elif code == _RPC_E_ACCESS_DENIED or (
                hasattr(ex, "error_code") and
                str(ex).find("rpc_s_access_denied") >= 0
            ):
                is_vulnerable = False  # access denied → patched → clean
                details = "Access denied (patched)"
            else:
                details = f"Unexpected error: {ex}"
                context.log.debug(f"[PrintNightmare] {details}")
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[PrintNightmare] {details}")
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

        if is_vulnerable:
            context.log.highlight("[PrintNightmare] VULNERABLE (CVE-2021-1675)")

        _save(db_path, "smb", getattr(connection, "port", 445),
              connection.host, getattr(connection, "hostname", None),
              getattr(connection, "domain", None),
              connection.username, None, None, None,
              "PrintNightmare (CVE-2021-1675)", is_vulnerable, details)

    def _check_ntlmv1_runasppl(self, context, connection):
        """Reads HKLM\\SYSTEM\\...\\Lsa once for both NTLMv1 and RunAsPPL."""
        _LSA_KEY = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
        db_path = _collector_db_path(context)
        remote_ops = None
        ntlmv1_data = _MISSING = object()
        runasppl_data = _MISSING

        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            handle = remote_ops._RemoteOperations__rrp
            if not handle:
                raise RuntimeError("RemoteRegistry handle unavailable")
            hklm = rrp.hOpenLocalMachine(handle)["phKey"]
            key  = rrp.hBaseRegOpenKey(handle, hklm, _LSA_KEY)["phkResult"]

            with contextlib.suppress(DCERPCException):
                _, ntlmv1_data = rrp.hBaseRegQueryValue(handle, key, "lmcompatibilitylevel\x00")

            with contextlib.suppress(DCERPCException):
                _, runasppl_data = rrp.hBaseRegQueryValue(handle, key, "RunAsPPL\x00")

        except Exception as ex:
            err = f"RemoteRegistry error: {ex}"  # couldn't read registry → None for both
            context.log.debug(f"[NTLMv1/RunAsPPL] {err}")
            _save(db_path, "smb", getattr(connection, "port", 445),
                  connection.host, getattr(connection, "hostname", None),
                  getattr(connection, "domain", None),
                  connection.username, None, None, None,
                  "NTLMv1", None, err)
            _save(db_path, "smb", getattr(connection, "port", 445),
                  connection.host, getattr(connection, "hostname", None),
                  getattr(connection, "domain", None),
                  connection.username, None, None, None,
                  "RunAsPPL", None, err)
            return
        finally:
            with contextlib.suppress(Exception):
                if remote_ops:
                    remote_ops.finish()

        # NTLMv1: absent key means default level 3 (Vista+) = NTLMv1 disabled
        if ntlmv1_data is _MISSING:
            is_vuln = False
            details = "LmCompatibilityLevel absent (default=3, NTLMv1 disabled)"
        else:
            is_vuln = ntlmv1_data in [0, 1, 2]
            details = f"LmCompatibilityLevel = {ntlmv1_data}"
            if is_vuln:
                context.log.highlight(f"[NTLMv1] ALLOWED — {details}")
        _save(db_path, "smb", getattr(connection, "port", 445),
              connection.host, getattr(connection, "hostname", None),
              getattr(connection, "domain", None),
              connection.username, None, None, None,
              "NTLMv1", is_vuln, details)

        # RunAsPPL: absent = disabled = lsass is unprotected
        if runasppl_data is _MISSING:
            runasppl_val = None
        else:
            runasppl_val = runasppl_data
        is_vuln = runasppl_val not in [1, 2]
        details = "RunAsPPL absent (disabled)" if runasppl_val is None else f"RunAsPPL = {runasppl_val}"
        if is_vuln:
            context.log.highlight("[RunAsPPL] DISABLED — lsass unprotected")
        _save(db_path, "smb", getattr(connection, "port", 445),
              connection.host, getattr(connection, "hostname", None),
              getattr(connection, "domain", None),
              connection.username, None, None, None,
              "RunAsPPL", is_vuln, details)

    def _check_uac(self, context, connection):
        _UAC_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        db_path = _collector_db_path(context)
        remote_ops = None
        is_vulnerable = None  # tri-state: stays None if registry can't be read
        details = ""
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            handle = remote_ops._RemoteOperations__rrp
            if not handle:
                details = "RemoteRegistry unavailable"
            else:
                hklm  = rrp.hOpenLocalMachine(handle)["phKey"]
                key   = rrp.hBaseRegOpenKey(handle, hklm, _UAC_KEY)["phkResult"]
                _, data = rrp.hBaseRegQueryValue(handle, key, "EnableLUA\x00")
                is_vulnerable = data == 0
                details = f"EnableLUA = {data}"
                if is_vulnerable:
                    context.log.highlight("[UAC] DISABLED")
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[UAC] {details}")
        finally:
            with contextlib.suppress(Exception):
                if remote_ops:
                    remote_ops.finish()

        _save(db_path, "smb", getattr(connection, "port", 445),
              connection.host, getattr(connection, "hostname", None),
              getattr(connection, "domain", None),
              connection.username, None, None, None,
              "UAC", is_vulnerable, details)

    def _check_wdigest(self, context, connection):
        _WDIGEST_KEY = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
        db_path = _collector_db_path(context)
        is_vulnerable = None  # tri-state: stays None if registry can't be read
        details = ""
        remote_ops = None
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            rrp_handle = remote_ops._RemoteOperations__rrp
            if not rrp_handle:
                details = "RemoteRegistry unavailable"  # → None
                context.log.debug(f"[WDigest] {details}")
            else:
                hklm = rrp.hOpenLocalMachine(rrp_handle)["phKey"]
                key = rrp.hBaseRegOpenKey(rrp_handle, hklm, _WDIGEST_KEY)["phkResult"]
                try:
                    _, data = rrp.hBaseRegQueryValue(rrp_handle, key, "UseLogonCredential\x00")
                    if int(data) == 1:
                        is_vulnerable = True
                        details = "UseLogonCredential = 1 (WDigest enabled)"
                    else:
                        is_vulnerable = False  # read OK, disabled → clean
                        details = f"UseLogonCredential = {data} (disabled)"
                except DCERPCException:
                    is_vulnerable = False  # key absent → disabled → clean
                    details = "UseLogonCredential key absent (disabled)"
        except Exception as ex:
            details = f"Error: {ex}"
            context.log.debug(f"[WDigest] {details}")
        finally:
            with contextlib.suppress(Exception):
                if remote_ops:
                    remote_ops.finish()

        if is_vulnerable:
            context.log.highlight("[WDigest] ENABLED — plaintext creds stored in LSASS")

        _save(
            db_path,
            protocol="smb",
            port=getattr(connection, "port", 445),
            ip=connection.host,
            hostname=getattr(connection, "hostname", None),
            domain=getattr(connection, "domain", None),
            username=connection.username,
            password=None,
            lmhash=None,
            nthash=None,
            vuln_name="WDigest",
            is_vulnerable=is_vulnerable,
            details=details,
        )

    # -- MS17-010 packet builders ---------------------------------------------

    @staticmethod
    def _flatten(*protos):
        out = b""
        for p in protos:
            out += NXCModule._flatten(*p) if isinstance(p, list) else p
        return out

    def _negotiate_proto_request(self):
        netbios = [b"\x00", b"\x00\x00\x54"]
        smb_header = [
            b"\xFF\x53\x4D\x42", b"\x72", b"\x00\x00\x00\x00",
            b"\x18", b"\x01\x28", b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00",
            b"\x00\x00", b"\x2F\x4B", b"\x00\x00", b"\xC5\x5E",
        ]
        body = [
            b"\x00", b"\x31\x00", b"\x02",
            b"\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00",
            b"\x02", b"\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00",
            b"\x02", b"\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00",
            b"\x02", b"\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00",
        ]
        return self._flatten(netbios, smb_header, body)

    def _session_setup_andx_request(self):
        netbios = [b"\x00", b"\x00\x00\x63"]
        smb_header = [
            b"\xFF\x53\x4D\x42", b"\x73", b"\x00\x00\x00\x00",
            b"\x18", b"\x01\x20", b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00",
            b"\x00\x00", b"\x2F\x4B", b"\x00\x00", b"\xC5\x5E",
        ]
        body = [
            b"\x0D", b"\xFF", b"\x00", b"\x00\x00",
            b"\xDF\xFF", b"\x02\x00", b"\x01\x00", b"\x00\x00\x00\x00",
            b"\x00\x00", b"\x00\x00", b"\x00\x00\x00\x00", b"\x40\x00\x00\x00",
            b"\x26\x00", b"\x00", b"\x2e\x00",
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00",
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00",
        ]
        return self._flatten(netbios, smb_header, body)

    def _tree_connect_andx_request(self, ip, userid):
        ipc = f"\\\\{ip}\\IPC$\x00".encode()
        smb_header = [
            b"\xFF\x53\x4D\x42", b"\x75", b"\x00\x00\x00\x00",
            b"\x18", b"\x01\x20", b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00",
            b"\x00\x00", b"\x2F\x4B", userid, b"\xC5\x5E",
        ]
        body = [
            b"\x04", b"\xFF", b"\x00", b"\x00\x00",
            b"\x00\x00", b"\x01\x00", b"\x1A\x00", b"\x00",
            ipc, b"\x3f\x3f\x3f\x3f\x3f\x00",
        ]
        length = len(self._flatten(smb_header)) + len(self._flatten(body))
        netbios = [b"\x00", struct.pack(">L", length)[-3:]]
        return self._flatten(netbios, smb_header, body)

    def _peeknamedpipe_request(self, treeid, processid, userid, multiplex_id):
        netbios = [b"\x00", b"\x00\x00\x4a"]
        smb_header = [
            b"\xFF\x53\x4D\x42", b"\x25", b"\x00\x00\x00\x00",
            b"\x18", b"\x01\x28", b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00",
            treeid, processid, userid, multiplex_id,
        ]
        body = [
            b"\x10", b"\x00\x00", b"\x00\x00", b"\xff\xff", b"\xff\xff",
            b"\x00", b"\x00", b"\x00\x00", b"\x00\x00\x00\x00", b"\x00\x00",
            b"\x00\x00", b"\x4a\x00", b"\x00\x00", b"\x4a\x00", b"\x02", b"\x00",
            b"\x23\x00", b"\x00\x00", b"\x07\x00", b"\x5c\x50\x49\x50\x45\x5c\x00",
        ]
        return self._flatten(netbios, smb_header, body)

    def _trans2_request(self, treeid, processid, userid, multiplex_id):
        netbios = [b"\x00", b"\x00\x00\x4f"]
        smb_header = [
            b"\xFF\x53\x4D\x42", b"\x32", b"\x00\x00\x00\x00",
            b"\x18", b"\x07\xc0", b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00",
            treeid, processid, userid, multiplex_id,
        ]
        body = [
            b"\x0f", b"\x0c\x00", b"\x00\x00", b"\x01\x00", b"\x00\x00",
            b"\x00", b"\x00", b"\x00\x00", b"\xa6\xd9\xa4\x00", b"\x00\x00",
            b"\x0c\x00", b"\x42\x00", b"\x00\x00", b"\x4e\x00", b"\x01", b"\x00",
            b"\x0e\x00", b"\x00\x00",
            b"\x0c\x00" + b"\x00" * 12,
        ]
        return self._flatten(netbios, smb_header, body)
