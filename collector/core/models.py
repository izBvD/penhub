"""
Pydantic models for /api/sync payload and other API bodies.
"""

from typing import List, Optional  # noqa: F401 (ConfCheckResultIn, DirectoryListingIn exported)
from pydantic import BaseModel


class HostIn(BaseModel):
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    dc: Optional[int] = None
    smbv1: Optional[int] = None
    signing: Optional[int] = None
    spooler: Optional[int] = None
    zerologon: Optional[int] = None
    petitpotam: Optional[int] = None
    nla: Optional[int] = None
    signing_required: Optional[int] = None
    channel_binding: Optional[str] = None
    port: Optional[int] = None
    banner: Optional[str] = None
    instances: Optional[int] = None


class CredIn(BaseModel):
    proto: str
    domain: str = ""
    username: str = ""
    password: str = ""
    credtype: str = "plaintext"
    pillaged_from_ip: Optional[str] = None
    pkey: Optional[str] = None


class AuthRelIn(BaseModel):
    proto: str
    host_ip: str
    cred_domain: str = ""
    cred_username: str = ""
    cred_password: str = ""
    cred_credtype: str = "plaintext"
    relation_type: str  # 'admin' | 'loggedin'
    shell: Optional[int] = None


class DpapiIn(BaseModel):
    host_ip: Optional[str] = None
    dpapi_type: Optional[str] = None
    windows_user: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None


class ShareIn(BaseModel):
    host_ip: Optional[str] = None
    host_hostname: Optional[str] = None
    proto: str = "SMB"
    cred_domain: Optional[str] = None
    cred_username: Optional[str] = None
    cred_password: Optional[str] = None
    cred_credtype: Optional[str] = None
    name: Optional[str] = None
    remark: Optional[str] = None
    read: Optional[int] = None
    write: Optional[int] = None


class SshKeyIn(BaseModel):
    cred_domain: str = ""
    cred_username: str = ""
    cred_password: str = ""
    cred_credtype: str = "plaintext"
    key_data: Optional[str] = None


class ConfCheckResultIn(BaseModel):
    host_ip: str
    check_name: str
    secure: Optional[int] = None
    reasons: Optional[str] = None


class DirectoryListingIn(BaseModel):
    proto: str
    host_ip: Optional[str] = None
    username: Optional[str] = None
    data: Optional[str] = None


class VulnFindingIn(BaseModel):
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    vuln_name: str  # slug, normalized by the operator reader
    is_vulnerable: Optional[int] = None  # tri-state: 1 / 0 / None(=could-not-check)
    details: Optional[str] = None


class SyncData(BaseModel):
    hosts: List[HostIn] = []
    credentials: List[CredIn] = []
    auth_relations: List[AuthRelIn] = []
    dpapi_secrets: List[DpapiIn] = []
    shares: List[ShareIn] = []
    ssh_keys: List[SshKeyIn] = []
    conf_checks_results: List[ConfCheckResultIn] = []
    directory_listings: List[DirectoryListingIn] = []
    vuln_findings: List[VulnFindingIn] = []


class SyncPayload(BaseModel):
    workspace: str
    operator: str = "unknown"
    data: SyncData


class WorkspaceCreate(BaseModel):
    name: str


class WorkspaceRename(BaseModel):
    name: str


class AdminCredBody(BaseModel):
    workspace_id: int
    domain: str = ""
    username: str = ""
    password: str = ""
    admin_cred: int = 1


class LocalAdminCredBody(BaseModel):
    workspace_id: int
    username: str = ""
    password: str = ""
    local_admin_cred: int = 1


class VulnOverrideBody(BaseModel):
    workspace_id: int
    ip: str
    vuln_name: str
    is_vulnerable: Optional[int]  # 1/0/None; required (no default) — must be explicitly provided
