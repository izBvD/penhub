"""
Central router — aggregates all sub-routers into one api_router.
Import order determines route priority; pages (/) must come last
to avoid shadowing more specific paths.
"""

from fastapi import APIRouter

from collector.api import (
    auth, data, dal, data_hosts, data_manage,
    export, hashkiller, notifications, pages, reports_local_admin, sync, timeline,
    toolbox, toolbox_exports, workspaces,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(workspaces.router)
api_router.include_router(sync.router)
api_router.include_router(data.router)
api_router.include_router(data_hosts.router)
api_router.include_router(data_manage.router)
api_router.include_router(dal.router)
api_router.include_router(notifications.router)
api_router.include_router(export.router)
api_router.include_router(hashkiller.router)
api_router.include_router(toolbox.router)
api_router.include_router(toolbox_exports.router)
api_router.include_router(timeline.router)
api_router.include_router(reports_local_admin.router)
api_router.include_router(pages.router)   # /, /hashkiller, /favicon.ico — last
