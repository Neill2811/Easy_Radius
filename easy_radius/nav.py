"""Sidebar entries and the cheap attention marks shown beside them.

Counts come from data already saved by a compliance check or a monitoring
check. Loading a page does not contact a router.
"""

from __future__ import annotations

from easy_radius.compliance import router_compliant

# endpoint name -> sidebar id
_PAGES: dict[str, set[str]] = {
    "dashboard": {"index"},
    "users": {"users", "user_new", "user_create", "user_edit", "user_update", "user_enabled"},
    "routers": {"routers", "server_address", "router_new", "router_create", "router_edit", "router_update", "router_enabled"},
    "access": {"grants", "grants_create"},
    "test": {"test_page", "test_post"},
    "apply": {"apply_page", "apply_post"},
    "automation": {
        "automation",
        "automation_account",
        "automation_task_new",
        "automation_task_create",
        "automation_task_edit",
        "automation_task_update",
        "automation_task_upload",
        "automation_task_delete",
        "automation_run_form",
        "automation_run_post",
        "automation_run_detail",
        "automation_export",
        "automation_restore",
    },
    "backups": {"config_backups", "config_backup_settings", "config_backup_run", "config_backup_diff"},
    "firmware": {"firmware", "firmware_latest", "firmware_refresh", "firmware_upgrade"},
    "compliance": {"compliance", "compliance_check", "compliance_fix"},
    "monitoring": {"monitoring", "monitoring_settings", "monitoring_check"},
    "logins": {"logins"},
    "sessions": {"sessions"},
    "inventory": {"inventory", "inventory_refresh", "inventory_csv"},
    "reports": {"reports", "reports_download"},
    "history": {"history", "history_rollback"},
    "security": {"security", "security_password", "security_start", "security_confirm", "security_disable"},
    "backup": {"backup_page", "backup_download", "backup_restore"},
}

NAV_GROUPS: list[dict] = [
    {
        "label": "",
        "items": [
            {"id": "dashboard", "label": "Dashboard", "endpoint": "index", "icon": "home"},
        ],
    },
    {
        "label": "Access",
        "items": [
            {"id": "users", "label": "Users", "endpoint": "users", "icon": "users"},
            {"id": "routers", "label": "Routers", "endpoint": "routers", "icon": "routers"},
            {"id": "access", "label": "Temporary access", "endpoint": "grants", "icon": "clock"},
            {"id": "test", "label": "Test login", "endpoint": "test_page", "icon": "play"},
        ],
    },
    {
        "label": "Configuration",
        "items": [
            {"id": "apply", "label": "Apply", "endpoint": "apply_page", "icon": "check"},
            {"id": "automation", "label": "Automation", "endpoint": "automation", "icon": "bolt"},
            {"id": "backups", "label": "Backups", "endpoint": "config_backups", "icon": "archive"},
            {"id": "firmware", "label": "Firmware", "endpoint": "firmware", "icon": "chip"},
            {"id": "compliance", "label": "Compliance", "endpoint": "compliance", "icon": "shield"},
        ],
    },
    {
        "label": "Monitoring",
        "items": [
            {"id": "monitoring", "label": "Monitoring", "endpoint": "monitoring", "icon": "pulse"},
            {"id": "logins", "label": "Logins", "endpoint": "logins", "icon": "list"},
            {"id": "sessions", "label": "Sessions", "endpoint": "sessions", "icon": "sessions"},
            {"id": "inventory", "label": "Inventory", "endpoint": "inventory", "icon": "grid"},
        ],
    },
    {
        "label": "Reports & audit",
        "items": [
            {"id": "reports", "label": "Reports", "endpoint": "reports", "icon": "file"},
            {"id": "history", "label": "History", "endpoint": "history", "icon": "history"},
        ],
    },
    {
        "label": "System",
        "items": [
            {"id": "security", "label": "Admin password & 2FA", "endpoint": "security", "icon": "lock"},
            {"id": "backup", "label": "Easy Radius backup", "endpoint": "backup_page", "icon": "download"},
        ],
    },
]


def current_nav(endpoint: str | None) -> str:
    if not endpoint:
        return ""
    for page_id, names in _PAGES.items():
        if endpoint in names:
            return page_id
    return ""


def failing_routers(state: dict) -> int:
    report = state.get("last_compliance")
    if not isinstance(report, dict):
        return 0
    count = 0
    for router in report.get("routers") or []:
        if isinstance(router, dict) and not router_compliant(router):
            count += 1
    return count


def monitoring_attention(state: dict) -> bool:
    """True when the last stored monitoring check left a down router or any alert."""
    alerts = state.get("monitor_alerts") or []
    return any(isinstance(alert, dict) for alert in alerts)
