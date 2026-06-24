"""
NXC Collector — shell page builder.

Generates HTML_PAGE once at import time.
CSS and JS are served as static files; the page contains only <link> and <script> tags.

Adding a new module (zero changes to this file):
  1. Create  static/modules/<name>/module.css
  2. Create  static/modules/<name>/module.js
  3. Override  static_css / static_js  in the module class (modules/base.py contract).
  4. Register the module in penhub/app.py  (already required for every module).
  The shell picks up new assets automatically via the registry.
"""

import hashlib
from pathlib import Path

from collector._frontend._html import HTML_LAYOUT
from penhub.shell.registry import shell_registry


def _v(path: Path) -> str:
    """8-char content hash for cache-busting (computed once at startup)."""
    try:
        return hashlib.md5(path.read_bytes()).hexdigest()[:8]
    except OSError:
        return "0"


def _build() -> str:
    # Shell CSS, split by zone; load order = former shell.css top-to-bottom (cascade preserved)
    shell_base_css     = Path("static/shell-base.css")
    shell_controls_css = Path("static/shell-controls.css")
    shell_table_css    = Path("static/shell-table.css")
    shell_sidebar_css  = Path("static/shell-sidebar.css")
    shell_misc_css     = Path("static/shell-misc.css")
    shell_login_css    = Path("static/shell-login.css")
    shell_projects_css = Path("static/shell-projects.css")
    shell_notif_css    = Path("static/shell-notifications.css")
    shell_core_js      = Path("static/shell-core.js")
    shell_projects_js  = Path("static/shell-projects.js")
    shell_notif_js     = Path("static/shell-notifications.js")
    sidebar_anim_js    = Path("static/sidebar-anim.js")
    # NXC Collector JS, split by responsibility; load order = former shell.js top-to-bottom
    nxc_filters_js        = Path("static/shell-nxc-filters.js")
    nxc_loaders_js        = Path("static/shell-nxc-loaders.js")
    nxc_manage_js         = Path("static/shell-nxc-manage.js")
    nxc_render_helpers_js = Path("static/shell-nxc-render-helpers.js")
    nxc_render_js         = Path("static/shell-nxc-render.js")
    nxc_shell_js          = Path("static/shell-nxc-shell.js")

    # DS token CSS files (define CSS variables used by the login React app)
    ds_colors_css     = Path("static/_ds/tokens/colors.css")
    ds_typography_css = Path("static/_ds/tokens/typography.css")
    ds_spacing_css    = Path("static/_ds/tokens/spacing.css")
    ds_effects_css    = Path("static/_ds/tokens/effects.css")
    ds_base_css       = Path("static/_ds/tokens/base.css")
    ds_core_css       = Path("static/_ds/components/core/core.css")

    # Login React app dependencies
    react_js          = Path("static/react.production.min.js")
    react_dom_js      = Path("static/react-dom.production.min.js")
    ds_bundle_js      = Path("static/_ds/_ds_bundle.js")
    auth_app_js       = Path("static/auth-app.js")

    css_tags: list[str] = [
        # DS token CSS must come before shell-login.css so variables are defined
        f'<link rel="stylesheet" href="/static/_ds/tokens/colors.css?v={_v(ds_colors_css)}">',
        f'<link rel="stylesheet" href="/static/_ds/tokens/typography.css?v={_v(ds_typography_css)}">',
        f'<link rel="stylesheet" href="/static/_ds/tokens/spacing.css?v={_v(ds_spacing_css)}">',
        f'<link rel="stylesheet" href="/static/_ds/tokens/effects.css?v={_v(ds_effects_css)}">',
        f'<link rel="stylesheet" href="/static/_ds/tokens/base.css?v={_v(ds_base_css)}">',
        f'<link rel="stylesheet" href="/static/_ds/components/core/core.css?v={_v(ds_core_css)}">',
        f'<link rel="stylesheet" href="/static/shell-base.css?v={_v(shell_base_css)}">',
        f'<link rel="stylesheet" href="/static/shell-controls.css?v={_v(shell_controls_css)}">',
        f'<link rel="stylesheet" href="/static/shell-table.css?v={_v(shell_table_css)}">',
        f'<link rel="stylesheet" href="/static/shell-sidebar.css?v={_v(shell_sidebar_css)}">',
        f'<link rel="stylesheet" href="/static/shell-misc.css?v={_v(shell_misc_css)}">',
        f'<link rel="stylesheet" href="/static/shell-login.css?v={_v(shell_login_css)}">',
        f'<link rel="stylesheet" href="/static/shell-projects.css?v={_v(shell_projects_css)}">',
        f'<link rel="stylesheet" href="/static/shell-notifications.css?v={_v(shell_notif_css)}">',
    ]
    # module CSS tags (injected before </head>, ordered by module.order)
    for mod in sorted(shell_registry.get_enabled(), key=lambda m: m.order):
        if mod.static_css and mod.static_css.exists():
            url = "/" + mod.static_css.as_posix()
            css_tags.append(f'<link rel="stylesheet" href="{url}?v={_v(mod.static_css)}">')

    # Load order:
    # 1. React + DS bundle + auth-app (login screen, mounts immediately to #app)
    # 2. shell-core.js (framework) → shell-projects.js (auth/projects) → shell-nxc-*.js (NXC collector)
    js_tags: list[str] = [
        f'<script src="/static/react.production.min.js?v={_v(react_js)}"></script>',
        f'<script src="/static/react-dom.production.min.js?v={_v(react_dom_js)}"></script>',
        f'<script src="/static/_ds/_ds_bundle.js?v={_v(ds_bundle_js)}"></script>',
        f'<script src="/static/auth-app.js?v={_v(auth_app_js)}"></script>',
        f'<script src="/static/shell-core.js?v={_v(shell_core_js)}"></script>',
        f'<script src="/static/shell-projects.js?v={_v(shell_projects_js)}"></script>',
        f'<script src="/static/sidebar-anim.js?v={_v(sidebar_anim_js)}"></script>',
        f'<script src="/static/shell-nxc-filters.js?v={_v(nxc_filters_js)}"></script>',
        f'<script src="/static/shell-nxc-loaders.js?v={_v(nxc_loaders_js)}"></script>',
        f'<script src="/static/shell-nxc-manage.js?v={_v(nxc_manage_js)}"></script>',
        f'<script src="/static/shell-nxc-render-helpers.js?v={_v(nxc_render_helpers_js)}"></script>',
        f'<script src="/static/shell-nxc-render.js?v={_v(nxc_render_js)}"></script>',
        f'<script src="/static/shell-nxc-shell.js?v={_v(nxc_shell_js)}"></script>',
        f'<script src="/static/shell-notifications.js?v={_v(shell_notif_js)}"></script>',
    ]
    # module JS tags (loaded after shell, ordered by module.order)
    for mod in sorted(shell_registry.get_enabled(), key=lambda m: m.order):
        if mod.static_js and mod.static_js.exists():
            url = "/" + mod.static_js.as_posix()
            js_tags.append(f'<script src="{url}?v={_v(mod.static_js)}"></script>')

    head = (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<title>PenHub</title>\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<link rel="icon" type="image/x-icon" href="/favicon.ico">\n'
        + '\n'.join(css_tags) + '\n'
        + '</head>\n'
    )
    scripts = '\n'.join(js_tags)

    return head + HTML_LAYOUT + '\n' + scripts + '\n</body>\n</html>'


# NOTE: _build() reads shell_registry at import time.
# Modules must be registered BEFORE this module is imported.
# The correct entry point is always penhub/app.py, which imports modules
# first and then imports collector.api.router → collector.frontend.
HTML_PAGE = _build()
