"""
PenHub — FastAPI application factory.

Initialises the shell registry, registers all platform modules,
then builds the FastAPI app with all module routes included.

Usage (from server.py):
    from penhub.app import app
"""

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  ДОБАВЛЕНИЕ НОВОГО МОДУЛЯ — всё, что нужно сделать                         ║
# ╠══════════════════════════════════════════════════════════════════════════════╣
# ║                                                                              ║
# ║  [Python]                                                                    ║
# ║  1. Создай модуль: modules/<name>/__init__.py                                ║
# ║     • Скопируй modules/hashkiller/__init__.py как шаблон                     ║
# ║     • Задай id, name, icon, order; унаследуй BaseModule                      ║
# ║     • Если у модуля есть CSS/JS — укажи static_css / static_js               ║
# ║       (подробности: modules/base.py → static_css / static_js)                ║
# ║                                                                              ║
# ║  2. Создай статику (если нужна): static/modules/<name>/module.css / .js      ║
# ║     • CSS и JS загружаются браузером автоматически через <link>/<script>      ║
# ║     • collector/frontend.py трогать НЕ нужно                                  ║
# ║                                                                              ║
# ║  3. Создай UI-фрагмент (если нужен): modules/<name>/ui.py                    ║
# ║     • Верни HTML из get_ui_fragment()                                         ║
# ║     • Загружается лениво через GET /api/shell/module/<id>/ui                  ║
# ║     • Пример: modules/hashkiller/ui.py                                        ║
# ║                                                                              ║
# ║  4. Зарегистрируй здесь — добавь одну строку импорта в блок ниже ↓           ║
# ║                                                                              ║
# ║  [JavaScript / HTML] — static/shell-core.js, shell-projects.js,              ║
# ║                        collector/_frontend/_html.py                          ║
# ║  5. static/shell-core.js → ModuleRegistry.register(...)                      ║
# ║     • Добавь строку регистрации рядом с hashkiller / toolbox                  ║
# ║                                                                              ║
# ║  6. static/shell-core.js → Shell.activate()                                  ║
# ║     • Добавь show/hide div-контейнера (блок const nxcDiv / hkDiv / tbDiv)    ║
# ║     • Добавь вызов XModule.onActivate(ws) в блок "Per-module activation"     ║
# ║                                                                              ║
# ║  6b. static/shell-nxc-shell.js — ДВА switch по id (оба обязательны):         ║
# ║     • sbNavigate(): case '<id>': Shell.activate('<id>'); break;              ║
# ║       ИНАЧЕ клик по плитке не активирует модуль (уходит в default)           ║
# ║     • _sbIsActive(): case '<id>': return Shell.isActive('<id>');             ║
# ║       ИНАЧЕ плитка не получит .active (нет подсветки и вертикальной          ║
# ║       развёртки в свёрнутом сайдбаре)                                        ║
# ║                                                                              ║
# ║  7. static/shell-projects.js → openProject()                                 ║
# ║     • Добавь строку: if (Shell.isActive('<id>')) XModule.onActivate(ws);     ║
# ║                                                                              ║
# ║  8. collector/_frontend/_html.py                                             ║
# ║     • Добавь <div id="mod-<id>" style="display:none;flex:1;overflow:hidden"> ║
# ║       рядом с mod-hashkiller / mod-toolbox                                   ║
# ║                                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

from contextlib import asynccontextmanager

import collector.db as db_mod
import collector.hashkiller_db as hk_db
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# ── Регистрация модулей ───────────────────────────────────────────────────────
# ВАЖНО: импорты модулей должны быть ДО collector.api.router.
# collector/frontend.py строит HTML_PAGE в момент импорта api_router,
# используя уже заполненный реестр. Нарушение порядка → модуль не получит CSS/JS.
import modules.nxc_collector  # noqa: F401
import modules.hashkiller      # noqa: F401
import modules.toolbox         # noqa: F401
import modules.reports         # noqa: F401
# ← добавь сюда: import modules.<name>  # noqa: F401

from penhub.shell.registry import shell_registry

# ── Route collection ──────────────────────────────────────────────────────────
# Imported AFTER module registration — collector/frontend.py builds HTML_PAGE
# during this import using the already-populated registry.
from collector.api.router import api_router
from penhub.shell.module_api import router as shell_module_router


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db_mod.init_db()
    hk_db.init_hk_db()
    hk_db.ensure_inbox_dir()
    for module in shell_registry.get_enabled():
        module.on_startup()
    yield
    for module in shell_registry.get_enabled():
        module.on_shutdown()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

# Static files — shell CSS/JS + per-module assets under static/modules/<id>/
# StaticFiles is part of Starlette (already a FastAPI dependency, no new packages).
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(api_router)
app.include_router(shell_module_router)
