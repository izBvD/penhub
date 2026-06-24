/* @ds-bundle: {"format":3,"namespace":"PenHubDesignSystem_d18661","components":[{"name":"Badge","sourcePath":"components/core/Badge.jsx"},{"name":"Button","sourcePath":"components/core/Button.jsx"},{"name":"Card","sourcePath":"components/core/Card.jsx"},{"name":"Input","sourcePath":"components/core/Input.jsx"},{"name":"Logo","sourcePath":"components/core/Logo.jsx"},{"name":"Pill","sourcePath":"components/core/Pill.jsx"},{"name":"Select","sourcePath":"components/core/Select.jsx"},{"name":"SidebarItem","sourcePath":"components/core/SidebarItem.jsx"},{"name":"StatChip","sourcePath":"components/core/StatChip.jsx"},{"name":"Toast","sourcePath":"components/core/Toast.jsx"}],"sourceHashes":{"components/core/Badge.jsx":"b814fb3cb8b7","components/core/Button.jsx":"83811b9ad82f","components/core/Card.jsx":"831e5c28efe6","components/core/Input.jsx":"10a8776235d5","components/core/Logo.jsx":"4132b75ff06a","components/core/Pill.jsx":"e832203fa77d","components/core/Select.jsx":"d08b79e8e3ce","components/core/SidebarItem.jsx":"017420f2bcd1","components/core/StatChip.jsx":"4533186a6678","components/core/Toast.jsx":"67ea98dd63ea","ui_kits/penhub/App.jsx":"6e1806a85ca0","ui_kits/penhub/Chrome.jsx":"c761b6abc1ca","ui_kits/penhub/Collector.jsx":"d1591ab45825","ui_kits/penhub/HashKiller.jsx":"5fe98e3be40a","ui_kits/penhub/Login.jsx":"60c57aafbb84","ui_kits/penhub/Projects.jsx":"0005e8de9736","ui_kits/penhub/Toolbox.jsx":"aee1bc8b326d","ui_kits/penhub/data.js":"7f03d6f9345d"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.PenHubDesignSystem_d18661 = window.PenHubDesignSystem_d18661 || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/core/Badge.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub table badge — tiny pill-let used in data cells to flag credential type,
 * access level, and vuln status.
 */
function Badge({
  variant = "plain",
  className = "",
  children,
  ...rest
}) {
  const cls = ["ph-badge", `ph-badge--${variant}`, className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("span", _extends({
    className: cls
  }, rest), children);
}
Object.assign(__ds_scope, { Badge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Badge.jsx", error: String((e && e.message) || e) }); }

// components/core/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub button. Transparent by default with a hairline border; each variant
 * lights up its signal color on hover. Use `icon`/`round` for square glyph buttons.
 */
function Button({
  variant = "default",
  icon = false,
  round = false,
  pressed,
  className = "",
  children,
  ...rest
}) {
  const cls = ["ph-btn", variant !== "default" && `ph-btn--${variant}`, icon && "ph-btn--icon", round && "ph-btn--round", variant === "toggle" && "ph-btn--toggle", className].filter(Boolean).join(" ");
  const extra = variant === "toggle" ? {
    "aria-pressed": !!pressed
  } : {};
  return /*#__PURE__*/React.createElement("button", _extends({
    className: cls
  }, extra, rest), children);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Button.jsx", error: String((e && e.message) || e) }); }

// components/core/Card.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub module card — the surface used by HashKiller / Toolbox panels.
 * Optional colored block `header` spans the card edge-to-edge; `title` is the
 * quieter tracked-caps label.
 */
function Card({
  header,
  headerColor = "green",
  title,
  className = "",
  children,
  ...rest
}) {
  const cls = ["ph-card", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("div", _extends({
    className: cls
  }, rest), header && /*#__PURE__*/React.createElement("div", {
    className: `ph-card__header ph-card__header--${headerColor}`
  }, header), title && /*#__PURE__*/React.createElement("div", {
    className: "ph-card__title"
  }, title), children);
}
Object.assign(__ds_scope, { Card });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Card.jsx", error: String((e && e.message) || e) }); }

// components/core/Input.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub text input. Set `search` for the leading magnifier glyph, `size="lg"`
 * for the login-scale field.
 */
function Input({
  search = false,
  size = "md",
  className = "",
  ...rest
}) {
  const input = /*#__PURE__*/React.createElement("input", _extends({
    className: ["ph-input", size === "lg" && "ph-input--lg", className].filter(Boolean).join(" ")
  }, rest));
  if (!search) return input;
  return /*#__PURE__*/React.createElement("span", {
    className: "ph-search"
  }, input);
}
Object.assign(__ds_scope, { Input });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Input.jsx", error: String((e && e.message) || e) }); }

// components/core/Logo.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub wordmark. Two lockups:
 *  - "wordmark" (default): cyan→green gradient "Pen" + amber "Hub" capsule.
 *  - "brand": compact solid-cyan glowing "PenHub" for the topbar.
 * Size with the `fontSize` prop (any CSS length) or by setting font-size in style.
 */
function Logo({
  variant = "wordmark",
  fontSize,
  className = "",
  style,
  ...rest
}) {
  const merged = {
    ...(fontSize ? {
      fontSize
    } : null),
    ...style
  };
  if (variant === "brand") {
    return /*#__PURE__*/React.createElement("span", _extends({
      className: ["ph-logo", "ph-logo--brand", className].filter(Boolean).join(" "),
      style: merged
    }, rest), "PenHub");
  }
  return /*#__PURE__*/React.createElement("span", _extends({
    className: ["ph-logo", className].filter(Boolean).join(" "),
    style: merged
  }, rest), /*#__PURE__*/React.createElement("span", {
    className: "ph-logo__pen"
  }, "Pen"), /*#__PURE__*/React.createElement("span", {
    className: "ph-logo__hub"
  }, "Hub"));
}
Object.assign(__ds_scope, { Logo });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Logo.jsx", error: String((e && e.message) || e) }); }

// components/core/Pill.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub filter pill. Rounded chip used for protocol filters, sub-filters, and
 * on/off toggles. Set `proto` to tint the active state per protocol; pass
 * `active` (filters) or `pressed` (toggles) for the lit state.
 */
function Pill({
  proto,
  active = false,
  pressed,
  toggle = false,
  className = "",
  children,
  ...rest
}) {
  const isActive = toggle ? !!pressed : !!active;
  const cls = ["ph-pill", proto && `ph-pill--${String(proto).toLowerCase()}`, toggle && "ph-pill--toggle", isActive && "is-active", className].filter(Boolean).join(" ");
  const extra = toggle ? {
    "aria-pressed": !!pressed
  } : {
    "aria-pressed": !!active
  };
  return /*#__PURE__*/React.createElement("button", _extends({
    className: cls
  }, extra, rest), children);
}
Object.assign(__ds_scope, { Pill });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Pill.jsx", error: String((e && e.message) || e) }); }

// components/core/Select.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/** PenHub select — dark dropdown matching the input field. */
function Select({
  className = "",
  children,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("select", _extends({
    className: ["ph-select", className].filter(Boolean).join(" ")
  }, rest), children);
}
Object.assign(__ds_scope, { Select });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Select.jsx", error: String((e && e.message) || e) }); }

// components/core/SidebarItem.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub sidebar navigation item — glyph + name with an active left-rail accent.
 * `tone` colors the active state per section.
 */
function SidebarItem({
  icon,
  tone = "default",
  active = false,
  className = "",
  children,
  ...rest
}) {
  const cls = ["ph-navitem", tone !== "default" && `ph-navitem--${tone}`, active && "is-active", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("div", _extends({
    className: cls,
    role: "button",
    tabIndex: 0
  }, rest), icon != null && /*#__PURE__*/React.createElement("span", {
    className: "ph-navitem__icon"
  }, icon), /*#__PURE__*/React.createElement("span", {
    className: "ph-navitem__name"
  }, children));
}
Object.assign(__ds_scope, { SidebarItem });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/SidebarItem.jsx", error: String((e && e.message) || e) }); }

// components/core/StatChip.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * PenHub stat chip — the "Hosts: 42" topbar/module readouts. The label is muted;
 * the bold value carries the tone color.
 */
function StatChip({
  label,
  value,
  tone = "default",
  className = "",
  ...rest
}) {
  const cls = ["ph-stat", tone !== "default" && `ph-stat--${tone}`, className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("span", _extends({
    className: cls
  }, rest), label, ": ", /*#__PURE__*/React.createElement("b", null, value));
}
Object.assign(__ds_scope, { StatChip });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/StatChip.jsx", error: String((e && e.message) || e) }); }

// components/core/Toast.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/** PenHub toast — capsule confirmation ("COPIED") or error ("ERROR"). */
function Toast({
  variant = "success",
  className = "",
  children,
  ...rest
}) {
  const cls = ["ph-toast", variant === "error" && "ph-toast--error", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("div", _extends({
    className: cls
  }, rest), children);
}
Object.assign(__ds_scope, { Toast });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Toast.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/App.jsx
try { (() => {
// PenHub UI kit — App orchestrator (login → projects → app modules)
function App() {
  const [screen, setScreen] = React.useState("login"); // login | projects | app
  const [project, setProject] = React.useState(null);
  const [active, setActive] = React.useState("all");
  const [toast, setToast] = React.useState(null);
  const toastTimer = React.useRef(null);
  function showToast(msg) {
    setToast(msg);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 1400);
  }
  function openProject(p) {
    setProject(p);
    setActive("all");
    setScreen("app");
  }
  function navigate(id) {
    if (id === "hashkiller" || id === "toolbox" || id === "nxc-collector") setActive(id);else setActive(id); // view filters all resolve to collector
  }
  const moduleView = active === "hashkiller" ? /*#__PURE__*/React.createElement(window.PHHashKiller, {
    onToast: showToast
  }) : active === "toolbox" ? /*#__PURE__*/React.createElement(window.PHToolbox, {
    onToast: showToast
  }) : /*#__PURE__*/React.createElement(window.PHCollector, {
    onToast: showToast
  });
  if (screen === "login") {
    return /*#__PURE__*/React.createElement("div", {
      className: "ph-app"
    }, /*#__PURE__*/React.createElement(window.PHLogin, {
      onAuth: () => setScreen("projects")
    }), /*#__PURE__*/React.createElement(ToastHost, {
      toast: toast
    }));
  }
  if (screen === "projects") {
    return /*#__PURE__*/React.createElement("div", {
      className: "ph-app"
    }, /*#__PURE__*/React.createElement(window.PHProjects, {
      onOpen: openProject,
      onExit: () => setScreen("login")
    }), /*#__PURE__*/React.createElement(ToastHost, {
      toast: toast
    }));
  }
  return /*#__PURE__*/React.createElement("div", {
    className: "ph-app"
  }, /*#__PURE__*/React.createElement(window.PHTopBar, {
    project: project,
    onBack: () => setScreen("projects"),
    onExit: () => setScreen("login")
  }), /*#__PURE__*/React.createElement("div", {
    className: "kit-body"
  }, /*#__PURE__*/React.createElement(window.PHSidebar, {
    project: project,
    active: active,
    onNavigate: navigate
  }), moduleView), /*#__PURE__*/React.createElement(ToastHost, {
    toast: toast
  }));
}
function ToastHost({
  toast
}) {
  const {
    Toast
  } = window.PenHubDesignSystem_d18661;
  if (!toast) return null;
  const isErr = /error|fail/i.test(toast);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      bottom: 30,
      left: "50%",
      transform: "translateX(-50%)",
      zIndex: 999
    }
  }, /*#__PURE__*/React.createElement(Toast, {
    variant: isErr ? "error" : "success"
  }, toast));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/App.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/Chrome.jsx
try { (() => {
// PenHub UI kit — shared TopBar + Sidebar chrome
const {
  Logo,
  StatChip,
  Button,
  SidebarItem
} = window.PenHubDesignSystem_d18661;
function TopBar({
  project,
  onBack,
  onExit
}) {
  const [live, setLive] = React.useState(true);
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-topbar"
  }, /*#__PURE__*/React.createElement(Logo, {
    variant: "brand",
    fontSize: "15px"
  }), /*#__PURE__*/React.createElement(Button, {
    onClick: onBack,
    style: {
      color: "var(--fg-2)"
    }
  }, "\u25C0 PROJECTS"), /*#__PURE__*/React.createElement("span", {
    className: "tb-page"
  }, project ? project.name : "Projects"), /*#__PURE__*/React.createElement("div", {
    className: "kit-stats"
  }, /*#__PURE__*/React.createElement(StatChip, {
    label: "Hosts",
    value: project ? project.hosts : "—"
  }), /*#__PURE__*/React.createElement(StatChip, {
    label: "Creds",
    value: project ? project.creds : "—"
  }), /*#__PURE__*/React.createElement(StatChip, {
    label: "PWN3D!",
    value: project ? project.admin : "—",
    tone: "danger"
  })), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "success"
  }, "+ NEW"), /*#__PURE__*/React.createElement(Button, {
    variant: "toggle",
    pressed: live,
    onClick: () => setLive(v => !v)
  }, "LIVE \u25CF"), /*#__PURE__*/React.createElement(Button, {
    variant: "danger",
    onClick: onExit
  }, "EXIT"));
}
function Sidebar({
  project,
  active,
  onNavigate
}) {
  const data = window.PHKIT_DATA;
  return /*#__PURE__*/React.createElement("nav", {
    className: "kit-sidebar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-sb-name",
    title: project && project.name
  }, project && project.name), /*#__PURE__*/React.createElement("div", {
    className: "kit-sb-sections"
  }, data.nav.map(sec => /*#__PURE__*/React.createElement("div", {
    key: sec.group,
    style: {
      padding: "2px 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-sb-label"
  }, sec.group), sec.items.map(it => /*#__PURE__*/React.createElement(SidebarItem, {
    key: it.id,
    icon: it.icon,
    tone: it.tone,
    active: active === it.id,
    onClick: () => onNavigate(it.id)
  }, it.name))))), /*#__PURE__*/React.createElement("button", {
    className: "kit-sb-collapse",
    title: "Collapse"
  }, "\u2039"));
}
window.PHTopBar = TopBar;
window.PHSidebar = Sidebar;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/Chrome.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/Collector.jsx
try { (() => {
// PenHub UI kit — NXC Collector (table view)
const {
  Pill,
  Badge,
  Button,
  Input
} = window.PenHubDesignSystem_d18661;
function protoCell(p) {
  return /*#__PURE__*/React.createElement("span", {
    className: "kit-proto kit-proto-" + p.toLowerCase()
  }, p);
}
function relBadge(rel) {
  if (rel === "admin") return /*#__PURE__*/React.createElement(Badge, {
    variant: "admin"
  }, "PWN3D!");
  if (rel === "loggedin") return /*#__PURE__*/React.createElement(Badge, {
    variant: "loggedin"
  }, "[+]");
  return /*#__PURE__*/React.createElement(Badge, {
    variant: "na"
  }, "\u2014");
}
function typeBadge(t) {
  if (t === "hash") return /*#__PURE__*/React.createElement(Badge, {
    variant: "hash"
  }, "HASH");
  if (t === "dpapi") return /*#__PURE__*/React.createElement(Badge, {
    variant: "dpapi"
  }, "DPAPI");
  return /*#__PURE__*/React.createElement(Badge, {
    variant: "plain"
  }, "plain");
}
function rowClass(r) {
  if (r.rel === "admin") return "row-admin";
  if (r.type === "dpapi") return "row-dpapi";
  if (r.proto === "CUSTOM") return "row-custom";
  return "";
}
function Collector({
  onToast
}) {
  const data = window.PHKIT_DATA;
  const [proto, setProto] = React.useState("ALL");
  const [uniq, setUniq] = React.useState(true);
  const [hk, setHk] = React.useState(true);
  const [guest, setGuest] = React.useState(true);
  const [q, setQ] = React.useState("");
  let rows = data.rows;
  if (proto !== "ALL") rows = rows.filter(r => r.proto === proto);
  if (guest) rows = rows.filter(r => !/default|anonymous|\(none\)|guest/i.test(r.user));
  if (q) rows = rows.filter(r => (r.user + r.ip + r.host + r.domain).toLowerCase().includes(q.toLowerCase()));
  const cols = ["", "Proto", "IP", "Host", "Banner", "Domain", "Login", "Password", "Type", "Rel", "Op", ""];
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-content"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-toolbar"
  }, data.protocols.map(p => /*#__PURE__*/React.createElement(Pill, {
    key: p,
    proto: p === "ALL" ? undefined : p.toLowerCase(),
    active: proto === p,
    onClick: () => setProto(p)
  }, p)), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement(Button, {
    round: true,
    variant: "danger",
    onClick: () => {
      setProto("ALL");
      setQ("");
    }
  }, "\u2715"), /*#__PURE__*/React.createElement(Input, {
    search: true,
    placeholder: "global search...",
    value: q,
    onChange: e => setQ(e.target.value)
  }), /*#__PURE__*/React.createElement(Pill, {
    proto: "mssql"
  }, "\u26A1 VULNS"), /*#__PURE__*/React.createElement(Pill, null, "\u2620 ADM CREDS"), /*#__PURE__*/React.createElement(Button, {
    icon: true,
    variant: "warning"
  }, "\u270E")), /*#__PURE__*/React.createElement("div", {
    className: "kit-toolbar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-subpills"
  }, /*#__PURE__*/React.createElement(Pill, {
    toggle: true,
    pressed: true
  }, "loggedin"), /*#__PURE__*/React.createElement(Pill, {
    toggle: true
  }, "admin")), /*#__PURE__*/React.createElement(Input, {
    search: true,
    placeholder: "filter table...",
    style: {
      width: 180
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement(Pill, {
    toggle: true,
    pressed: hk,
    onClick: () => setHk(v => !v)
  }, "\uD83D\uDD13 HK"), /*#__PURE__*/React.createElement(Pill, {
    toggle: true,
    pressed: uniq,
    onClick: () => setUniq(v => !v)
  }, "UNIQ"), /*#__PURE__*/React.createElement(Pill, {
    toggle: true,
    pressed: guest,
    onClick: () => setGuest(v => !v)
  }, "\uD83D\uDEAB GUEST"), /*#__PURE__*/React.createElement(Button, {
    variant: "info",
    onClick: () => onToast("EXPORTED")
  }, "XLSX\u2193"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: () => onToast("EXPORTED")
  }, "ALL CREDS\u2193")), /*#__PURE__*/React.createElement("div", {
    className: "kit-table-wrap"
  }, /*#__PURE__*/React.createElement("table", {
    className: "kit-table"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, cols.map((c, i) => /*#__PURE__*/React.createElement("th", {
    key: i
  }, c)))), /*#__PURE__*/React.createElement("tbody", null, rows.map((r, i) => /*#__PURE__*/React.createElement("tr", {
    key: i,
    className: rowClass(r)
  }, /*#__PURE__*/React.createElement("td", {
    style: {
      width: 24,
      textAlign: "center",
      opacity: .4
    }
  }, "\u2620"), /*#__PURE__*/React.createElement("td", null, protoCell(r.proto)), /*#__PURE__*/React.createElement("td", {
    className: "cell-copy",
    onClick: () => onToast("COPIED")
  }, r.ip), /*#__PURE__*/React.createElement("td", {
    className: "cell-mute"
  }, r.host), /*#__PURE__*/React.createElement("td", {
    className: "cell-sm",
    title: r.banner
  }, r.banner.slice(0, 28)), /*#__PURE__*/React.createElement("td", {
    className: "cell-mute"
  }, r.domain), /*#__PURE__*/React.createElement("td", {
    className: "cell-copy",
    onClick: () => onToast("COPIED")
  }, /*#__PURE__*/React.createElement("b", null, r.user)), /*#__PURE__*/React.createElement("td", {
    className: "cell-copy",
    onClick: () => onToast("COPIED")
  }, r.pass), /*#__PURE__*/React.createElement("td", null, typeBadge(r.type)), /*#__PURE__*/React.createElement("td", null, relBadge(r.rel)), /*#__PURE__*/React.createElement("td", {
    className: "cell-sm"
  }, r.op), /*#__PURE__*/React.createElement("td", {
    style: {
      width: 44
    }
  }, /*#__PURE__*/React.createElement(Button, {
    icon: true,
    onClick: () => onToast("COPIED"),
    style: {
      width: 20,
      height: 20,
      fontSize: 11
    }
  }, "\u2398"))))))), /*#__PURE__*/React.createElement("div", {
    className: "kit-pager"
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--fg-2)"
    }
  }, "Rows:"), /*#__PURE__*/React.createElement(Pill, {
    active: true
  }, "100"), /*#__PURE__*/React.createElement(Pill, null, "500"), /*#__PURE__*/React.createElement(Pill, null, "1000"), /*#__PURE__*/React.createElement(Pill, null, "ALL"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 10
    }
  }, rows.length, " of ", data.rows.length, " credentials"), /*#__PURE__*/React.createElement("div", {
    className: "spacer"
  }), /*#__PURE__*/React.createElement(Button, {
    onClick: () => onToast("RELOADED")
  }, "\u21BB RELOAD")));
}
window.PHCollector = Collector;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/Collector.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/HashKiller.jsx
try { (() => {
// PenHub UI kit — HashKiller module
const {
  Card,
  Button,
  StatChip,
  Input
} = window.PenHubDesignSystem_d18661;
function HashKiller({
  onToast
}) {
  const [busy, setBusy] = React.useState(false);
  const [pct, setPct] = React.useState(0);
  function run() {
    setBusy(true);
    setPct(0);
    const t = setInterval(() => {
      setPct(p => {
        if (p >= 100) {
          clearInterval(t);
          setBusy(false);
          onToast("KILLED 41 HASHES");
          return 0;
        }
        return p + 12;
      });
    }, 120);
  }
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-content",
    style: {
      overflow: "hidden",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-module-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kit-module-title"
  }, "\u2620 HASHKILLER"), /*#__PURE__*/React.createElement("div", {
    className: "kit-statchips",
    style: {
      marginLeft: 8
    }
  }, /*#__PURE__*/React.createElement(StatChip, {
    label: "pairs",
    value: "12,488",
    tone: "primary"
  }), /*#__PURE__*/React.createElement(StatChip, {
    label: "smart",
    value: "318"
  }), /*#__PURE__*/React.createElement(StatChip, {
    label: "\u26A0 warning",
    value: "6"
  }))), /*#__PURE__*/React.createElement("div", {
    className: "kit-module"
  }, /*#__PURE__*/React.createElement(Card, {
    header: "\u25B6 IMPORT \u2014 paste or upload hash:plain pairs",
    headerColor: "green"
  }, /*#__PURE__*/React.createElement("textarea", {
    className: "kit-textarea",
    defaultValue: "8846f7eaee8fb117ad06bdd830b7586c:Password1\naad3b435b51404ee...:8846f7...:Password1\n31d6cfe0d16ae931b73c59d7e0c089c0:<empty_password>"
  }), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginTop: 8
    }
  }, /*#__PURE__*/React.createElement(Button, null, "\uD83D\uDCC4 Upload .potfile / .txt"), /*#__PURE__*/React.createElement("div", {
    className: "spacer",
    style: {
      flex: 1
    }
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "success",
    onClick: () => onToast("IMPORTED 204 PAIRS")
  }, "\u25B6 IMPORT"))), /*#__PURE__*/React.createElement(Card, {
    header: "\u26A1 ACTIONS",
    headerColor: "purple"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "accent",
    onClick: () => onToast("ENRICHED")
  }, "\u26A1 SMART ENRICH"), /*#__PURE__*/React.createElement(Button, {
    variant: "danger",
    onClick: run,
    disabled: busy
  }, "\uD83D\uDD2B KILL THEM ALL"), /*#__PURE__*/React.createElement(Button, {
    variant: "info",
    onClick: () => onToast("DOWNLOADED")
  }, "\u2193 HASHES.TXT")), busy && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-progress"
  }, /*#__PURE__*/React.createElement("i", {
    style: {
      width: pct + "%"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--fg-2)",
      marginTop: 6
    }
  }, "Looking up uncracked hashes\u2026 ", pct, "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 14,
      paddingTop: 10,
      borderTop: "1px dashed rgba(255,51,85,.25)",
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "danger",
    style: {
      borderStyle: "dashed"
    }
  }, "\u2622 ALL WORKSPACES"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10,
      color: "var(--accent-red)",
      opacity: .7
    }
  }, "applies to all projects incl. archived"))), /*#__PURE__*/React.createElement(Card, {
    header: "\uD83D\uDCBE DB WORK",
    headerColor: "orange"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "warning"
  }, "\u21E9 DOWNLOAD DB"), /*#__PURE__*/React.createElement(Button, null, "\u21E7 UPLOAD DB"), /*#__PURE__*/React.createElement(Button, {
    variant: "accent"
  }, "\u21E9 EXPORT SMART"), /*#__PURE__*/React.createElement(Button, {
    style: {
      color: "var(--accent-amber)",
      borderColor: "var(--accent-amber)"
    }
  }, "\u26A0\u21E9 EXPORT WARNING")), /*#__PURE__*/React.createElement("div", {
    className: "ph-card__title",
    style: {
      marginBottom: 6
    }
  }, "DELETE PAIR \u2014 by hash or plaintext"), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row"
  }, /*#__PURE__*/React.createElement(Input, {
    placeholder: "hash (32-hex), plaintext, or hash:plain",
    style: {
      flex: 1,
      minWidth: 220
    }
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "danger"
  }, "\u2715 DELETE")))));
}
window.PHHashKiller = HashKiller;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/HashKiller.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/Login.jsx
try { (() => {
// PenHub UI kit — Login screen
const {
  Logo,
  Input,
  Button
} = window.PenHubDesignSystem_d18661;
function Login({
  onAuth
}) {
  const [val, setVal] = React.useState("");
  const [err, setErr] = React.useState("");
  function submit() {
    if (!val.trim()) {
      setErr("access key required");
      return;
    }
    setErr("");
    onAuth();
  }
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-login"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-login-panel"
  }, /*#__PURE__*/React.createElement(Logo, {
    fontSize: "64px",
    style: {
      justifyContent: "center",
      marginBottom: 4
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "kit-login-sub"
  }, "Authorized Access Only"), /*#__PURE__*/React.createElement(Input, {
    size: "lg",
    type: "password",
    placeholder: "access key",
    value: val,
    onChange: e => setVal(e.target.value),
    onKeyDown: e => e.key === "Enter" && submit(),
    style: {
      marginBottom: 12
    }
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    style: {
      width: "100%",
      justifyContent: "center",
      padding: 13,
      letterSpacing: 4
    }
  }, "AUTHENTICATE"), /*#__PURE__*/React.createElement("div", {
    className: "kit-login-err"
  }, err)));
}
window.PHLogin = Login;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/Login.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/Projects.jsx
try { (() => {
// PenHub UI kit — Projects (folder) screen
const {
  Button
} = window.PenHubDesignSystem_d18661;
function Projects({
  onOpen,
  onExit
}) {
  const data = window.PHKIT_DATA;
  const [tab, setTab] = React.useState("active");
  const list = data.projects.filter(p => tab === "active" ? !p.archived : p.archived);
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-projects"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-folder-tabs"
  }, /*#__PURE__*/React.createElement("button", {
    className: "kit-folder-tab" + (tab === "active" ? " active" : ""),
    onClick: () => setTab("active")
  }, "Active"), /*#__PURE__*/React.createElement("button", {
    className: "kit-folder-tab" + (tab === "archive" ? " active" : ""),
    onClick: () => setTab("archive")
  }, "Archive"), /*#__PURE__*/React.createElement("div", {
    className: "kit-folder-gap"
  }), /*#__PURE__*/React.createElement("div", {
    className: "kit-folder-headbtns"
  }, /*#__PURE__*/React.createElement(Button, null, "\u21E9 DB"), /*#__PURE__*/React.createElement(Button, {
    variant: "success"
  }, "+ NEW"), /*#__PURE__*/React.createElement(Button, {
    variant: "danger",
    onClick: onExit
  }, "\u2715 EXIT"))), /*#__PURE__*/React.createElement("div", {
    className: "kit-folder-body"
  }, list.map(p => /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-card",
    key: p.id,
    onClick: () => onOpen(p)
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-info"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-name"
  }, p.name), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-date"
  }, p.date, p.archived ? " · archived" : "")), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stats"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-val"
  }, p.hosts), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-lbl"
  }, "Hosts")), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-val"
  }, p.creds), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-lbl"
  }, "Creds")), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-val admin"
  }, p.admin), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-stat-lbl"
  }, "PWN3D!"))), /*#__PURE__*/React.createElement("div", {
    className: "kit-ws-actions",
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "warning"
  }, "\u2304 Archive"), /*#__PURE__*/React.createElement(Button, {
    round: true,
    variant: "danger"
  }, "\u2715")))), !list.length && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "rgba(57,211,83,.18)",
      fontSize: 11,
      letterSpacing: 2,
      textAlign: "center",
      padding: "72px 24px"
    }
  }, "No ", tab === "active" ? "active" : "archived", " projects")));
}
window.PHProjects = Projects;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/Projects.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/Toolbox.jsx
try { (() => {
// PenHub UI kit — Toolbox module
const {
  Card,
  Button,
  Input,
  Select
} = window.PenHubDesignSystem_d18661;
function Toolbox({
  onToast
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "kit-content",
    style: {
      overflow: "hidden",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-module-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kit-module-title"
  }, "\u2699 TOOLBOX")), /*#__PURE__*/React.createElement("div", {
    className: "kit-module"
  }, /*#__PURE__*/React.createElement(Card, {
    header: "\u21E7 CUSTOM IMPORT",
    headerColor: "green"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-hint",
    style: {
      marginBottom: 12
    }
  }, "Download the XLSX template, fill in your credentials, then upload to a workspace.", /*#__PURE__*/React.createElement("br", null), "Columns: Proto \xB7 IP \xB7 Port \xB7 Domain \xB7 ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "var(--fg-0)"
    }
  }, "Login"), " \xB7 ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "var(--fg-0)"
    }
  }, "Password"), " \xB7 Type \xB7 URL \xB7 Source \xB7 Comment."), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 DOWNLOAD TEMPLATE"), /*#__PURE__*/React.createElement(Button, {
    variant: "accent",
    onClick: () => onToast("IMPORTED")
  }, "\u21E7 IMPORT XLSX")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 14,
      paddingTop: 14,
      borderTop: "1px solid rgba(255,255,255,.12)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ph-card__title",
    style: {
      marginBottom: 8
    }
  }, "Domain Admin Watchlist"), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginBottom: 5
    }
  }, /*#__PURE__*/React.createElement(Input, {
    placeholder: "ACME",
    style: {
      width: 240
    }
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "accent"
  }, "\u21E7 ADD USER LIST")), /*#__PURE__*/React.createElement("div", {
    className: "kit-or"
  }, "OR"), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row"
  }, /*#__PURE__*/React.createElement(Input, {
    placeholder: "administrator",
    style: {
      width: 240
    }
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "accent"
  }, "+ ADD ONE ADM USER")))), /*#__PURE__*/React.createElement(Card, {
    header: "\u2193 NXCEXTRACTOR LISTS",
    headerColor: "cyan"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 ALL UNIQ LOGINS"), /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 ALL UNIQ PASS"), /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 ALL UNIQ HASHES"), /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 ALL UNIQ IP")), /*#__PURE__*/React.createElement("div", {
    style: {
      paddingTop: 14,
      borderTop: "1px solid rgba(255,255,255,.12)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ph-card__title",
    style: {
      marginBottom: 8
    }
  }, "nxc --no-bruteforce spray lists"), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginBottom: 6
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "accent",
    onClick: () => onToast("ARCHIVE READY")
  }, "\u2193 DOWNLOAD ARCHIVE"), /*#__PURE__*/React.createElement(Button, {
    variant: "accent"
  }, "\u2193 NOT PWN3D IPs")), /*#__PURE__*/React.createElement("div", {
    className: "kit-hint"
  }, "archive: not_pwn3d_ip.txt \u2014 plaintext_logins/passes.txt \u2014 hashes_logins/passes.txt \u2014 line-paired, ready for nxc spray"))), /*#__PURE__*/React.createElement(Card, {
    header: "\uD83D\uDD27 OPERATOR ENVIRONMENT CONFIG",
    headerColor: "orange"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "info"
  }, "\u2193 DOWNLOAD SCRIPTS"), /*#__PURE__*/React.createElement("span", {
    className: "kit-hint"
  }, "Install or update: ", /*#__PURE__*/React.createElement("code", null, "./nxc_collector --install"))), /*#__PURE__*/React.createElement("div", {
    style: {
      paddingTop: 14,
      borderTop: "1px solid rgba(255,255,255,.12)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ph-card__title",
    style: {
      marginBottom: 8
    }
  }, "Copy BloodHound config string"), /*#__PURE__*/React.createElement("div", {
    className: "kit-bh-grid"
  }, /*#__PURE__*/React.createElement("span", {
    className: "kit-field-label"
  }, "--bh-ip"), /*#__PURE__*/React.createElement(Input, {
    placeholder: "BloodHound IP (required)"
  }), /*#__PURE__*/React.createElement("span", {
    className: "kit-field-label"
  }, "--bh-login"), /*#__PURE__*/React.createElement(Input, {
    defaultValue: "neo4j"
  }), /*#__PURE__*/React.createElement("span", {
    className: "kit-field-label"
  }, "--bh-pass"), /*#__PURE__*/React.createElement(Input, {
    defaultValue: "bloodhoundcommunityedition"
  }), /*#__PURE__*/React.createElement("span", {
    className: "kit-field-label"
  }, "--bh-port"), /*#__PURE__*/React.createElement(Input, {
    defaultValue: "7687",
    style: {
      width: 80
    }
  }), /*#__PURE__*/React.createElement("span", {
    className: "kit-field-label"
  }, "--bh-enable"), /*#__PURE__*/React.createElement(Select, {
    defaultValue: "true",
    style: {
      width: 90
    }
  }, /*#__PURE__*/React.createElement("option", {
    value: "true"
  }, "true"), /*#__PURE__*/React.createElement("option", {
    value: "false"
  }, "false"))), /*#__PURE__*/React.createElement("div", {
    className: "kit-actions-row",
    style: {
      marginTop: 8
    }
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "success",
    onClick: () => onToast("CONFIG COPIED")
  }, "\u2726 COPY BH CONFIG"))))));
}
window.PHToolbox = Toolbox;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/Toolbox.jsx", error: String((e && e.message) || e) }); }

// ui_kits/penhub/data.js
try { (() => {
// PenHub UI kit — mock data (fabricated; no real credentials).
window.PHKIT_DATA = {
  projects: [{
    id: 1,
    name: "ACME-CORP / internal-2026",
    date: "2026-05-28 14:02",
    hosts: 184,
    creds: 1320,
    admin: 23,
    archived: false
  }, {
    id: 2,
    name: "RedTeam · NORTHWIND",
    date: "2026-05-21 09:41",
    hosts: 96,
    creds: 612,
    admin: 9,
    archived: false
  }, {
    id: 3,
    name: "engagement-fox-trot",
    date: "2026-05-12 18:20",
    hosts: 41,
    creds: 188,
    admin: 2,
    archived: false
  }, {
    id: 4,
    name: "INITECH external perimeter",
    date: "2026-04-30 11:05",
    hosts: 12,
    creds: 47,
    admin: 0,
    archived: false
  }, {
    id: 5,
    name: "GLOBEX retest Q1",
    date: "2026-03-08 16:33",
    hosts: 220,
    creds: 1890,
    admin: 31,
    archived: true
  }],
  // Collector rows (SMB view shape)
  rows: [{
    proto: "SMB",
    ip: "10.10.14.21",
    host: "DC01",
    banner: "Windows Server 2022 Build 20348",
    os: "Windows",
    domain: "ACME",
    user: "Administrator",
    pass: "Summer2026!",
    type: "plain",
    rel: "admin",
    op: "n0va"
  }, {
    proto: "SMB",
    ip: "10.10.14.21",
    host: "DC01",
    banner: "Windows Server 2022 Build 20348",
    os: "Windows",
    domain: "ACME",
    user: "svc_backup",
    pass: "aad3b435b51404ee:8846f7eaee8fb1",
    type: "hash",
    rel: "admin",
    op: "n0va"
  }, {
    proto: "LDAP",
    ip: "10.10.14.21",
    host: "DC01",
    banner: "Active Directory",
    os: "Windows",
    domain: "ACME",
    user: "j.harlow",
    pass: "Welcome1",
    type: "plain",
    rel: "loggedin",
    op: "kx"
  }, {
    proto: "SMB",
    ip: "10.10.14.55",
    host: "FILE02",
    banner: "Windows Server 2019 Build 17763",
    os: "Windows",
    domain: "ACME",
    user: "m.okafor",
    pass: "Pa$$w0rd2025",
    type: "plain",
    rel: "loggedin",
    op: "kx"
  }, {
    proto: "MSSQL",
    ip: "10.10.14.88",
    host: "SQL01",
    banner: "Microsoft SQL Server 2019",
    os: "Windows",
    domain: "ACME",
    user: "sa",
    pass: "31d6cfe0d16ae931b73c",
    type: "hash",
    rel: "admin",
    op: "n0va"
  }, {
    proto: "SSH",
    ip: "10.10.20.10",
    host: "build-runner",
    banner: "OpenSSH 8.9p1 Ubuntu",
    os: "Ubuntu 22.04",
    domain: "-",
    user: "deploy",
    pass: "ci-deploy-2026",
    type: "plain",
    rel: "admin",
    op: "rl"
  }, {
    proto: "WINRM",
    ip: "10.10.14.55",
    host: "FILE02",
    banner: "Microsoft HTTPAPI 2.0",
    os: "Windows",
    domain: "ACME",
    user: "m.okafor",
    pass: "Pa$$w0rd2025",
    type: "plain",
    rel: "loggedin",
    op: "kx"
  }, {
    proto: "RDP",
    ip: "10.10.14.103",
    host: "WKS-2210",
    banner: "xrdp / NLA",
    os: "Windows 11",
    domain: "ACME",
    user: "t.vasquez",
    pass: "—",
    type: "plain",
    rel: "",
    op: "rl"
  }, {
    proto: "SMB",
    ip: "10.10.14.140",
    host: "HRAPP",
    banner: "Windows Server 2016",
    os: "Windows",
    domain: "ACME",
    user: "DefaultAccount",
    pass: "—",
    type: "plain",
    rel: "",
    op: "kx"
  }, {
    proto: "CUSTOM",
    ip: "10.10.20.42",
    host: "jenkins",
    banner: "Jenkins 2.440",
    os: "Linux",
    domain: "-",
    user: "admin",
    pass: "jenkins-token-7f3a",
    type: "plain",
    rel: "",
    op: "n0va"
  }, {
    proto: "LDAP",
    ip: "10.10.14.21",
    host: "DC01",
    banner: "Active Directory",
    os: "Windows",
    domain: "ACME",
    user: "krbtgt",
    pass: "f4c2...DPAPI",
    type: "dpapi",
    rel: "",
    op: "n0va"
  }, {
    proto: "VNC",
    ip: "10.10.20.77",
    host: "kiosk-3",
    banner: "RealVNC 6.x",
    os: "Linux",
    domain: "-",
    user: "(none)",
    pass: "no-auth",
    type: "plain",
    rel: "admin",
    op: "rl"
  }, {
    proto: "FTP",
    ip: "10.10.14.200",
    host: "legacy-ftp",
    banner: "vsftpd 3.0.3",
    os: "Linux",
    domain: "-",
    user: "anonymous",
    pass: "(blank)",
    type: "plain",
    rel: "loggedin",
    op: "kx"
  }, {
    proto: "SSH",
    ip: "10.10.20.11",
    host: "monitoring",
    banner: "OpenSSH 9.3 Debian",
    os: "Debian 12",
    domain: "-",
    user: "grafana",
    pass: "obs-pl4tform!",
    type: "plain",
    rel: "loggedin",
    op: "rl"
  }],
  protocols: ["ALL", "SMB", "LDAP", "MSSQL", "FTP", "SSH", "WINRM", "RDP", "VNC", "WMI", "NFS", "CUSTOM"],
  nav: [{
    group: "VIEWS",
    items: [{
      id: "all",
      icon: "☰",
      name: "All",
      tone: "default"
    }, {
      id: "admin",
      icon: "☠",
      name: "PWN3D!",
      tone: "admin"
    }, {
      id: "dpapi",
      icon: "🔑",
      name: "DPAPI",
      tone: "dpapi"
    }, {
      id: "acred",
      icon: "★",
      name: "ADM CREDS",
      tone: "default"
    }, {
      id: "vulns",
      icon: "⚡",
      name: "Vulns",
      tone: "vulns"
    }]
  }, {
    group: "MODULES",
    items: [{
      id: "nxc-collector",
      icon: "◎",
      name: "NXC Collector",
      tone: "default"
    }, {
      id: "hashkiller",
      icon: "☠",
      name: "HashKiller",
      tone: "default"
    }, {
      id: "toolbox",
      icon: "⚙",
      name: "Toolbox",
      tone: "vulns"
    }]
  }]
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/penhub/data.js", error: String((e && e.message) || e) }); }

__ds_ns.Badge = __ds_scope.Badge;

__ds_ns.Button = __ds_scope.Button;

__ds_ns.Card = __ds_scope.Card;

__ds_ns.Input = __ds_scope.Input;

__ds_ns.Logo = __ds_scope.Logo;

__ds_ns.Pill = __ds_scope.Pill;

__ds_ns.Select = __ds_scope.Select;

__ds_ns.SidebarItem = __ds_scope.SidebarItem;

__ds_ns.StatChip = __ds_scope.StatChip;

__ds_ns.Toast = __ds_scope.Toast;

})();
