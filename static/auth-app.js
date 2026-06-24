/* PenHub Access Terminal — precompiled (no Babel needed).
   Modified from Claude Design source: real /api/login integration. */
const { Logo, Button } = window.PenHubDesignSystem_d18661;

/* ── Fabricated credential generators (all data is fake) ─────────────────── */
const HEX = "0123456789abcdef";
const USERS = ["administrator", "admin", "svc_sql", "backup", "root", "jsmith", "dwilson", "sa", "helpdesk", "krbtgt", "operator", "webadmin", "sshd", "ftpuser", "ldap_bind", "mgomez", "aturner", "guest"];
const WORDS = ["P@ssw0rd!", "Summer2025", "Welcome1", "Spring#26", "Qwerty123", "Companynet1", "Hunter2!", "Letmein99", "Dragon#7", "Passw0rd1", "Tr0ub4dor", "Winter2024", "Changeme1", "Football!", "ZxCvBn123", "Pa$$w0rd", "Admin@123", "S3cur3!t"];
const PROTOS = ["SMB", "LDAP", "MSSQL", "WINRM", "SSH", "RDP", "FTP", "VNC"];
const rnd = a => a[Math.floor(Math.random() * a.length)];
const hex = n => Array.from({ length: n }, () => rnd(HEX)).join("");
const ip = () => rnd(["10.10", "192.168", "172.16", "10.0"]) + "." + (Math.floor(Math.random() * 254) + 1) + "." + (Math.floor(Math.random() * 254) + 1);
const ntlm = () => hex(32) + ":" + hex(32);
function credPair() {
  const r = Math.random();
  if (r < 0.30) return { t: rnd(USERS) + ":" + rnd(WORDS), c: "cyan" };
  if (r < 0.52) return { t: ntlm().slice(0, 33) + "…", c: "purple" };
  if (r < 0.70) return { t: ip() + " " + rnd(PROTOS), c: "green" };
  if (r < 0.82) return { t: rnd(USERS) + "$:" + hex(16), c: "amber" };
  if (r < 0.90) return { t: "aad3b…:" + hex(24), c: "k" };
  if (r < 0.96) return { t: rnd(USERS) + ":" + rnd(WORDS), c: "red" };
  return { t: hex(20), c: "k" };
}
function credToken() {
  const tok = credPair();
  tok.gap = 70 + Math.floor(Math.random() * 220);
  return tok;
}

/* ── Background rain — credentials are actively "brute-forced" ───────────── */
const SCRAMBLE = "ABCDEFGHJKLMNPQRSTUVWXYZabcdef0123456789!@#$%&*";
const scrCh = () => SCRAMBLE[Math.floor(Math.random() * SCRAMBLE.length)];
const keepCh = ch => !/[A-Za-z0-9]/.test(ch);

function Rain() {
  const rootRef = React.useRef(null);
  const [cols, setCols] = React.useState([]);
  React.useEffect(() => {
    function build() {
      const w = window.innerWidth;
      const count = Math.max(4, Math.floor(w / 240));
      const arr = [];
      for (let i = 0; i < count; i++) {
        const cells = Array.from({ length: 9 }, credToken);
        arr.push({
          left: i / count * 100 + (Math.random() * 4 - 2),
          dur: 13 + Math.random() * 12,
          delay: -Math.random() * 22,
          cells,
          toks: cells.concat(cells)
        });
      }
      setCols(arr);
    }
    build();
    window.addEventListener("resize", build);
    return () => window.removeEventListener("resize", build);
  }, []);

  React.useEffect(() => {
    if (!cols.length || !rootRef.current) return;
    const root = rootRef.current;
    const cells = [];
    cols.forEach((col, ci) => col.cells.forEach((cell, k) => {
      const spans = root.querySelectorAll('[data-c="' + ci + '-' + k + '"]');
      cells.push({ spans, base: cell.t, color: cell.c, rev: 0, hold: 0, speed: 0.16 + Math.random() * 0.32 });
    }));
    const id = setInterval(() => {
      for (const c of cells) {
        let txt, cls;
        if (c.hold > 0) {
          c.hold--;
          txt = c.base;
          cls = "at-tok " + c.color + " lock";
          if (c.hold === 0) {
            c.rev = 0;
            const np = credPair();
            c.base = np.t;
            c.color = np.c;
          }
        } else if (c.rev >= c.base.length) {
          c.hold = 6 + Math.floor(Math.random() * 16);
          txt = c.base;
          cls = "at-tok " + c.color + " lock";
        } else {
          if (Math.random() < c.speed) c.rev++;
          let s = c.base.slice(0, c.rev);
          for (let i = c.rev; i < c.base.length; i++) s += keepCh(c.base[i]) ? c.base[i] : scrCh();
          txt = s;
          cls = "at-tok scan";
        }
        for (const sp of c.spans) {
          sp.textContent = txt;
          sp.className = cls;
        }
      }
    }, 65);
    return () => clearInterval(id);
  }, [cols]);
  return React.createElement("div", {
    className: "at-rain",
    "aria-hidden": "true",
    ref: rootRef
  }, cols.map((col, i) => React.createElement("div", {
    key: i,
    className: "at-col",
    style: { left: col.left + "%", animationDuration: col.dur + "s", animationDelay: col.delay + "s" }
  }, col.toks.map((tk, j) => React.createElement("span", {
    key: j,
    "data-c": i + "-" + j % col.cells.length,
    className: "at-tok scan",
    style: { marginBottom: tk.gap + "px" }
  }, tk.t)))));
}

/* ── Typing subtitle with blinking cursor ────────────────────────────────── */
const SUBTITLE = "AUTHORIZED ACCESS ONLY";
function useTyping(text, speed = 55, startDelay = 350) {
  const [n, setN] = React.useState(0);
  React.useEffect(() => {
    let i = 0, id;
    const start = setTimeout(() => {
      id = setInterval(() => {
        i++;
        setN(i);
        if (i >= text.length) clearInterval(id);
      }, speed);
    }, startDelay);
    return () => { clearTimeout(start); clearInterval(id); };
  }, [text]);
  return n;
}

/* ── Brute-force attack sequence ─────────────────────────────────────────── */
function App() {
  const [val, setVal] = React.useState("");
  const [err, setErr] = React.useState("");
  const [phase, setPhase] = React.useState("idle"); // idle | cracking | granted
  const [log, setLog] = React.useState([]);
  const [current, setCurrent] = React.useState("");
  const [progress, setProgress] = React.useState(0);
  const [attempts, setAttempts] = React.useState(0);
  const [cracked, setCracked] = React.useState(null);
  const [hubStage, setHubStage] = React.useState("capsule"); // capsule -> glitch -> revealed

  React.useEffect(() => {
    const t1 = setTimeout(() => setHubStage("glitch"), 2000);
    const t2 = setTimeout(() => setHubStage("revealed"), 2000 + 520);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, []);

  const typed = useTyping(SUBTITLE);

  function submit() {
    if (phase !== "idle") return;
    if (!val.trim()) { setErr("access key required"); return; }
    setErr("");
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: val })
    }).then(r => {
      if (!r.ok) { setErr("Access denied"); return; }
      runAttack();
    }).catch(() => { setErr("Connection error"); });
  }

  function runAttack() {
    setPhase("cracking");
    setLog([{ c: "info", tag: "[*]", u: "", pw: "loading rockyou.txt · 14,344,391 keys" }]);
    let n = 0;
    const total = 16 + Math.floor(Math.random() * 6);
    const startCount = 8.4e6 + Math.floor(Math.random() * 4e6);
    const hitUser = rnd(USERS);
    const hitPw = rnd(WORDS);
    const tick = setInterval(() => {
      n++;
      setProgress(Math.min(100, Math.round(n / total * 100)));
      setAttempts(startCount + n * (52000 + Math.floor(Math.random() * 120000)));
      setCurrent(rnd(USERS) + " : " + rnd(WORDS));
      if (n % 4 === 0) {
        setLog(prev => {
          const line = { c: "fail", tag: "[-]", u: rnd(USERS), pw: rnd(WORDS) };
          return prev.concat(line).slice(-6);
        });
      }
      if (n >= total) {
        clearInterval(tick);
        setProgress(100);
        setCurrent(hitUser + " : " + hitPw);
        setLog(prev => prev.concat({ c: "hit", tag: "[+]", u: hitUser, pw: hitPw + "  ✓ CRACKED" }).slice(-6));
        setCracked({ user: hitUser, pw: hitPw });
        setTimeout(() => setPhase("granted"), 500);
        // 0.5s after ACCESS GRANTED appears → transition to projects page
        setTimeout(() => { if (window.__phInitApp) window.__phInitApp(); }, 1000);
      }
    }, 80);
  }

  const panelClass = "at-column" + (phase === "cracking" ? " is-cracking" : phase === "granted" ? " is-granted" : "");
  return React.createElement("div", {
    className: "at-stage"
  }, React.createElement(Rain, null), React.createElement("div", {
    className: panelClass
  }, React.createElement("div", {
    className: "at-logo"
  }, React.createElement("span", {
    className: "ph-logo__pen"
  }, "Pen"), React.createElement("span", {
    className: "ph-logo__hub" + (hubStage === "glitch" ? " is-glitch" : hubStage === "revealed" ? " is-revealed" : "")
  }, "Hub")), React.createElement("div", {
    className: "at-sub"
  }, typed < SUBTITLE.length ? React.createElement("span", null, SUBTITLE.slice(0, typed), React.createElement("span", {
    className: "at-cursor"
  }, "_")) : React.createElement("span", null, React.createElement("span", {
    className: "dot"
  }, "●"), " ", React.createElement("span", {
    className: "at-glitch",
    "data-text": SUBTITLE
  }, SUBTITLE), " ", React.createElement("span", {
    className: "at-cursor"
  }, "_"))), phase === "granted" ? React.createElement("div", {
    className: "at-granted"
  }, "✓ ACCESS GRANTED", React.createElement("span", {
    className: "key"
  }, "session::", cracked.user, " · key resolved in ", attempts.toLocaleString(), " attempts")) : React.createElement("div", {
    className: "at-form"
  }, React.createElement("div", {
    className: "at-input-wrap"
  }, React.createElement("input", {
    className: "ph-input ph-input--lg",
    type: "password",
    placeholder: "access key",
    value: val,
    disabled: phase === "cracking",
    onChange: e => setVal(e.target.value),
    onKeyDown: e => e.key === "Enter" && submit()
  })), phase === "idle" ? React.createElement(Button, {
    variant: "primary",
    className: "at-btn-auth",
    onClick: submit
  }, "AUTHENTICATE") : React.createElement(Button, {
    variant: "warning",
    className: "at-btn-auth",
    disabled: true
  }, "⚡ BRUTEFORCING…"), phase === "cracking" && React.createElement("div", {
    className: "at-console"
  }, React.createElement("div", {
    className: "at-con-head"
  }, React.createElement("span", null, "⚡ dictionary attack"), React.createElement("span", null, React.createElement("b", null, attempts.toLocaleString()), " k/s")), React.createElement("div", {
    className: "at-con-log"
  }, log.map((l, i) => React.createElement("div", {
    key: i,
    className: "at-line " + l.c
  }, React.createElement("span", {
    className: "tag"
  }, l.tag), " ", l.u && React.createElement("span", {
    className: "u"
  }, l.u), l.u && " : ", React.createElement("span", {
    className: "pw"
  }, l.pw)))), React.createElement("div", {
    className: "at-current"
  }, React.createElement("span", {
    className: "label"
  }, "TRY"), React.createElement("span", {
    className: "val"
  }, current)), React.createElement("div", {
    className: "at-current"
  }, React.createElement("div", {
    className: "at-bar"
  }, React.createElement("span", {
    style: { width: progress + "%" }
  })))), React.createElement("div", {
    className: "at-err"
  }, err))));
}

window.__phAuthRoot = ReactDOM.createRoot(document.getElementById("app"));
window.__phAuthRoot.render(React.createElement(App, null));
