// ── Sidebar ambient cube animation ─────────────────────────────────────────
// Decorative only. Six 3D wireframe cubes float and bounce behind the nav.
// Collapse → cubes scatter into small slow squares.
// Expand   → cubes reassemble and become active.
const SbAnim = (() => {
  'use strict';
  const G = [57, 211, 83]; // --a2 console green

  // Unit cube: 8 verts, 12 edges
  const V0 = [
    [-1,-1,-1],[1,-1,-1],[1,1,-1],[-1,1,-1],
    [-1,-1, 1],[1,-1, 1],[1,1, 1],[-1,1, 1]
  ];
  const EE = [
    [0,1],[1,2],[2,3],[3,0],
    [4,5],[5,6],[6,7],[7,4],
    [0,4],[1,5],[2,6],[3,7]
  ];

  let canvas, ctx, W = 0, H = 0, cubes = [], raf = null;
  let _col = false, _inited = false;

  function rX(v, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [v[0], v[1]*c - v[2]*s, v[1]*s + v[2]*c];
  }
  function rY(v, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [v[0]*c + v[2]*s, v[1], -v[0]*s + v[2]*c];
  }
  function rZ(v, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [v[0]*c - v[1]*s, v[0]*s + v[1]*c, v[2]];
  }

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function sgn()     { return Math.random() < 0.5 ? 1 : -1; }

  function makeCube() {
    const base = rnd(13, 25);
    const r = base * 1.4;
    return {
      x:   rnd(r, Math.max(W - r, r + 1)),
      y:   rnd(r, Math.max(H - r, r + 1)),
      vx:  sgn() * rnd(0.38, 0.80),
      vy:  sgn() * rnd(0.38, 0.80),
      ax:  rnd(0, Math.PI * 2),
      ay:  rnd(0, Math.PI * 2),
      az:  rnd(0, Math.PI * 2),
      dax: sgn() * rnd(0.003, 0.008),
      day: sgn() * rnd(0.004, 0.010),
      daz: sgn() * rnd(0.002, 0.006),
      size: base,
      base,
      alpha: rnd(0.40, 0.68),
    };
  }

  function drawCube(c) {
    const s = c.size;
    const pts = V0.map(v => {
      let w = [v[0]*s, v[1]*s, v[2]*s];
      w = rX(w, c.ax);
      w = rY(w, c.ay);
      w = rZ(w, c.az);
      const fov = s * 5;
      const k   = fov / (fov + w[2] + s * 2);
      return [w[0]*k + c.x, w[1]*k + c.y];
    });
    ctx.strokeStyle = `rgba(${G[0]},${G[1]},${G[2]},${c.alpha})`;
    ctx.lineWidth   = 0.65;
    ctx.beginPath();
    for (const [a, b] of EE) {
      ctx.moveTo(pts[a][0], pts[a][1]);
      ctx.lineTo(pts[b][0], pts[b][1]);
    }
    ctx.stroke();
  }

  function update() {
    const spdMul = _col ? 0.06 : 1;
    const maxV   = _col ? 0.12 : 1.20;
    const minV   = _col ? 0.03 : 0.24;
    const N = cubes.length;

    for (let i = 0; i < N; i++) {
      const c = cubes[i];

      // Rotate (much slower when collapsed)
      c.ax += c.dax * spdMul;
      c.ay += c.day * spdMul;
      c.az += c.daz * spdMul;

      // Lerp size towards target
      const tgt = _col ? c.base * 0.40 : c.base;
      c.size += (tgt - c.size) * 0.035;

      // Move
      c.x += c.vx;
      c.y += c.vy;

      // Bounce off walls
      const r = c.size * 1.4;
      if (c.x < r)     { c.x = r;     c.vx =  Math.abs(c.vx); }
      if (c.x > W - r) { c.x = W - r; c.vx = -Math.abs(c.vx); }
      if (c.y < r)     { c.y = r;     c.vy =  Math.abs(c.vy); }
      if (c.y > H - r) { c.y = H - r; c.vy = -Math.abs(c.vy); }

      // Repulsion between cubes
      for (let j = i + 1; j < N; j++) {
        const d = cubes[j];
        const dx = c.x - d.x, dy = c.y - d.y;
        const dist2 = dx*dx + dy*dy;
        const minD  = (c.size + d.size) * 1.0;
        if (dist2 > 0 && dist2 < minD * minD) {
          const dist = Math.sqrt(dist2);
          const f    = (minD - dist) / dist * 0.011;
          c.vx += dx*f; c.vy += dy*f;
          d.vx -= dx*f; d.vy -= dy*f;
        }
      }

      // Dampen + clamp + floor (prevents cubes from stopping)
      c.vx *= 0.9993; c.vy *= 0.9993;
      const v = Math.sqrt(c.vx*c.vx + c.vy*c.vy);
      if      (v > maxV)       { c.vx = c.vx/v*maxV; c.vy = c.vy/v*maxV; }
      else if (v > 0 && v < minV) { c.vx = c.vx/v*minV; c.vy = c.vy/v*minV; }
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (const c of cubes) drawCube(c);
  }

  function tick() {
    update();
    draw();
    raf = requestAnimationFrame(tick);
  }

  function resize() {
    if (!canvas) return;
    const sb = document.getElementById('sidebar');
    if (!sb) return;
    W = sb.offsetWidth;
    H = sb.offsetHeight;
    canvas.width  = W;
    canvas.height = H;
    for (const c of cubes) {
      const r = c.size * 1.4;
      c.x = Math.min(Math.max(c.x, r), Math.max(W - r, r));
      c.y = Math.min(Math.max(c.y, r), Math.max(H - r, r));
    }
  }

  function init() {
    if (_inited) return;
    _inited = true;
    canvas = document.getElementById('sbCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    const sb = document.getElementById('sidebar');
    W = sb.offsetWidth;
    H = sb.offsetHeight;
    canvas.width  = W;
    canvas.height = H;
    cubes = Array.from({ length: 8 }, makeCube);
    if (raf) cancelAnimationFrame(raf);
    tick();
    if (window.ResizeObserver) {
      new ResizeObserver(resize).observe(sb);
    }
  }

  function onCollapse() {
    _col = true;
    for (const c of cubes) {
      c.vx += sgn() * rnd(0.18, 0.55);
      c.vy += sgn() * rnd(0.18, 0.55);
    }
    resize();
  }

  function onExpand() {
    _col = false;
    for (const c of cubes) {
      c.vx += sgn() * rnd(0.06, 0.22);
      c.vy += sgn() * rnd(0.06, 0.22);
    }
    resize();
  }

  return { init, onCollapse, onExpand };
})();
