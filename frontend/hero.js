"use strict";
// Halftone dots that change shape: an agent, the glass that tests it, the touchmark it earns.
// Every dot lands on the 9 px halftone grid behind it, so each shape prints like a riso plate.
(() => {
  const canvas = document.getElementById("dots");
  const caption = document.getElementById("dots-caption");
  if (!canvas || !canvas.getContext) return;
  const SIZE = 480, STEP = 9;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ctx = canvas.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = SIZE * dpr; canvas.height = SIZE * dpr;
  ctx.scale(dpr, dpr);

  function ink(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#1d2b4f"; }

  // Each shape is drawn twice into a mask: dark ink, then the red second colour.
  function sample(draw) {
    const off = document.createElement("canvas"); off.width = off.height = SIZE;
    const o = off.getContext("2d");
    const out = [];
    for (const [layer, color] of [["ink", 0], ["red", 1]]) {
      o.clearRect(0, 0, SIZE, SIZE); o.fillStyle = o.strokeStyle = "#000";
      draw(o, layer);
      const data = o.getImageData(0, 0, SIZE, SIZE).data;
      for (let y = STEP / 2; y < SIZE; y += STEP) for (let x = STEP / 2; x < SIZE; x += STEP) {
        const a = data[(Math.floor(y) * SIZE + Math.floor(x)) * 4 + 3];
        if (a > 100) {
          const existing = out.findIndex((p) => p.x === x && p.y === y);
          const dot = { x, y, color, r: color ? 3.3 : 2.4 + (a / 255) * 0.9 };
          if (existing >= 0) out[existing] = dot; else out.push(dot);
        }
      }
    }
    return out;
  }

  const agent = sample((o, layer) => {
    if (layer === "ink") {
      o.beginPath(); o.roundRect(130, 150, 220, 190, 46); o.fill();
      o.lineWidth = 14; o.beginPath(); o.moveTo(240, 150); o.lineTo(240, 102); o.stroke();
      o.beginPath(); o.roundRect(165, 340, 150, 50, 18); o.fill();
      o.globalCompositeOperation = "destination-out";
      o.beginPath(); o.arc(196, 236, 22, 0, 7); o.arc(284, 236, 22, 0, 7); o.fill();
      o.beginPath(); o.roundRect(200, 286, 80, 16, 8); o.fill();
      o.globalCompositeOperation = "source-over";
    } else {
      o.beginPath(); o.arc(240, 92, 20, 0, 7); o.fill();
      o.beginPath(); o.arc(196, 236, 10, 0, 7); o.arc(284, 236, 10, 0, 7); o.fill();
    }
  });
  const glass = sample((o, layer) => {
    if (layer === "ink") {
      o.lineWidth = 30; o.beginPath(); o.arc(212, 206, 104, 0, 7); o.stroke();
      o.lineWidth = 40; o.lineCap = "round"; o.beginPath(); o.moveTo(292, 290); o.lineTo(378, 376); o.stroke();
    } else {
      // A code line under the glass, and the one flagged line.
      for (const [y, w] of [[168, 110], [196, 70], [252, 96]]) { o.fillRect(160, y - 5, w, 10); }
      o.fillRect(160, 219, 130, 12);
    }
  });
  const mark = sample((o, layer) => {
    o.save(); o.translate(64, 64); o.scale(5.5, 5.5);
    if (layer === "ink") {
      o.fill(new Path2D("M14 4h36a10 10 0 0 0 10 10v36a10 10 0 0 0-10 10H14A10 10 0 0 0 4 50V14A10 10 0 0 0 14 4Z"));
      o.globalCompositeOperation = "destination-out";
      o.fill(new Path2D("M32 13c1.5 11.4 7.9 17.8 19.3 19.3C39.9 33.8 33.5 40.2 32 51.6 30.5 40.2 24.1 33.8 12.7 32.3 24.1 30.8 30.5 24.4 32 13Z"));
    } else {
      o.fill(new Path2D("M33.6 11.5c1.5 11.4 7.9 17.8 19.3 19.3-11.4 1.5-17.8 7.9-19.3 19.3-1.5-11.4-7.9-17.8-19.3-19.3 11.4-1.5 17.8-7.9 19.3-19.3Z"));
    }
    o.restore();
  });

  const shapes = [{ points: agent, label: "an agent" }, { points: glass, label: "under the glass" }, { points: mark, label: "touchmarked" }];
  // Sort by angle around the centre so dots sweep round instead of crossing at random.
  for (const s of shapes) s.points.sort((a, b) => Math.atan2(a.y - 240, a.x - 240) - Math.atan2(b.y - 240, b.x - 240));
  const count = Math.max(...shapes.map((s) => s.points.length));
  function target(shape, i) {
    const p = shape.points;
    return i < p.length ? p[i] : { ...p[(i * 7) % p.length], r: 0 }; // spare dots hide inside the shape
  }
  const dots = Array.from({ length: count }, (_, i) => {
    const t = target(shapes[0], i);
    return { x: t.x, y: t.y, r: t.r, color: t.color, from: t, to: t, delay: Math.random() * 0.35 };
  });

  const colors = () => [ink("--ink"), ink("--red")];
  function draw(palette) {
    ctx.clearRect(0, 0, SIZE, SIZE);
    for (const d of dots) {
      if (d.r < 0.2) continue;
      ctx.fillStyle = palette[d.color];
      ctx.beginPath(); ctx.arc(d.x, d.y, d.r, 0, 6.2832); ctx.fill();
    }
  }
  const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

  if (reduce) {
    dots.forEach((d, i) => Object.assign(d, target(shapes[2], i)));
    draw(colors()); caption.textContent = shapes[2].label;
    return;
  }

  let index = 0, start = performance.now(), running = true, morphing = false;
  const HOLD = 2600, MORPH = 1500;
  const next = () => (index + 1) % shapes.length;
  function frame(now) {
    if (!running) return;
    const t = now - start;
    if (!morphing && t > HOLD) {
      morphing = true;
      dots.forEach((d, i) => { d.from = { x: d.x, y: d.y, r: d.r, color: d.color }; d.to = target(shapes[next()], i); });
    }
    if (morphing) {
      const m = Math.min(1, (t - HOLD) / MORPH);
      for (const d of dots) {
        const k = ease(Math.max(0, Math.min(1, (m - d.delay * 0.5) / (1 - d.delay * 0.5))));
        // Arc outward a little on the way, so the change reads as a metamorphosis, not a slide.
        const lift = Math.sin(k * Math.PI) * 26;
        const ang = Math.atan2(d.from.y - 240, d.from.x - 240);
        d.x = d.from.x + (d.to.x - d.from.x) * k + Math.cos(ang) * lift;
        d.y = d.from.y + (d.to.y - d.from.y) * k + Math.sin(ang) * lift;
        d.r = Math.max(0, d.from.r + (d.to.r - d.from.r) * k - Math.sin(k * Math.PI) * 0.8);
        d.color = k > 0.5 ? d.to.color : d.from.color;
      }
      if (m >= 1) {
        morphing = false; index = next(); start = now;
        if (caption) caption.textContent = shapes[index].label;
      }
    }
    draw(colors());
    requestAnimationFrame(frame);
  }
  if (caption) caption.textContent = shapes[0].label;
  // Pause off screen; there is no reason to burn a phone battery.
  new IntersectionObserver(([e]) => {
    const was = running; running = e.isIntersecting;
    if (running && !was) { start = performance.now() - Math.min(performance.now() - start, HOLD); requestAnimationFrame(frame); }
  }).observe(canvas);
  requestAnimationFrame(frame);
})();
