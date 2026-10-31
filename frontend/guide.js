"use strict";
// The Guide: scroll reveals, the contents rail and its mascot, the audit timeline, the score explorer.
(() => {
  const doc = document.documentElement;
  doc.classList.add("g-js");
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (id) => document.getElementById(id);
  const mascot = () => window.TouchmarkMascot;

  // ---------------------------------------------------------------- reveals
  const reveals = document.querySelectorAll(".g-reveal");
  if ("IntersectionObserver" in window && !reduce) {
    const io = new IntersectionObserver((entries) => entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
    }), { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });
    reveals.forEach((el) => io.observe(el));
  } else reveals.forEach((el) => el.classList.add("is-in"));

  // ------------------------------------------------- contents rail + mascot
  const plates = [...document.querySelectorAll(".g-plate[id]")];
  const links = new Map([...document.querySelectorAll(".g-toc a")].map((a) => [a.getAttribute("href").slice(1), a]));
  let active = "";
  function setActive(id) {
    if (!id || id === active) return;
    active = id;
    links.forEach((a, key) => { a.classList.toggle("is-active", key === id); if (key === id) a.setAttribute("aria-current", "location"); else a.removeAttribute("aria-current"); });
    const plate = $(id);
    const rail = $("rail-mascot");
    if (rail && rail.tmMascot && plate) rail.tmMascot.set(plate.dataset.mascot || "idle", { tone: plate.dataset.tone || "risk" });
    const say = $("rail-say");
    if (say && plate && plate.dataset.say) say.textContent = plate.dataset.say;
    // Keep the active chip visible in the horizontal contents strip on small screens.
    const link = links.get(id);
    const strip = link && link.closest("ol");
    if (strip && strip.scrollWidth > strip.clientWidth) {
      const a = link.getBoundingClientRect(), s = strip.getBoundingClientRect();
      if (a.left < s.left || a.right > s.right) {
        strip.scrollTo({ left: strip.scrollLeft + a.left - s.left - 16, behavior: reduce ? "auto" : "smooth" });
      }
    }
  }

  // ------------------------------------------------------------ timeline
  const timeline = $("timeline");
  const stages = timeline ? [...timeline.querySelectorAll(".g-stage")] : [];

  function onScroll() {
    const vh = window.innerHeight;
    // Active plate: the last one whose top passed a third of the screen.
    let current = plates[0] && plates[0].id;
    for (const p of plates) if (p.getBoundingClientRect().top < vh * 0.34) current = p.id;
    setActive(current);
    const max = doc.scrollHeight - vh;
    doc.style.setProperty("--read", max > 0 ? Math.min(1, window.scrollY / max).toFixed(3) : "0");

    if (timeline) {
      const line = vh * 0.62;
      const r = timeline.getBoundingClientRect();
      const p = Math.max(0, Math.min(1, (line - r.top) / Math.max(1, r.height - 40)));
      timeline.style.setProperty("--p", p.toFixed(3));
      let last = null;
      stages.forEach((s) => {
        const dot = s.querySelector(".g-stage-dot").getBoundingClientRect();
        const reached = dot.top + dot.height / 2 < line;
        s.classList.toggle("is-reached", reached);
        s.classList.remove("is-current");
        if (reached) last = s;
      });
      if (last) last.classList.add("is-current");
    }
  }
  let ticking = false;
  window.addEventListener("scroll", () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => { ticking = false; onScroll(); });
  }, { passive: true });
  window.addEventListener("resize", onScroll);

  // ------------------------------------------------- Punch in the hero
  const HERO_LINES = [
    ["pointing", "<b>I'm Punch.</b> I strike the touchmark, but only after I have read every line that can touch a key."],
    ["scanning", "<b>Reading.</b> Requests in, keys and payments out: I follow every path between them."],
    ["warning", "<b>Found one.</b> A limit in the prompt is not a limit in the code."],
    ["success", "<b>Struck.</b> No actionable risk in the reviewed code. Bound to this commit."],
    ["error", "<b>Hm?</b> That reference has no source I can read. Try a GitHub link."],
  ];
  const hero = document.querySelector(".g-hero-mascot");
  const bubble = $("hero-bubble");
  if (hero && bubble) {
    let i = 0;
    hero.setAttribute("tabindex", "0");
    hero.setAttribute("role", "button");
    hero.setAttribute("aria-label", "Punch: show another pose");
    bubble.setAttribute("aria-live", "polite");
    const next = () => {
      i = (i + 1) % HERO_LINES.length;
      const [state, line] = HERO_LINES[i];
      if (hero.tmMascot) hero.tmMascot.set(state);
      bubble.innerHTML = line;
    };
    hero.addEventListener("click", next);
    hero.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); next(); } });
  }

  // The closing Punch strikes when it comes into view.
  const end = $("end-mascot");
  if (end && "IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting && end.tmMascot) { end.tmMascot.set("success"); io.disconnect(); }
    }, { threshold: 0.6 });
    io.observe(end);
  }

  // ------------------------------------------------------- score explorer
  // The same arithmetic as backend/app/swarm/judge.py: score_breakdown and band_score.
  const WEIGHT = { critical: 30, high: 14, medium: 6, low: 2 };
  const GRADE = { confirmed: 1, inferred: 0.6 };
  const SAMPLE = [
    { id: "dest", sev: "critical", grade: "confirmed", conf: 0.9, places: 1, group: "spend", title: "The model picks the payment destination and amount" },
    { id: "net", sev: "high", grade: "confirmed", conf: 0.85, places: 2, group: "net", title: "Declared testnet only, but a tool argument can select mainnet" },
    { id: "day", sev: "high", grade: "inferred", conf: 0.8, places: 1, group: "day", title: "The declared per_day limit has no running total near the payment code" },
    { id: "retry", sev: "medium", grade: "inferred", conf: 0.7, places: 1, group: "retry", title: "A retry after a timeout can pay twice" },
    { id: "idem", sev: "low", grade: "inferred", conf: 0.7, places: 1, group: "idem", title: "The idempotency key is chosen by the model" },
  ];
  const list = $("ex-list");
  if (list) {
    const fixed = new Set();
    const scope = (n) => (n > 1 ? Math.min(1.75, 1 + 0.25 * Math.log2(n)) : 1);
    function compute() {
      const open = SAMPLE.filter((f) => !fixed.has(f.id))
        .map((f) => ({ ...f, base: WEIGHT[f.sev] * GRADE[f.grade] * Math.max(0.4, f.conf) * scope(f.places) }))
        .sort((a, b) => b.base - a.base);
      const groups = new Set(), perSev = {};
      let total = 0;
      const ded = {};
      for (const f of open) {
        let factor = 0.3;
        if (!groups.has(f.group)) { const n = perSev[f.sev] || 0; factor = 1 / (1 + 0.25 * n); perSev[f.sev] = n + 1; groups.add(f.group); }
        ded[f.id] = Math.round(f.base * factor * 100) / 100;
        total += ded[f.id];
      }
      const raw = Math.round(100 * Math.exp(-total / 100) * 10) / 10;
      const actionable = open.filter((f) => f.sev === "critical" || f.sev === "high");
      let score = raw, band = "no actionable risk";
      if (actionable.length) {
        const critical = actionable.some((f) => f.sev === "critical" && f.grade === "confirmed");
        const ceiling = critical ? 39 : 64, knee = ceiling - 10;
        band = critical ? "confirmed critical: at most 39" : "actionable risk: at most 64";
        if (raw > knee) score = Math.round((knee + 10 * (raw - knee) / (100 - knee)) * 10) / 10;
      }
      const decision = actionable.length || score < 65 ? "needs_fixes" : "pass";
      return { ded, total, raw, score, band, decision };
    }
    function render(bump) {
      const r = compute();
      list.querySelectorAll("label").forEach((label) => {
        const id = label.dataset.id;
        label.classList.toggle("fixed", fixed.has(id));
        label.querySelector(".pts").textContent = fixed.has(id) ? "fixed" : "−" + (r.ded[id] || 0).toFixed(1);
      });
      $("ex-score").textContent = r.score.toFixed(1);
      const stamp = $("ex-stamp");
      stamp.className = "g-ex-stamp " + r.decision;
      if (bump && !reduce) { void stamp.offsetWidth; stamp.classList.add("bump"); }
      const d = $("ex-decision");
      d.className = "decision " + r.decision;
      d.textContent = r.decision === "pass" ? "pass*" : "needs fixes";
      $("ex-sum").textContent = `${r.total.toFixed(1)} risk points → ${r.raw}${r.score !== r.raw ? " → " + r.score : ""} (${r.band})`
        + (r.decision === "pass" ? ". *With the full review complete." : "");
    }
    SAMPLE.forEach((f) => {
      const li = document.createElement("li");
      li.innerHTML = `<label class="${f.sev}" data-id="${f.id}"><input type="checkbox" aria-label="Mark as fixed: ${f.title}">`
        + `<span><span class="t">${f.title}</span><span class="m">${f.sev} · ${f.grade} · confidence ${f.conf} · ${f.places} ${f.places === 1 ? "place" : "places"}</span></span><span class="pts"></span></label>`;
      li.querySelector("input").addEventListener("change", (e) => { if (e.target.checked) fixed.add(f.id); else fixed.delete(f.id); render(true); });
      list.append(li);
    });
    render(false);
  }

  // Mascots are mounted by mascot.js on DOMContentLoaded; run the first layout pass after it.
  const start = () => { if (mascot()) mascot().upgrade(document); active = ""; onScroll(); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
