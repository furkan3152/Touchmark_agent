/* Punch, the Touchmark mascot: a hallmark punch who reads the code before striking the mark.
 *
 * One source for every copy of the character. The page script and scripts/build_mascot.cjs
 * (which writes the standalone public/mascot/*.svg files) both use markup() below.
 *
 *   TouchmarkMascot.mount(el, "scanning")          // render into el, returns a controller
 *   ctl.set("success")                             // change state; one-shot motions replay
 *   TouchmarkMascot.create("idle", { size: 120 })  // a detached <svg>
 *   TouchmarkMascot.forDecision("needs_fixes")     // → { state: "warning", tone: "risk" }
 *   <span data-tm-mascot="pointing"></span>        // upgraded on DOMContentLoaded
 *
 * Styling and motion live in mascot.css. No dependencies; safe under a script-src 'self' CSP.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.TouchmarkMascot = api;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => api.upgrade(document));
    else api.upgrade(document);
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const NAME = "Punch";
  const STATES = ["idle", "scanning", "success", "warning", "error", "pointing"];
  const ALIASES = { thinking: "scanning", scan: "scanning", pass: "success", approved: "success",
    issues: "warning", found: "warning", confused: "error", explain: "pointing", guide: "pointing" };
  const LABELS = {
    idle: `${NAME}, the Touchmark mascot`,
    scanning: `${NAME} is reading the code`,
    success: `${NAME} strikes the touchmark: approved`,
    warning: `${NAME} raises a flag: issues found`,
    "warning:evidence": `${NAME} raises a flag: more evidence needed`,
    error: `${NAME} is confused: something went wrong`,
    pointing: `${NAME} points the way`,
  };
  // The four-point star of the Touchmark logo (frontend/brand/mark.svg), 64-unit box.
  const STAR = "M32 13c1.5 11.4 7.9 17.8 19.3 19.3C39.9 33.8 33.5 40.2 32 51.6 30.5 40.2 24.1 33.8 12.7 32.3 24.1 30.8 30.5 24.4 32 13Z";
  // The logo plate: a square with its corners punched in.
  const PLATE = "M70 66H130A14 14 0 0 0 144 80V136A14 14 0 0 0 130 150H70A14 14 0 0 0 56 136V80A14 14 0 0 0 70 66Z";
  let serial = 0;

  function normalize(state) {
    const s = String(state || "idle").toLowerCase();
    const name = ALIASES[s] || s;
    return STATES.includes(name) ? name : "idle";
  }

  function label(state, tone) {
    return LABELS[`${state}:${tone}`] || LABELS[state];
  }

  /** The SVG markup for a state. opts: size (px), tone ("risk" | "evidence"), facing ("right" | "left"),
   *  label (accessible name), decorative (hide from assistive tech), standalone (adds xmlns). */
  function markup(state, opts = {}) {
    const s = normalize(state);
    const id = `tm${++serial}`;
    const tone = opts.tone === "evidence" ? "evidence" : "risk";
    const size = opts.size ? ` width="${Number(opts.size)}" height="${Number(opts.size)}"` : "";
    const name = String(opts.label || label(s, tone)).replace(/[<>&"]/g, "");
    const a11y = opts.decorative ? ' aria-hidden="true" focusable="false"'
      : ` role="img" aria-labelledby="${id}-t"`;
    const ns = opts.standalone ? ' xmlns="http://www.w3.org/2000/svg"' : "";
    return `<svg${ns} class="tm-mascot" viewBox="0 0 200 200"${size} data-state="${s}" data-tone="${tone}" data-facing="${opts.facing === "left" ? "left" : "right"}"${a11y}>`
      + (opts.decorative ? "" : `<title id="${id}-t">${name}</title>`)
      + `<defs><filter id="${id}-ink" x="-20%" y="-20%" width="140%" height="140%"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="7"/><feDisplacementMap in="SourceGraphic" scale="1.8"/></filter></defs>`
      + `<ellipse class="tm-shadow" cx="100" cy="171" rx="46" ry="4.5"/>`
      // The mark it leaves on the paper (success).
      + `<g class="tm-fx tm-fx-imprint" filter="url(#${id}-ink)"><g transform="translate(171 166) rotate(-12)">`
      +   `<circle r="17" class="tm-imprint-ring"/><circle r="12.6" class="tm-imprint-inner"/>`
      +   `<path d="${STAR}" transform="scale(.42) translate(-32 -32.3)" class="tm-imprint-star"/></g></g>`
      + `<g class="tm-flip"><g class="tm-rig"><g class="tm-breath">`
      // Behind the body: the sheet it reads, the flag it raises.
      +   `<g class="tm-fx tm-fx-scan"><g transform="rotate(5 171 142)"><rect class="tm-sheet" x="150" y="114" width="42" height="56" rx="3"/>`
      +     `<rect class="tm-line" x="156" y="122" width="26" height="3" rx="1.5"/><rect class="tm-line" x="156" y="130" width="30" height="3" rx="1.5"/>`
      +     `<rect class="tm-line tm-line-hit" x="156" y="138" width="20" height="3" rx="1.5"/><rect class="tm-line" x="156" y="146" width="28" height="3" rx="1.5"/>`
      +     `<rect class="tm-line" x="156" y="154" width="24" height="3" rx="1.5"/><rect class="tm-line" x="156" y="162" width="14" height="3" rx="1.5"/>`
      +     `<rect class="tm-beam" x="151" y="115" width="40" height="7" rx="2"/></g></g>`
      +   `<g class="tm-fx tm-fx-warn"><path class="tm-pole" d="M163 108V24"/><g class="tm-pennant"><path class="tm-flag" d="M164.5 25L195 36 164.5 48Z"/>`
      +     `<g class="tm-glyph-risk"><rect class="tm-glyph" x="172.6" y="29.5" width="3.2" height="9.5" rx="1.4"/><circle class="tm-glyph" cx="174.2" cy="42.8" r="1.8"/></g>`
      +     `<g class="tm-glyph-evidence"><path class="tm-glyph-q" d="M170.4 32.4q3.8-4.2 7.6-.4q2.2 3-1.8 5q-1.9 1-1.9 3.4"/><circle class="tm-glyph" cx="174.3" cy="44" r="1.6"/></g></g></g>`
      // The body: knob, neck, plate (with its off-register second ink), face, pad.
      +   `<g class="tm-body"><path class="tm-offset" d="${PLATE}" transform="translate(4 4)"/>`
      +     `<rect class="tm-neck" x="93" y="50" width="14" height="18"/><rect class="tm-collar" x="87" y="61" width="26" height="7" rx="2.5"/>`
      +     `<g class="tm-knob"><ellipse class="tm-knob-cap" cx="100" cy="41" rx="18" ry="13.5"/><path class="tm-knob-shine" d="M89.5 36.5q4-5 12-5.2"/></g>`
      +     `<path class="tm-plate" d="${PLATE}"/>`
      +     `<rect class="tm-pad" x="51" y="147" width="98" height="10.5" rx="3"/><rect class="tm-rubber" x="55" y="156" width="90" height="5" rx="1.6"/>`
      +     `<rect class="tm-face" x="66" y="78" width="68" height="52" rx="13"/>`
      +     `<path class="tm-emblem" d="${STAR}" transform="translate(100 140) scale(.25) translate(-32 -32.3)"/>`
      +     `<g class="tm-cheeks"><circle cx="76" cy="115" r="1.5"/><circle cx="80" cy="117.5" r="1.5"/><circle cx="76" cy="120" r="1.5"/>`
      +       `<circle cx="124" cy="115" r="1.5"/><circle cx="120" cy="117.5" r="1.5"/><circle cx="124" cy="120" r="1.5"/></g>`
      +     `<path class="tm-brow tm-brow-l" d="M81 89Q86 86.5 91 89"/><path class="tm-brow tm-brow-r" d="M108 84.6Q114 82 120 84.6"/>`
      +     `<g class="tm-eyes tm-eyes-open"><g class="tm-gaze"><ellipse class="tm-pupil" cx="86" cy="100" rx="4.4" ry="5.8"/><ellipse class="tm-pupil" cx="114" cy="100" rx="5.4" ry="7"/>`
      +       `<circle class="tm-glint" cx="87.7" cy="97.6" r="1.3"/><circle class="tm-glint" cx="116" cy="97.2" r="1.6"/></g></g>`
      +     `<g class="tm-eyes tm-eyes-happy"><path d="M81 102.5Q86 95 91 102.5"/><path d="M108.5 102.5Q114 94.5 119.5 102.5"/></g>`
      +     `<g class="tm-eyes tm-eyes-dizzy"><path d="M86 100m-4.2 0a4.2 4.2 0 1 1 4.2 4.2a2.6 2.6 0 1 1-2.6-2.6"/><path d="M114 100m4.2 0a4.2 4.2 0 1 0-4.2 4.2a2.6 2.6 0 1 0 2.6-2.6"/></g>`
      // The assayer's loupe over the right eye, on a short chain.
      +     `<g class="tm-loupe"><path class="tm-chain" d="M124 104.5Q132.5 116 128.5 128"/><circle class="tm-lens" cx="114" cy="100" r="10.6"/><path class="tm-lens-shine" d="M106.8 94.6a8 8 0 0 1 5.6-3.4"/></g>`
      +     `<path class="tm-mouth tm-mouth-smile" d="M93 116.5Q100 122.5 107 116.5"/>`
      +     `<path class="tm-mouth tm-mouth-grin" d="M91 114.5Q100 127 109 114.5Z"/>`
      +     `<path class="tm-mouth tm-mouth-flat" d="M94.5 118.6Q100 119.4 105.5 117.6"/>`
      +     `<ellipse class="tm-mouth tm-mouth-o" cx="100" cy="119" rx="3.6" ry="4.6"/>`
      +     `<path class="tm-mouth tm-mouth-wobble" d="M90.5 119.5q2.4-3 4.8 0t4.8 0t4.8 0t4.8 0"/>`
      +     `<path class="tm-mouth tm-mouth-talk" d="M93.5 115.5Q100 125 106.5 115.5Z"/></g>`
      // Arms: one group per pose; mascot.css shows the poses of the current state.
      +   `<g class="tm-arm tm-arm-l"><g class="tm-pose tm-pose-rest"><path d="M58 112C48 118 44 128 46 137"/><circle cx="46" cy="140" r="6"/></g>`
      +     `<g class="tm-pose tm-pose-up"><path d="M58 104C46 96 41 84 41 73"/><circle cx="41" cy="69" r="6"/></g>`
      +     `<g class="tm-pose tm-pose-scratch"><path d="M58 106C44 98 48 72 68 61"/><circle cx="71" cy="59" r="6"/></g></g>`
      +   `<g class="tm-arm tm-arm-r"><g class="tm-pose tm-pose-rest"><path d="M142 112C152 118 156 128 154 137"/><circle cx="154" cy="140" r="6"/></g>`
      +     `<g class="tm-pose tm-pose-up"><path d="M142 104C154 96 159 84 159 73"/><circle cx="159" cy="69" r="6"/></g>`
      +     `<g class="tm-pose tm-pose-point"><path d="M142 109C156 105 166 97 173 87"/><circle cx="175.5" cy="83.5" r="6"/><path class="tm-finger" d="M179 79.5L187.5 70"/></g>`
      +     `<g class="tm-pose tm-pose-hold"><path d="M142 116C150 121 155 127 158 133"/><circle cx="159.5" cy="136" r="6"/></g>`
      +     `<g class="tm-pose tm-pose-flag"><path d="M142 110C151 104 157 94 160 86"/><circle cx="162.5" cy="83" r="6"/></g></g>`
      // In front: thinking dots, impact lines, the question, the pointing flicks.
      +   `<g class="tm-fx tm-fx-think"><circle cx="129" cy="29" r="2.6"/><circle cx="138" cy="20.5" r="3.3"/><circle cx="149" cy="11" r="4"/></g>`
      +   `<g class="tm-fx tm-fx-burst"><path d="M44 158l-12-3M47 149l-10-8M156 158l12-3M153 149l10-8"/></g>`
      +   `<g class="tm-fx tm-fx-error"><path class="tm-q" d="M140 33q8-10 16-2.5q5 7-4 11q-4 2-4 8"/><circle class="tm-q-dot" cx="148" cy="58" r="2.6"/><path class="tm-swirl" d="M70 28q-7-3-3-10M62 38q-7 1-8-6"/></g>`
      +   `<g class="tm-fx tm-fx-point"><path d="M191.5 66.5l5-5.5M193 75l6 .6M185.5 60.5l2-6"/></g>`
      + `</g></g></g></svg>`;
  }

  function fromString(svg) {
    const tpl = document.createElement("template");
    tpl.innerHTML = svg.trim();
    return tpl.content.firstElementChild;
  }

  /** A detached <svg class="tm-mascot"> for the state. */
  function create(state, opts = {}) {
    return fromString(markup(state, opts));
  }

  /** Set the state of a rendered mascot (the <svg>, or the element it was mounted into).
   *  Setting the same state again replays its one-shot motion (the success strike). */
  function set(el, state, opts = {}) {
    const svg = el && (el.matches && el.matches("svg.tm-mascot") ? el : el.querySelector && el.querySelector("svg.tm-mascot"));
    if (!svg) return null;
    const s = normalize(state);
    const tone = opts.tone === "evidence" ? "evidence" : opts.tone === "risk" ? "risk" : svg.getAttribute("data-tone") || "risk";
    svg.removeAttribute("data-state");
    void svg.getBoundingClientRect(); // restart CSS animations keyed on the state
    svg.setAttribute("data-tone", tone);
    svg.setAttribute("data-state", s);
    const title = svg.querySelector("title");
    if (title && !opts.keepLabel) title.textContent = opts.label || label(s, tone);
    return svg;
  }

  /** Render into an element (replacing its content) and return a small controller. */
  function mount(target, state = "idle", opts = {}) {
    const el = typeof target === "string" ? document.querySelector(target) : target;
    if (!el) return null;
    const svg = create(state, opts);
    el.replaceChildren(svg);
    return {
      el: svg,
      get state() { return svg.getAttribute("data-state"); },
      set(next, o) { set(svg, next, o); return this; },
      /** Show a state for a while, then return to the previous one. */
      flash(next, ms = 1600, o) {
        const back = svg.getAttribute("data-state");
        set(svg, next, o);
        clearTimeout(svg._tmFlash);
        svg._tmFlash = setTimeout(() => set(svg, back), ms);
        return this;
      },
    };
  }

  /** Mount every [data-tm-mascot] under root that has not been mounted yet. Attributes:
   *  data-tm-mascot (state), data-tm-size, data-tm-tone, data-tm-facing, data-tm-label, data-tm-decorative. */
  function upgrade(root = document) {
    root.querySelectorAll("[data-tm-mascot]:not([data-tm-ready])").forEach((el) => {
      const d = el.dataset;
      const ctl = mount(el, d.tmMascot, { size: d.tmSize, tone: d.tmTone, facing: d.tmFacing, label: d.tmLabel,
        decorative: d.tmDecorative !== undefined });
      el.setAttribute("data-tm-ready", "");
      el.tmMascot = ctl;
    });
  }

  /** The state that tells an audit decision: pass → success; needs_fixes → warning (risk);
   *  needs_evidence → warning (evidence); anything else → idle. */
  function forDecision(decision) {
    return { pass: { state: "success", tone: "risk" }, needs_fixes: { state: "warning", tone: "risk" },
      needs_evidence: { state: "warning", tone: "evidence" } }[decision] || { state: "idle", tone: "risk" };
  }

  return { NAME, STATES, markup, create, set, mount, upgrade, forDecision, normalize, label };
});
