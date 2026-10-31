# Punch, the Touchmark mascot

Punch is a hallmark punch: the small steel stamp an assay office strikes into silver once the metal has been tested. In Touchmark it works the same desk for AI agents. Its body is the Touchmark plate with the corners punched in, its red knob is the handle you press, and the four-point star on its chest is the mark it leaves. It wears an assayer's loupe over one eye because it reads everything up close, and it will not strike on a promise: a limit written in a prompt is not a limit to Punch until it finds it in the code that signs. It is patient while it reads, plain about what it finds, and only ever pleased with evidence. It prints in the site's riso inks: the page ink for the body, the second ink (red) for the knob, the cheeks and the off-register plate behind it.

## Files

| File | What it is |
|---|---|
| `frontend/mascot.js` | The one source of the drawing (`markup()`) and a tiny API to render and switch states. No dependencies; works under `script-src 'self'`. |
| `frontend/mascot.css` | Colours, poses and motion per state. Light and dark follow `prefers-color-scheme` (and `[data-theme]` if a page sets it). All motion is off under `prefers-reduced-motion`; every state still reads as a still pose. |
| `public/mascot/*.svg` | Standalone, self-styled files for READMEs, social cards and slides: `idle`, `scanning`, `success`, `warning`, `warning-evidence`, `error`, `pointing`. Generated: run `node scripts/build_mascot.cjs` after changing the JS or CSS (`--check` fails when they are stale; a test runs it). |

## States

| State | Pose | Use it for |
|---|---|---|
| `idle` | Breathes, blinks, an occasional nod of the knob | Resting, empty states |
| `scanning` (alias `thinking`) | Holds a sheet of code, eyes reading, a red scan line, thinking dots | Long-running audits |
| `success` | Leaps, strikes, arms up; a green ring with the red star appears on the paper | `pass`, a credential issued |
| `warning` | Raises a red flag with `!`; with tone `evidence`, an amber flag with `?` | `needs_fixes`; `needs_evidence` |
| `error` | Scratches its head, loupe knocked askew, a red `?` | A failed request, a reference with no source |
| `pointing` | Points to its right and talks; `facing: "left"` mirrors it | Guides, tips, onboarding |

## Using it

```html
<link rel="stylesheet" href="/ui/mascot.css">
<script src="/ui/mascot.js" defer></script>

<!-- Declarative: mounted on load. -->
<span data-tm-mascot="scanning" data-tm-size="120"></span>
<span data-tm-mascot="warning" data-tm-tone="evidence" data-tm-decorative></span>
```

```js
const punch = TouchmarkMascot.mount("#audit-mascot", "scanning", { size: 120 });
// … when the audit returns:
const { state, tone } = TouchmarkMascot.forDecision(data.decision); // pass → success, needs_fixes → warning, needs_evidence → warning/evidence
punch.set(state, { tone });
// … on a failed request:
punch.set("error");
punch.flash("success", 1600); // show a state for a while, then go back
```

`TouchmarkMascot.create(state, opts)` returns a detached `<svg>`; `TouchmarkMascot.markup(state, opts)` returns its markup as a string. Options: `size` (px), `tone` (`risk` or `evidence`), `facing` (`right` or `left`), `label` (accessible name; each state has a default), `decorative` (hide it from assistive technology when the text next to it already says the same thing). Setting the same state again replays its one-shot motion, so a second pass strikes again.
