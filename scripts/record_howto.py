#!/usr/bin/env python3
"""Record the Touchmark how-to video from the real site.

Drives the demo in a browser: paste an agent, read the verdict, fix and re-test, stamp a
passing agent on Stellar testnet. Title cards, captions and a visible cursor are injected
into the page; long waits (the AI review, ledger transactions) are marked so that
scripts/cut_howto.sh can speed them up. Writes the raw recording and a marks file.

    python scripts/record_howto.py --url http://localhost:8011/ --out media-build/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import time
from pathlib import Path

from playwright.async_api import async_playwright

REPO = "https://github.com/furkan3152/agentveritas-stellar/tree/main/examples/demo"
UNSAFE, SAFE = f"{REPO}/unsafe-treasury-agent", f"{REPO}/safe-treasury-agent"

OVERLAY = r"""
(() => {
  const css = `
  #hv-cursor{position:fixed;left:0;top:0;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;
    background:rgba(226,67,42,.25);border:2.5px solid #e2432a;z-index:99999;pointer-events:none;transition:transform .12s}
  #hv-cursor.down{transform:scale(.7)}
  #hv-cap{position:fixed;left:28px;bottom:28px;z-index:99998;display:flex;align-items:center;gap:14px;max-width:760px;
    background:#fbf7ee;color:#1d2b4f;border:2.5px solid #1d2b4f;border-radius:6px;padding:14px 20px 14px 14px;
    box-shadow:6px 6px 0 #e2432a;font:600 21px/1.3 Archivo,sans-serif;transform:translateY(160%);transition:transform .45s cubic-bezier(.2,1.2,.3,1)}
  #hv-cap.on{transform:none}
  #hv-cap b{flex:none;display:grid;place-items:center;width:42px;height:42px;border-radius:50%;background:#1d2b4f;color:#f4eee1;font:700 22px Fraunces,serif}
  #hv-fast{position:fixed;right:28px;top:24px;z-index:99998;background:#1d2b4f;color:#f4eee1;font:600 15px 'IBM Plex Mono',monospace;
    padding:8px 12px;border-radius:4px;letter-spacing:1px;opacity:0;transition:opacity .3s}
  #hv-fast.on{opacity:1}
  #hv-card{position:fixed;inset:0;z-index:100000;display:grid;place-items:center;background:#f4eee1;color:#1d2b4f;transition:opacity .6s;
    background-image:radial-gradient(rgba(29,43,79,.13) 1.1px,transparent 1.5px);background-size:9px 9px}
  #hv-card.off{opacity:0;pointer-events:none}
  #hv-card .in{text-align:center;max-width:980px;padding:40px}
  #hv-card svg{width:120px;height:120px}
  #hv-card h1{font:700 74px/1 Fraunces,serif;letter-spacing:-2px;margin:26px 0 14px}
  #hv-card h1 em{color:#e2432a;font-style:italic;font-weight:600}
  #hv-card p{font:500 24px/1.45 Archivo,sans-serif;color:#4e5878;margin:0}
  #hv-card code{font:600 22px 'IBM Plex Mono',monospace;background:#fbf7ee;border:2px solid #1d2b4f;padding:4px 10px;border-radius:4px;color:#1d2b4f}
  `;
  const style = document.createElement("style"); style.textContent = css; document.head.append(style);
  const cursor = document.createElement("div"); cursor.id = "hv-cursor"; document.body.append(cursor);
  document.addEventListener("mousemove", (e) => { cursor.style.left = e.clientX + "px"; cursor.style.top = e.clientY + "px"; }, true);
  document.addEventListener("mousedown", () => cursor.classList.add("down"), true);
  document.addEventListener("mouseup", () => cursor.classList.remove("down"), true);
  const cap = document.createElement("div"); cap.id = "hv-cap"; cap.innerHTML = "<b></b><span></span>"; document.body.append(cap);
  const fast = document.createElement("div"); fast.id = "hv-fast"; fast.textContent = "▶▶ SPED UP"; document.body.append(fast);
  const card = document.createElement("div"); card.id = "hv-card"; card.className = "off"; document.body.append(card);
  window.hv = {
    caption(n, text) { cap.classList.remove("on"); setTimeout(() => { cap.querySelector("b").textContent = n; cap.querySelector("span").textContent = text; cap.classList.add("on"); }, 250); },
    hideCaption() { cap.classList.remove("on"); },
    fast(on) { fast.classList.toggle("on", on); },
    card(html) { card.innerHTML = `<div class="in"><svg><use href="#mark"/></svg>${html}</div>`; card.classList.remove("off"); },
    hideCard() { card.classList.add("off"); },
  };
})();
"""


class Recorder:
    def __init__(self, page, t0: float):
        self.page, self.t0, self.marks = page, t0, []

    def now(self) -> float:
        return round(time.monotonic() - self.t0, 2)

    async def pause(self, seconds: float):
        await self.page.wait_for_timeout(int(seconds * 1000))

    async def move_to(self, selector: str, *, click: bool = False):
        box = await self.page.locator(selector).first.bounding_box()
        x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        await self.page.mouse.move(x, y, steps=28)
        await self.pause(0.25)
        if click:
            await self.page.mouse.down(); await self.pause(0.08); await self.page.mouse.up()
        return x, y

    async def type_into(self, selector: str, text: str):
        await self.move_to(selector, click=True)
        await self.page.locator(selector).fill("")
        await self.page.keyboard.type(text, delay=28)

    async def scroll_to(self, selector: str, offset: int = 90):
        await self.page.evaluate("([s, o]) => { const el = document.querySelector(s); window.scrollTo({top: el.getBoundingClientRect().top + window.scrollY - o, behavior: 'smooth'}); }", [selector, offset])
        await self.pause(1.1)

    async def wait_fast(self, selector: str, timeout: float = 300):
        """Wait for a selector; the wait is marked so the editor speeds it up."""
        start = self.now()
        await self.page.evaluate("hv.fast(true)")
        await self.page.wait_for_selector(selector, timeout=timeout * 1000)
        await self.page.evaluate("hv.fast(false)")
        end = self.now()
        if end - start > 3:
            self.marks.append({"fast": [start + 0.6, end - 0.4]})

    async def caption(self, n: str, text: str):
        await self.page.evaluate("([n, t]) => hv.caption(n, t)", [n, text])


async def record(url: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
        context = await browser.new_context(viewport={"width": 1280, "height": 720}, color_scheme="light",
                                            record_video_dir=str(out / "raw"), record_video_size={"width": 1280, "height": 720})
        page = await context.new_page()
        r = Recorder(page, time.monotonic())
        await page.goto(url)
        await page.evaluate(OVERLAY)
        await page.evaluate("""hv.card('<h1>Test the agent.<br><em>Stamp the proof.</em></h1><p>How to use Touchmark, in four steps.</p>')""")
        await page.wait_for_timeout(3600)
        await page.evaluate("hv.hideCard()")
        await r.pause(4.6)  # the dots turn from an agent into the glass

        await r.caption("1", "Paste an agent: a GitHub repo or folder, an agent id, a C… contract or a G… account.")
        await r.pause(1.2)
        await r.type_into("#reference", UNSAFE)
        await r.pause(0.6)
        await r.move_to("#run", click=True)
        await r.pause(1.6)
        await r.caption("1", "It pins the exact commit, reads the code, and an AI reviewer tries to misuse it.")
        await r.wait_fast("#result:not([hidden])")
        await r.pause(0.4)
        await r.scroll_to("#result", 70)

        await r.caption("2", "The verdict, stamped. This agent lets the model pick who gets paid, and how much.")
        await r.pause(3.4)
        await r.scroll_to("#risks", 90)
        await r.caption("2", "Every risk points to the file and line, with how to fix it.")
        await r.pause(3.2)
        await r.scroll_to("#why-box", 80)
        await r.caption("2", "“Why this score?” shows every point it lost.")
        await r.pause(3.4)

        await r.scroll_to("#recheck", 140)
        await r.caption("3", "Fixed it? Paste the fixed version and test again.")
        await r.type_into("#fixed", SAFE)
        await r.pause(0.4)
        await r.move_to("#run-recheck", click=True)
        await r.wait_fast("#diff:not([hidden])")
        await r.pause(0.3)
        await r.scroll_to("#diff", 160)
        await r.caption("3", "It shows what the fix closed, what is still open, and anything new.")
        await r.pause(3.6)

        await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        await r.pause(1.2)
        await r.caption("4", "A passing agent can be stamped on Stellar.")
        await r.type_into("#reference", SAFE)
        await r.move_to("#run", click=True)
        await r.wait_fast("#result:not([hidden])")
        await r.pause(0.4)
        await r.scroll_to("#result", 70)
        await r.pause(2.6)
        await r.scroll_to(".credential", 90)
        await r.caption("4", "One click: the report hash and score are written to Stellar testnet.")
        await r.move_to("#issue", click=True)
        await r.wait_fast("#cred-done:not([hidden])", timeout=180)
        await r.pause(0.4)
        await r.scroll_to("#cred-done", 110)
        await r.caption("4", "Read back from the ledger: anyone can check it. That stamp is the touchmark.")
        await r.pause(4.4)
        await page.evaluate("hv.hideCaption()")
        await page.evaluate("""hv.card('<h1>Earn your <em>touchmark.</em></h1><p>Add <code>touchmark.json</code> with your Stellar account to receive the credential yourself.<br><br><code>agentveritas-stellar.vercel.app</code></p>')""")
        await r.pause(4.8)
        await context.close()
        await browser.close()

    raw = next((out / "raw").glob("*.webm"))
    shutil.move(str(raw), out / "raw.webm")
    shutil.rmtree(out / "raw", ignore_errors=True)
    (out / "marks.json").write_text(json.dumps(r.marks, indent=1))
    print("recorded", out / "raw.webm", r.marks)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8011/")
    ap.add_argument("--out", default="media-build")
    args = ap.parse_args()
    asyncio.run(record(args.url, Path(args.out)))


if __name__ == "__main__":
    main()
