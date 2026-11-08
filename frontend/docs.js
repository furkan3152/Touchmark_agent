/* The docs: copy buttons on code, the contents rail following the reader, and the rail as a
   menu on small screens. */
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".doc pre").forEach((pre) => {
      const button = document.createElement("button");
      button.type = "button"; button.className = "copy-code"; button.textContent = "Copy";
      button.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(pre.querySelector("code").innerText); button.textContent = "Copied"; }
        catch { button.textContent = "Select it"; }
        setTimeout(() => { button.textContent = "Copy"; }, 1500);
      });
      pre.append(button);
    });

    const toc = document.querySelector(".toc");
    const toggle = document.querySelector(".toc-toggle");
    toggle.addEventListener("click", () => {
      const open = toc.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    toc.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => {
      toc.classList.remove("open"); toggle.setAttribute("aria-expanded", "false");
    }));

    const links = new Map([...toc.querySelectorAll("a")].map((a) => [a.getAttribute("href").slice(1), a]));
    const seen = new Set();
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((e) => (e.isIntersecting ? seen.add(e.target.id) : seen.delete(e.target.id)));
      const first = [...links.keys()].find((id) => seen.has(id));
      if (!first) return;
      links.forEach((a, id) => a.classList.toggle("on", id === first));
    }, { rootMargin: "0px 0px -65% 0px" });
    document.querySelectorAll(".doc section[id]").forEach((s) => observer.observe(s));
  });
})();
