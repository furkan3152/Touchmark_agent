"use strict";
/* The home page's ways into the Studio. After a result, the slip carries the audited reference over
 * (demo.js leaves it on #result as data-reference / data-repository / data-decision); the Studio reads
 * /studio?ref=… and sessionStorage "touchmark.studio.handoff" ({ reference, repository, decision, score })
 * and opens prefilled. The "counter or back room" section carries whatever is typed in the ticket. */
(() => {
  const result = document.getElementById("result");
  const slip = document.getElementById("studio-slip");
  const link = document.getElementById("studio-slip-link");
  const input = document.getElementById("reference");
  if (!result || !slip || !link) return;
  const short = (ref) => ref.replace(/^https:\/\/github\.com\//, "").replace(/\/(?:tree|blob)\/[^/]+/, "");
  const href = (ref) => ref ? `/studio?ref=${encodeURIComponent(ref)}#workspace` : "/studio#workspace";
  const audited = () => (result.dataset.reference || input?.value || "").trim();

  function sync() {
    if (result.hidden) return;
    const reference = audited();
    document.getElementById("studio-slip-ref").textContent = reference ? short(reference) : "this agent";
    link.href = href(reference);
  }
  new MutationObserver(sync).observe(result, { attributes: true, attributeFilter: ["hidden", "data-reference"] });
  sync();

  link.addEventListener("click", () => {
    const reference = audited();
    if (!reference) return;
    const score = (document.getElementById("score")?.textContent || "").trim();
    try {
      sessionStorage.setItem("touchmark.studio.handoff", JSON.stringify({
        reference, repository: result.dataset.repository || "", decision: result.dataset.decision || "",
        score: /^\d/.test(score) ? score : "",
      }));
    } catch { /* storage off: the query string still carries the reference */ }
  });

  // The section link carries a reference typed into the ticket, if there is one.
  const section = document.getElementById("cos-studio-link");
  if (section && input) {
    const carry = () => { section.href = href(input.value.trim()); };
    input.addEventListener("input", carry);
    carry();
  }
})();
