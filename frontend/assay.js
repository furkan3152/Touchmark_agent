/* The payment ticket of the assay book (frontend/assay.css, services/assay_book.py).
 * A report is released for a testnet payment that the server reads back from Horizon; this
 * script only helps the payer send it: Freighter signs a payment the server prepared, or the
 * payer sends it from any wallet and asks the server to look for it.
 *
 *   TouchmarkAssay.mount(element, { onReleased })   // element carries data-entry, data-memo, ...
 */
(function () {
  "use strict";
  const TESTNET = "Test SDF Network ; September 2015";

  async function post(url, body) {
    const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    let data = {};
    try { data = await response.json(); } catch { /* not JSON */ }
    if (!response.ok) {
      const detail = Array.isArray(data.detail) ? "That input was not accepted." : data.detail;
      throw new Error(detail || `The server answered ${response.status}.`);
    }
    return data;
  }

  function mount(root, options = {}) {
    if (!root || root.dataset.mounted) return;
    root.dataset.mounted = "1";
    const entry = root.dataset.entry;
    const q = (sel) => root.querySelector(sel);
    const status = q(".status");
    const say = (text, tone = "") => { status.textContent = text; status.className = "status" + (tone ? " " + tone : ""); };

    root.querySelectorAll(".copy").forEach((button) => button.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = "Copied"; }
      catch { button.textContent = "Select it"; }
      setTimeout(() => { button.textContent = "Copy"; }, 1600);
    }));

    function released(result) {
      say("Paid. Punch read your payment from the ledger and released the report.", "good");
      if (options.onReleased) options.onReleased(result);
      else window.location.reload();
    }

    const freighter = q(".pay-freighter");
    freighter.addEventListener("click", async () => {
      const label = freighter.textContent;
      freighter.disabled = true;
      try {
        const api = window.freighterApi;
        if (!api) throw new Error("The Freighter library did not load. Install Freighter, or send the payment from any wallet below.");
        const installed = await api.isConnected();
        if (installed.error || !installed.isConnected) throw new Error("Install the Freighter extension, or send the payment from any wallet below.");
        const access = await api.requestAccess();
        if (access.error || !access.address) throw new Error("Freighter did not share an account.");
        const network = await api.getNetworkDetails();
        if (network.error || network.networkPassphrase !== TESTNET) throw new Error("Switch Freighter to Stellar Testnet.");
        freighter.textContent = "Preparing the payment…";
        const prepared = await post("/api/v1/assay/pay/prepare", { entry, payer: access.address });
        freighter.textContent = "Confirm in Freighter…";
        const signed = await api.signTransaction(prepared.unsigned_xdr, { networkPassphrase: prepared.network_passphrase, address: access.address });
        if (signed.error || !signed.signedTxXdr) throw new Error("The payment was not signed.");
        freighter.textContent = "Sending on testnet…";
        say("Waiting for the ledger…");
        released(await post("/api/v1/assay/pay/submit", { entry, signed_xdr: signed.signedTxXdr }));
      } catch (error) {
        say(error.message, "bad");
      } finally {
        freighter.disabled = false;
        freighter.textContent = label;
      }
    });

    const form = q(".check-row");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      button.disabled = true;
      say("Reading the ledger…");
      try {
        const txHash = form.querySelector("input").value.trim().toLowerCase();
        const result = await post("/api/v1/assay/claim", { entry, tx_hash: txHash });
        if (result.paid) released(result);
        else say(result.message || "No payment yet.", "bad");
      } catch (error) {
        say(error.message, "bad");
      } finally {
        button.disabled = false;
      }
    });
  }

  /** The ticket's markup, for pages that build it in the browser (the demo result). */
  function ticket(payment, entry) {
    const wrap = document.createElement("section");
    wrap.className = "paywall";
    wrap.dataset.entry = entry;
    const text = (tag, cls, value) => { const n = document.createElement(tag); if (cls) n.className = cls; n.textContent = value; return n; };
    const kicker = text("p", "kicker", "");
    kicker.append(text("span", "", "Printed report"), text("span", "", "Stellar testnet"));
    const h2 = document.createElement("h2");
    h2.append("Take the full report for ", text("em", "", `${payment.price_xlm} XLM`));
    const lead = text("p", "", "The designed report with every finding, the line it cites, the verifier's verdict and the fix. Punch reads your payment from the ledger, releases the report and sends a receipt stamp back to your wallet.");
    const row = text("div", "pay-row", "");
    const pay = text("button", "pay-freighter", "Pay with Freighter"); pay.type = "button";
    row.append(pay, text("span", "or", "or send it from any testnet wallet"));
    const dl = document.createElement("dl"); dl.className = "manual";
    const line = (label, value, copy) => {
      const dd = document.createElement("dd"); dd.append(text("code", "", value));
      if (copy) { const c = text("button", "copy", "Copy"); c.type = "button"; c.dataset.copy = value; dd.append(c); }
      dl.append(text("dt", "", label), dd);
    };
    line("To", payment.destination, true); line("Amount", `${payment.price_xlm} XLM`, false); line("Memo (text)", payment.memo, true);
    const form = document.createElement("form"); form.className = "check-row";
    const input = document.createElement("input"); input.placeholder = "Transaction hash (optional)"; input.maxLength = 64; input.setAttribute("aria-label", "Payment transaction hash, optional");
    const check = text("button", "ghost", "I paid · check the ledger"); check.type = "submit";
    form.append(input, check);
    const status = text("p", "status", ""); status.setAttribute("role", "status");
    wrap.append(kicker, h2, lead, row, dl, form, status);
    return wrap;
  }

  window.TouchmarkAssay = { mount, ticket };
  document.addEventListener("DOMContentLoaded", () => {
    const page = document.querySelector("#paywall[data-entry]");
    if (page) mount(page);
  });
})();
