/* ==========================================================================
   AgentVeritas — arayüz mantığı
   ==========================================================================
   Bağımlılık yok, derleme adımı yok: backend `/ui` altından statik servis
   ediyor ve tek dosya olması hata ayıklamayı kolaylaştırıyor.

   Kurallar
   --------
   1. Sunucudan gelen her metin `esc()` ile kaçırılır. Ajan adı, bulgu
      başlığı, hata mesajı — hepsi denetlenen tarafın kontrolündeki veridir.
   2. Her uzak çağrının üç durumu vardır: yükleniyor (iskelet), boş (ne
      yapılacağını söyleyen mesaj), hata (yeniden dene düğmesi).
      Sessizce boş kalan bir panel hata gizler.
   3. Sayısal bant eşikleri backend'deki `BADGE_THRESHOLDS` ile aynıdır;
      tek yerde tanımlıdır (`band()`).
   ========================================================================== */
(() => {
  "use strict";

  const API = "/api/v1";
  const OPERATOR_KEY = "agentveritas_stellar_admin_key";
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  let runtimeConfig = { billing: { enabled: false, asset_code: "SAC" } };

  /* ------------------------------------------------------------- yardımcılar */

  /** HTML kaçırma. Şablon içine giren HER dış değer bundan geçer. */
  const esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
    );

  /** Sayı biçimlendirme. `null`/`undefined` için en-dash, sıfır için "0". */
  const num = (v, digits = 1) =>
    typeof v === "number" && Number.isFinite(v) ? v.toFixed(digits) : "–";

  /**
   * Skoru renk bandına çevirir. Eşikler backend'deki `BADGE_THRESHOLDS`
   * ile birebir aynı: SAFE ≥ 85, CAUTION ≥ 65, HIGH_RISK ≥ 40, altı BLOCKLIST.
   */
  const band = (score) => {
    if (typeof score !== "number") return "";
    if (score >= 85) return "safe";
    if (score >= 65) return "caution";
    if (score >= 40) return "risk";
    return "block";
  };

  /** Badge adını renk bandına eşler (backend `Badge` enum'u). */
  const badgeBand = (badge) =>
    ({ safe: "safe", caution: "caution", high_risk: "risk", blocklist: "block" }[
      String(badge || "").toLowerCase()
    ] || "");

  /** Uzun hash/adresleri ortadan kısaltır — kopyalanabilir tam hâli title'da. */
  const short = (v, head = 10, tail = 6) => {
    const s = String(v || "");
    return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
  };

  const readOperatorKey = () => {
    try {
      return sessionStorage.getItem(OPERATOR_KEY) || "";
    } catch {
      return "";
    }
  };

  const writeOperatorKey = (value) => {
    try {
      if (value) sessionStorage.setItem(OPERATOR_KEY, value);
      else sessionStorage.removeItem(OPERATOR_KEY);
      return true;
    } catch {
      return false;
    }
  };

  const errorDetail = (data, status) => {
    const detail = data?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (Array.isArray(detail)) {
      return detail.map((item) => item?.msg || JSON.stringify(item)).join("; ");
    }
    if (detail && typeof detail === "object") return JSON.stringify(detail);
    return `HTTP ${status}`;
  };

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    const operatorKey = readOperatorKey();
    if (operatorKey && String(options.method || "GET").toUpperCase() !== "GET") {
      headers.Authorization = `Bearer ${operatorKey}`;
    }
    const res = await fetch(API + path, {
      ...options,
      headers,
    });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { detail: text };
    }
    if (!res.ok) throw new Error(errorDetail(data, res.status));
    return data;
  }

  const operatorInput = $("#in-api-key");
  if (operatorInput) operatorInput.value = readOperatorKey();

  $("#operatorSaveBtn")?.addEventListener("click", () => {
    const saved = writeOperatorKey(operatorInput?.value || "");
    notice(
      $("#runNotice"),
      saved ? "Operatör anahtarı bu sekme için saklandı." : "sessionStorage kullanılamıyor.",
      saved ? "ok" : "error"
    );
  });

  $("#operatorClearBtn")?.addEventListener("click", () => {
    writeOperatorKey("");
    if (operatorInput) operatorInput.value = "";
    notice($("#runNotice"), "Operatör anahtarı bu sekmeden temizlendi.", "ok");
  });

  /* ------------------------------------------------------------ durum mesajı */

  const ICON = {
    ok: '<svg class="notice-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="m3.5 8.5 3 3 6-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    error:
      '<svg class="notice-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 5v4m0 2.5v.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="8" r="6.2" stroke="currentColor" stroke-width="1.4"/></svg>',
    warn:
      '<svg class="notice-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2.8 14.2 13H1.8L8 2.8Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.6v2.6m0 1.9v.4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  };

  /**
   * Durum mesajı yazar. `kind` yalnızca renk değiştirmez; ikon da ekler,
   * böylece renk körlüğü olan kullanıcı için renk tek sinyal olmaz.
   */
  function notice(node, message, kind = "") {
    if (!node) return;
    if (!message) {
      node.textContent = "";
      node.removeAttribute("data-kind");
      return;
    }
    node.dataset.kind = kind || "info";
    node.innerHTML = `${ICON[kind] || ""}<span>${esc(message)}</span>`;
  }

  /** Yükleniyor iskeleti — `rows` kadar gri şerit. */
  const skeleton = (rows = 3) =>
    Array.from({ length: rows }, () => '<div class="skeleton skeleton-row"></div>').join("");

  /**
   * Boş durum: her zaman "ne yapılacağını" söyler. Sadece "veri yok"
   * yazmak kullanıcıyı çıkmaz sokakta bırakır.
   */
  const empty = (title, action) =>
    `<div class="empty"><span class="empty-title">${esc(title)}</span>${
      action ? esc(action) : ""
    }</div>`;

  /** Hata durumu: sebep + yeniden dene. `data-retry` app tarafından bağlanır. */
  const failure = (message, retryId) =>
    `<div class="notice" data-kind="error">${ICON.error}<span>${esc(message)}</span></div>` +
    (retryId
      ? `<div class="btn-row" style="margin-top:var(--space-3)">
           <button type="button" class="btn btn-quiet btn-sm" data-retry="${esc(retryId)}">
             Yeniden dene
           </button>
         </div>`
      : "");

  /**
   * Düğmeyi bekleme durumuna alır ve geri alma fonksiyonu döner.
   * Metin korunur, yanına spinner eklenir: buton genişliği sabit kalır,
   * yerleşim zıplamaz.
   */
  function busy(btn, label) {
    if (!btn) return () => {};
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" aria-hidden="true"></span><span>${esc(
      label || btn.textContent.trim()
    )}</span>`;
    return () => {
      btn.disabled = false;
      btn.innerHTML = original;
    };
  }

  /* ==========================================================================
     Sekmeler — klavye erişimi dahil
     ==========================================================================
     `role="tablist"` sözleşmesi ok tuşlarıyla gezinmeyi zorunlu kılar; yalnızca
     tıklamayı bağlamak ARIA rolünü yanlış beyan etmek olur.
     ========================================================================== */
  const tabs = $$(".segment-item[role=tab]");
  let activeTab = "onchain";

  function selectTab(name, { focus = false } = {}) {
    activeTab = name;
    tabs.forEach((t) => {
      const on = t.dataset.tab === name;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
    });
    $$("[data-pane]").forEach((p) => {
      p.hidden = p.dataset.pane !== name;
    });
  }

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => selectTab(tab.dataset.tab));
    tab.addEventListener("keydown", (e) => {
      const i = tabs.indexOf(tab);
      let next = null;
      if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
      else if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === "Home") next = tabs[0];
      else if (e.key === "End") next = tabs[tabs.length - 1];
      if (next) {
        e.preventDefault();
        selectTab(next.dataset.tab, { focus: true });
      }
    });
  });

  /* ==========================================================================
     ZIP okuma
     ========================================================================== */
  let zipBase64 = "";

  $("#in-zip")?.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) {
      zipBase64 = "";
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    // 32 KB parçalar: `apply` çağrı yığınını taşırmadan base64'e çevirir.
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    zipBase64 = btoa(binary);
    notice(
      $("#runNotice"),
      `${file.name} hazır · ${(file.size / 1024).toFixed(0)} KB`,
      "ok"
    );
  });

  /* ==========================================================================
     Yükleme isteği gövdesi
     ========================================================================== */
  function payload() {
    const fd = new FormData($("#ingestForm"));
    const get = (k) => (fd.get(k) || "").toString().trim();

    const shared = {
      agent_wallet: get("agent_wallet"),
      domain: get("domain"),
      privacy_mode: fd.get("privacy_mode") === "on",
      // Sahiplik imzası backend'de Stellar Ed25519 ile doğrulanır.
      // Geçersiz imza sessizce yok sayılmaz; raporda nedeni yazılır.
      owner: get("owner"),
      owner_signature: get("owner_signature"),
    };

    if (activeTab === "onchain") {
      return { kind: "onchain_address", address: get("address"), agent_contract_id: get("agent_contract_id"), ...shared };
    }
    if (activeTab === "repo") {
      return {
        kind: "repo",
        repo_url: get("repo_url"),
        local_path: get("local_path"),
        zip_base64: zipBase64,
        ...shared,
      };
    }
    if (activeTab === "endpoint") {
      return {
        kind: "endpoint",
        endpoint_url: get("endpoint_url"),
        endpoint_protocol: get("endpoint_protocol") || "http",
        auth_header: get("auth_header"),
        ...shared,
      };
    }
    return {
      kind: "wizard",
      template: get("template"),
      name: get("name"),
      system_prompt: get("system_prompt"),
      capabilities: get("capabilities").split(",").map((s) => s.trim()).filter(Boolean),
      ...shared,
    };
  }

  /* ==========================================================================
     Sahiplik (KYA) — Stellar Ed25519 dış imza akışı
     ========================================================================== */

  /** İmza mesajı bu referansa bağlanır; backend ile aynı öncelik sırası. */
  function agentRef() {
    const fd = new FormData($("#ingestForm"));
    const get = (k) => (fd.get(k) || "").toString().trim();
    return get("agent_wallet") || get("address") || get("agent_contract_id") || get("name");
  }

  async function verifySignature() {
    const owner = $("#in-owner")?.value.trim();
    const signature = $("#in-signature")?.value.trim();
    const node = $("#ownerNotice");
    if (!owner || !signature) {
      return notice(node, "Sahip adresi ve imza gerekli.", "error");
    }
    try {
      const res = await api("/ownership/verify", {
        method: "POST",
        body: JSON.stringify({ agent_ref: agentRef(), owner, signature }),
      });
      notice(node, res.evidence, res.verified ? "ok" : "error");
    } catch (err) {
      notice(node, `Doğrulanamadı: ${err.message}`, "error");
    }
  }

  $("#signBtn")?.addEventListener("click", async (e) => {
    const node = $("#ownerNotice");
    const owner = $("#in-owner")?.value.trim();
    const ref = agentRef();

    if (!owner) return notice(node, "Önce sahip cüzdan adresini girin.", "error");
    if (!ref) return notice(node, "Önce agent cüzdanı, adresi veya adı girin.", "error");
    const done = busy(e.currentTarget, "Hazırlanıyor");
    try {
      const { message } = await api(
        `/ownership/message?agent_ref=${encodeURIComponent(ref)}&owner=${encodeURIComponent(owner)}`
      );
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(message);
        notice(node, "Ağ-bağlı mesaj panoya kopyalandı. SEP-53 uyumlu G-account signer ile imzalayıp base64 imzayı yapıştırın.", "ok");
      } else {
        notice(node, `Dış signer ile imzalanacak mesaj: ${message}`, "warn");
      }
    } catch (err) {
      notice(node, `Mesaj hazırlanamadı: ${err.message}`, "error");
    } finally {
      done();
    }
  });

  $("#verifyBtn")?.addEventListener("click", verifySignature);

  /* ==========================================================================
     Denetim akışı
     ========================================================================== */
  async function runAudit(body, tier, btn) {
    const node = $("#runNotice");
    const done = busy(btn || $("#runBtn"), "Denetleniyor");
    try {
      const operatorKey = $("#in-api-key")?.value || "";
      if (operatorKey) writeOperatorKey(operatorKey);
      notice(node, "Ajan yükleniyor ve normalize ediliyor…");
      const agent = await api("/agents/ingest", { method: "POST", body: JSON.stringify(body) });

      notice(
        node,
        `“${agent.name}” alındı · ${agent.code_files} dosya · ${agent.tools.length} araç · ` +
          `7 denetçi paralel çalışıyor…`
      );

      const job = await api("/jobs", {
        method: "POST",
        body: JSON.stringify({ agent_id: agent.agent_id, tier, auto_run: true }),
      });
      if (job.state === "failed") throw new Error(job.error || "denetim başarısız");

      renderReport(agent, job);
      const r = job.report;
      notice(
        node,
        `${String(r.badge).toUpperCase()} · ${num(r.overall_score)}/100 · ${r.duration_ms} ms`,
        badgeBand(r.badge) === "safe" ? "ok" : "warn"
      );
      loadStats();
      loadLeaderboard();
      loadBadges();
      loadJobs();
      const monitorAgent = $("#monitor-agent-id");
      if (monitorAgent) monitorAgent.value = agent.agent_id;
    } catch (err) {
      notice(node, `Hata: ${err.message}`, "error");
    } finally {
      done();
    }
  }

  $("#ingestForm")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const tier = (new FormData(e.target).get("tier") || "basic").toString();
    runAudit(payload(), tier);
  });

  // Örnek düğmeleri: korpus ajanları `deep` koşar, çünkü ayrım gücü LLM ve
  // saldırı süiti açıkken görünür.
  $$("[data-demo]").forEach((btn) =>
    btn.addEventListener("click", () =>
      runAudit({ kind: "repo", local_path: `./examples/${btn.dataset.demo}` }, "deep", btn)
    )
  );

  /* ==========================================================================
     Rapor
     ========================================================================== */

  /**
   * Skor çemberi. `conic-gradient` yerine SVG: kenarlar pürüzsüz ve
   * `stroke-dashoffset` geçişi tek özellik üzerinden akıcı animasyon verir.
   * R=44 → çevre 2πr ≈ 276.5.
   */
  const CIRCUMFERENCE = 2 * Math.PI * 44;

  function scoreRing(score) {
    const pct = Math.max(0, Math.min(100, score || 0)) / 100;
    const offset = CIRCUMFERENCE * (1 - pct);
    return `
      <div class="score" role="img" aria-label="Güven skoru ${num(score)} / 100">
        <svg width="104" height="104" viewBox="0 0 104 104" aria-hidden="true">
          <circle class="score-track" cx="52" cy="52" r="44" fill="none" stroke-width="7" />
          <circle class="score-ring-value" data-band="${band(score)}" cx="52" cy="52" r="44"
                  fill="none" stroke-width="7"
                  stroke-dasharray="${CIRCUMFERENCE.toFixed(1)}"
                  stroke-dashoffset="${offset.toFixed(1)}" />
        </svg>
        <div class="score-label">
          <span class="score-value">${num(score)}</span>
          <span class="score-max">/ 100</span>
        </div>
      </div>`;
  }

  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  function renderDims(list) {
    return (list || [])
      .map(
        (d) => `
        <div class="dim">
          <span class="dim-label">${esc(d.dimension)}
            <span class="dim-weight">${(d.weight * 100).toFixed(0)}%</span>
          </span>
          <span class="dim-track">
            <span class="dim-fill" data-band="${band(d.score)}"
                  style="width:${Math.max(0, Math.min(100, d.score))}%"></span>
          </span>
          <span class="dim-value">${num(d.score)}</span>
        </div>`
      )
      .join("");
  }

  function renderFindings(list) {
    return (list || [])
      .slice()
      .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
      .map((f) => {
        const grade = String(f.evidence_grade || "confirmed").toLowerCase();
        return `
        <article class="finding" data-sev="${esc(f.severity)}">
          <div class="finding-head">
            <h3 class="finding-title">${esc(f.title)}</h3>
            <span class="tag" data-sev="${esc(f.severity)}">${esc(f.severity)}</span>
            <span class="tag" data-grade="${esc(grade)}">${esc(grade)}</span>
            <span class="tag">${esc(f.dimension)}</span>
            <span class="tag">güven ${(f.confidence * 100).toFixed(0)}%</span>
          </div>
          <p class="finding-detail">${esc(f.detail)}</p>
          ${f.evidence ? `<p class="finding-evidence mono">${esc(f.evidence)}</p>` : ""}
          ${f.remediation ? `<p class="finding-fix">→ ${esc(f.remediation)}</p>` : ""}
        </article>`;
      })
      .join("");
  }

  function renderReport(agent, job) {
    const r = job.report;
    const att = r.attestation || {};
    const escrow = job.escrow || {};
    const counts = r.severity_counts || {};
    const billing = runtimeConfig.billing || {};
    const asset = billing.asset_code || "SAC";
    const escrowFacts = billing.enabled && escrow.mode !== "not_required"
      ? `<span>escrow <b>${num(escrow.amount_usdc, 3)} ${esc(asset)}</b></span>
         <span>ücret <b>${num(escrow.platform_fee_usdc, 3)} ${esc(asset)}</b></span>
         <span>swarm <b>${num(escrow.swarm_payout_usdc, 3)} ${esc(asset)}</b></span>`
      : '<span>ödeme <b>çekirdek akışta yok</b></span>';

    const sevChips = SEV_ORDER.filter((s) => counts[s])
      .map((s) => {
        const state = { critical: "danger", high: "warn", medium: "warn" }[s] || "";
        return `<span class="chip" data-state="${state}"><span class="chip-dot"></span>${esc(
          s
        )} ${counts[s]}</span>`;
      })
      .join("");

    const auditors = (r.auditors || [])
      .map(
        (a) => `
        <tr>
          <td class="cell-primary">${esc(a.auditor)}</td>
          <td>${esc(a.dimension)}</td>
          <td class="num">${num(a.score)}</td>
          <td class="num">${
            a.scenarios?.length
              ? `${a.scenarios.filter((s) => s.passed).length}/${a.scenarios.length}`
              : "–"
          }</td>
          <td>${a.llm_assisted ? "LLM" : "sezgisel"}</td>
          <td class="num">${a.duration_ms} ms</td>
        </tr>`
      )
      .join("");

    const notes = (r.judge_notes || []).map((n) => `<li>${esc(n)}</li>`).join("");

    $("#reportRoot").innerHTML = `
      <div class="verdict">
        ${scoreRing(r.overall_score)}
        <div class="verdict-body">
          <span class="badge" data-band="${badgeBand(r.badge)}">${esc(r.badge)}</span>
          <h3 class="verdict-name">${esc(agent.name)}</h3>
          <p class="verdict-sub">${esc(agent.source_kind)} · ${esc(job.tier)} seviye</p>
          <div class="verdict-facts">
            <span>uzlaşmazlık σ <b>${num(r.disagreement_index)}</b></span>
            <span>süre <b>${r.duration_ms} ms</b></span>
            ${escrowFacts}
            <span>attestation <b>${esc(att.mode || "–")}</b></span>
          </div>
        </div>
      </div>

      <div class="dims">${renderDims(r.dimension_scores)}</div>

      <div class="btn-row">${
        sevChips ||
        '<span class="chip" data-state="ok"><span class="chip-dot"></span>bulgu yok</span>'
      }</div>

      <div class="finding-list">${renderFindings(r.findings)}</div>

      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Denetçi</th><th>Boyut</th><th class="num">Skor</th>
              <th class="num">Senaryo</th><th>Mod</th><th class="num">Süre</th>
            </tr>
          </thead>
          <tbody>${auditors}</tbody>
        </table>
      </div>

      ${notes ? `<ul class="note-list">${notes}</ul>` : ""}

      <div class="link-row">
        <a href="${API}/jobs/${encodeURIComponent(job.id)}/report.md"
           target="_blank" rel="noopener">Markdown rapor</a>
        <a href="${API}/jobs/${encodeURIComponent(job.id)}/report.json"
           target="_blank" rel="noopener">JSON rapor</a>
        ${
          r.report_uri && /^https:\/\//.test(r.report_uri)
            ? `<a href="${esc(r.report_uri)}" target="_blank" rel="noopener"
                  title="${esc(r.report_cid)}">IPFS ${esc(short(r.report_cid, 8, 6))}</a>`
            : r.report_cid
            ? `<span class="mono" title="${esc(r.report_uri)}">yerel CAS ${esc(
                short(r.report_cid, 8, 6)
              )}</span>`
            : ""
        }
      </div>

      <details class="raw">
        <summary>Ham job verisi</summary>
        <pre class="mono">${esc(JSON.stringify(job, null, 2))}</pre>
      </details>`;

    const card = $("#reportCard");
    card.hidden = false;
    card.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
  }

  /* ==========================================================================
     Paneller
     ==========================================================================
     Her panel `loader()` sarmalayıcısından geçer: yükleniyor → içerik veya
     hata + yeniden dene. Hiçbir panel sessizce boş kalmaz.
     ========================================================================== */

  /** Kayıtlı yükleyiciler; "Yeniden dene" düğmesi buradan çağırır. */
  const loaders = {};

  /**
   * @param {string} id          panel kökünün id'si (retry anahtarı)
   * @param {Function} fetcher   veri getiren async fonksiyon
   * @param {Function} render    veriyi HTML'e çeviren fonksiyon
   * @param {number} skeletonRows iskelet satır sayısı
   */
  function loader(id, fetcher, render, skeletonRows = 3) {
    const run = async () => {
      const host = document.getElementById(id);
      if (!host) return;
      host.innerHTML = skeleton(skeletonRows);
      host.setAttribute("aria-busy", "true");
      try {
        host.innerHTML = render(await fetcher());
      } catch (err) {
        host.innerHTML = failure(err.message, id);
      } finally {
        host.removeAttribute("aria-busy");
      }
    };
    loaders[id] = run;
    return run;
  }

  // Tek delege dinleyici: dinamik olarak basılan her "Yeniden dene" çalışır.
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-retry]");
    if (btn) loaders[btn.dataset.retry]?.();
  });

  /* --------------------------------------------------------------- istatistik */
  const loadStats = loader(
    "statGrid",
    () => api("/stats"),
    (s) =>
      [
        ["Denetim", s.completed_audits],
        ["Ajan", s.agents],
        ["Ort. skor", num(s.avg_score)],
        ["Aktif izleme", s.active_monitors],
      ]
        .map(
          ([label, value]) =>
            `<div class="stat"><span class="stat-value">${esc(
              value
            )}</span><span class="stat-label">${esc(label)}</span></div>`
        )
        .join(""),
    4
  );

  /* ------------------------------------------------------------------- swarm */
  const loadLeaderboard = loader(
    "leaderboardRoot",
    () => api("/swarm/leaderboard"),
    (d) => {
      const rows = d.swarm || [];
      if (!rows.length) {
        return empty(
          "Henüz denetim yok",
          "Bir örnek ajanı denetleyin; simülasyon stake'i ve ELO geçmişi burada görünür."
        );
      }
      return `
        <div class="table-scroll">
          <table>
            <thead>
              <tr><th>Denetçi</th><th class="num">ELO</th><th class="num">Stake (sim.)</th>
                  <th class="num">Denetim</th><th class="num">Kazanç (sim.)</th><th class="num">Slash (sim.)</th></tr>
            </thead>
            <tbody>
              ${rows
                .map(
                  (s) => `<tr>
                    <td><span class="cell-primary">${esc(s.name)}</span>
                        <span class="cell-sub">${esc(s.dimension)}</span></td>
                    <td class="num">${s.elo}</td>
                    <td class="num">${num(s.stake_usdc, 2)}</td>
                    <td class="num">${s.audits}</td>
                    <td class="num">${num(s.earned_usdc, 3)}</td>
                    <td class="num">${num(s.slashed_usdc, 3)}</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`;
    },
    2
  );

  /* ---------------------------------------------------------------- rozetler */
  const loadBadges = loader(
    "badgeRoot",
    () => api("/badges"),
    (d) => {
      const rows = d.badges || [];
      if (!rows.length) {
        return empty(
          "Henüz rozet basılmadı",
          "Rozet denetim tamamlandığında offchain üretilir; confirmed alanı registry kanıt sınırını gösterir."
        );
      }
      return `
        <div class="table-scroll">
          <table>
            <thead>
              <tr><th>Ajan</th><th>Rozet</th><th class="num">Skor</th><th>Rapor</th></tr>
            </thead>
            <tbody>
              ${rows
                .map(
                  (b) => `<tr>
                    <td><span class="cell-primary">${esc(b.agent_name)}</span>
                        <span class="cell-sub mono">${esc(short(b.account || b.agent_contract_id || b.agent_id))}</span></td>
                    <td><span class="badge" data-band="${badgeBand(b.badge)}">${esc(
                    b.badge
                  )}</span></td>
                    <td class="num">${num(b.score)}</td>
                    <td class="mono" title="${esc(b.report_cid || "")}">${esc(
                    short(b.report_cid || "–", 10, 4)
                  )}</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`;
    },
    1
  );

  /* ------------------------------------------------------------ zincir durumu */
  const loadChain = loader(
    "chainRoot",
    () => api("/chain/status"),
    (s) => {
      const net = s.network || {};
      const rpc = s.rpc || {};

      const row = (key, value) =>
        `<div class="kv-row"><span class="kv-key">${esc(key)}</span>
         <span class="kv-val">${value}</span></div>`;

      const contracts = Object.entries(s.contracts || {})
        .map(
          ([name, c]) => `<tr>
            <td class="cell-primary">${esc(name)}</td>
            <td class="mono">${
              c.explorer_url
                ? `<a href="${esc(c.explorer_url)}" target="_blank" rel="noopener"
                      title="${esc(c.contract_id)}">${esc(short(c.contract_id))}</a>`
                : esc(short(c.contract_id || "tanımsız"))
            }</td>
            <td>${
              c.onchain_verified
                ? '<span class="chip" data-state="ok"><span class="chip-dot"></span>doğrulandı</span>'
                : c.configured
                ? '<span class="chip" data-state="warn"><span class="chip-dot"></span>yalnız yapılandırıldı</span>'
                : '<span class="chip" data-state="warn"><span class="chip-dot"></span>tanımsız</span>'
            }</td>
          </tr>`
        )
        .join("");

      const blockers = (s.blockers || []).map((b) => `<li>${esc(b)}</li>`).join("");

      return `
        <div class="kv-list">
          ${row("Ağ", `${esc(net.name || "–")} · ${esc(net.key || "–")}`)}
          ${row("Network passphrase", `<span class="mono">${esc(short(net.passphrase || "–", 18, 8))}</span>`)}
          ${row(
            "RPC",
            rpc.reachable
              ? `bağlı · ledger ${esc(rpc.latest_ledger ?? "–")}`
              : `<span style="color:var(--block-text)">bağlı değil${
                  rpc.error ? ` — ${esc(rpc.error)}` : ""
                }</span>`
          )}
          ${row(
            "Validation hazırlığı",
            s.validation_ready
              ? '<span class="chip" data-state="warn"><span class="chip-dot"></span>dış imza bekler</span>'
              : '<span class="chip" data-state="warn"><span class="chip-dot"></span>eksik yapılandırma</span>'
          )}
          ${row("Backend signer", s.submission?.backend_signing ? "açık" : "kapalı (güvenlik sınırı)")}
          ${row("Event deposu", `${esc(s.event_ingestion?.events ?? 0)} event · ${esc(s.event_ingestion?.streams ?? 0)} cursor`)}
        </div>
        ${blockers ? `<ul class="note-list" style="margin-top:var(--space-4)">${blockers}</ul>` : ""}
        ${
          contracts
            ? `<div class="table-scroll" style="margin-top:var(--space-4)">
                 <table>
                   <thead><tr><th>Kontrat</th><th>ID</th><th>Kanıt</th></tr></thead>
                   <tbody>${contracts}</tbody>
                 </table>
               </div>`
            : ""
        }
        <p class="card-note" style="margin-top:var(--space-4)">
          Contract ID yapılandırılması deployment kanıtı değildir. Başarı için RPC transaction sonucu
          ve beklenen registry state/event birlikte geri okunmalıdır.
        </p>`;
    }
  );

  /* -------------------------------------------------------------- attestation */
  const loadAttestations = loader(
    "attestationRoot",
    () => api("/chain/attestations?limit=10"),
    (d) => {
      if (!d.count) {
        return empty(
          "Zincirde henüz attestation yok",
          d.error
            ? `Registry okunamadı: ${d.error}`
            : d.note || "Önce doğrulanmış registry event ingestion çalıştırın."
        );
      }
      return `
        <p class="card-note">
          ValidationRegistry
          ${
            d.explorer_url
              ? `<a href="${esc(d.explorer_url)}" target="_blank" rel="noopener"
                    title="${esc(d.registry)}">${esc(short(d.registry))}</a>`
              : `<span class="mono">${esc(short(d.registry))}</span>`
          }
          · ${d.count} kayıt zincirden geri okundu
        </p>
        <div class="table-scroll" style="margin-top:var(--space-4)">
          <table>
            <thead>
              <tr><th class="num">#</th><th>requestHash</th>
                  <th class="num">Skor</th><th>Rapor CID</th></tr>
            </thead>
            <tbody>
              ${(d.entries || [])
                .map(
                  (e) => `<tr>
                    <td class="num">${e.index}</td>
                    <td class="mono" title="${esc(e.request_hash)}">${esc(
                    short(e.request_hash, 12, 6)
                  )}</td>
                    <td class="num">
                      <span class="badge" data-band="${band(e.score)}">${e.score}</span>
                    </td>
                    <td class="mono" title="${esc(e.report_uri || "")}">${esc(
                    short(e.report_uri || "–", 10, 8)
                  )}</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`;
    },
    2
  );

  /* ------------------------------------------------------------------ escrow */
  const loadEscrow = loader(
    "escrowRoot",
    () => api("/chain/escrow"),
    (d) => {
      if (d.error) {
        throw new Error(d.error);
      }
      const configured = Boolean(d.contract_id && d.sac_contract_id);
      const contractValue = (value) =>
        value ? `<span class="mono" title="${esc(value)}">${esc(short(value, 12, 8))}</span>` : "tanımsız";

      const row = (k, v) =>
        `<div class="kv-row"><span class="kv-key">${esc(k)}</span>
         <span class="kv-val">${v}</span></div>`;

      return `
        <p class="card-note">
          Escrow doğrulama çekirdeğinden bağımsızdır. Etkinleştirilirse SEP-41 Stellar Asset
          Contract client kullanır; backend yine imzalama veya settlement yapmaz.
        </p>
        <div class="btn-row">
          <span class="chip" data-state="accent">mod: ${esc(d.mode)}</span>
          <span class="chip" data-state="${configured ? "warn" : "accent"}"><span class="chip-dot"></span>${
            configured ? "yapılandırıldı; zincir kanıtı bekleniyor" : "çekirdek ödeme gerektirmez"
          }</span>
        </div>
        <div class="kv-list">
          ${row("AuditEscrow", contractValue(d.contract_id))}
          ${row("SAC", contractValue(d.sac_contract_id))}
          ${row("Backend signer", d.backend_signing ? "açık" : "kapalı")}
          ${row("Onchain confirmed", d.confirmed ? "evet" : "hayır")}
          ${row("Kanıt notu", esc(d.note || "–"))}
        </div>`;
    },
    2
  );

  /* ==========================================================================
     Sistem durumu (selftest)
     ========================================================================== */
  const STATE_ICON = { ok: "✓", warn: "!", fail: "✕" };

  async function runSelfTest(deep) {
    const host = $("#selftestRoot");
    const btn = deep ? $("#selftestDeepBtn") : $("#selftestBtn");
    if (!host) return;

    const done = busy(btn, deep ? "Koşuluyor" : "Test");
    host.setAttribute("aria-busy", "true");
    host.innerHTML = skeleton(deep ? 5 : 3);

    try {
      if (deep) {
        const operatorKey = $("#in-api-key")?.value || "";
        if (operatorKey) sessionStorage.setItem("agentveritas_stellar_admin_key", operatorKey);
      }
      const d = await api(deep ? "/selftest/deep" : "/selftest", deep ? { method: "POST" } : {});
      const s = d.summary || {};

      // Genel karar: yalnızca `fail` varsa kırmızı. Kapalı entegrasyon sarı.
      const verdict = !d.ok
        ? `<span class="chip" data-state="danger"><span class="chip-dot"></span>${s.fail} arıza</span>`
        : s.warn
        ? `<span class="chip" data-state="ok"><span class="chip-dot"></span>çalışıyor</span>
           <span class="chip" data-state="warn"><span class="chip-dot"></span>${s.warn} kapalı</span>`
        : `<span class="chip" data-state="ok"><span class="chip-dot"></span>her şey açık</span>`;

      host.innerHTML = `
        <div class="btn-row">
          ${verdict}
          <span class="chip">${s.ok} ok</span>
          <span class="chip">${d.duration_ms} ms</span>
          ${d.deep ? '<span class="chip" data-state="accent">derin</span>' : ""}
        </div>
        <div class="status-list" style="margin-top:var(--space-4)">
          ${(d.checks || [])
            .map(
              (c) => `
            <div class="status-row" data-state="${esc(c.state)}">
              <span class="status-icon" aria-hidden="true">${STATE_ICON[c.state] || "?"}</span>
              <span class="status-name">${esc(c.name)}</span>
              <span class="status-detail">${esc(c.detail)}
                ${c.hint ? `<span class="status-hint">${esc(c.hint)}</span>` : ""}
              </span>
            </div>`
            )
            .join("")}
        </div>`;
    } catch (err) {
      host.innerHTML = failure(`Test çalıştırılamadı: ${err.message}`, "selftestRoot");
    } finally {
      host.removeAttribute("aria-busy");
      done();
    }
  }

  // "Yeniden dene" için kaydet (hata durumundaki düğme bunu çağırır).
  loaders.selftestRoot = () => runSelfTest(false);

  $("#selftestBtn")?.addEventListener("click", () => runSelfTest(false));
  $("#selftestDeepBtn")?.addEventListener("click", () => runSelfTest(true));

  /* ==========================================================================
     Üst şerit: çalışma modları + kanıt kaynakları
     ==========================================================================
     Bu iki şerit farklı soruları yanıtlar ve kasıtlı olarak ayrıdır:
       modeStrip     → "sistem hangi modda çalışıyor?"
       evidenceStrip → "skor ne kadar sağlam kanıta dayanıyor?"
     Kapalı bir kanıt kaynağı arıza değil, kapsam daralmasıdır (sarı).
     ========================================================================== */
  async function renderTopStrips() {
    const modeHost = $("#modeStrip");
    const evHost = $("#evidenceStrip");

    const chip = (label, state, title) =>
      `<span class="chip"${state ? ` data-state="${state}"` : ""}${
        title ? ` title="${esc(title)}"` : ""
      }><span class="chip-dot"></span>${esc(label)}</span>`;

    let health;
    try {
      health = await api("/health");
    } catch {
      if (modeHost) modeHost.innerHTML = chip("API erişilemiyor", "danger");
      return;
    }

    const m = health.modes || {};
    const netName = health.network?.name || "ağ yok";

    if (modeHost) {
      modeHost.innerHTML = [
        chip(netName, health.network?.is_testnet ? "accent" : "warn"),
        chip("LLM", m.llm ? "ok" : "warn", m.llm ? "" : "kapalı — yalnızca sezgisel analiz"),
        chip("RPC", m.rpc ? "ok" : "warn"),
        chip("Backend signer kapalı", m.contract_submission ? "danger" : "ok", "Dış imza güvenlik sınırı"),
        chip("IPFS", m.ipfs ? "ok" : "warn", m.ipfs ? "" : "kapalı — rapor pinlenmez"),
      ].join("");
    }

    if (!evHost) return;

    const chips = (health.integrations || []).map((it) =>
      chip(
        it.value || it.key,
        it.enabled ? "ok" : "warn",
        it.enabled ? it.unlocks : `kapalı → ${it.fallback}`
      )
    );

    // OFAC ayrı bir uçtan gelir; adres sayısı ve tazelik kanıt gücünü belirler.
    try {
      const s = await api("/compliance/sanctions");
      if (!s.enabled) {
        chips.push(chip("OFAC kapalı", "warn", "yaptırım kontrolü yapılmıyor"));
      } else if (!s.available) {
        chips.push(
          chip("OFAC önbellek yok", "warn", "backend.cli sanctions --refresh çalıştırın")
        );
      } else {
        chips.push(
          chip(
            `OFAC ${s.total_addresses}`,
            s.fresh ? "ok" : "warn",
            s.fresh
              ? `${s.publisher} · güncel`
              : `önbellek ${s.max_age_hours} saatten eski — yenileyin`
          )
        );
      }
    } catch {
      /* uyum ucu yoksa şerit yine anlamlı kalır */
    }

    evHost.innerHTML = chips.join("");
  }

  /* ==========================================================================
     Başlangıç
     ==========================================================================
     Paneller paralel yüklenir: biri yavaş olduğunda diğerleri beklemez.
     ========================================================================== */
  async function bootstrap() {
    selectTab("onchain");

    renderTopStrips();
    loadStats();
    loadChain();
    loadAttestations();
    loadEscrow();
    loadLeaderboard();
    loadBadges();
    runSelfTest(false);

    // Şablon listesi ve fiyatlar: fiyat kaynağı kontrat, `.env` yalnızca tahmin.
    try {
      const cfg = await api("/config");
      const select = $("#in-template");
      (cfg.templates || []).forEach((t) => {
        const opt = document.createElement("option");
        opt.value = t.key || t.id || t.name;
        opt.textContent = t.name || t.key;
        select?.appendChild(opt);
      });
      $("#footerMeta").textContent =
        `basic ${cfg.pricing.basic_usdc} · deep ${cfg.pricing.deep_usdc} USDC · ` +
        `ücret %${(cfg.pricing.platform_fee_bps / 100).toFixed(1)}`;
    } catch {
      /* config yoksa şablon sekmesi boş kalır, geri kalan çalışır */
    }
  }

  bootstrap();
})();

