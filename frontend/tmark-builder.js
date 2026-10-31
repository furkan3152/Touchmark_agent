"use strict";
/* The .tmark builder on /guide/tmark, and a client-side copy of the .tmark v1 (1.1) rules.
 *
 * TmarkRules.validate(obj) → [{ path, msg }] mirrors backend/app/services/tmark.py: the same
 * fields, limits, cross-field rules and wording ("agent.purpose: String should have at least 20
 * characters"), including Stellar address checksums. The server stays the authority: the
 * "Check with Touchmark" button posts the file to POST /api/v1/tmark/check ({ text }).
 *
 * Hooks for other pages:
 *   window.TmarkRules  { validate(obj), check(text), minorFeatures(obj), isAccount(value, prefix), EXAMPLES }
 *   window.TmarkBuilder { load(objOrText), get(), text() }  (only on the builder page)
 *   the builder root (#tmark-builder) dispatches "tmark:change" with { text, valid, errors }.
 *
 * Hand-offs between pages (sessionStorage, same origin, cleared once read):
 *   "touchmark.tmark.toBuilder"  text the home page sends to the builder (/guide/tmark#builder)
 *   "touchmark.tmark.toAudit"    text the builder sends back to the home page audit (/#declare)
 */
(() => {
  const SCHEMA_URL = "https://touchmark-stellar.vercel.app/schemas/tmark-v1.json";

  // ------------------------------------------------------------ StrKey
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function crc16(bytes) {
    let crc = 0;
    for (const b of bytes) {
      crc ^= b << 8;
      for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    return crc;
  }
  /** A checksummed Stellar address: G (ed25519 public key) or C (contract). */
  function isAccount(value, prefix = "G") {
    if (typeof value !== "string" || value.length !== 56 || value[0] !== prefix) return false;
    const version = { G: 6 << 3, C: 2 << 3 }[prefix];
    if (version === undefined) return false;
    let bits = 0, acc = 0;
    const out = [];
    for (const ch of value) {
      const v = B32.indexOf(ch);
      if (v < 0) return false;
      acc = (acc << 5) | v; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    if (out.length !== 35 || out[0] !== version) return false;
    if (bits && (acc & ((1 << bits) - 1))) return false;
    const sum = crc16(out.slice(0, 33));
    return out[33] === (sum & 0xff) && out[34] === (sum >> 8);
  }

  // ------------------------------------------------------------ rules
  const AMOUNT = /^(?:0|[1-9]\d{0,11})(?:\.\d{1,7})?$/;
  const ASSET = /^(?:XLM|native|[A-Za-z0-9]{1,12}:G[A-Z2-7]{55}|C[A-Z2-7]{55})$/;
  const KINDS = ["mcp_server", "autonomous_agent", "x402_client", "x402_server", "sdk", "skill", "contract", "other"];
  const SIGNS = ["payments", "contract_calls", "account_changes", "trustlines", "foreign_transactions", "messages"];
  const KEY_SOURCES = ["env", "kms", "external_signer", "wallet_prompt", "none", "caller_supplied", "agent_generated"];
  const KEY_SOURCES_1_1 = ["caller_supplied", "agent_generated"];
  const VERSIONS = ["1", "1.1"];
  const GENERATED_PATTERN = "^[A-Za-z0-9_.:*?\\[\\]{}-]+$";
  const literal = (opts) => "Input should be " + (opts.length === 1 ? `'${opts[0]}'`
    : opts.slice(0, -1).map((o) => `'${o}'`).join(", ") + ` or '${opts[opts.length - 1]}'`);
  const TRUE = new Set(["true", "1", "yes", "y", "on", "t"]), FALSE = new Set(["false", "0", "no", "n", "off", "f"]);
  const isTrue = (v) => v === true || v === 1 || (typeof v === "string" && TRUE.has(v.trim().toLowerCase()));

  /** The 1.1 fields and values a declaration uses (services/tmark.py Tmark.minor_features). */
  function minorFeatures(raw) {
    const used = [];
    if (!raw || typeof raw !== "object") return used;
    const src = raw.authority && typeof raw.authority.key_source === "string" ? raw.authority.key_source.trim() : "";
    if (KEY_SOURCES_1_1.includes(src)) used.push(`authority.key_source ${src}`);
    const tools = Array.isArray(raw.tools) ? raw.tools : [];
    tools.forEach((t, i) => { if (t && isTrue(t.executes_code)) used.push(`tools.${i}.executes_code`); });
    tools.forEach((t, i) => { if (t && t.generated !== undefined && t.generated !== null) used.push(`tools.${i}.generated`); });
    return used;
  }

  /** Validate a parsed .tmark object. Returns [{ path, msg }], at most 20, like the server. */
  function validate(raw) {
    const errors = [];
    const add = (path, msg) => errors.push({ path: path || "(file)", msg });
    const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

    // Each check returns true when the value is valid (so model-level rules may run).
    function str(v, path, { min = 0, max = Infinity, pattern = null } = {}) {
      if (typeof v !== "string") { add(path, "Input should be a valid string"); return false; }
      const s = v.trim();
      if (s.length < min) { add(path, `String should have at least ${min} character${min === 1 ? "" : "s"}`); return false; }
      if (s.length > max) { add(path, `String should have at most ${max} character${max === 1 ? "" : "s"}`); return false; }
      if (pattern && !new RegExp(pattern).test(s)) { add(path, `String should match pattern '${pattern}'`); return false; }
      return true;
    }
    function bool(v, path) {
      if (typeof v === "boolean" || v === 0 || v === 1) return true;
      if (typeof v === "string" && (TRUE.has(v.trim().toLowerCase()) || FALSE.has(v.trim().toLowerCase()))) return true;
      // pydantic: a string or number it cannot read says so; other types do not.
      add(path, typeof v === "string" || typeof v === "number" ? "Input should be a valid boolean, unable to interpret input" : "Input should be a valid boolean");
      return false;
    }
    const asBool = isTrue;
    function lit(v, path, opts) {
      if (typeof v === "string" && opts.includes(v.trim())) return true;
      add(path, literal(opts)); return false;
    }
    function fields(obj, path, allowed, required) {
      let ok = true;
      for (const k of Object.keys(obj)) if (!allowed.includes(k)) { add(path ? `${path}.${k}` : k, "unknown field; see the .tmark schema for allowed fields"); ok = false; }
      for (const k of required) if (!(k in obj)) { add(path ? `${path}.${k}` : k, "required"); ok = false; }
      return ok;
    }
    function object(v, path, model) {
      if (!isObj(v)) { add(path, `Input should be a valid dictionary or instance of ${model}`); return false; }
      return true;
    }
    function list(v, path, max) {
      if (!Array.isArray(v)) { add(path, "Input should be a valid list"); return false; }
      if (v.length > max) { add(path, `List should have at most ${max} item${max === 1 ? "" : "s"} after validation, not ${v.length}`); return false; }
      return true;
    }
    function account(v, path, prefix) {
      if (!str(v, path)) return false;
      const s = v.trim();
      const p = prefix || s.slice(0, 1);
      if (!isAccount(s, p)) { add(path, `must be a valid Stellar ${p}... address (checksum included)`); return false; }
      return true;
    }
    function money(v, path) {
      if (v === null) return true;
      if (!object(v, path, "Money")) return false;
      let ok = fields(v, path, ["amount", "asset"], ["amount", "asset"]);
      if ("amount" in v && str(v.amount, `${path}.amount`)) {
        const a = v.amount.trim();
        if (!AMOUNT.test(a) || Number(a) <= 0) { add(`${path}.amount`, "must be a positive decimal string with at most 7 decimal places, e.g. \"25\""); ok = false; }
      } else if ("amount" in v) ok = false;
      if ("asset" in v && str(v.asset, `${path}.asset`)) {
        const a = v.asset.trim();
        if (!ASSET.test(a)) { add(`${path}.asset`, "must be XLM, CODE:ISSUER (G... issuer) or a C... token contract"); ok = false; }
        else if (a.includes(":") && !isAccount(a.split(":")[1], "G")) { add(`${path}.asset`, "must be a valid Stellar G... address (checksum included)"); ok = false; }
        else if (a.startsWith("C") && !isAccount(a, "C")) { add(`${path}.asset`, "must be a valid Stellar C... address (checksum included)"); ok = false; }
      } else if ("asset" in v) ok = false;
      return ok;
    }

    if (!isObj(raw)) { add("(file)", "the file must be one JSON object"); return errors; }
    let fileOk = fields(raw, "", ["$schema", "tmark", "agent", "owner", "authority", "limits", "tools", "forbidden", "entrypoints", "contact"], ["tmark", "agent", "authority"]);
    if ("$schema" in raw && !str(raw.$schema, "$schema")) fileOk = false;
    // A literal: matched exactly, not trimmed.
    if ("tmark" in raw && !VERSIONS.includes(raw.tmark)) { add("tmark", literal(VERSIONS)); fileOk = false; }

    // agent
    const ag = raw.agent;
    if ("agent" in raw && object(ag, "agent", "Agent")) {
      let ok = fields(ag, "agent", ["name", "purpose", "kind", "network", "discloses_ai"], ["name", "purpose", "kind", "network"]);
      if ("name" in ag) ok = str(ag.name, "agent.name", { min: 2, max: 80 }) && ok;
      if ("purpose" in ag) ok = str(ag.purpose, "agent.purpose", { min: 20, max: 1000 }) && ok;
      if ("kind" in ag) ok = lit(ag.kind, "agent.kind", KINDS) && ok;
      if ("network" in ag) ok = lit(ag.network, "agent.network", ["testnet", "mainnet", "both"]) && ok;
      if ("discloses_ai" in ag) ok = bool(ag.discloses_ai, "agent.discloses_ai") && ok;
      fileOk = ok && fileOk;
    } else if ("agent" in raw) fileOk = false;

    // owner
    if ("owner" in raw && raw.owner !== null) {
      if (object(raw.owner, "owner", "Owner")) {
        let ok = fields(raw.owner, "owner", ["stellar_account"], ["stellar_account"]);
        if ("stellar_account" in raw.owner) ok = account(raw.owner.stellar_account, "owner.stellar_account", "G") && ok;
        fileOk = ok && fileOk;
      } else fileOk = false;
    }

    // authority
    const au = raw.authority;
    let signs = [];
    if ("authority" in raw && object(au, "authority", "Authority")) {
      let ok = fields(au, "authority", ["holds_keys", "key_source", "signs", "agent_account"], ["holds_keys", "key_source"]);
      if ("holds_keys" in au) ok = bool(au.holds_keys, "authority.holds_keys") && ok;
      if ("key_source" in au) ok = lit(au.key_source, "authority.key_source", KEY_SOURCES) && ok;
      if ("signs" in au) {
        if (list(au.signs, "authority.signs", 6)) {
          au.signs.forEach((s, i) => { ok = lit(s, `authority.signs.${i}`, SIGNS) && ok; });
          signs = au.signs;
        } else ok = false;
      }
      if ("agent_account" in au && au.agent_account !== "") ok = account(au.agent_account, "authority.agent_account") && ok;
      if (ok) {
        const holds = asBool(au.holds_keys), src = String(au.key_source).trim();
        if (holds && (src === "none" || src === "wallet_prompt")) { add("authority", "holds_keys is true, so key_source cannot be none or wallet_prompt"); ok = false; }
        else if (!holds && (src === "env" || src === "kms")) { add("authority", "key_source env or kms means the agent holds a key; set holds_keys to true"); ok = false; }
        else if (!holds && src === "agent_generated") { add("authority", "key_source agent_generated means the agent stores a key; set holds_keys to true"); ok = false; }
        else if (new Set(signs).size !== signs.length) { add("authority", "signs lists a value twice"); ok = false; }
      }
      fileOk = ok && fileOk;
    } else if ("authority" in raw) fileOk = false;

    // limits
    const li = raw.limits;
    if ("limits" in raw && li !== null) {
      if (object(li, "limits", "Limits")) {
        let ok = fields(li, "limits", ["per_payment", "per_day", "recipients", "human_approval"], ["recipients", "human_approval"]);
        if ("per_payment" in li) ok = money(li.per_payment, "limits.per_payment") && ok;
        if ("per_day" in li) ok = money(li.per_day, "limits.per_day") && ok;
        if ("recipients" in li) ok = lit(li.recipients, "limits.recipients", ["allowlist", "any", "none"]) && ok;
        if ("human_approval" in li) ok = lit(li.human_approval, "limits.human_approval", ["always", "above_limit", "never"]) && ok;
        fileOk = ok && fileOk;
      } else fileOk = false;
    }

    // tools
    let tools = [];
    if ("tools" in raw) {
      if (list(raw.tools, "tools", 60)) {
        tools = raw.tools;
        tools.forEach((t, i) => {
          const p = `tools.${i}`;
          if (!object(t, p, "Tool")) { fileOk = false; return; }
          let ok = fields(t, p, ["name", "description", "moves_funds", "signs", "network", "files", "executes_code", "generated", "max_amount"], ["name", "description", "moves_funds", "signs", "network"]);
          if ("name" in t) ok = str(t.name, `${p}.name`, { min: 1, max: 80, pattern: "^[A-Za-z0-9_.:-]+$" }) && ok;
          if ("description" in t) ok = str(t.description, `${p}.description`, { min: 8, max: 400 }) && ok;
          for (const k of ["moves_funds", "signs", "network", "files", "executes_code"]) if (k in t) ok = bool(t[k], `${p}.${k}`) && ok;
          // 1.1: a family of tools the code generates at run time.
          if ("generated" in t && t.generated !== null) {
            const g = t.generated, gp = `${p}.generated`;
            if (object(g, gp, "Generated")) {
              let gok = fields(g, gp, ["pattern", "source"], ["pattern", "source"]);
              if ("pattern" in g) gok = str(g.pattern, `${gp}.pattern`, { min: 1, max: 120, pattern: GENERATED_PATTERN }) && gok;
              if ("source" in g) gok = str(g.source, `${gp}.source`, { min: 8, max: 300 }) && gok;
              ok = gok && ok;
            } else ok = false;
          }
          if ("max_amount" in t) ok = money(t.max_amount, `${p}.max_amount`) && ok;
          if (ok && t.max_amount != null && !asBool(t.moves_funds)) { add(p, "max_amount is set but moves_funds is false"); ok = false; }
          fileOk = ok && fileOk;
        });
      } else fileOk = false;
    }

    // forbidden
    if ("forbidden" in raw) {
      if (list(raw.forbidden, "forbidden", 30)) {
        let ok = true;
        raw.forbidden.forEach((f, i) => { ok = str(f, `forbidden.${i}`) && ok; });
        if (ok && raw.forbidden.some((f) => f.trim().length < 8 || f.trim().length > 300)) { add("forbidden", "each forbidden item must be 8 to 300 characters"); ok = false; }
        fileOk = ok && fileOk;
      } else fileOk = false;
    }

    // entrypoints
    if ("entrypoints" in raw) {
      if (list(raw.entrypoints, "entrypoints", 10)) {
        raw.entrypoints.forEach((e, i) => {
          const p = `entrypoints.${i}`;
          if (!object(e, p, "Entrypoint")) { fileOk = false; return; }
          let ok = fields(e, p, ["path", "symbol"], ["path", "symbol"]);
          if ("path" in e && str(e.path, `${p}.path`, { min: 1, max: 160, pattern: "^[A-Za-z0-9_][A-Za-z0-9_./-]*$" })) {
            const s = e.path.trim();
            if (s.split("/").includes("..") || s.includes("//")) { add(`${p}.path`, "must be a relative path inside the repository"); ok = false; }
          } else if ("path" in e) ok = false;
          if ("symbol" in e) ok = str(e.symbol, `${p}.symbol`, { pattern: "^[A-Za-z_][A-Za-z0-9_]{0,79}$" }) && ok;
          fileOk = ok && fileOk;
        });
      } else fileOk = false;
    }

    // contact
    if ("contact" in raw && raw.contact !== null) {
      if (object(raw.contact, "contact", "Contact")) {
        let ok = fields(raw.contact, "contact", ["security"], ["security"]);
        if ("security" in raw.contact) ok = str(raw.contact.security, "contact.security", { min: 5, max: 200 }) && ok;
        fileOk = ok && fileOk;
      } else fileOk = false;
    }

    // Rules across the file run only when every field is valid, as on the server.
    if (fileOk && !errors.length) {
      const pays = signs.includes("payments") || tools.some((t) => asBool(t.moves_funds));
      if (pays && (raw.limits == null)) add("(file)", "the agent moves funds, so limits is required");
      else if (pays && raw.limits.recipients.trim() === "none") add("(file)", "limits.recipients is none but the agent moves funds");
      else if (tools.some((t) => asBool(t.signs)) && !signs.length) add("(file)", "a tool signs, so authority.signs must list what it signs");
      else if (new Set(tools.map((t) => t.name.trim())).size !== tools.length) add("(file)", "two tools have the same name");
      else if (raw.tmark === "1" && minorFeatures(raw).length) add("(file)", `uses .tmark 1.1 fields (${minorFeatures(raw).join(", ")}); set "tmark": "1.1"`);
    }
    return errors.slice(0, 20);
  }

  /** Parse and validate .tmark text: { obj, errors }. */
  function check(text) {
    if (new TextEncoder().encode(text).length > 64000) return { obj: null, errors: [{ path: "(file)", msg: "the file is larger than 64000 bytes" }] };
    let obj;
    try { obj = JSON.parse(text); } catch (e) { return { obj: null, errors: [{ path: "(file)", msg: `not valid JSON: ${e.message}` }] }; }
    return { obj, errors: validate(obj) };
  }

  // ---------------------------------------------------------- examples
  // Valid against .tmark 1 / 1.1 (checked with backend/app/services/tmark.py). The payments agent is
  // examples/demo/safe-treasury-agent/.tmark; the MCP server and the SDK are honest declarations
  // for public Stellar repositories (stellar-mcp-server by Jose Toscano, @stellar/mpp).
  const EXAMPLES = {
    blank: { $schema: SCHEMA_URL, tmark: "1",
      agent: { name: "", purpose: "", kind: "mcp_server", network: "testnet", discloses_ai: true },
      authority: { holds_keys: false, key_source: "none", signs: [] } },
    minimal: { $schema: SCHEMA_URL, tmark: "1",
      agent: { name: "Ledger reader", purpose: "Answers questions about Stellar testnet accounts by reading balances and history from Horizon. It never signs or pays.", kind: "autonomous_agent", network: "testnet" },
      authority: { holds_keys: false, key_source: "none" } },
    payments: { $schema: SCHEMA_URL, tmark: "1",
      agent: { name: "Treasury agent", purpose: "Pays two listed suppliers in XLM on request and reads invoices from one fixed host.", kind: "mcp_server", network: "testnet", discloses_ai: true },
      authority: { holds_keys: true, key_source: "env", signs: ["payments"] },
      limits: { per_payment: { amount: "500", asset: "XLM" }, per_day: { amount: "1000", asset: "XLM" }, recipients: "allowlist", human_approval: "never" },
      tools: [
        { name: "send_payment", description: "Pay a listed supplier in XLM: at most 500 per payment and 1000 per day, once per request id", moves_funds: true, signs: true, network: true, files: true, max_amount: { amount: "500", asset: "XLM" } },
        { name: "fetch_invoice", description: "Read an invoice by id from the fixed invoice host", moves_funds: false, signs: false, network: true },
      ],
      forbidden: ["pay anyone who is not in the supplier table", "pay more than 500 XLM in one payment", "pay more than 1000 XLM in one day"] },
    mcp: { $schema: SCHEMA_URL, tmark: "1.1",
      agent: { name: "stellar-mcp-server (Jose Toscano)", purpose: "Stdio MCP server for Soroban on Stellar testnet. It creates and funds testnet accounts, reads accounts and history from Horizon, and signs auth entries and envelopes of a caller-supplied Soroban transaction XDR with a caller-supplied secret key (or as a passkey smart-wallet signer) before submitting it through Launchtube.", kind: "mcp_server", network: "testnet", discloses_ai: true },
      authority: { holds_keys: false, key_source: "caller_supplied", signs: ["contract_calls", "foreign_transactions"] },
      limits: { recipients: "any", human_approval: "never" },
      tools: [
        { name: "create-account", description: "Generate a random keypair and return the public and secret key to the caller", moves_funds: false, signs: false, network: false },
        { name: "fund-account", description: "Fund an address with testnet lumens from Friendbot", moves_funds: false, signs: false, network: true },
        { name: "get-account", description: "Read balances and signers of an account from testnet Horizon", moves_funds: false, signs: false, network: true },
        { name: "sign-and-submit-transaction", description: "Sign the auth entries and envelope of a caller-supplied Soroban XDR with a caller-supplied secret, or as a smart-wallet signer, and submit via Launchtube", moves_funds: true, signs: true, network: true },
        { name: "submit-signed-xdr", description: "Submit an already signed transaction XDR through Launchtube", moves_funds: true, signs: false, network: true },
      ] },
    contracts: { $schema: SCHEMA_URL, tmark: "1.1",
      agent: { name: "Contract tools server", purpose: "MCP server that turns each function of a Soroban contract the caller registers into a tool. It simulates every call on testnet, then signs it with a secret the caller passes in with that request; it keeps no key. It can also build a contract from a folder with the stellar CLI.", kind: "mcp_server", network: "testnet", discloses_ai: true },
      authority: { holds_keys: false, key_source: "caller_supplied", signs: ["contract_calls"] },
      limits: { recipients: "any", human_approval: "never" },
      tools: [
        { name: "register_contract", description: "Read a contract's interface by its C… address and generate one tool per function", moves_funds: false, signs: false, network: true },
        { name: "invoke_function", description: "Call one function of a registered contract: simulate, then sign with the caller's secret and submit", moves_funds: true, signs: true, network: true,
          generated: { pattern: "invoke_*", source: "each function of a contract the caller registers" } },
        { name: "build_contract", description: "Compile a Soroban contract from a folder in the workspace with the stellar CLI", moves_funds: false, signs: false, network: false, files: true, executes_code: true },
      ],
      forbidden: ["sign with any secret other than the one passed in with this request", "submit a call whose simulation failed"] },
    sdk: { $schema: SCHEMA_URL, tmark: "1",
      agent: { name: "@stellar/mpp", purpose: "SDK for the Machine Payments Protocol on Stellar. The client side signs a SEP-41 token transfer (or an off-chain channel commitment) to pay a server's 402 challenge, checking that the signed auth tree is exactly that transfer; the server side verifies and broadcasts client payments, optionally sponsoring fees, and closes payment channels.", kind: "sdk", network: "both", discloses_ai: true },
      authority: { holds_keys: true, key_source: "env", signs: ["payments", "contract_calls", "foreign_transactions", "messages"] },
      limits: { recipients: "any", human_approval: "never" },
      tools: [
        { name: "charge_client", description: "Pay a 402 charge challenge: build, check and sign a SEP-41 transfer of the challenge amount to the challenge recipient", moves_funds: true, signs: true, network: true },
        { name: "charge_server", description: "Issue charge challenges, verify the client transfer, optionally fee-bump, sign and broadcast it, and keep a replay store", moves_funds: true, signs: true, network: true },
        { name: "channel_client", description: "Sign cumulative off-chain commitments for a one-way payment channel", moves_funds: true, signs: true, network: true },
        { name: "channel_server", description: "Verify channel commitments against on-chain channel state and close the channel to settle", moves_funds: true, signs: true, network: true },
      ],
      forbidden: ["sign an authorization tree that is anything other than the requested SEP-41 transfer", "accept the same payment credential twice"] },
  };

  // ----------------------------------------------------- serializer
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const ORDER = ["$schema", "tmark", "agent", "owner", "authority", "limits", "tools", "forbidden", "entrypoints", "contact",
    "name", "purpose", "description", "kind", "network", "discloses_ai", "stellar_account", "holds_keys", "key_source", "signs",
    "agent_account", "per_payment", "per_day", "recipients", "human_approval", "moves_funds", "files", "executes_code", "generated",
    "pattern", "source", "max_amount", "amount", "asset", "path", "symbol", "security"];
  const rank = (k) => { const i = ORDER.indexOf(k); return i < 0 ? 99 : i; };
  function scalar(v) {
    if (typeof v === "string") return `<span class="j-s">${esc(JSON.stringify(v))}</span>`;
    if (typeof v === "boolean") return `<span class="j-b">${v}</span>`;
    if (v === null) return `<span class="j-null">null</span>`;
    return `<span class="j-n">${esc(JSON.stringify(v))}</span>`;
  }
  /** Lines of { html, text, path } for JSON.stringify(value, null, 2), keys in the format's order. */
  function lines(value, path = "", indent = "", key = null, last = true) {
    const out = [];
    const k = key === null ? "" : (typeof key === "number" ? "" : `<span class="j-k">${esc(JSON.stringify(key))}</span><span class="j-p">: </span>`);
    const kt = key === null || typeof key === "number" ? "" : `${JSON.stringify(key)}: `;
    const comma = last ? "" : `<span class="j-p">,</span>`, ct = last ? "" : ",";
    if (value !== null && typeof value === "object") {
      const arr = Array.isArray(value);
      const entries = arr ? value.map((v, i) => [i, v]) : Object.keys(value).sort((a, b) => rank(a) - rank(b)).map((x) => [x, value[x]]);
      const [open, close] = arr ? ["[", "]"] : ["{", "}"];
      if (!entries.length) {
        out.push({ html: `${indent}${k}<span class="j-p">${open}${close}</span>${comma}`, text: `${indent}${kt}${open}${close}${ct}`, path });
        return out;
      }
      out.push({ html: `${indent}${k}<span class="j-p">${open}</span>`, text: `${indent}${kt}${open}`, path });
      entries.forEach(([ck, cv], i) => out.push(...lines(cv, path ? `${path}.${ck}` : String(ck), indent + "  ", ck, i === entries.length - 1)));
      out.push({ html: `${indent}<span class="j-p">${close}</span>${comma}`, text: `${indent}${close}${ct}`, path });
    } else {
      out.push({ html: `${indent}${k}${scalar(value)}${comma}`, text: `${indent}${kt}${JSON.stringify(value)}${ct}`, path });
    }
    return out;
  }
  function highlight(value) {
    const ls = lines(value);
    return { html: ls.map((l) => `<span class="ln" data-path="${esc(l.path)}">${l.html}</span>`).join(""), text: ls.map((l) => l.text).join("\n") + "\n" };
  }

  window.TmarkRules = { validate, check, minorFeatures, isAccount, highlight, EXAMPLES, SCHEMA_URL };

  // Worked examples on the page: render each, and wire the tabs.
  document.querySelectorAll("pre.t-example[data-example]").forEach((pre) => {
    const ex = EXAMPLES[pre.dataset.example];
    if (ex) pre.innerHTML = `<code>${highlight(ex).html}</code>`;
  });
  const tablist = document.querySelector(".t-tablist");
  if (tablist) {
    const tabs = [...tablist.querySelectorAll("[role=tab]")];
    const select = (tab, focus) => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    };
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => select(t));
      t.addEventListener("keydown", (e) => {
        const n = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
        if (n) { e.preventDefault(); select(tabs[(i + n + tabs.length) % tabs.length], true); }
        else if (e.key === "Home") { e.preventDefault(); select(tabs[0], true); }
        else if (e.key === "End") { e.preventDefault(); select(tabs[tabs.length - 1], true); }
      });
    });
  }

  // ------------------------------------------------------------ builder
  const root = document.getElementById("tmark-builder");
  if (!root) return;
  const form = document.getElementById("tb-form");
  const $ = (id) => document.getElementById(id);
  const code = $("tb-code").querySelector("code");
  const limitsOn = $("f-limits-on");
  const lists = { tools: $("tb-tools"), forbidden: $("tb-forbidden"), entrypoints: $("tb-entrypoints") };
  let current = { obj: null, text: "", errors: [] };
  let touched = new Set();
  let showAll = false;

  const get = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
  function put(obj, path, value) {
    const keys = path.split(".");
    let o = obj;
    keys.slice(0, -1).forEach((k) => { o[k] = o[k] && typeof o[k] === "object" ? o[k] : {}; o = o[k]; });
    o[keys[keys.length - 1]] = value;
  }

  // Repeatable rows.
  let uid = 0;
  function toolRow(t = {}) {
    const n = ++uid;
    const li = document.createElement("li");
    li.className = "tb-item";
    li.innerHTML = `
      <div class="tb-row">
        <div class="tb-field" data-rel="name"><label for="t${n}-name">Tool name</label><input id="t${n}-name" class="mono" data-k="name" maxlength="80" spellcheck="false" placeholder="send_payment"></div>
        <button type="button" class="tb-remove" aria-label="Remove this tool">Remove</button>
      </div>
      <div class="tb-field" data-rel="description"><label for="t${n}-desc">What it does <small>8 to 400 characters</small></label><input id="t${n}-desc" data-k="description" maxlength="400" placeholder="Pay a listed supplier in XLM, at most 500 per payment"></div>
      <div class="tb-tags tb-flags" role="group" aria-label="What this tool can do">
        <label><input type="checkbox" data-k="moves_funds"><span>moves funds</span></label>
        <label><input type="checkbox" data-k="signs"><span>signs</span></label>
        <label><input type="checkbox" data-k="network"><span>network</span></label>
        <label><input type="checkbox" data-k="files"><span>files</span></label>
        <label><input type="checkbox" data-k="executes_code"><span>runs code <small class="tb-v11">1.1</small></span></label>
      </div>
      <div class="tb-field tb-gen" data-rel="generated">
        <label class="tb-check tb-gen-on"><input type="checkbox" data-k="generated.on"> Stands for a family of tools the code generates at run time <code>generated</code> <small class="tb-v11">1.1</small></label>
        <div class="tb-gen-fields" hidden>
          <div class="tb-field" data-rel="generated.pattern"><label for="t${n}-gp">Name pattern <small>a glob every generated name matches</small></label><input id="t${n}-gp" class="mono" data-k="generated.pattern" maxlength="120" spellcheck="false" placeholder="invoke_*"></div>
          <div class="tb-field" data-rel="generated.source"><label for="t${n}-gs">Generated from <small>8 to 300 characters</small></label><input id="t${n}-gs" data-k="generated.source" maxlength="300" placeholder="each function of a contract the caller registers"></div>
        </div>
      </div>
      <div class="tb-field tb-money" data-rel="max_amount"><span class="tb-label">Max per call <small>optional, only when it moves funds</small></span>
        <div class="tb-money-in"><input aria-label="Tool cap amount" class="mono" data-k="max_amount.amount" data-rel="max_amount.amount" inputmode="decimal" placeholder="500"><input aria-label="Tool cap asset" class="mono" data-k="max_amount.asset" data-rel="max_amount.asset" list="tb-assets" placeholder="XLM"></div></div>`;
    li.querySelector('[data-k="name"]').value = t.name || "";
    li.querySelector('[data-k="description"]').value = t.description || "";
    for (const k of ["moves_funds", "signs", "network", "files", "executes_code"]) li.querySelector(`[data-k="${k}"]`).checked = isTrue(t[k]);
    const gen = t.generated && typeof t.generated === "object" ? t.generated : null;
    li.querySelector('[data-k="generated.on"]').checked = !!gen;
    li.querySelector(".tb-gen-fields").hidden = !gen;
    li.querySelector('[data-k="generated.pattern"]').value = (gen && gen.pattern) || "";
    li.querySelector('[data-k="generated.source"]').value = (gen && gen.source) || "";
    li.querySelector('[data-k="max_amount.amount"]').value = (t.max_amount && t.max_amount.amount) || "";
    li.querySelector('[data-k="max_amount.asset"]').value = (t.max_amount && t.max_amount.asset) || "";
    return li;
  }
  function textRow(v = "") {
    const n = ++uid;
    const li = document.createElement("li");
    li.className = "tb-item tb-item-inline";
    li.innerHTML = `<div class="tb-field" data-rel=""><label class="g-vh" for="r${n}">Refusal</label><input id="r${n}" data-k="" maxlength="300" placeholder="pay anyone who is not in the supplier table"></div><button type="button" class="tb-remove" aria-label="Remove this refusal">Remove</button>`;
    li.querySelector("input").value = v;
    return li;
  }
  function entryRow(e = {}) {
    const n = ++uid;
    const li = document.createElement("li");
    li.className = "tb-item tb-item-inline";
    li.innerHTML = `<div class="tb-field" data-rel="path"><label class="g-vh" for="e${n}p">Path</label><input id="e${n}p" class="mono" data-k="path" spellcheck="false" placeholder="src/server.ts"></div>
      <div class="tb-field" data-rel="symbol"><label class="g-vh" for="e${n}s">Symbol</label><input id="e${n}s" class="mono" data-k="symbol" spellcheck="false" placeholder="handleRequest"></div>
      <button type="button" class="tb-remove" aria-label="Remove this entry point">Remove</button>`;
    li.querySelector('[data-k="path"]').value = e.path || "";
    li.querySelector('[data-k="symbol"]').value = e.symbol || "";
    return li;
  }
  const ROW = { tools: toolRow, forbidden: textRow, entrypoints: entryRow };
  function renumber() {
    for (const [name, ol] of Object.entries(lists)) {
      [...ol.children].forEach((li, i) => {
        li.dataset.path = `${name}.${i}`;
        li.querySelectorAll(".tb-field[data-rel]").forEach((f) => { f.dataset.path = f.dataset.rel ? `${name}.${i}.${f.dataset.rel}` : `${name}.${i}`; });
        li.querySelectorAll("input[data-rel]").forEach((inp) => { inp.dataset.path = `${name}.${i}.${inp.dataset.rel}`; });
      });
    }
  }

  // Form → object.
  function read() {
    const o = { $schema: SCHEMA_URL, tmark: "1", agent: {}, authority: {} };
    form.querySelectorAll("[data-bind]").forEach((el) => {
      const path = el.dataset.bind;
      if (el.closest("#tb-limits") && !limitsOn.checked) return;
      if (el.type === "radio") { if (el.checked) put(o, path, el.dataset.type === "bool" ? el.value === "true" : el.value); }
      else if (el.type === "checkbox" && el.dataset.type === "set") { const cur = get(o, path) || []; if (el.checked) cur.push(el.value); put(o, path, cur); }
      else if (el.type === "checkbox") put(o, path, el.checked);
      else if (el.value.trim() !== "" || !/^(owner|contact|authority\.agent_account|limits\.per_)/.test(path)) put(o, path, el.value);
    });
    if (!o.authority.signs) o.authority.signs = [];
    if (o.limits) {
      for (const k of ["per_payment", "per_day"]) {
        const m = o.limits[k];
        if (m && !m.amount) delete o.limits[k];
        else if (m && !m.asset) m.asset = "XLM";
      }
    }
    const tools = [...lists.tools.children].map((li) => {
      const t = { name: li.querySelector('[data-k="name"]').value, description: li.querySelector('[data-k="description"]').value };
      for (const k of ["moves_funds", "signs", "network"]) t[k] = li.querySelector(`[data-k="${k}"]`).checked;
      if (li.querySelector('[data-k="files"]').checked) t.files = true;
      if (li.querySelector('[data-k="executes_code"]').checked) t.executes_code = true;
      if (li.querySelector('[data-k="generated.on"]').checked) {
        t.generated = { pattern: li.querySelector('[data-k="generated.pattern"]').value, source: li.querySelector('[data-k="generated.source"]').value };
      }
      const amount = li.querySelector('[data-k="max_amount.amount"]').value.trim();
      if (amount) t.max_amount = { amount, asset: li.querySelector('[data-k="max_amount.asset"]').value.trim() || "XLM" };
      return t;
    });
    if (tools.length) o.tools = tools;
    const forbidden = [...lists.forbidden.querySelectorAll("input")].map((i) => i.value);
    if (forbidden.length) o.forbidden = forbidden;
    const entries = [...lists.entrypoints.children].map((li) => ({ path: li.querySelector('[data-k="path"]').value, symbol: li.querySelector('[data-k="symbol"]').value }));
    if (entries.length) o.entrypoints = entries;
    // "1.1" only when a 1.1 field is used: every other file stays readable as "1".
    o.tmark = minorFeatures(o).length ? "1.1" : "1";
    return o;
  }

  // Object → form. Unknown fields are not loaded (they are reported by load()).
  function fill(obj) {
    form.reset();
    const has = (p) => get(obj, p) !== undefined && get(obj, p) !== null;
    limitsOn.checked = has("limits");
    form.querySelectorAll("[data-bind]").forEach((el) => {
      const v = get(obj, el.dataset.bind);
      if (el.type === "radio") el.checked = v !== undefined && String(v) === el.value;
      else if (el.type === "checkbox" && el.dataset.type === "set") el.checked = Array.isArray(v) && v.includes(el.value);
      else if (el.type === "checkbox") el.checked = v === undefined ? el.dataset.bind === "agent.discloses_ai" : !!v;
      else el.value = v == null ? "" : String(v);
    });
    if (limitsOn.checked && !has("limits.per_payment.asset")) form.querySelector('[data-bind="limits.per_payment.asset"]').value = "";
    for (const [name, ol] of Object.entries(lists)) {
      ol.replaceChildren(...(Array.isArray(obj[name]) ? obj[name].map((x) => ROW[name](x)) : []));
    }
    $("tb-limits").hidden = !limitsOn.checked;
    renumber();
  }

  function load(input, { quiet } = {}) {
    let obj = input, errors = [];
    if (typeof input === "string") { const r = check(input); obj = r.obj; errors = r.errors; if (!obj) return errors; }
    fill(obj);
    touched = new Set(); showAll = !!quiet ? false : true;
    update();
    return errors;
  }

  // Inline errors, the error list, the status, the code.
  function update() {
    const obj = read();
    const errors = validate(obj);
    const { html, text } = highlight(obj);
    current = { obj, text, errors };
    code.innerHTML = html;
    const bad = new Set(errors.map((e) => e.path));
    code.querySelectorAll(".ln").forEach((ln) => {
      const p = ln.dataset.path;
      if (p && [...bad].some((b) => b === p || p.startsWith(b + "."))) ln.classList.add("is-bad");
    });

    // Field messages: show for fields the user has touched (or after loading / checking).
    form.querySelectorAll(".tb-msg").forEach((m) => m.remove());
    form.querySelectorAll("[aria-invalid]").forEach((el) => el.removeAttribute("aria-invalid"));
    form.querySelectorAll(".is-bad").forEach((el) => el.classList.remove("is-bad"));
    const shown = [];
    errors.forEach((e, i) => {
      const host = form.querySelector(`[data-path="${CSS.escape(e.path)}"]`);
      const visible = showAll || [...touched].some((t) => t === e.path || t.startsWith(e.path + ".") || e.path.startsWith(t + "."));
      if (!visible) return;
      shown.push(e);
      if (!host) return;
      const box = host.matches("fieldset, li, .tb-item") ? host : host.closest(".tb-field, .tb-check, fieldset, li") || host;
      box.classList.add("is-bad");
      const msg = document.createElement("p");
      msg.className = "tb-msg";
      msg.id = `tb-msg-${i}`;
      msg.textContent = e.msg;
      const anchor = box.matches("fieldset") ? box.querySelector("legend") : null;
      if (anchor) anchor.after(msg); else box.append(msg);
      const input = host.matches("input, textarea, select") ? host : box.querySelector("input:not([type=radio]):not([type=checkbox]), textarea, select");
      if (input && !box.matches("fieldset")) { input.setAttribute("aria-invalid", "true"); input.setAttribute("aria-describedby", msg.id); }
    });

    const list = $("tb-errors");
    list.replaceChildren(...errors.map((e) => {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.innerHTML = `<code>${esc(e.path)}</code> ${esc(e.msg)}`;
      b.addEventListener("click", () => focusPath(e.path));
      li.append(b);
      return li;
    }));
    list.hidden = !errors.length;
    const status = $("tb-status");
    status.className = "tb-status " + (errors.length ? "bad" : "ok");
    status.textContent = errors.length ? `${errors.length} ${errors.length === 1 ? "problem" : "problems"}` : `valid .tmark ${obj.tmark}`;
    const minor = minorFeatures(obj);
    $("tb-version").textContent = minor.length
      ? `"tmark": "1.1", because it uses ${minor.map((f) => f.replace(/^tools\.(\d+)\./, (_, i) => `tool ${Number(i) + 1} `)).join(", ")}.`
      : `"tmark": "1": no 1.1 field is used, so any Touchmark reader accepts it.`;
    const m = $("tb-mascot");
    if (m && m.tmMascot) {
      const want = errors.length ? "warning" : "success";
      if (m.tmMascot.state !== want) m.tmMascot.set(want, { tone: "evidence" });
    }
    $("tb-server").textContent = "";
    $("tb-server").className = "tb-server";
    // Purpose counter.
    const cnt = form.querySelector('[data-count="agent.purpose"]');
    const len = (obj.agent.purpose || "").trim().length;
    cnt.textContent = `${len} / 1000`;
    cnt.classList.toggle("short", len < 20);
    root.dispatchEvent(new CustomEvent("tmark:change", { detail: { text, valid: !errors.length, errors } }));
  }

  function focusPath(path) {
    let host = form.querySelector(`[data-path="${CSS.escape(path)}"]`);
    if (!host && path.startsWith("contact") || !host && path.startsWith("entrypoints")) form.querySelector(".tb-more").open = true;
    host = host || form.querySelector(`[data-path="${CSS.escape(path.split(".").slice(0, -1).join("."))}"]`) || form.querySelector("fieldset");
    const more = host.closest("details"); if (more) more.open = true;
    const input = host.matches("input, textarea, select") ? host : host.querySelector("input, textarea, select, button");
    host.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
    if (input) setTimeout(() => input.focus({ preventScroll: true }), 250);
  }

  // Which line of the file a focused field writes.
  function glow(path) {
    code.querySelectorAll(".is-focus").forEach((l) => l.classList.remove("is-focus"));
    if (!path) return;
    const hits = [...code.querySelectorAll(".ln")].filter((l) => l.dataset.path === path || l.dataset.path.startsWith(path + "."));
    hits.forEach((l) => l.classList.add("is-focus"));
    const pre = $("tb-code");
    if (hits[0]) {
      const top = hits[0].offsetTop - pre.clientHeight / 3;
      pre.scrollTo({ top: Math.max(0, top), behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    }
  }
  const pathOf = (el) => el.dataset.path || el.dataset.bind || (el.closest("[data-path]") || {}).dataset?.path || "";

  let typing;
  form.addEventListener("input", (e) => {
    const p = pathOf(e.target);
    if (p) touched.add(p.replace(/\.(amount|asset)$/, "") === p ? p : p);
    if (e.target.dataset.k !== undefined) {
      const row = e.target.closest("li[data-path]");
      if (row) touched.add(row.dataset.path + (e.target.dataset.k ? "." + e.target.dataset.k.replace(/\.on$/, "") : ""));
      if (e.target.dataset.k === "generated.on") {
        row.querySelector(".tb-gen-fields").hidden = !e.target.checked;
        if (e.target.checked) setTimeout(() => row.querySelector('[data-k="generated.pattern"]').focus(), 0);
      }
    }
    update();
    glow(p || (e.target.closest("li[data-path]") || {}).dataset?.path);
    const m = $("tb-mascot");
    if (m && m.tmMascot && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      m.tmMascot.set("scanning");
      clearTimeout(typing);
      typing = setTimeout(() => m.tmMascot.set(current.errors.length ? "warning" : "success", { tone: "evidence" }), 700);
    }
  });
  form.addEventListener("focusin", (e) => {
    const row = e.target.closest("li[data-path]");
    glow(e.target.dataset.k !== undefined && row ? row.dataset.path + (e.target.dataset.k ? "." + e.target.dataset.k.split(".")[0] : "") : pathOf(e.target));
  });
  form.addEventListener("focusout", () => glow(""));
  form.addEventListener("submit", (e) => e.preventDefault());
  limitsOn.addEventListener("change", () => {
    $("tb-limits").hidden = !limitsOn.checked;
    if (limitsOn.checked && !form.querySelector('[data-bind="limits.recipients"]:checked')) {
      form.querySelector('[data-bind="limits.recipients"][value="allowlist"]').checked = true;
      form.querySelector('[data-bind="limits.human_approval"][value="above_limit"]').checked = true;
    }
    touched.add("limits");
    update();
  });
  root.addEventListener("click", (e) => {
    const add = e.target.closest("[data-add]");
    if (add) {
      const name = add.dataset.add;
      const row = ROW[name]();
      lists[name].append(row);
      renumber(); update();
      const first = row.querySelector("input"); if (first) first.focus();
      return;
    }
    const rm = e.target.closest(".tb-remove");
    if (rm) {
      const li = rm.closest("li");
      const ol = li.parentElement;
      const next = li.nextElementSibling || li.previousElementSibling;
      li.remove(); renumber(); update();
      const target = next ? next.querySelector("input") : ol.parentElement.querySelector(".tb-add");
      if (target) target.focus();
    }
  });

  // Start-from buttons (the toolbar and the worked examples).
  document.querySelectorAll("[data-load]").forEach((b) => b.addEventListener("click", () => {
    const ex = EXAMPLES[b.dataset.load];
    if (!ex) return;
    load(JSON.parse(JSON.stringify(ex)), { quiet: b.dataset.load === "blank" });
    document.querySelectorAll(".tb-toolbar [data-load]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.load === b.dataset.load)));
    if (!b.closest(".tb-toolbar")) root.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }));

  // Paste an existing file.
  $("tb-paste-load").addEventListener("click", () => {
    const text = $("tb-paste-text").value;
    const msg = $("tb-paste-msg");
    const r = check(text);
    if (!r.obj || typeof r.obj !== "object" || Array.isArray(r.obj)) { msg.textContent = r.errors.length ? r.errors[0].msg : "the file must be one JSON object"; msg.className = "tb-paste-msg bad"; return; }
    load(r.obj);
    const unknown = r.errors.filter((e) => e.msg.startsWith("unknown field"));
    msg.className = "tb-paste-msg " + (r.errors.length ? "bad" : "ok");
    msg.textContent = r.errors.length
      ? `Loaded. As pasted, the file had ${r.errors.length} ${r.errors.length === 1 ? "problem" : "problems"}${unknown.length ? `; unknown fields were left out: ${unknown.map((e) => e.path).join(", ")}` : ""}.`
      : "Loaded. As pasted, the file is valid.";
  });

  // Copy, download, check.
  function flashButton(b, label) { const was = b.textContent; b.textContent = label; setTimeout(() => { b.textContent = was; }, 1400); }
  $("tb-copy").addEventListener("click", async (e) => {
    try { await navigator.clipboard.writeText(current.text); flashButton(e.currentTarget, "Copied ✓"); }
    catch { const r = document.createRange(); r.selectNodeContents(code); const s = getSelection(); s.removeAllRanges(); s.addRange(r); flashButton(e.currentTarget, "Selected: press Ctrl+C"); }
  });
  $("tb-download").addEventListener("click", () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([current.text], { type: "application/json" }));
    a.download = ".tmark";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $("tb-check").addEventListener("click", async (e) => {
    const b = e.currentTarget, out = $("tb-server");
    b.disabled = true; out.className = "tb-server"; out.textContent = "Asking Touchmark…";
    const m = $("tb-mascot"); if (m && m.tmMascot) m.tmMascot.set("scanning");
    try {
      const res = await fetch(b.dataset.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: current.text }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `the check failed (${res.status})`);
      if (data.valid) {
        out.className = "tb-server ok";
        out.textContent = `Touchmark says: valid. ${data.agent ? `“${data.agent}” on ${data.network}.` : ""} Nothing was stored.`;
        if (m && m.tmMascot) m.tmMascot.set("success");
      } else {
        out.className = "tb-server bad";
        out.textContent = `Touchmark says: not valid. ${(data.errors || []).join(" · ")}`;
        showAll = true; update(); out.className = "tb-server bad"; out.textContent = `Touchmark says: not valid. ${(data.errors || []).join(" · ")}`;
        if (m && m.tmMascot) m.tmMascot.set("warning", { tone: "risk" });
      }
    } catch (err) {
      out.className = "tb-server bad";
      out.textContent = `Could not reach the checker: ${err.message}. The checks above still apply.`;
      if (m && m.tmMascot) m.tmMascot.set("error");
    } finally { b.disabled = false; }
  });

  // Back to the home page audit with this file (and the repository it came with, if any).
  let handoffReference = "";
  $("tb-audit").addEventListener("click", () => {
    try { sessionStorage.setItem("touchmark.tmark.toAudit", JSON.stringify({ text: current.text, reference: handoffReference })); } catch { /* storage off: the link still opens */ }
    location.href = "/#declare";
  });

  window.TmarkBuilder = { load: (x) => load(x), get: () => current.obj, text: () => current.text };

  // A file handed over from the home page opens prefilled; ?example=payments preloads an
  // example; otherwise start from the payments agent.
  const start = new URLSearchParams(location.search).get("example");
  function takeHandoff() {
    let raw = null;
    try { raw = sessionStorage.getItem("touchmark.tmark.toBuilder"); sessionStorage.removeItem("touchmark.tmark.toBuilder"); } catch { return false; }
    if (!raw) return false;
    let handed;
    try { handed = JSON.parse(raw); } catch { return false; }
    if (!handed || typeof handed.text !== "string" || !handed.text.trim()) return false;
    handoffReference = typeof handed.reference === "string" ? handed.reference.slice(0, 300) : "";
    const note = $("tb-handoff");
    const r = check(handed.text);
    if (!r.obj || typeof r.obj !== "object" || Array.isArray(r.obj)) {
      load(JSON.parse(JSON.stringify(EXAMPLES.blank)), { quiet: true });
      $("tb-paste-text").value = handed.text;
      document.querySelector(".tb-paste").open = true;
      note.textContent = `The .tmark from your audit is not readable yet (${r.errors[0] ? r.errors[0].msg : "not one JSON object"}). It is in the paste box below: fix it there and load it.`;
    } else {
      load(r.obj);
      const unknown = r.errors.filter((e) => e.msg.startsWith("unknown field")).map((e) => e.path);
      note.textContent = `Opened the .tmark from your audit${handoffReference ? ` of ${handoffReference.replace("https://github.com/", "")}` : ""}.`
        + (r.errors.length ? ` As handed over it had ${r.errors.length} ${r.errors.length === 1 ? "problem" : "problems"}, marked below.` : " It is valid as it stands.")
        + (unknown.length ? ` Unknown fields were left out: ${unknown.join(", ")}.` : "");
    }
    note.hidden = false;
    document.querySelectorAll(".tb-toolbar [data-load]").forEach((x) => x.setAttribute("aria-pressed", "false"));
    return true;
  }
  const boot = () => {
    if (takeHandoff()) return;
    load(JSON.parse(JSON.stringify(EXAMPLES[start] || EXAMPLES.payments)), { quiet: true });
    document.querySelectorAll(".tb-toolbar [data-load]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.load === (EXAMPLES[start] ? start : "payments")))); };
  if (window.TouchmarkMascot) boot(); else document.addEventListener("DOMContentLoaded", boot);
})();
