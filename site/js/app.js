/* WebLog Sentinel – interfaz. Todo corre en el navegador: los logs nunca salen de tu equipo. */
(function () {
  "use strict";
  const { LogParser, Detector, SAMPLE_LOG } = window;
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const SEV = ["critical", "high", "medium", "low", "info"];
  const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };

  const T = {
    es: {
      intro: 'Pegá o soltá un archivo de <b>log de acceso web</b> (Nginx o Apache) y detectá patrones de ataque: inyección SQL, XSS, path traversal, fuerza bruta, escaneo y más. Cada detección se mapea al <b>OWASP Top 10</b> y a <b>MITRE ATT&CK</b>. Todo se procesa en tu navegador: <b>los logs nunca se envían a ningún servidor</b>.',
      inputTitle: "Log de acceso", loadEx: "Cargar ejemplo", upload: "Subir archivo", clear: "Limpiar",
      placeholder: '192.168.1.50 - - [30/Oct/2026:14:22:01 +0000] "GET /products?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
      drop: "También podés arrastrar un archivo .log acá.",
      parsed: (p, f) => `${p.toLocaleString("es-AR")} líneas analizadas` + (f ? ` · ${f} no reconocidas` : ""),
      kTotal: "Peticiones", kIps: "IPs únicas", kSusp: "IPs sospechosas", kDet: "Detecciones", kTypes: "Tipos de ataque",
      types: "Ataques detectados", suspects: "IPs sospechosas", timeline: "Actividad en el tiempo",
      clean: "✓ No se detectaron patrones de ataque en este log.",
      empty: "El análisis aparece acá cuando cargás un log.",
      requests: "peticiones", uniquePaths: "rutas únicas", window: "ventana", evidence: "Evidencia",
      remediation: "Recomendación", andMore: (n) => `…y ${n} más`,
      export: "Exportar", copyMd: "Copiar informe (Markdown)", copyJson: "Copiar JSON", copyFb: "Copiar para Findings Builder", copied: "¡Copiado!",
      sevName: { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Info" },
      aboutTitle: "Cómo funciona y cómo leerlo",
    },
    en: {
      intro: 'Paste or drop a <b>web access log</b> file (Nginx or Apache) to detect attack patterns: SQL injection, XSS, path traversal, brute force, scanning and more. Each detection is mapped to the <b>OWASP Top 10</b> and <b>MITRE ATT&CK</b>. Everything runs in your browser: <b>logs are never sent to any server</b>.',
      inputTitle: "Access log", loadEx: "Load example", upload: "Upload file", clear: "Clear",
      placeholder: '192.168.1.50 - - [30/Oct/2026:14:22:01 +0000] "GET /products?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
      drop: "You can also drag a .log file here.",
      parsed: (p, f) => `${p.toLocaleString("en-US")} lines analyzed` + (f ? ` · ${f} unrecognized` : ""),
      kTotal: "Requests", kIps: "Unique IPs", kSusp: "Suspicious IPs", kDet: "Detections", kTypes: "Attack types",
      types: "Detected attacks", suspects: "Suspicious IPs", timeline: "Activity over time",
      clean: "✓ No attack patterns detected in this log.",
      empty: "The analysis shows up here once you load a log.",
      requests: "requests", uniquePaths: "unique paths", window: "window", evidence: "Evidence",
      remediation: "Remediation", andMore: (n) => `…and ${n} more`,
      export: "Export", copyMd: "Copy report (Markdown)", copyJson: "Copy JSON", copyFb: "Copy for Findings Builder", copied: "Copied!",
      sevName: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
      aboutTitle: "How it works and how to read it",
    },
  };
  // nombres y descripciones de detectores por idioma (desc viene del motor en ES; acá traducimos nombres de UI)
  const DET_NAME = {
    en: { sqli: "SQL Injection", xss: "Cross-Site Scripting (XSS)", "path-traversal": "Path traversal / LFI", "cmd-injection": "Command injection",
      log4shell: "Log4Shell (JNDI)", ssti: "Server-Side Template Injection", "sensitive-file": "Sensitive file probing",
      "scanner-ua": "Scanner tool detected", "suspicious-ua": "Automated client (non-browser)",
      "brute-force": "Authentication brute force", "dir-scan": "Directory scanning", enumeration: "Endpoint enumeration" },
  };

  let lang = (navigator.language || "es").toLowerCase().startsWith("es") ? "es" : "en";
  let lastResult = null;
  const t = () => T[lang];
  const detName = (id, fallback) => (lang === "en" && DET_NAME.en[id]) ? DET_NAME.en[id] : fallback;

  function toast(msg) { const el = $("#toast"); el.textContent = msg; el.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (el.hidden = true), 1600); }

  function render() {
    const T_ = t();
    $("#intro").innerHTML = T_.intro;
    $("#inputTitle").textContent = T_.inputTitle;
    $("#input").placeholder = T_.placeholder;
    $("#dropHint").textContent = T_.drop;
    $("#exBtns").innerHTML = `<button class="btn sm pri" data-act="example">${T_.loadEx}</button><button class="btn sm" data-act="upload">${T_.upload}</button><button class="btn sm ghost" data-act="clear">${T_.clear}</button>`;
    renderAbout();
    $("#foot").innerHTML = lang === "es"
      ? '🔒 Todo se procesa en tu navegador. Ningún log se envía a ningún servidor. · <a href="https://github.com/ulisespignatelli/weblog-sentinel" target="_blank" rel="noopener">Código</a>'
      : '🔒 Everything runs in your browser. No log is sent to any server. · <a href="https://github.com/ulisespignatelli/weblog-sentinel" target="_blank" rel="noopener">Source</a>';
    analyze();
  }

  function analyze() {
    const T_ = t();
    const text = $("#input").value;
    if (!text.trim()) { lastResult = null; $("#parseInfo").textContent = ""; $("#results").innerHTML = `<div class="empty">${T_.empty}</div>`; return; }
    const { entries, stats } = LogParser.parseLog(text);
    $("#parseInfo").textContent = T_.parsed(stats.parsed, stats.failed);
    const res = Detector.analyze(entries);
    lastResult = { res, entries };
    renderResults(res, entries);
  }

  function renderResults(res, entries) {
    const T_ = t();
    if (!res.totalRequests) { $("#results").innerHTML = `<div class="empty">${T_.empty}</div>`; return; }
    const kpis = `<div class="kpis">
      <div class="kpi"><div class="v">${res.totalRequests.toLocaleString()}</div><div class="l">${T_.kTotal}</div></div>
      <div class="kpi"><div class="v">${res.totalIps}</div><div class="l">${T_.kIps}</div></div>
      <div class="kpi ${res.suspiciousIps.length ? "alert" : "ok"}"><div class="v">${res.suspiciousIps.length}</div><div class="l">${T_.kSusp}</div></div>
      <div class="kpi ${res.detectionCount ? "alert" : "ok"}"><div class="v">${res.detectionCount}</div><div class="l">${T_.kDet}</div></div>
      <div class="kpi"><div class="v">${Object.keys(res.byType).length}</div><div class="l">${T_.kTypes}</div></div>
    </div>`;

    if (!res.suspiciousIps.length) { $("#results").innerHTML = kpis + `<div class="clean">${T_.clean}</div>`; return; }

    // tipos
    const typesHtml = `<div class="card"><div class="card-h"><h2>${T_.types}</h2></div><div class="types">${
      Object.entries(res.byType).sort((a, b) => b[1] - a[1]).map(([id, n]) => {
        const sev = (Detector.DETECTORS.find((d) => d.id === id) || {}).severity || aggSev(id);
        const label = detName(id, (Detector.DETECTORS.find((d) => d.id === id) || {}).name || aggName(id));
        return `<span class="type-chip"><span class="c" style="background:${SEV_COLOR[sev]}"></span>${esc(label)} <b>${n}</b></span>`;
      }).join("")}</div></div>`;

    const timeline = renderTimeline(entries, res);

    const suspects = `<div class="section-t">🚨 ${T_.suspects} (${res.suspiciousIps.length})</div>` +
      res.suspiciousIps.map((ip, i) => ipCard(ip, i)).join("");

    const exportBar = `<div class="export-bar"><button class="btn" data-exp="md">${T_.copyMd}</button><button class="btn" data-exp="json">${T_.copyJson}</button><button class="btn" data-exp="fb">${T_.copyFb}</button></div>`;

    $("#results").innerHTML = kpis + typesHtml + timeline + suspects + exportBar;
    $("#results").querySelectorAll(".ip-h").forEach((el) => { el.onclick = () => el.closest(".ip-card").classList.toggle("open"); });
    $("#results").querySelectorAll("[data-exp]").forEach((b) => { b.onclick = () => doExport(b.dataset.exp); });
  }

  const aggMeta = { "brute-force": { sev: "high", name: "Fuerza bruta de autenticación" }, "dir-scan": { sev: "medium", name: "Escaneo de directorios" }, enumeration: { sev: "low", name: "Enumeración de endpoints" } };
  const aggSev = (id) => (aggMeta[id] || {}).sev || "info";
  const aggName = (id) => (aggMeta[id] || {}).name || id;

  function ipCard(ip, i) {
    const T_ = t();
    const types = [...new Set(ip.detections.map((d) => d.id))];
    const tagsHtml = types.map((id) => {
      const sev = (Detector.DETECTORS.find((d) => d.id === id) || {}).severity || aggSev(id);
      return `<span class="badge sev-${sev}">${esc(detName(id, (Detector.DETECTORS.find((d) => d.id === id) || {}).name || aggName(id)))}</span>`;
    }).join("");
    const span = ip.firstSeen && ip.lastSeen ? `${fmtTime(ip.firstSeen)}–${fmtTime(ip.lastSeen)}` : "";
    // agrupar detecciones por tipo
    const groups = {};
    for (const d of ip.detections) (groups[d.id] = groups[d.id] || []).push(d);
    const detailHtml = Object.entries(groups).map(([id, ds]) => detBlock(id, ds)).join("");
    return `<div class="ip-card">
      <div class="ip-h b-${ip.worst}">
        <span class="rank" style="background:${SEV_COLOR[ip.worst]}">${i + 1}</span>
        <div><span class="caret">▸</span><span class="ipn">${esc(ip.ip)}</span>
          <div class="sub">${ip.requests.toLocaleString()} ${T_.requests} · ${ip.pathCount} ${T_.uniquePaths}${span ? " · " + span : ""} · <span class="mono">score ${ip.score}</span></div></div>
        <div class="tags">${tagsHtml}</div>
      </div>
      <div class="ip-b">${detailHtml}</div></div>`;
  }

  function detBlock(id, ds) {
    const T_ = t();
    const def = Detector.DETECTORS.find((d) => d.id === id);
    const sev = def ? def.severity : aggSev(id);
    const name = detName(id, def ? def.name : aggName(id));
    const owasp = def ? def.owasp : (aggMeta[id] ? aggOwasp(id) : "");
    const mitre = (def && def.mitre) || mitreOf(id);
    const desc = def ? def.desc : (ds[0].detail || "");
    const rem = def ? def.rem : aggRem(id);
    const perReq = ds.filter((d) => !d.aggregate);
    const ev = perReq.slice(0, 4).map((d) => evidenceLine(d)).join("");
    const more = perReq.length > 4 ? `<div class="more">${T_.andMore(perReq.length - 4)}</div>` : "";
    const aggLine = ds.find((d) => d.aggregate);
    return `<div class="det"><div class="det-h"><span class="badge sev-${sev}">${esc(T_.sevName[sev])}</span><span class="nm">${esc(name)}</span>
      ${owasp ? `<span class="tag owasp">OWASP ${esc(owasp)}</span>` : ""}${mitre ? `<span class="tag att">ATT&CK ${esc(mitre)}</span>` : ""}<span class="tag">${perReq.length || (aggLine ? 1 : 0)}×</span></div>
      <div class="det-b"><p>${esc(desc)}</p>${aggLine ? `<p class="mono" style="color:var(--tx)">${esc(aggLine.detail)}</p>` : ""}
      ${ev ? `<div class="evidence"><div class="hint">${T_.evidence}:</div>${ev}${more}</div>` : ""}
      <div class="rem"><b>→</b> ${esc(rem)}</div></div></div>`;
  }

  function evidenceLine(d) {
    // resalta el fragmento que disparó la detección dentro de la línea cruda
    let raw = esc(d.raw || "");
    if (d.match) {
      const m = esc(d.match);
      const idx = raw.indexOf(m);
      if (idx >= 0) raw = raw.slice(0, idx) + '<span class="hl">' + m + "</span>" + raw.slice(idx + m.length);
    }
    return `<div class="ev">${raw}</div>`;
  }

  function renderTimeline(entries, res) {
    const T_ = t();
    const { from, to } = res.timespan;
    if (!from || !to || from.getTime() === to.getTime()) return "";
    const BINS = 48, span = to - from;
    const bins = Array.from({ length: BINS }, () => ({ n: 0, att: 0 }));
    const suspIps = new Set(res.suspiciousIps.map((x) => x.ip));
    const attackLines = new Set();
    for (const ip of res.suspiciousIps) for (const d of ip.detections) if (d.lineNo) attackLines.add(d.lineNo);
    for (const e of entries) {
      if (!e.parsed || !e.date) continue;
      const b = Math.min(BINS - 1, Math.floor(((e.date - from) / span) * BINS));
      bins[b].n++;
      if (attackLines.has(e.lineNo)) bins[b].att++;
    }
    const max = Math.max(1, ...bins.map((b) => b.n));
    const bars = bins.map((b) => `<div class="b ${b.att ? "att" : ""}" style="height:${Math.max(3, (b.n / max) * 100)}%" title="${b.n} ${T_.requests}${b.att ? ", " + b.att + " ⚠" : ""}"></div>`).join("");
    void suspIps;
    return `<div class="card"><div class="card-h"><h2>${T_.timeline}</h2></div><div class="timeline">${bars}</div>
      <div class="axis"><span>${fmtTime(from)}</span><span style="color:var(--crit)">■ ${lang === "es" ? "con ataques" : "with attacks"}</span><span>${fmtTime(to)}</span></div></div>`;
  }

  // ---- exportación
  function doExport(kind) {
    if (!lastResult) return;
    if (kind === "md") copy(exportMd(lastResult.res), t().copied);
    if (kind === "json") copy(JSON.stringify(serialize(lastResult.res), null, 2), t().copied);
    if (kind === "fb") copy(exportFb(lastResult.res), t().copied);
  }
  function serialize(res) {
    return {
      source: "weblog-sentinel",
      summary: { totalRequests: res.totalRequests, totalIps: res.totalIps, suspiciousIps: res.suspiciousIps.length, detections: res.detectionCount },
      byType: res.byType,
      suspects: res.suspiciousIps.map((ip) => ({
        ip: ip.ip, score: ip.score, worst: ip.worst, requests: ip.requests,
        detections: [...new Set(ip.detections.map((d) => d.id))],
      })),
    };
  }
  function exportMd(res) {
    const L = [`# WebLog Sentinel – ${lang === "es" ? "Informe de detección" : "Detection report"}`, "",
      `- ${t().kTotal}: ${res.totalRequests}`, `- ${t().kIps}: ${res.totalIps}`, `- ${t().kSusp}: ${res.suspiciousIps.length}`, `- ${t().kDet}: ${res.detectionCount}`, ""];
    for (const ip of res.suspiciousIps) {
      const types = [...new Set(ip.detections.map((d) => d.id))].map((id) => detName(id, (Detector.DETECTORS.find((d) => d.id === id) || {}).name || aggName(id)));
      L.push(`## ${ip.ip} — ${t().sevName[ip.worst]} (score ${ip.score})`, "", `**${ip.requests} ${t().requests}** · ${types.join(", ")}`, "");
      const seen = new Set();
      for (const d of ip.detections) { if (seen.has(d.id)) continue; seen.add(d.id); const def = Detector.DETECTORS.find((x) => x.id === d.id); L.push(`- **${detName(d.id, def ? def.name : aggName(d.id))}** ${def ? "(OWASP " + def.owasp + ", " + def.mitre + ")" : ""}`); }
      L.push("");
    }
    return L.join("\n");
  }
  function exportFb(res) {
    const sev = res.suspiciousIps[0] ? res.suspiciousIps[0].worst : "info";
    return JSON.stringify({
      source: "weblog-sentinel",
      title: lang === "es" ? "Actividad de ataque detectada en logs" : "Attack activity detected in logs",
      severity: sev,
      detail: `${res.detectionCount} ${lang === "es" ? "detecciones en" : "detections across"} ${res.suspiciousIps.length} ${lang === "es" ? "IPs sospechosas" : "suspicious IPs"}.`,
      suspects: serialize(res).suspects,
    }, null, 2);
  }
  function copy(text, ok) {
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(() => toast(ok)).catch(() => {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); toast(ok); } catch { } ta.remove();
    });
  }

  // mapeos auxiliares para agregados
  function aggOwasp(id) { return { "brute-force": "A07:2021", "dir-scan": "A05:2021", enumeration: "" }[id] || ""; }
  function mitreOf(id) { return { "brute-force": "T1110", "dir-scan": "T1595", enumeration: "T1595" }[id] || ""; }
  function aggRem(id) {
    const r = {
      es: { "brute-force": "Limitar intentos por IP y por cuenta, aplicar MFA y CAPTCHA, y alertar ante este patrón.", "dir-scan": "Bloquear la IP, ocultar recursos sensibles y considerar un WAF que corte el escaneo.", enumeration: "Monitorear; si persiste, limitar la tasa de peticiones por IP." },
      en: { "brute-force": "Rate-limit per IP and account, enforce MFA and CAPTCHA, and alert on this pattern.", "dir-scan": "Block the IP, hide sensitive resources and consider a WAF to stop scanning.", enumeration: "Monitor; if it persists, rate-limit requests per IP." },
    };
    return (r[lang] || r.es)[id] || "";
  }

  function fmtTime(d) { return d.toISOString().slice(11, 19); }

  // ---- entrada: archivo, drag&drop, ejemplos
  function loadFile(file) {
    if (!file) return;
    const r = new FileReader();
    r.onload = () => { $("#input").value = String(r.result).slice(0, 8_000_000); analyze(); };
    r.readAsText(file);
  }
  const inp = $("#input");
  ["dragenter", "dragover"].forEach((ev) => inp.addEventListener(ev, (e) => { e.preventDefault(); inp.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => inp.addEventListener(ev, (e) => { e.preventDefault(); inp.classList.remove("drag"); }));
  inp.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]); });
  inp.addEventListener("input", analyze);
  $("#fileInput").addEventListener("change", (e) => { loadFile(e.target.files[0]); e.target.value = ""; });
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    if (b.dataset.act === "example") { $("#input").value = SAMPLE_LOG; analyze(); }
    if (b.dataset.act === "upload") $("#fileInput").click();
    if (b.dataset.act === "clear") { $("#input").value = ""; analyze(); }
  });
  $("#lang").addEventListener("change", (e) => { lang = e.target.value; render(); });

  function renderAbout() {
    const T_ = t();
    $("#about").innerHTML = lang === "es" ? `
      <h2 style="font-size:17px">${T_.aboutTitle}</h2>
      <p>Cada vez que alguien accede a un servidor web queda una línea en el <b>log de acceso</b>: la IP, la fecha, qué pidió, el código de respuesta y el navegador. Un ataque deja huellas reconocibles en esas líneas. Esta herramienta las busca.</p>
      <h3>Qué detecta</h3>
      <table><tr><th>Detección</th><th>OWASP</th><th>MITRE ATT&CK</th></tr>
      <tr><td>Inyección SQL</td><td>A03:2021</td><td>T1190</td></tr>
      <tr><td>Cross-Site Scripting (XSS)</td><td>A03:2021</td><td>T1059.007</td></tr>
      <tr><td>Path traversal / LFI</td><td>A01:2021</td><td>T1083</td></tr>
      <tr><td>Inyección de comandos</td><td>A03:2021</td><td>T1190</td></tr>
      <tr><td>Log4Shell (JNDI)</td><td>A06:2021</td><td>T1190</td></tr>
      <tr><td>Sondeo de archivos sensibles</td><td>A05:2021</td><td>T1083</td></tr>
      <tr><td>Herramientas de escaneo (sqlmap, nikto…)</td><td>A05:2021</td><td>T1595</td></tr>
      <tr><td>Fuerza bruta de login</td><td>A07:2021</td><td>T1110</td></tr>
      <tr><td>Escaneo de directorios</td><td>A05:2021</td><td>T1595</td></tr></table>
      <h3>Cómo leerlo</h3>
      <p>Las IPs se ordenan por severidad y por cantidad de detecciones. Abrí cada una para ver la evidencia: las líneas de log exactas, con el fragmento sospechoso resaltado. <b>OWASP</b> indica la categoría de la vulnerabilidad; <b>MITRE ATT&CK</b>, la técnica del atacante.</p>
      <div class="warn-box">⚠️ Es una herramienta de apoyo y aprendizaje, no un SIEM. Puede haber falsos positivos (un parámetro legítimo que parece un ataque) y falsos negativos (ataques ofuscados). Validá siempre la evidencia antes de actuar.</div>
      <p>Referencias: <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener">OWASP Top 10</a> · <a href="https://attack.mitre.org/" target="_blank" rel="noopener">MITRE ATT&CK</a>.</p>`
      : `
      <h2 style="font-size:17px">${T_.aboutTitle}</h2>
      <p>Every request to a web server leaves a line in the <b>access log</b>: the IP, date, what was requested, the response code and the browser. Attacks leave recognizable traces in those lines. This tool looks for them.</p>
      <h3>What it detects</h3>
      <table><tr><th>Detection</th><th>OWASP</th><th>MITRE ATT&CK</th></tr>
      <tr><td>SQL injection</td><td>A03:2021</td><td>T1190</td></tr>
      <tr><td>Cross-Site Scripting (XSS)</td><td>A03:2021</td><td>T1059.007</td></tr>
      <tr><td>Path traversal / LFI</td><td>A01:2021</td><td>T1083</td></tr>
      <tr><td>Command injection</td><td>A03:2021</td><td>T1190</td></tr>
      <tr><td>Log4Shell (JNDI)</td><td>A06:2021</td><td>T1190</td></tr>
      <tr><td>Sensitive file probing</td><td>A05:2021</td><td>T1083</td></tr>
      <tr><td>Scanner tools (sqlmap, nikto…)</td><td>A05:2021</td><td>T1595</td></tr>
      <tr><td>Login brute force</td><td>A07:2021</td><td>T1110</td></tr>
      <tr><td>Directory scanning</td><td>A05:2021</td><td>T1595</td></tr></table>
      <h3>How to read it</h3>
      <p>IPs are ranked by severity and number of detections. Expand each one to see the evidence: the exact log lines with the suspicious fragment highlighted. <b>OWASP</b> is the vulnerability category; <b>MITRE ATT&CK</b> is the attacker technique.</p>
      <div class="warn-box">⚠️ This is a learning and triage aid, not a SIEM. There can be false positives (a legitimate parameter that looks like an attack) and false negatives (obfuscated attacks). Always validate the evidence before acting.</div>
      <p>References: <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener">OWASP Top 10</a> · <a href="https://attack.mitre.org/" target="_blank" rel="noopener">MITRE ATT&CK</a>.</p>`;
  }

  $("#lang").value = lang;
  render();
})();
