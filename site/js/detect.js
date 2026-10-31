/*
 * Motor de detección de WebLog Sentinel.
 *  - DETECTORS: reglas por petición (firmas de SQLi, XSS, traversal, etc.).
 *  - analyze(entries): corre las reglas, correlaciona por IP, detecta ataques por volumen
 *    (fuerza bruta, escaneo) y calcula un puntaje de riesgo por IP.
 * Cada detección se mapea al OWASP Top 10 y a una técnica de MITRE ATT&CK.
 * Puro y sin DOM.
 */
(function (root) {
  "use strict";

  const SEV_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };

  // ---- reglas por petición. Se evalúan sobre la URL decodificada y el user-agent.
  const DETECTORS = [
    {
      id: "sqli", name: "Inyección SQL", severity: "critical", owasp: "A03:2021", mitre: "T1190",
      patterns: [/\bunion\b[\s\S]{0,60}\bselect\b/i, /'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+/i, /\bselect\b[\s\S]{0,60}\bfrom\b/i,
        /\b(sleep|benchmark|pg_sleep)\s*\(/i, /\bwaitfor\s+delay\b/i, /\b(information_schema|updatexml|extractvalue)\b/i, /'\s*(or|and)\s+'1'\s*=\s*'1/i, /\bor\b\s+1\s*=\s*1/i],
      where: "url",
      desc: "Intento de inyección SQL: manipular una consulta a la base de datos a través de un parámetro.",
      rem: "Usar consultas parametrizadas (prepared statements). Bloquear la IP y revisar si alguna petición tuvo éxito (status 200 con payload).",
    },
    {
      id: "xss", name: "Cross-Site Scripting (XSS)", severity: "high", owasp: "A03:2021", mitre: "T1059.007",
      patterns: [/<script\b/i, /javascript:/i, /\bon(error|load|mouseover|focus)\s*=/i, /<img[^>]+src\s*=/i, /<svg\b/i, /<iframe\b/i, /document\.cookie/i, /alert\s*\(/i],
      where: "url",
      desc: "Intento de inyección de JavaScript en un parámetro para ejecutarlo en el navegador de otros usuarios.",
      rem: "Codificar la salida según el contexto y aplicar Content-Security-Policy. Revisar si el parámetro se refleja sin escapar.",
    },
    {
      id: "path-traversal", name: "Path traversal / LFI", severity: "high", owasp: "A01:2021", mitre: "T1083",
      patterns: [/\.\.[\/\\]/, /\/etc\/(passwd|shadow)/i, /\bboot\.ini\b/i, /\/proc\/self\//i, /\bwin\.ini\b/i, /php:\/\/filter/i, /\bfile:\/\//i],
      where: "url",
      desc: "Intento de leer archivos fuera del directorio web usando secuencias como ../ o rutas absolutas.",
      rem: "No construir rutas con datos del usuario; normalizar y validar contra un directorio base. Revisar qué archivos respondieron con 200.",
    },
    {
      id: "cmd-injection", name: "Inyección de comandos", severity: "critical", owasp: "A03:2021", mitre: "T1190",
      patterns: [/[;|`]\s*(id|whoami|cat|ls|uname|wget|curl|nc|bash|sh|ping|dir|type)\b/i, /\$\([^)]*\)/, /%0a\s*(id|whoami|cat|ls)/i, /\|\s*(id|whoami|cat)\b/i],
      where: "url",
      desc: "Intento de ejecutar comandos del sistema operativo encadenándolos con caracteres como ; | o $().",
      rem: "Evitar invocar comandos del sistema con datos del usuario. Si el status fue 200/500, investigar como posible compromiso.",
    },
    {
      id: "log4shell", name: "Log4Shell (JNDI)", severity: "critical", owasp: "A06:2021", mitre: "T1190",
      patterns: [/\$\{jndi:(ldap|rmi|dns|ldaps):/i, /\$\{[^}]*j[^}]*n[^}]*d[^}]*i/i],
      where: "both",
      desc: "Intento de explotar Log4Shell (CVE-2021-44228) mediante una cadena JNDI, normalmente en el User-Agent o un header.",
      rem: "Actualizar Log4j a 2.17+ o mitigar. Es explotación activa (está en el catálogo CISA KEV): tratar como incidente.",
    },
    {
      id: "ssti", name: "Server-Side Template Injection", severity: "high", owasp: "A03:2021", mitre: "T1190",
      patterns: [/\{\{[\s\S]{0,40}[*+\-/]{1}[\s\S]{0,40}\}\}/, /\$\{\s*\d+\s*[*+\-]\s*\d+\s*\}/, /<%[\s\S]{0,40}%>/],
      where: "url",
      desc: "Intento de inyección en un motor de plantillas (por ejemplo {{7*7}}) para ejecutar código en el servidor.",
      rem: "No pasar datos del usuario al motor de plantillas. Usar sandboxing del motor.",
    },
    {
      id: "sensitive-file", name: "Sondeo de archivos sensibles", severity: "medium", owasp: "A05:2021", mitre: "T1083",
      patterns: [/\/\.env\b/i, /\/\.git\//i, /\/\.svn\//i, /\/\.aws\//i, /\/wp-(admin|login|config)/i, /\/phpmyadmin/i,
        /\/\.htaccess\b/i, /\/config\.(php|json|ya?ml|inc)\b/i, /\.(bak|old|sql|zip|tar\.gz|backup|swp)(\?|$)/i, /\/(id_rsa|id_dsa)\b/i, /\/\.DS_Store\b/i],
      where: "path",
      desc: "Petición a archivos o rutas sensibles que no deberían ser públicos (código, credenciales, backups, paneles).",
      rem: "Quitar esos archivos del directorio público y bloquear su acceso. Rotar cualquier credencial que haya quedado expuesta.",
    },
    {
      id: "scanner-ua", name: "Herramienta de escaneo detectada", severity: "medium", owasp: "A05:2021", mitre: "T1595",
      patterns: [/\b(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|nuclei|acunetix|nessus|zgrab|hydra|ffuf|feroxbuster|dirb|whatweb|arachni|openvas)\b/i],
      where: "ua",
      desc: "El User-Agent corresponde a una herramienta de escaneo o ataque automatizado.",
      rem: "No es concluyente (el UA se falsifica), pero combinado con otros indicadores, señala una IP hostil. Revisar y considerar bloqueo.",
    },
    {
      id: "suspicious-ua", name: "Cliente automatizado (no navegador)", severity: "low", owasp: "", mitre: "T1595",
      patterns: [/\b(curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|java\/\d|okhttp)\b/i],
      where: "ua",
      desc: "Cliente automatizado (no es un navegador). Puede ser legítimo (una API), pero también reconocimiento.",
      rem: "Contextualizar: una ráfaga de estas peticiones hacia muchas rutas sugiere escaneo.",
    },
  ];

  function detectOnEntry(e) {
    if (!e.parsed) return [];
    const hits = [];
    const url = e.url || "", path = e.path || "", ua = e.userAgent || "";
    for (const det of DETECTORS) {
      const haystacks = det.where === "ua" ? [ua] : det.where === "path" ? [path] : det.where === "both" ? [url, ua] : [url];
      for (const h of haystacks) {
        const p = det.patterns.find((re) => re.test(h));
        if (p) { hits.push({ id: det.id, name: det.name, severity: det.severity, owasp: det.owasp, mitre: det.mitre, match: (p.exec(h) || [""])[0].slice(0, 120) }); break; }
      }
    }
    return hits;
  }

  // ---- análisis completo
  function analyze(entries, opts = {}) {
    const bruteThreshold = opts.bruteThreshold || 15;   // fallos de login/auth por IP
    const scanThreshold = opts.scanThreshold || 25;     // 404 o rutas únicas por IP
    const ips = new Map();

    const getIp = (ip) => {
      if (!ips.has(ip)) ips.set(ip, { ip, requests: 0, statuses: {}, paths: new Set(), authFails: 0, notFound: 0, detections: [], firstSeen: null, lastSeen: null, entries: [] });
      return ips.get(ip);
    };

    let detTotal = 0;
    for (const e of entries) {
      if (!e.parsed || !e.ip) continue;
      const rec = getIp(e.ip);
      rec.requests++;
      rec.statuses[e.status] = (rec.statuses[e.status] || 0) + 1;
      rec.paths.add(e.path);
      if (e.status === 404) rec.notFound++;
      const isAuth = /log[\-_]?in|sign[\-_]?in|auth|wp-login|session/i.test(e.path);
      if ((e.status === 401 || e.status === 403) || (isAuth && e.method === "POST" && (e.status === 200 || e.status === 302 || e.status === 401))) {
        if (e.status === 401 || e.status === 403 || (isAuth && e.method === "POST")) rec.authFails++;
      }
      if (e.date) { if (!rec.firstSeen || e.date < rec.firstSeen) rec.firstSeen = e.date; if (!rec.lastSeen || e.date > rec.lastSeen) rec.lastSeen = e.date; }
      const hits = detectOnEntry(e);
      for (const h of hits) { rec.detections.push({ ...h, lineNo: e.lineNo, url: e.rawUrl, status: e.status, date: e.dateStr, raw: e.raw }); detTotal++; }
      if (rec.entries.length < 500) rec.entries.push(e);
    }

    // detecciones por volumen (agregadas)
    const addAgg = (rec, id, name, severity, owasp, mitre, detail) =>
      rec.detections.push({ id, name, severity, owasp, mitre, aggregate: true, detail });

    for (const rec of ips.values()) {
      if (rec.authFails >= bruteThreshold)
        addAgg(rec, "brute-force", "Fuerza bruta de autenticación", "high", "A07:2021", "T1110",
          `${rec.authFails} peticiones de login/auth fallidas o repetidas desde esta IP.`);
      if (rec.notFound >= scanThreshold)
        addAgg(rec, "dir-scan", "Escaneo de directorios", "medium", "A05:2021", "T1595",
          `${rec.notFound} respuestas 404: patrón típico de fuerza bruta de rutas o descubrimiento de contenido.`);
      else if (rec.paths.size >= scanThreshold * 2)
        addAgg(rec, "enumeration", "Enumeración de endpoints", "low", "", "T1595",
          `${rec.paths.size} rutas distintas solicitadas desde esta IP.`);

      // puntaje de riesgo
      rec.score = rec.detections.reduce((a, d) => a + (SEV_WEIGHT[d.severity] || 0), 0);
      rec.worst = ["critical", "high", "medium", "low", "info"].find((s) => rec.detections.some((d) => d.severity === s)) || null;
      rec.pathCount = rec.paths.size;
      delete rec.paths;
    }

    const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, null: 5 };
    const suspicious = [...ips.values()].filter((r) => r.detections.length > 0)
      .sort((a, b) => (SEV_RANK[a.worst] - SEV_RANK[b.worst]) || (b.score - a.score));
    const byType = {};
    for (const rec of ips.values()) for (const d of rec.detections) byType[d.id] = (byType[d.id] || 0) + 1;

    return {
      totalRequests: entries.filter((e) => e.parsed).length,
      totalIps: ips.size,
      suspiciousIps: suspicious,
      detectionCount: detTotal,
      byType,
      timespan: timespan(entries),
    };
  }

  function timespan(entries) {
    let min = null, max = null;
    for (const e of entries) if (e.date) { if (!min || e.date < min) min = e.date; if (!max || e.date > max) max = e.date; }
    return { from: min, to: max };
  }

  const api = { DETECTORS, detectOnEntry, analyze, SEV_WEIGHT };
  root.Detector = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
