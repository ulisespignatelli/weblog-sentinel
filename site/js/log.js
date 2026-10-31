/*
 * Parser de logs de acceso web para WebLog Sentinel.
 * Soporta los formatos comunes de Nginx y Apache (Common y Combined Log Format).
 * Puro y sin DOM: corre igual en el navegador (window.LogParser) y en Node (tests).
 */
(function (root) {
  "use strict";

  // host ident auth [date] "METHOD url proto" status bytes "referer" "user-agent"
  const CLF = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

  // 30/Oct/2026:14:22:01 +0000  ->  Date (UTC)
  function parseDate(s) {
    const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+\-]\d{4})?/.exec(s || "");
    if (!m) return null;
    const off = m[7] || "+0000";
    const sign = off[0] === "-" ? -1 : 1;
    const offMin = sign * (parseInt(off.slice(1, 3), 10) * 60 + parseInt(off.slice(3, 5), 10));
    const utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]) - offMin * 60000;
    const d = new Date(utc);
    return isNaN(d) ? null : d;
  }

  function safeDecode(s) {
    let out = s;
    for (let i = 0; i < 2; i++) { // doble decode para payloads tipo %252e%252e
      try { const dec = decodeURIComponent(out); if (dec === out) break; out = dec; } catch { break; }
    }
    return out;
  }

  function parseRequest(req) {
    if (!req || req === "-") return { method: "", url: "", protocol: "", rawUrl: "" };
    const parts = req.split(" ");
    const method = parts[0] || "";
    const protocol = parts.length > 2 ? parts[parts.length - 1] : "";
    const rawUrl = parts.length > 2 ? parts.slice(1, -1).join(" ") : (parts[1] || "");
    return { method, protocol, rawUrl, url: safeDecode(rawUrl) };
  }

  function parseLine(line, lineNo) {
    const raw = String(line).trim();
    if (!raw) return null;
    const m = CLF.exec(raw);
    if (!m) return { lineNo, raw, parsed: false };
    const req = parseRequest(m[4]);
    const qIdx = req.url.indexOf("?");
    return {
      lineNo, raw, parsed: true,
      ip: m[1],
      user: m[2] === "-" ? "" : m[2],
      date: parseDate(m[3]),
      dateStr: m[3],
      method: req.method,
      url: req.url,
      rawUrl: req.rawUrl,
      path: qIdx >= 0 ? req.url.slice(0, qIdx) : req.url,
      query: qIdx >= 0 ? req.url.slice(qIdx + 1) : "",
      protocol: req.protocol,
      status: parseInt(m[5], 10),
      bytes: m[6] === "-" ? 0 : parseInt(m[6], 10) || 0,
      referer: m[7] || "",
      userAgent: m[8] || "",
    };
  }

  function parseLog(text) {
    const lines = String(text).split(/\r?\n/);
    const entries = [];
    let parsed = 0, failed = 0;
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const e = parseLine(lines[i], i + 1);
      if (!e) continue;
      if (e.parsed) parsed++; else failed++;
      entries.push(e);
    }
    return { entries, stats: { total: entries.length, parsed, failed } };
  }

  const api = { parseLine, parseLog, parseDate, safeDecode, parseRequest };
  root.LogParser = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
