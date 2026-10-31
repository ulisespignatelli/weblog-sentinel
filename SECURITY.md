# Security Policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via **Security → Report a vulnerability** on this repository. Include reproduction steps and impact; I will acknowledge within 7 days.

## Security & privacy design

Access logs contain IP addresses and request data, so the tool is built so that no log ever leaves the user's machine:

- **No backend, no network.** Static site. The CSP sets `connect-src 'none'`, so the page cannot make any network request; the uploaded log is read locally with the `FileReader` API.
- **Strict Content-Security-Policy** (`script-src 'self'`, no inline scripts, `form-action 'none'`, `object-src 'none'`, `base-uri 'none'`).
- **Output encoding.** Every value rendered from a log line (URL, user-agent, the raw line shown as evidence) is HTML-escaped first, so a crafted log line containing an XSS payload cannot execute in the analyzer itself — it is shown as inert text with the payload highlighted. This is covered by the test suite and is intentional: the tool analyzes hostile input by design.
- **Bounded work.** Per-IP stored samples and the input size are capped to keep a huge log from freezing the tab.
- **Supply chain.** Zero third-party dependencies. CodeQL and Dependabot are enabled.

## Intended use

For analyzing logs from systems you own or are **authorized** to review (incident response, pentest reporting, learning). Detections are heuristic and may produce false positives/negatives — always validate the evidence.
