# Bounded live-door probe and 2026 anomaly classification

## Preregistration

- Candidate list: 195 paths built only from creator/page-authenticated vocabulary.
- Seal: `b2936e7fff2d27b03ea9eebdbb3458881018e890cf6c2ad779c57e57ecc277ef`.
- Intended acceptance: both byte length and SHA-256 differ from the app-shell controls.

## Live result on 2026-08-04

The prerequisite behind that acceptance rule is no longer true: `gsmg.io` does not currently serve the puzzle app shell. DNS resolves to `103.224.212.141`, and the host serves a domain-parking fingerprint/redirect template.

The bounded run obtained:

- three nonexistent-path controls;
- both historically real controls (`/theseedisplanted` and `/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself`);
- the first 20 lexicographically ordered sealed candidates.

All 25 responses returned HTTP 200, title `gsmg.io`, and exactly obeyed:

```text
response_length = 1029 + 3 * len(path)
```

The three length contributions are the same requested path reflected into the parking redirect script/fallback links. Consequently, different length and SHA-256 are automatic for every distinct path and cannot identify a real page. The server then rate-limited/reset repeated TLS connections. The remaining sealed paths were not sent because the first 25 responses already identify one deterministic path-reflecting template and the original app-shell acceptance control no longer exists live.

**Classification:** no live candidate was accepted. As of this probe, the historic puzzle pages are no longer live at their distinct content; `another door` cannot presently be discovered by live path enumeration on `gsmg.io`.

Raw request metadata is preserved in `live_probe_checkpoint.json`. No cipher or password test was performed.

## 2026-07-08 `/4f7a1e4e…` captures

CDX records:

1. `20260708020344`, path `/4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081`, CDX length 1,253.
2. `20260708020345`, the same path plus `tr_uuid` and fingerprint parameters, CDX length 906.

The first archived body is an automated parking-domain fingerprint page. It loads `/js/fingerprint/iife.min.js`, computes a visitor fingerprint, and redirects to the same path with `tr_uuid=...&fp=...`; JavaScript-disabled and timeout fallbacks do the same.

The second archived body is:

```html
<!DOCTYPE html>
<html>
<head>
<title>gsmg.io</title>
<script async src="https://assets.abovedomains.com/javascript/forsale.min.js?d=gsmg.io"></script>
<style>body{background:#101c36;color:#fff}h1{text-align:center;margin-top:1rem}</style>
</head>
<body>
<h1>gsmg.io</h1>
</body>
</html>
```

**Classification:** parking/for-sale infrastructure, not a puzzle door, app shell, or creator payload.
