# ECDAT - Enterprise Cryptographic Discovery & Analysis Tool

**Phase 1 prototype** for SIH 2026, problem statement SIH26164 (NTRO).
It scans source code, config files and X.509 certificates for cryptography, scores each finding with
Mosca's inequality, suggests post-quantum (PQC) replacements and exports a CycloneDX 1.6 CBOM.

ECDAT runs fully offline: it makes no network calls and sends no telemetry (Streamlit usage stats are
switched off in `.streamlit/config.toml`). Binary, container and KMS/HSM scanning are **not** part of
Phase 1. They are on the roadmap.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

The dashboard scans the bundled `sample_repo/` on start-up, so the demo works without any setup.
To scan something else, enter a folder path in the sidebar or upload a `.zip`.

Before a demo, run `python make_sample.py` to regenerate the sample repo. This refreshes the
certificate expiry dates: the legacy RSA-1024/SHA-1 certificate is created to expire 60 days after generation.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

`tests/test_cbom.py::test_official_schema` validates the CBOM against the official CycloneDX 1.6
JSON schema that ships with `cyclonedx-python-lib`. If that library is not installed, the test is skipped.

## Deploy to Streamlit Community Cloud

1. Push this folder to a GitHub repo, with `app.py` at the repo root (or note its sub-path).
   Commit `sample_repo/` and `.streamlit/config.toml` too.
2. Go to <https://share.streamlit.io> and choose **Create app**. Pick the repo and branch, set the main file to `app.py`
   (or `ecdat/app.py` if it is in a sub-folder), then **Deploy**.
3. `requirements.txt` is installed automatically. Under *Advanced settings* you can pick a Python version (3.10 or newer).

On Cloud, the folder-path box can only reach files inside the deployed repo, such as `sample_repo`.
Use the zip upload to scan other code.

## Layout

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI (scan results cached in `st.session_state`; sliders only re-score) |
| `scanner.py` | Folder walk, line-by-line rules, PEM key loading, X.509 parsing, de-duplication |
| `rules.py` | Detection rules and knowledge base. Add a detection by appending a `Rule(...)` |
| `risk.py` | Mosca engine, tier thresholds, path-keyword criticality map |
| `recommend.py` | PQC / hybrid replacements, qualitative trade-offs, roadmap ordering |
| `cbom.py` | CycloneDX 1.6 CBOM writer and validator |
| `report.py` | CSV and PDF (reportlab) export |
| `make_sample.py` | Generates `sample_repo/`. All keys and certs in it are throwaway test material |

## CBOM field names

All CycloneDX fields used by `cbom.py` were checked against the official `bom-1.6.SNAPSHOT.schema.json`
bundled with `cyclonedx-python-lib`, and the generated CBOM passes strict schema validation in the tests.
Fields used: `cryptoProperties.assetType`, `algorithmProperties.{primitive, parameterSetIdentifier, curve,
mode, nistQuantumSecurityLevel}`, `certificateProperties.{subjectName, issuerName, notValidBefore,
notValidAfter, signatureAlgorithmRef, subjectPublicKeyRef, certificateFormat}`,
`protocolProperties.{type, version, cipherSuites[].name}`, `relatedCryptoMaterialProperties.{type, size,
format}`, `evidence.occurrences[].{location, line, additionalContext}`, and `properties[]`.

**Unverified fields:** none. Fields we were unsure of (for example `oid` values and `cryptoFunctions`)
are left out rather than guessed.

ECDAT-specific data (tier, confidence, overshoot, recommendation) goes into `properties` under the
`ecdat:` namespace. The private-key *value* is never written to the CBOM.

## Honest limitations

- Detection is regex-based. Results marked *medium* confidence are keyword hits and need a manual check.
  Crypto used through wrappers or configuration that the rules don't cover will be missed.
- The criticality map and the X/Y/Z defaults are illustrative. Z is a scenario parameter, not a prediction.
- Trade-offs are qualitative. ECDAT includes no benchmarks.
