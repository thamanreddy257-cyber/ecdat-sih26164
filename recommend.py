"""PQC / hybrid replacement suggestions with qualitative trade-offs.

Trade-offs are deliberately qualitative - no benchmark numbers.
Standards referenced: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
"""
from __future__ import annotations

import pandas as pd

from risk import TIER_RANK, TIERS

KEX = {
    "replacement": "ML-KEM (FIPS 203), or hybrid X25519 + ML-KEM during transition",
    "tradeoff": "Larger public keys and ciphertexts, so more handshake bandwidth; needs library and "
                "peer support; hybrid mode keeps classical security if either component holds.",
    "effort": "High",
}
SIG = {
    "replacement": "ML-DSA (FIPS 204); SLH-DSA (FIPS 205) as a conservative hash-based option",
    "tradeoff": "Larger keys and signatures; SLH-DSA signatures are much larger and slower to sign; "
                "certificate chains, HSMs and verifiers must all support the new algorithm.",
    "effort": "High",
}
PKE = {
    "replacement": "Key transport/exchange: ML-KEM (FIPS 203) or hybrid X25519 + ML-KEM. "
                   "Signing: ML-DSA (FIPS 204)",
    "tradeoff": "RSA usage must first be identified (encryption vs signing); larger keys and "
                "ciphertexts/signatures; needs library support on both ends.",
    "effort": "High",
}

# (match function, recommendation) - first match wins. Order matters.
RECOMMENDATIONS = [
    (lambda r: r.family == "PQC",
     {"replacement": "No change - already post-quantum", "tradeoff": "Track library maturity and "
      "keep crypto-agility so parameters can be updated.", "effort": "Low"}),
    (lambda r: r.kind == "certificate",
     {"replacement": "Re-issue certificate: plan ML-DSA (FIPS 204) or hybrid/composite certificates "
                     "when your CA supports them; meanwhile RSA-3072+ / ECDSA P-256+ with SHA-256",
      "tradeoff": "PQC certificates are larger; CA, client and HSM ecosystem support is still maturing.",
      "effort": "Medium"}),
    (lambda r: r.family == "key-material",
     {"replacement": "Remove the hard-coded key, rotate it, store keys in a secrets manager / HSM; "
                     "generate the replacement with a PQC or hybrid algorithm",
      "tradeoff": "Requires a key-management workflow and redeploying dependent services.",
      "effort": "Medium"}),
    (lambda r: r.algorithm in {"TLSv1.0", "TLSv1.1"},
     {"replacement": "TLS 1.3 only (disable TLS 1.0/1.1), then enable hybrid X25519MLKEM768 key exchange",
      "tradeoff": "Very old clients lose connectivity; hybrid groups need recent TLS libraries.",
      "effort": "Low"}),
    (lambda r: r.algorithm in {"TLSv1.2", "TLSv1.3"},
     {"replacement": "Prefer TLS 1.3 and enable hybrid X25519MLKEM768 key exchange",
      "tradeoff": "Larger ClientHello; needs recent TLS library on client and server; "
                  "middleboxes may need testing.",
      "effort": "Low"}),
    (lambda r: r.algorithm == "Weak TLS cipher list",
     {"replacement": "Restrict to AEAD suites (AES-GCM / ChaCha20-Poly1305) with ECDHE, "
                     "and move to TLS 1.3 suites",
      "tradeoff": "Legacy clients that only speak RC4/3DES lose connectivity.", "effort": "Low"}),
    (lambda r: r.primitive == "key-agree", KEX),
    (lambda r: r.primitive == "signature" and r.family in {"RSA", "ECC", "DH/DSA"}, SIG),
    (lambda r: r.family == "RSA", PKE),
    (lambda r: r.algorithm == "AES-ECB",
     {"replacement": "AES-256-GCM (authenticated encryption)",
      "tradeoff": "Needs unique nonce management; existing ciphertext must be re-encrypted.",
      "effort": "Medium"}),
    (lambda r: r.algorithm == "AES-CBC",
     {"replacement": "AES-256-GCM (or CBC + HMAC encrypt-then-MAC)",
      "tradeoff": "Needs nonce management; data format changes.", "effort": "Medium"}),
    (lambda r: r.family == "AES" and r.param == "128",
     {"replacement": "AES-256 (same mode)",
      "tradeoff": "Slightly more compute per block; key storage and derivation must change.",
      "effort": "Low"}),
    (lambda r: r.family == "legacy-cipher",
     {"replacement": "AES-256-GCM", "tradeoff": "Data re-encryption and protocol/format changes; "
      "peers must be upgraded together.", "effort": "Medium"}),
    (lambda r: r.algorithm in {"MD5", "SHA-1"},
     {"replacement": "SHA-256 or SHA-3 (use HMAC / a password KDF where a key or password is involved)",
      "tradeoff": "Longer digests; stored hashes and signatures must be regenerated.",
      "effort": "Low"}),
]

NO_ACTION = {"replacement": "No change needed (adequate today)",
             "tradeoff": "Keep monitoring; maintain crypto-agility.", "effort": "Low"}


def recommend(row) -> dict:
    for match, rec in RECOMMENDATIONS:
        if match(row):
            return rec
    return NO_ACTION


def add_recommendations(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    recs = [recommend(r) for r in out.itertuples()] if not out.empty else []
    out["replacement"] = [r["replacement"] for r in recs]
    out["tradeoff"] = [r["tradeoff"] for r in recs]
    out["effort"] = [r["effort"] for r in recs]
    return out


def roadmap(df: pd.DataFrame) -> pd.DataFrame:
    """Prioritised roadmap: one row per (tier, asset), Critical first."""
    cols = ["priority", "tier", "asset", "family", "occurrences", "locations",
            "replacement", "tradeoff", "effort"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    d = add_recommendations(df) if "replacement" not in df else df
    d = d.assign(loc=d["file"] + ":" + d["line"].astype(str))
    g = (d.groupby(["tier", "asset", "family", "replacement", "tradeoff", "effort"], sort=False)
          .agg(occurrences=("loc", "size"), locations=("loc", lambda s: ", ".join(s.iloc[:6]) +
                                                       (f" (+{len(s) - 6} more)" if len(s) > 6 else "")))
          .reset_index())
    effort_rank = {"Low": 0, "Medium": 1, "High": 2}
    g["_t"] = g["tier"].map(TIER_RANK)
    g["_e"] = g["effort"].map(effort_rank)
    # Within a tier: most occurrences first, then cheapest fix first (quick wins).
    g = g.sort_values(["_t", "occurrences", "_e"], ascending=[True, False, True]).reset_index(drop=True)
    g["priority"] = range(1, len(g) + 1)
    return g[cols]


__all__ = ["recommend", "add_recommendations", "roadmap", "TIERS"]
