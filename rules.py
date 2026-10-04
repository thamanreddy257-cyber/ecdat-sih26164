"""Detection rules and algorithm knowledge base for ECDAT.

Each Rule is one regex applied line by line. To add a detection, append a
Rule(...) to RULES - nothing else needs to change.

Confidence:
  high   - exact API call / identifier match (e.g. KeyPairGenerator.getInstance("RSA"))
  medium - keyword in a config value, string or comment (e.g. "RSA" in a cipher list)
A medium rule is upgraded to high when the same line also matches its
`high_context` regex (e.g. TLSv1 inside an `ssl_protocols` directive).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Families used across the tool. "legacy-cipher" covers DES / 3DES / RC4.
FAMILIES = ["RSA", "ECC", "DH/DSA", "AES", "legacy-cipher", "hash",
            "protocol", "PQC", "key-material"]

ANY = ("any",)
PY, JAVA, JS, GO, CONF = ("py",), ("java",), ("js", "ts", "mjs"), ("go",), ("conf", "cfg", "ini", "yaml", "yml", "toml", "properties", "xml")

# File extension -> language hint used by the `languages` field.
EXT_LANG = {
    ".py": "py", ".java": "java", ".kt": "java", ".js": "js", ".mjs": "js", ".ts": "ts",
    ".go": "go", ".conf": "conf", ".cfg": "cfg", ".ini": "ini", ".yaml": "yaml",
    ".yml": "yml", ".toml": "toml", ".properties": "properties", ".xml": "xml",
}


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str              # base algorithm name, e.g. "RSA", "AES-ECB", "TLSv1.0"
    family: str                 # one of FAMILIES
    pattern: str                # regex searched on each line
    languages: tuple = ANY      # language hints; "any" = every text file
    confidence: str = "high"    # "high" | "medium"
    quantum_vulnerable: bool = False   # broken by Shor's algorithm on a CRQC
    classically_weak: bool = False     # already weak today, quantum or not
    notes: str = ""
    primitive: str = "unknown"  # CycloneDX 1.6 algorithmProperties.primitive
    kind: str = "algorithm"     # CycloneDX assetType: algorithm | protocol | related-crypto-material
    param_pattern: str = ""     # optional regex; group(1) = key size / curve / parameter set
    high_context: str = ""      # optional regex; upgrades medium -> high on the same line
    _rx: re.Pattern = field(default=None, repr=False, compare=False)

    def regex(self) -> re.Pattern:
        if self._rx is None:
            object.__setattr__(self, "_rx", re.compile(self.pattern))
        return self._rx

    def applies_to(self, lang: str) -> bool:
        return "any" in self.languages or lang in self.languages


RSA_NOTE = "RSA is broken by Shor's algorithm on a CRQC (harvest-now-decrypt-later risk)."
ECC_NOTE = "Elliptic-curve crypto is broken by Shor's algorithm on a CRQC."
DH_NOTE = "Finite-field DH / DSA are broken by Shor's algorithm on a CRQC."
TLS_PQ_NOTE = "Key exchange is classical (ECDHE/RSA) unless hybrid PQC groups are configured."

RULES: list[Rule] = [
    # ---------------- RSA ----------------
    Rule("RSA-PY-GEN", "RSA", "RSA", r"rsa\.generate_private_key\s*\(", PY,
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke",
         param_pattern=r"key_size\s*=\s*(\d+)"),
    Rule("RSA-JAVA-KPG", "RSA", "RSA", r'KeyPairGenerator\.getInstance\(\s*"RSA"', JAVA,
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke",
         param_pattern=r"initialize\(\s*(\d+)"),
    Rule("RSA-JAVA-CIPHER", "RSA", "RSA", r'Cipher\.getInstance\(\s*"RSA', JAVA,
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke"),
    Rule("RSA-JS-GEN", "RSA", "RSA", r"""generateKeyPair(?:Sync)?\(\s*['"]rsa['"]""", JS,
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke",
         param_pattern=r"modulusLength\s*:\s*(\d+)"),
    Rule("RSA-GO-GEN", "RSA", "RSA", r"rsa\.GenerateKey\s*\(", GO,
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke",
         param_pattern=r"GenerateKey\([^,]*,\s*(\d+)"),
    Rule("RSA-KEYWORD", "RSA", "RSA", r"\bRSA\b", confidence="medium",
         quantum_vulnerable=True, notes=RSA_NOTE, primitive="pke"),
    Rule("SIG-SHA1-RSA", "SHA1withRSA", "RSA", r"\bSHA1with(?:RSA|RSAEncryption)\b",
         quantum_vulnerable=True, classically_weak=True, primitive="signature",
         notes="RSA signature over SHA-1: SHA-1 collisions are practical; RSA is quantum-vulnerable."),
    Rule("SIG-SHA2-RSA", "SHA256withRSA", "RSA", r"\bSHA(?:256|384|512)withRSA\b",
         quantum_vulnerable=True, primitive="signature", notes=RSA_NOTE),

    # ---------------- ECC ----------------
    Rule("EC-JAVA-KPG", "ECDSA", "ECC", r'KeyPairGenerator\.getInstance\(\s*"EC"', JAVA,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="signature",
         param_pattern=r'ECGenParameterSpec\(\s*"([\w-]+)"'),
    Rule("SIG-ECDSA-JAVA", "ECDSA", "ECC", r"\bSHA\d+withECDSA\b", JAVA,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="signature"),
    Rule("EC-PY-GEN", "ECDSA", "ECC", r"ec\.generate_private_key\s*\(", PY,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="signature",
         param_pattern=r"ec\.(SECP\d+[RK]1)"),
    Rule("ECDH-JS", "ECDH", "ECC", r"createECDH\s*\(", JS,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="key-agree",
         param_pattern=r"""createECDH\(\s*['"]([\w-]+)['"]"""),
    Rule("ECDH-GO", "ECDH", "ECC", r"ecdh\.(?:P256|P384|P521|X25519)\s*\(", GO,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="key-agree",
         param_pattern=r"ecdh\.(P256|P384|P521|X25519)"),
    Rule("ECDSA-GO", "ECDSA", "ECC", r"ecdsa\.GenerateKey\s*\(", GO,
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="signature",
         param_pattern=r"elliptic\.(P\d+)"),
    Rule("ECDSA-KEYWORD", "ECDSA", "ECC", r"\bECDSA\b", confidence="medium",
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="signature"),
    Rule("ECDH-KEYWORD", "ECDH", "ECC", r"\b(?:ECDHE?|X25519)\b", confidence="medium",
         quantum_vulnerable=True, notes=ECC_NOTE, primitive="key-agree"),

    # ---------------- DH / DSA ----------------
    Rule("DH-JAVA-KPG", "DH", "DH/DSA", r'KeyPairGenerator\.getInstance\(\s*"(?:DH|DiffieHellman)"', JAVA,
         quantum_vulnerable=True, notes=DH_NOTE, primitive="key-agree"),
    Rule("DH-PY-PARAMS", "DH", "DH/DSA", r"dh\.generate_parameters\s*\(", PY,
         quantum_vulnerable=True, notes=DH_NOTE, primitive="key-agree",
         param_pattern=r"key_size\s*=\s*(\d+)"),
    Rule("DSA-JAVA-KPG", "DSA", "DH/DSA", r'KeyPairGenerator\.getInstance\(\s*"DSA"', JAVA,
         quantum_vulnerable=True, notes=DH_NOTE, primitive="signature"),
    Rule("DSA-PY-GEN", "DSA", "DH/DSA", r"dsa\.generate_private_key\s*\(", PY,
         quantum_vulnerable=True, notes=DH_NOTE, primitive="signature"),
    Rule("DH-KEYWORD", "DH", "DH/DSA", r"\b(?:Diffie-?Hellman|DHE)\b", confidence="medium",
         quantum_vulnerable=True, notes=DH_NOTE, primitive="key-agree"),

    # ---------------- AES (mode + key size) ----------------
    Rule("AES-PY-ECB", "AES-ECB", "AES", r"modes\.ECB\s*\(", PY, classically_weak=True,
         primitive="block-cipher", param_pattern=r"(?:AES|key)[-_ ]?(128|192|256)",
         notes="ECB leaks plaintext patterns (identical blocks -> identical ciphertext)."),
    Rule("AES-PY-CBC", "AES-CBC", "AES", r"modes\.CBC\s*\(", PY, primitive="block-cipher",
         param_pattern=r"(?:AES|key)[-_ ]?(128|192|256)",
         notes="CBC has no integrity; padding-oracle risk if not paired with a MAC."),
    Rule("AES-PY-GCM", "AES-GCM", "AES", r"\bAESGCM\b|modes\.GCM\s*\(", PY, primitive="ae",
         param_pattern=r"bit_length\s*=\s*(\d+)",
         notes="Authenticated encryption. AES-256 keeps an adequate margin against Grover's algorithm."),
    Rule("AES-JAVA-DEFAULT", "AES-ECB", "AES", r'Cipher\.getInstance\(\s*"AES"\s*\)', JAVA,
         classically_weak=True, primitive="block-cipher",
         notes='Cipher.getInstance("AES") defaults to AES/ECB/PKCS5Padding in the SunJCE provider.'),
    Rule("AES-JAVA-ECB", "AES-ECB", "AES", r'"AES/ECB', JAVA, classically_weak=True,
         primitive="block-cipher", notes="ECB leaks plaintext patterns."),
    Rule("AES-JAVA-CBC", "AES-CBC", "AES", r'"AES/CBC', JAVA, primitive="block-cipher",
         notes="CBC has no integrity; padding-oracle risk if not paired with a MAC."),
    Rule("AES-JAVA-GCM", "AES-GCM", "AES", r'"AES/GCM', JAVA, primitive="ae",
         notes="Authenticated encryption."),
    Rule("AES-KEYWORD", "AES", "AES", r"\bAES(?:-?(?:128|192|256))?\b", confidence="medium",
         primitive="block-cipher", param_pattern=r"AES-?(128|192|256)",
         notes="AES keyword in config/string/comment; mode not visible."),

    # ---------------- Legacy ciphers ----------------
    Rule("3DES", "3DES", "legacy-cipher", r"\b(?:DESede|TripleDES|3DES|DES-CBC3|des-ede3)\b",
         classically_weak=True, primitive="block-cipher",
         high_context=r'getInstance\(|algorithms\.TripleDES|createCipheriv',
         confidence="medium", notes="64-bit block (Sweet32); deprecated by NIST."),
    Rule("DES", "DES", "legacy-cipher", r'Cipher\.getInstance\(\s*"DES[/"]|\bDES-CBC\b',
         classically_weak=True, primitive="block-cipher", notes="56-bit key; brute-forceable."),
    Rule("RC4", "RC4", "legacy-cipher", r"\b(?:RC4|ARC4|arcfour)\b", confidence="medium",
         classically_weak=True, primitive="stream-cipher",
         high_context=r"algorithms\.ARC4|getInstance\(", notes="Biased keystream; prohibited in TLS (RFC 7465)."),

    # ---------------- Hashes ----------------
    Rule("MD5-API", "MD5", "hash",
         r"""hashlib\.md5\s*\(|MessageDigest\.getInstance\(\s*"MD5"|hashes\.MD5\s*\(|createHash\(\s*['"]md5""",
         classically_weak=True, primitive="hash", notes="Practical collisions; unfit for security use."),
    Rule("MD5-KEYWORD", "MD5", "hash", r"\bMD5\b", confidence="medium",
         classically_weak=True, primitive="hash", notes="Practical collisions; unfit for security use."),
    Rule("SHA1-API", "SHA-1", "hash",
         r"""hashlib\.sha1\s*\(|MessageDigest\.getInstance\(\s*"SHA-?1"|hashes\.SHA1\s*\(|createHash\(\s*['"]sha1""",
         classically_weak=True, primitive="hash", notes="Practical collisions (SHAttered); deprecated for signatures."),
    Rule("SHA1-KEYWORD", "SHA-1", "hash", r"\bSHA-?1\b", confidence="medium",
         classically_weak=True, primitive="hash", notes="Deprecated for signatures."),
    Rule("SHA2-API", "SHA-2", "hash",
         r"""hashlib\.sha(?:256|384|512)\s*\(|hashes\.SHA(?:256|384|512)\s*\(|MessageDigest\.getInstance\(\s*"SHA-(?:256|384|512)"|createHash\(\s*['"]sha(?:256|384|512)""",
         primitive="hash", param_pattern=r"(?:sha|SHA)-?(256|384|512)",
         notes="SHA-2 is considered adequate post-quantum for hashing."),
    Rule("SHA3-API", "SHA-3", "hash", r"\bsha3_(?:224|256|384|512)\b|\bSHA3[-_]?(?:224|256|384|512)\b",
         primitive="hash", param_pattern=r"(?:sha3_|SHA3[-_]?)(\d+)", notes="SHA-3 family."),

    # ---------------- Protocols (TLS) ----------------
    Rule("TLS10", "TLSv1.0", "protocol", r"\bTLSv1(?:\.0)?(?![.\d])", confidence="medium",
         quantum_vulnerable=True, classically_weak=True, kind="protocol", primitive="other",
         high_context=r"ssl_protocols|SSLProtocol|setEnabledProtocols|SSLContext\.getInstance|minVersion|MinVersion",
         notes="Deprecated by RFC 8996. " + TLS_PQ_NOTE),
    Rule("TLS11", "TLSv1.1", "protocol", r"\bTLSv1\.1\b", confidence="medium",
         quantum_vulnerable=True, classically_weak=True, kind="protocol", primitive="other",
         high_context=r"ssl_protocols|SSLProtocol|setEnabledProtocols|SSLContext\.getInstance|minVersion|MinVersion",
         notes="Deprecated by RFC 8996. " + TLS_PQ_NOTE),
    Rule("TLS12", "TLSv1.2", "protocol", r"\bTLSv1\.2\b", confidence="medium",
         quantum_vulnerable=True, kind="protocol", primitive="other",
         high_context=r"ssl_protocols|SSLProtocol|setEnabledProtocols|SSLContext\.getInstance|minVersion|MinVersion",
         notes=TLS_PQ_NOTE),
    Rule("TLS13", "TLSv1.3", "protocol", r"\bTLSv1\.3\b", confidence="medium",
         quantum_vulnerable=True, kind="protocol", primitive="other",
         high_context=r"ssl_protocols|SSLProtocol|setEnabledProtocols|SSLContext\.getInstance|minVersion|MinVersion",
         notes=TLS_PQ_NOTE),
    Rule("TLS-WEAK-CIPHERS", "Weak TLS cipher list", "protocol",
         r"(?:ssl_ciphers|SSLCipherSuite)\b.*\b(?:RC4|DES|3DES|DES-CBC3|MD5|NULL|EXPORT|aNULL)\b",
         classically_weak=True, quantum_vulnerable=True, kind="protocol", primitive="other",
         notes="Cipher list allows legacy suites (RC4/3DES/MD5/NULL/EXPORT)."),

    # ---------------- Key material ----------------
    Rule("PEM-PRIVATE-KEY", "Private key (PEM)", "key-material",
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
         classically_weak=True, kind="related-crypto-material", primitive="other",
         notes="Hard-coded private key in source. Rotate it and move it to a secrets manager / HSM."),

    # ---------------- Post-quantum (already migrated) ----------------
    Rule("PQC-MLKEM", "ML-KEM", "PQC", r"\b(?:ML-KEM|MLKEM)(?:-?\d+)?\b", confidence="medium",
         primitive="kem", param_pattern=r"ML-?KEM-?(512|768|1024)",
         high_context=r"KeyEncapsulation\(|oqs\.", notes="FIPS 203 post-quantum KEM."),
    Rule("PQC-KYBER", "ML-KEM", "PQC", r"\b(?:CRYSTALS-)?Kyber(?:512|768|1024)?\b", confidence="medium",
         primitive="kem", param_pattern=r"Kyber-?(512|768|1024)",
         high_context=r"KeyEncapsulation\(|oqs\.", notes="Kyber is the pre-standard name of ML-KEM (FIPS 203)."),
    Rule("PQC-MLDSA", "ML-DSA", "PQC", r"\b(?:ML-DSA|MLDSA)(?:-?\d+)?\b", confidence="medium",
         primitive="signature", param_pattern=r"ML-?DSA-?(44|65|87)",
         high_context=r"Signature\(|oqs\.", notes="FIPS 204 post-quantum signature."),
    Rule("PQC-DILITHIUM", "ML-DSA", "PQC", r"\b(?:CRYSTALS-)?Dilithium[2-5]?\b", confidence="medium",
         primitive="signature", high_context=r"Signature\(|oqs\.",
         notes="Dilithium is the pre-standard name of ML-DSA (FIPS 204)."),
    Rule("PQC-SLHDSA", "SLH-DSA", "PQC", r"\b(?:SLH-DSA|SPHINCS\+?)\S*", confidence="medium",
         primitive="signature", high_context=r"Signature\(|oqs\.",
         notes="FIPS 205 stateless hash-based signature."),
]

# NIST PQC security categories that are fixed by the standards (FIPS 203/204)
# plus AES key sizes that define categories 1/3/5. Used in the CBOM only.
NIST_QUANTUM_LEVEL = {
    ("ML-KEM", "512"): 1, ("ML-KEM", "768"): 3, ("ML-KEM", "1024"): 5,
    ("ML-DSA", "44"): 2, ("ML-DSA", "65"): 3, ("ML-DSA", "87"): 5,
}

# Lines that are pure base64 (e.g. inside a PEM block) are skipped so random
# letters such as "/RSA+" never produce false positives.
BASE64_LINE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
