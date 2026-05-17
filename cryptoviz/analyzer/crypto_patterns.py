"""Known crypto library patterns for PyCryptodome, cryptography, hashlib, and hmac."""

from __future__ import annotations
from dataclasses import dataclass, field
from cryptoviz.graph.models import NodeType


@dataclass
class FunctionPattern:
    """Describes a function call that maps to a crypto operation."""
    node_type: NodeType
    label_template: str
    algorithm: str | None = None
    mode_arg_index: int | None = None
    key_arg_index: int | None = None
    data_arg_index: int | None = None


# Maps (module_attr_chain, function_name) → FunctionPattern
# module_attr_chain is the dotted prefix, e.g. "AES", "hashlib", "Cipher"
FUNCTION_PATTERNS: dict[tuple[str, str], FunctionPattern] = {
    # ── PyCryptodome / PyCryptodomex ──────────────────────────────────────────
    ("AES",    "new"):   FunctionPattern(NodeType.CIPHER_INIT, "AES Init",    algorithm="AES",    mode_arg_index=1, key_arg_index=0),
    ("DES",    "new"):   FunctionPattern(NodeType.CIPHER_INIT, "DES Init",    algorithm="DES",    mode_arg_index=1, key_arg_index=0),
    ("DES3",   "new"):   FunctionPattern(NodeType.CIPHER_INIT, "3DES Init",   algorithm="3DES",   mode_arg_index=1, key_arg_index=0),
    ("ARC4",   "new"):   FunctionPattern(NodeType.CIPHER_INIT, "RC4 Init",    algorithm="RC4",    key_arg_index=0),
    ("Blowfish","new"):  FunctionPattern(NodeType.CIPHER_INIT, "Blowfish Init",algorithm="Blowfish",key_arg_index=0),
    ("ChaCha20","new"):  FunctionPattern(NodeType.CIPHER_INIT, "ChaCha20 Init",algorithm="ChaCha20",key_arg_index=0),
    ("Salsa20", "new"):  FunctionPattern(NodeType.CIPHER_INIT, "Salsa20 Init", algorithm="Salsa20", key_arg_index=0),

    ("RSA",    "generate"): FunctionPattern(NodeType.KEY_GENERATION, "RSA Key Gen", algorithm="RSA"),
    ("DSA",    "generate"): FunctionPattern(NodeType.KEY_GENERATION, "DSA Key Gen", algorithm="DSA"),
    ("ECC",    "generate"): FunctionPattern(NodeType.KEY_GENERATION, "ECC Key Gen", algorithm="ECC"),
    ("RSA",    "import_key"): FunctionPattern(NodeType.KEY_GENERATION, "RSA Import Key", algorithm="RSA"),
    ("RSA",    "importKey"):  FunctionPattern(NodeType.KEY_GENERATION, "RSA Import Key", algorithm="RSA"),

    ("PKCS1_OAEP", "new"): FunctionPattern(NodeType.CIPHER_INIT, "RSA-OAEP Init", algorithm="RSA-OAEP"),
    ("PKCS1_v1_5", "new"): FunctionPattern(NodeType.CIPHER_INIT, "RSA-PKCS1v15 Init", algorithm="RSA-PKCS1v15"),

    ("SHA256",  "new"): FunctionPattern(NodeType.HASH, "SHA-256",  algorithm="SHA-256"),
    ("SHA512",  "new"): FunctionPattern(NodeType.HASH, "SHA-512",  algorithm="SHA-512"),
    ("SHA1",    "new"): FunctionPattern(NodeType.HASH, "SHA-1",    algorithm="SHA-1"),
    ("MD5",     "new"): FunctionPattern(NodeType.HASH, "MD5",      algorithm="MD5"),
    ("SHA3_256","new"): FunctionPattern(NodeType.HASH, "SHA3-256", algorithm="SHA3-256"),
    ("SHA3_512","new"): FunctionPattern(NodeType.HASH, "SHA3-512", algorithm="SHA3-512"),
    ("BLAKE2b", "new"): FunctionPattern(NodeType.HASH, "BLAKE2b",  algorithm="BLAKE2b"),
    ("BLAKE2s", "new"): FunctionPattern(NodeType.HASH, "BLAKE2s",  algorithm="BLAKE2s"),

    ("HMAC",    "new"): FunctionPattern(NodeType.HMAC, "HMAC",     algorithm="HMAC", key_arg_index=0),

    ("PBKDF2",  ""):           FunctionPattern(NodeType.KEY_DERIVATION, "PBKDF2",     algorithm="PBKDF2"),
    ("scrypt",  ""):           FunctionPattern(NodeType.KEY_DERIVATION, "scrypt",     algorithm="scrypt"),
    ("bcrypt",  ""):           FunctionPattern(NodeType.KEY_DERIVATION, "bcrypt",     algorithm="bcrypt"),

    # ── hashlib ───────────────────────────────────────────────────────────────
    ("hashlib", "sha256"):   FunctionPattern(NodeType.HASH, "SHA-256",  algorithm="SHA-256"),
    ("hashlib", "sha512"):   FunctionPattern(NodeType.HASH, "SHA-512",  algorithm="SHA-512"),
    ("hashlib", "sha1"):     FunctionPattern(NodeType.HASH, "SHA-1",    algorithm="SHA-1"),
    ("hashlib", "sha224"):   FunctionPattern(NodeType.HASH, "SHA-224",  algorithm="SHA-224"),
    ("hashlib", "sha384"):   FunctionPattern(NodeType.HASH, "SHA-384",  algorithm="SHA-384"),
    ("hashlib", "md5"):      FunctionPattern(NodeType.HASH, "MD5",      algorithm="MD5"),
    ("hashlib", "sha3_256"): FunctionPattern(NodeType.HASH, "SHA3-256", algorithm="SHA3-256"),
    ("hashlib", "sha3_512"): FunctionPattern(NodeType.HASH, "SHA3-512", algorithm="SHA3-512"),
    ("hashlib", "blake2b"):  FunctionPattern(NodeType.HASH, "BLAKE2b",  algorithm="BLAKE2b"),
    ("hashlib", "new"):      FunctionPattern(NodeType.HASH, "Hash",     algorithm=None),
    ("hashlib", "pbkdf2_hmac"): FunctionPattern(NodeType.KEY_DERIVATION, "PBKDF2-HMAC", algorithm="PBKDF2"),
    ("hashlib", "scrypt"):   FunctionPattern(NodeType.KEY_DERIVATION, "scrypt",      algorithm="scrypt"),

    # ── hmac ──────────────────────────────────────────────────────────────────
    ("hmac",   "new"):      FunctionPattern(NodeType.HMAC, "HMAC", algorithm="HMAC", key_arg_index=0),
    ("hmac",   "digest"):   FunctionPattern(NodeType.HMAC, "HMAC digest", algorithm="HMAC"),

    # ── os / secrets ─────────────────────────────────────────────────────────
    ("os",      "urandom"): FunctionPattern(NodeType.KEY_GENERATION, "Random Bytes", algorithm="CSPRNG"),
    ("secrets", "token_bytes"): FunctionPattern(NodeType.KEY_GENERATION, "Random Bytes", algorithm="CSPRNG"),
    ("secrets", "token_hex"):   FunctionPattern(NodeType.KEY_GENERATION, "Random Hex",   algorithm="CSPRNG"),

    # ── cryptography (hazmat) ─────────────────────────────────────────────────
    ("Cipher",  ""):          FunctionPattern(NodeType.CIPHER_INIT, "Cipher Init", algorithm=None),
    ("algorithms", "AES"):    FunctionPattern(NodeType.CIPHER_INIT, "AES Init",   algorithm="AES", key_arg_index=0),
    ("algorithms", "TripleDES"): FunctionPattern(NodeType.CIPHER_INIT, "3DES Init", algorithm="3DES", key_arg_index=0),
    ("algorithms", "ChaCha20"): FunctionPattern(NodeType.CIPHER_INIT, "ChaCha20 Init", algorithm="ChaCha20"),
    ("padding",  "PKCS7"):    FunctionPattern(NodeType.PADDING, "PKCS7 Padding",  algorithm="PKCS7"),
    ("padding",  "ANSIX923"): FunctionPattern(NodeType.PADDING, "ANSI X9.23",     algorithm="ANSIX923"),
    ("hashes",   "SHA256"):   FunctionPattern(NodeType.HASH, "SHA-256", algorithm="SHA-256"),
    ("hashes",   "SHA512"):   FunctionPattern(NodeType.HASH, "SHA-512", algorithm="SHA-512"),
    ("hashes",   "SHA1"):     FunctionPattern(NodeType.HASH, "SHA-1",   algorithm="SHA-1"),
    ("hashes",   "MD5"):      FunctionPattern(NodeType.HASH, "MD5",     algorithm="MD5"),
    ("hmac",     "HMAC"):     FunctionPattern(NodeType.HMAC, "HMAC",    algorithm="HMAC"),
    ("rsa",      "generate_private_key"): FunctionPattern(NodeType.KEY_GENERATION, "RSA Key Gen", algorithm="RSA"),
    ("ec",       "generate_private_key"): FunctionPattern(NodeType.KEY_GENERATION, "EC Key Gen",  algorithm="EC"),
    ("dsa",      "generate_private_key"): FunctionPattern(NodeType.KEY_GENERATION, "DSA Key Gen", algorithm="DSA"),
    ("pbkdf2",   "PBKDF2HMAC"):           FunctionPattern(NodeType.KEY_DERIVATION, "PBKDF2",      algorithm="PBKDF2"),
    ("scrypt",   "Scrypt"):               FunctionPattern(NodeType.KEY_DERIVATION, "scrypt",      algorithm="scrypt"),
    ("x25519",   "X25519PrivateKey"):     FunctionPattern(NodeType.KEY_GENERATION, "X25519 Key",  algorithm="X25519"),
    ("ed25519",  "Ed25519PrivateKey"):    FunctionPattern(NodeType.KEY_GENERATION, "Ed25519 Key", algorithm="Ed25519"),
}

# Methods called on cipher/hash objects
METHOD_PATTERNS: dict[str, FunctionPattern] = {
    "encrypt":             FunctionPattern(NodeType.ENCRYPT,  "Encrypt",          data_arg_index=0),
    "decrypt":             FunctionPattern(NodeType.DECRYPT,  "Decrypt",          data_arg_index=0),
    "encrypt_and_digest":  FunctionPattern(NodeType.ENCRYPT,  "Encrypt + Tag",    data_arg_index=0),
    "decrypt_and_verify":  FunctionPattern(NodeType.DECRYPT,  "Decrypt + Verify", data_arg_index=0),
    "update":              FunctionPattern(NodeType.HASH,      "Hash Update",      data_arg_index=0),
    "digest":              FunctionPattern(NodeType.HASH,      "Digest",),
    "hexdigest":           FunctionPattern(NodeType.HASH,      "Hex Digest"),
    "finalize":            FunctionPattern(NodeType.ENCRYPT,   "Finalize"),
    "sign":                FunctionPattern(NodeType.SIGN,      "Sign"),
    "verify":              FunctionPattern(NodeType.VERIFY,    "Verify"),
    "encode":              FunctionPattern(NodeType.ENCODE,    "Encode (pad)"),
}

# Insecure modes in PyCryptodome
ECB_MODE_NAMES = {"AES.MODE_ECB", "DES.MODE_ECB", "DES3.MODE_ECB"}

# Weak algorithms
WEAK_ALGORITHMS = {"MD5", "SHA-1", "DES", "RC4", "3DES"}

# Insecure modes
INSECURE_MODES = {"ECB"}

# Ideal key sizes per algorithm
IDEAL_KEY_SIZES: dict[str, list[int]] = {
    "AES":   [16, 24, 32],
    "DES":   [8],
    "3DES":  [16, 24],
    "RC4":   list(range(1, 257)),
    "ChaCha20": [32],
    "Salsa20":  [16, 32],
    "Blowfish": list(range(4, 57)),
}

# Crypto module import patterns (module path → canonical name)
KNOWN_CRYPTO_IMPORTS: dict[str, str] = {
    "Crypto.Cipher.AES":    "AES",
    "Crypto.Cipher.DES":    "DES",
    "Crypto.Cipher.DES3":   "DES3",
    "Crypto.Cipher.ARC4":   "ARC4",
    "Crypto.Cipher.Blowfish": "Blowfish",
    "Crypto.Cipher.ChaCha20": "ChaCha20",
    "Crypto.Cipher.Salsa20":  "Salsa20",
    "Crypto.PublicKey.RSA":   "RSA",
    "Crypto.PublicKey.DSA":   "DSA",
    "Crypto.PublicKey.ECC":   "ECC",
    "Crypto.Cipher.PKCS1_OAEP": "PKCS1_OAEP",
    "Crypto.Signature.pkcs1_15": "PKCS1_v1_5",
    "Crypto.Hash.SHA256":    "SHA256",
    "Crypto.Hash.SHA512":    "SHA512",
    "Crypto.Hash.SHA1":      "SHA1",
    "Crypto.Hash.MD5":       "MD5",
    "Crypto.Hash.SHA3_256":  "SHA3_256",
    "Crypto.Hash.SHA3_512":  "SHA3_512",
    "Crypto.Hash.BLAKE2b":   "BLAKE2b",
    "Crypto.Hash.BLAKE2s":   "BLAKE2s",
    "Crypto.Hash.HMAC":      "HMAC",
    "Crypto.Protocol.KDF":   "KDF",
    "Cryptodome.Cipher.AES": "AES",
    "cryptography.hazmat.primitives.ciphers":         "Cipher",
    "cryptography.hazmat.primitives.ciphers.algorithms": "algorithms",
    "cryptography.hazmat.primitives.ciphers.modes":      "modes",
    "cryptography.hazmat.primitives.hashes":             "hashes",
    "cryptography.hazmat.primitives.hmac":               "hmac",
    "cryptography.hazmat.primitives.kdf.pbkdf2":         "pbkdf2",
    "cryptography.hazmat.primitives.kdf.scrypt":         "scrypt",
    "cryptography.hazmat.primitives.asymmetric.rsa":     "rsa",
    "cryptography.hazmat.primitives.asymmetric.ec":      "ec",
    "cryptography.hazmat.primitives.asymmetric.dsa":     "dsa",
    "cryptography.hazmat.primitives.asymmetric.ed25519": "ed25519",
    "cryptography.hazmat.primitives.asymmetric.x25519":  "x25519",
    "cryptography.hazmat.primitives.padding":            "padding",
    "hashlib": "hashlib",
    "hmac":    "hmac",
    "os":      "os",
    "secrets": "secrets",
}
