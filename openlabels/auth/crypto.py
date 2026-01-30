"""
Cryptographic primitives for OpenLabels auth.

Provides:
- Password hashing (Argon2id)
- Key derivation (Argon2id)
- Symmetric encryption (AES-256-GCM)
- Secure random generation

Security notes:
- Uses Argon2id for password hashing (resistant to GPU/ASIC attacks)
- Uses AES-256-GCM for authenticated encryption
- All keys are 256 bits
- Nonces are randomly generated, never reused
"""

import secrets
from dataclasses import dataclass


# Argon2 parameters (OWASP recommended for 2024)
ARGON2_TIME_COST = 3           # Number of iterations
ARGON2_MEMORY_COST = 65536     # 64 MB
ARGON2_PARALLELISM = 4         # Threads
ARGON2_HASH_LEN = 32           # 256 bits
ARGON2_SALT_LEN = 16           # 128 bits

# AES-GCM parameters
AES_KEY_LEN = 32               # 256 bits
AES_NONCE_LEN = 12             # 96 bits (GCM standard)


@dataclass
class EncryptedData:
    """Container for encrypted data with nonce."""
    ciphertext: bytes
    nonce: bytes

    def to_bytes(self) -> bytes:
        """Serialize to bytes (nonce || ciphertext)."""
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """Deserialize from bytes."""
        return cls(
            nonce=data[:AES_NONCE_LEN],
            ciphertext=data[AES_NONCE_LEN:],
        )


class CryptoProvider:
    """
    Cryptographic operations provider.

    Encapsulates all crypto operations for easier testing and potential
    future hardware security module (HSM) integration.

    Example:
        crypto = CryptoProvider()

        # Hash a password
        salt = crypto.generate_salt()
        hash = crypto.hash_password("mypassword", salt)

        # Verify password
        if crypto.verify_password("mypassword", hash, salt):
            print("Valid!")

        # Derive key from password
        kek = crypto.derive_key("mypassword", salt)

        # Encrypt data
        encrypted = crypto.encrypt(b"secret data", kek)

        # Decrypt data
        plaintext = crypto.decrypt(encrypted, kek)
    """

    def __init__(self):
        """Initialize crypto provider."""
        # Lazy import to avoid hard dependency at module load
        self._argon2 = None
        self._aesgcm = None

    def _get_argon2(self):
        """Lazy load argon2-cffi."""
        if self._argon2 is None:
            try:
                from argon2 import PasswordHasher
                from argon2.low_level import hash_secret_raw, Type
                self._argon2 = {
                    "hasher": PasswordHasher(
                        time_cost=ARGON2_TIME_COST,
                        memory_cost=ARGON2_MEMORY_COST,
                        parallelism=ARGON2_PARALLELISM,
                        hash_len=ARGON2_HASH_LEN,
                    ),
                    "hash_raw": hash_secret_raw,
                    "type": Type.ID,
                }
            except ImportError:
                raise ImportError(
                    "argon2-cffi is required for authentication. "
                    "Install with: pip install openlabels[auth]"
                )
        return self._argon2

    def _get_aesgcm(self):
        """Lazy load cryptography AESGCM."""
        if self._aesgcm is None:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                self._aesgcm = AESGCM
            except ImportError:
                raise ImportError(
                    "cryptography is required for vault encryption. "
                    "Install with: pip install openlabels[auth]"
                )
        return self._aesgcm

    def generate_salt(self) -> bytes:
        """Generate a random salt for password hashing."""
        return secrets.token_bytes(ARGON2_SALT_LEN)

    def generate_key(self) -> bytes:
        """Generate a random 256-bit key."""
        return secrets.token_bytes(AES_KEY_LEN)

    def generate_nonce(self) -> bytes:
        """Generate a random nonce for AES-GCM."""
        return secrets.token_bytes(AES_NONCE_LEN)

    def generate_recovery_key(self) -> str:
        """
        Generate a human-readable recovery key.

        Returns:
            A 32-character base32 string (grouped for readability)
            Example: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
        """
        import base64
        # 20 bytes = 160 bits of entropy, encodes to 32 base32 chars
        raw = secrets.token_bytes(20)
        b32 = base64.b32encode(raw).decode().rstrip("=")
        # Group into 4-char chunks with dashes
        return "-".join(b32[i:i+4] for i in range(0, len(b32), 4))

    def hash_password(self, password: str, salt: bytes) -> bytes:
        """
        Hash a password using Argon2id.

        Args:
            password: The password to hash
            salt: Unique salt for this user

        Returns:
            The password hash
        """
        argon2 = self._get_argon2()
        return argon2["hash_raw"](
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=argon2["type"],
        )

    def verify_password(self, password: str, hash: bytes, salt: bytes) -> bool:
        """
        Verify a password against a hash.

        Args:
            password: The password to verify
            hash: The stored password hash
            salt: The salt used when hashing

        Returns:
            True if password matches
        """
        computed = self.hash_password(password, salt)
        return secrets.compare_digest(computed, hash)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password.

        Uses Argon2id with the same parameters as password hashing.
        The derived key can be used as a Key Encryption Key (KEK).

        Args:
            password: The password
            salt: Unique salt

        Returns:
            256-bit derived key
        """
        # Use same function as password hashing - Argon2 output is suitable for keys
        return self.hash_password(password, salt)

    def derive_key_from_recovery(self, recovery_key: str) -> bytes:
        """
        Derive an encryption key from a recovery key.

        Args:
            recovery_key: The recovery key (with or without dashes)

        Returns:
            256-bit derived key
        """
        import hashlib
        # Normalize: remove dashes, uppercase
        normalized = recovery_key.replace("-", "").upper()
        # Use SHA-256 for recovery key derivation (recovery keys have enough entropy)
        return hashlib.sha256(normalized.encode()).digest()

    def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedData:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            key: 256-bit encryption key

        Returns:
            EncryptedData containing ciphertext and nonce
        """
        AESGCM = self._get_aesgcm()
        nonce = self.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return EncryptedData(ciphertext=ciphertext, nonce=nonce)

    def decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            encrypted: The encrypted data with nonce
            key: 256-bit encryption key

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If decryption fails (wrong key or tampered data)
        """
        AESGCM = self._get_aesgcm()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data=None)

    def encrypt_with_nonce(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes
    ) -> bytes:
        """
        Encrypt data with a specific nonce (for deterministic encryption).

        Warning: Only use when nonce uniqueness is guaranteed externally.

        Args:
            plaintext: Data to encrypt
            key: 256-bit encryption key
            nonce: 96-bit nonce (must be unique for this key)

        Returns:
            Ciphertext (without nonce)
        """
        AESGCM = self._get_aesgcm()
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, associated_data=None)

    def decrypt_with_nonce(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Decrypt data with a specific nonce.

        Args:
            ciphertext: Encrypted data (without nonce)
            key: 256-bit encryption key
            nonce: 96-bit nonce used during encryption

        Returns:
            Decrypted plaintext
        """
        AESGCM = self._get_aesgcm()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
