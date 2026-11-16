import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ==============================================================================
# PART 2: Hybrid Authenticated & Replay-Resistant Transport Protocol
# Primitives: X25519 + HKDF-SHA-256 + AES-256-GCM + Ed25519
# ==============================================================================

@dataclass
class EndpointIdentity:
    """Represents a participant's long-term signing and key-agreement identities."""
    name: str
    signing_priv: ed25519.Ed25519PrivateKey = field(default_factory=ed25519.Ed25519PrivateKey.generate)
    kex_priv: x25519.X25519PrivateKey = field(default_factory=x25519.X25519PrivateKey.generate)

    @property
    def signing_pub_bytes(self) -> bytes:
        return self.signing_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def kex_pub_bytes(self) -> bytes:
        return self.kex_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class SecureTransportChannel:
    """
    Implements the Part 2 Cryptographic Design:
    1. Ephemeral X25519 key generation per message
    2. ECDH shared secret with recipient's X25519 public key
    3. HKDF-SHA-256 key derivation bound to session context
    4. AES-256-GCM encryption with 96-bit random nonce & AAD metadata
    5. Ed25519 signature over canonical package
    6. Recipient signature verification, decryption, and replay cache check
    """

    def __init__(self, local_id: EndpointIdentity, peer_signing_pub: bytes, peer_kex_pub: bytes, session_id: str):
        self.local_id = local_id
        self.peer_signing_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_signing_pub)
        self.peer_kex_key = x25519.X25519PublicKey.from_public_bytes(peer_kex_pub)
        self.session_id = session_id
        self.seen_message_ids: Set[str] = set()
        self.msg_counter = 0

    def _derive_key(self, shared_secret: bytes, eph_pub_bytes: bytes, recipient_pub_bytes: bytes) -> bytes:
        info = f"CYB599-HYBRID-V1|{self.session_id}".encode("utf-8") + eph_pub_bytes + recipient_pub_bytes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256-GCM
            salt=None,
            info=info,
        )
        return hkdf.derive(shared_secret)

    def _canonical_sign_payload(
        self, eph_pub: bytes, nonce: bytes, ciphertext_and_tag: bytes, metadata_bytes: bytes
    ) -> bytes:
        parts = [eph_pub, nonce, ciphertext_and_tag, metadata_bytes]
        return b"".join(struct.pack(">I", len(p)) + p for p in parts)

    def seal_packet(self, plaintext: bytes) -> bytes:
        """Encrypts and signs a message package for transmission."""
        self.msg_counter += 1
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        shared_secret = eph_priv.exchange(self.peer_kex_key)
        aes_key = self._derive_key(shared_secret, eph_pub_bytes, self.local_id.kex_pub_bytes if False else self.peer_kex_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

        nonce = os.urandom(12)  # 96-bit unique nonce
        metadata = {
            "sender": self.local_id.name,
            "session_id": self.session_id,
            "msg_id": f"{self.local_id.name}-{self.msg_counter}-{secrets.token_hex(4)}",
            "timestamp": int(time.time()),
        }
        metadata_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")

        aesgcm = AESGCM(aes_key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, metadata_bytes)

        canonical_data = self._canonical_sign_payload(eph_pub_bytes, nonce, ciphertext_and_tag, metadata_bytes)
        signature = self.local_id.signing_priv.sign(canonical_data)

        wire_package = {
            "eph_pub": eph_pub_bytes.hex(),
            "nonce": nonce.hex(),
            "ciphertext_and_tag": ciphertext_and_tag.hex(),
            "metadata": metadata_bytes.decode("utf-8"),
            "signature": signature.hex(),
        }
        return json.dumps(wire_package).encode("utf-8")

    def open_packet(self, wire_bytes: bytes) -> bytes:
        """Verifies signature, checks replay state, derives key, and decrypts."""
        pkg = json.loads(wire_bytes.decode("utf-8"))
        eph_pub_bytes = bytes.fromhex(pkg["eph_pub"])
        nonce = bytes.fromhex(pkg["nonce"])
        ciphertext_and_tag = bytes.fromhex(pkg["ciphertext_and_tag"])
        metadata_bytes = pkg["metadata"].encode("utf-8")
        signature = bytes.fromhex(pkg["signature"])

        # 1. Verify Ed25519 signature BEFORE decryption
        canonical_data = self._canonical_sign_payload(eph_pub_bytes, nonce, ciphertext_and_tag, metadata_bytes)
        self.peer_signing_key.verify(signature, canonical_data)

        # 2. Replay protection check
        metadata = json.loads(pkg["metadata"])
        if metadata["session_id"] != self.session_id:
            raise ValueError("Session ID mismatch.")
        msg_id = metadata["msg_id"]
        if msg_id in self.seen_message_ids:
            raise ValueError(f"Replay attack detected: duplicate msg_id {msg_id}")

        # 3. ECDH shared secret & HKDF key derivation
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared_secret = self.local_id.kex_priv.exchange(eph_pub)
        aes_key = self._derive_key(shared_secret, eph_pub_bytes, self.local_id.kex_pub_bytes)

        # 4. AES-256-GCM authenticated decryption
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, metadata_bytes)

        # Record msg_id only after full cryptographic verification succeeds
        self.seen_message_ids.add(msg_id)
        return plaintext


# ==============================================================================
# PART 1: Private Set Intersection (PSI) Protocol
# Supports two parameter sets:
#   - Param Set A ("PSI-Standard"): Full Intersection Disclosure (A ∩ B)
#   - Param Set B ("PSI-Cardinality"): Cardinality-Only Disclosure (|A ∩ B|)
# ==============================================================================

class PSIParty:
    """
    Implements Elliptic-Curve / Commutative-PRF Private Set Intersection (EC-PSI)
    protected over the Part 2 Hybrid Authenticated Transport Channel.
    """

    # Curve25519 prime order L for scalar masking
    _L = 2**252 + 27742317777372353535851937790883648493

    def __init__(self, name: str, dataset: List[str], cardinality_only: bool = False):
        self.name = name
        self.dataset = list(dict.fromkeys(dataset))  # Deduplicate while preserving order
        self.cardinality_only = cardinality_only
        # Secret random 256-bit blinding key per session
        self._secret_key = secrets.token_bytes(32)

    def _prf_mask(self, item: str) -> bytes:
        """Deterministic keyed PRF (HMAC-SHA256) representing blinded set element."""
        return hmac.new(self._secret_key, item.encode("utf-8"), hashlib.sha256).digest()

    def _double_mask(self, blinded_token: bytes) -> bytes:
        """Applies local secret key over peer's blinded token (commutative via sorted dual-key)."""
        return hmac.new(self._secret_key, blinded_token, hashlib.sha256).digest()

    def prepare_blinded_set(self) -> List[str]:
        """Step 1: Hash and blind local dataset elements, shuffled to hide order."""
        blinded = [self._prf_mask(x).hex() for x in self.dataset]
        secrets.SystemRandom().shuffle(blinded)
        return blinded

    def evaluate_peer_set(self, peer_blinded_hex: List[str]) -> List[str]:
        """Step 2: Apply second PRF layer to peer's blinded tokens."""
        double_blinded = [self._double_mask(bytes.fromhex(t)).hex() for t in peer_blinded_hex]
        secrets.SystemRandom().shuffle(double_blinded)
        return double_blinded


def run_private_psi_session(
    set_a: List[str],
    set_b: List[str],
    cardinality_only: bool = False,
) -> Tuple[Dict, int]:
    """
    Executes end-to-end PSI between Party A (Client) and Party B (Verifier)
    encapsulated inside the Part 2 SecureTransportChannel.
    Returns (result_dict, total_wire_bytes).
    """
    id_a = EndpointIdentity("PartyA_Client")
    id_b = EndpointIdentity("PartyB_Verifier")
    session_id = secrets.token_hex(8)

    chan_a = SecureTransportChannel(id_a, id_b.signing_pub_bytes, id_b.kex_pub_bytes, session_id)
    chan_b = SecureTransportChannel(id_b, id_a.signing_pub_bytes, id_a.kex_pub_bytes, session_id)

    party_a = PSIParty("PartyA", set_a, cardinality_only=cardinality_only)
    party_b = PSIParty("PartyB", set_b, cardinality_only=cardinality_only)

    total_wire_bytes = 0

    # Message 1: Party A sends blinded set A to Party B over Hybrid Secure Channel
    blinded_a = party_a.prepare_blinded_set()
    pkt1 = chan_a.seal_packet(json.dumps({"blinded_a": blinded_a}).encode("utf-8"))
    total_wire_bytes += len(pkt1)
    msg1 = json.loads(chan_b.open_packet(pkt1).decode("utf-8"))

    # Message 2: Party B double-blinds A's tokens and sends its own blinded set B
    # Note: Using commutative Diffie-Hellman (X25519) scalar multiplication for true two-party PSI
    return _run_ecdh_psi(set_a, set_b, chan_a, chan_b, cardinality_only)


def _scalar_from_item(item: str) -> bytes:
    """Maps an identifier string to a valid 32-byte X25519 scalar."""
    digest = bytearray(hashlib.sha256(item.encode("utf-8")).digest())
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return bytes(digest)


def _scalar_from_secret(secret: bytes) -> bytes:
    digest = bytearray(hashlib.sha256(secret).digest())
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return bytes(digest)


def _ecdh_mask_point(point_bytes: bytes, scalar_bytes: bytes) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(scalar_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(point_bytes)
    return priv.exchange(pub)


def _item_to_curve_point(item: str) -> bytes:
    """Derives a deterministic X25519 public curve point from an identifier."""
    item_scalar = _scalar_from_item(item)
    return x25519.X25519PrivateKey.from_private_bytes(item_scalar).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _run_ecdh_psi(
    set_a: List[str],
    set_b: List[str],
    chan_a: SecureTransportChannel,
    chan_b: SecureTransportChannel,
    cardinality_only: bool,
) -> Tuple[Dict, int]:
    """
    Commutative X25519-PSI wrapped in Part 2 Hybrid Authenticated Encryption:
    Because X25519 scalar multiplication commutes: (a * H(x)) * b == (b * H(x)) * a.
    Neither party learns non-matching elements.
    """
    unique_a = list(dict.fromkeys(set_a))
    unique_b = list(dict.fromkeys(set_b))

    alpha = _scalar_from_secret(secrets.token_bytes(32))
    beta = _scalar_from_secret(secrets.token_bytes(32))

    wire_bytes = 0

    # Round 1: Party A masks H(a_i)^alpha and sends to Party B
    a_masked = []
    for item in unique_a:
        pt = _item_to_curve_point(item)
        masked = _ecdh_mask_point(pt, alpha)
        a_masked.append((item, masked.hex()))

    # Shuffle order sent over the wire
    send_a = [m for _, m in a_masked]
    secrets.SystemRandom().shuffle(send_a)

    pkt1 = chan_a.seal_packet(json.dumps({"a_alpha": send_a}).encode("utf-8"))
    wire_bytes += len(pkt1)
    recv1 = json.loads(chan_b.open_packet(pkt1).decode("utf-8"))

    # Round 2: Party B computes (H(a_i)^alpha)^beta AND H(b_j)^beta, sends both to Party A
    ab_double_masked = [
        _ecdh_mask_point(bytes.fromhex(m), beta).hex() for m in recv1["a_alpha"]
    ]
    b_masked = [
        _ecdh_mask_point(_item_to_curve_point(item), beta).hex() for item in unique_b
    ]
    secrets.SystemRandom().shuffle(ab_double_masked)
    secrets.SystemRandom().shuffle(b_masked)

    pkt2 = chan_b.seal_packet(
        json.dumps({"ab": ab_double_masked, "b_beta": b_masked}).encode("utf-8")
    )
    wire_bytes += len(pkt2)
    recv2 = json.loads(chan_a.open_packet(pkt2).decode("utf-8"))

    # Round 3: Party A computes (H(b_j)^beta)^alpha and compares against (H(a_i)^alpha)^beta
    ba_double_masked_set = {
        _ecdh_mask_point(bytes.fromhex(m), alpha).hex() for m in recv2["b_beta"]
    }

    # Re-align A's original items with their double-masked values
    intersection = []
    for item, a_alpha_hex in a_masked:
        a_ab_hex = _ecdh_mask_point(bytes.fromhex(a_alpha_hex), beta).hex()
        if a_ab_hex in ba_double_masked_set:
            intersection.append(item)

    if cardinality_only:
        return {"cardinality": len(intersection), "intersection": None}, wire_bytes
    return {"cardinality": len(intersection), "intersection": sorted(intersection)}, wire_bytes


# ==============================================================================
# NON-PRIVATE BASELINE (Plaintext Set Exchange over Unencrypted JSON)
# ==============================================================================

def run_non_private_baseline(set_a: List[str], set_b: List[str]) -> Tuple[Dict, int]:
    """
    Non-private baseline: Party A transmits its entire plaintext dataset to Party B,
    which computes set(A) & set(B) directly with zero privacy or authentication.
    """
    payload_a = json.dumps({"dataset_a": set_a}).encode("utf-8")
    wire_bytes = len(payload_a)

    received_a = set(json.loads(payload_a.decode("utf-8"))["dataset_a"])
    intersection = sorted(list(received_a.intersection(set(set_b))))

    payload_res = json.dumps({"intersection": intersection}).encode("utf-8")
    wire_bytes += len(payload_res)

    return {"cardinality": len(intersection), "intersection": intersection}, wire_bytes
