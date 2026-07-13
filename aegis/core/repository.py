from __future__ import annotations

import base64
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from aegis.core.service import VaultMeta
from aegis.crypto.aead import Envelope
from aegis.crypto.kdf import KdfParams


class InMemoryVaultRepository:
    def __init__(self) -> None:
        self._meta: VaultMeta | None = None

    def load(self) -> VaultMeta | None:
        return self._meta

    def save(self, meta: VaultMeta) -> None:
        self._meta = meta


class JsonFileVaultRepository:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> VaultMeta | None:
        if not self._path.exists():
            return None

        raw = json.loads(self._path.read_text())
        return VaultMeta(
            kdf_salt=base64.b64decode(raw["kdf_salt"]),
            kdf_params=KdfParams(**raw["kdf_params"]),
            dek_envelope=Envelope(
                nonce=base64.b64decode(raw["dek_envelope"]["nonce"]),
                ciphertext=base64.b64decode(raw["dek_envelope"]["ciphertext"]),
            ),
            initialized_at=datetime.fromisoformat(raw["initialized_at"]),
        )

    def save(self, meta: VaultMeta) -> None:
        raw = {
            "kdf_salt": base64.b64encode(meta.kdf_salt).decode("ascii"),
            "kdf_params": asdict(meta.kdf_params),
            "dek_envelope": {
                "nonce": base64.b64encode(meta.dek_envelope.nonce).decode("ascii"),
                "ciphertext": base64.b64encode(meta.dek_envelope.ciphertext).decode("ascii"),
            },
            "initialized_at": meta.initialized_at.isoformat(),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(raw, indent=2))
