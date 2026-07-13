from __future__ import annotations

from enum import StrEnum


class VaultState(StrEnum):
    UNINITIALIZED = "uninitialized"
    SEALED = "sealed"
    UNSEALED = "unsealed"
