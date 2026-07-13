#!/usr/bin/env python
"""
Usage:
    python scripts/vault_cli.py init
    python scripts/vault_cli.py unseal
    python scripts/vault_cli.py status
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from aegis.core.repository import JsonFileVaultRepository
from aegis.core.service import (
    InvalidPassphrase,
    VaultAlreadyInitialized,
    VaultNotInitialized,
    VaultService,
)

VAULT_PATH = Path("./data/vault.json")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("init", "unseal", "seal", "status"):
        print(f"usage: {sys.argv[0]} [init|unseal|status]")
        sys.exit(1)

    command = sys.argv[1]
    repository = JsonFileVaultRepository(VAULT_PATH)
    service = VaultService(repository)

    if command == "status":
        print(f"vault status: {service.status().value}")
        return

    elif command == "init":
        passphrase = getpass.getpass("New master passphrase: ")
        confirm = getpass.getpass("Confirm: ")
        if passphrase != confirm:
            print("passphrases did not match", file=sys.stderr)
            sys.exit(1)
        try:
            service.initialize(passphrase)
        except VaultAlreadyInitialized:
            print("vault is already initialized", file=sys.stderr)
            sys.exit(1)
        print(f"vault initialized at {VAULT_PATH}, status: {service.status().value}")
        return

    elif command == "unseal":
        passphrase = getpass.getpass("Master passphrase: ")
        try:
            service.unseal(passphrase)
        except VaultNotInitialized:
            print("vault has not been initialized -- run 'init' first", file=sys.stderr)
            sys.exit(1)
        except InvalidPassphrase:
            print("incorrect passphrase", file=sys.stderr)
            sys.exit(1)
        print(f"vault unsealed, status: {service.status().value}")

    elif command == "seal":
        service.seal()
        print(f"vault sealed, status: {service.status().value}")


if __name__ == "__main__":
    main()
