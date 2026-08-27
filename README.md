# Aegis

![logo](images/aegis-logo.png)

Aegis is a secret management and cryptographic service inspired by HashiCorp Vault and AWS Key Management Service (KMS). It provides secure secret storage and cryptographic operations through a centralized service, ensuring that sensitive data and encryption keys are never exposed to client applications.

---

## Features

- **Secure Secret Management** – Store and retrieve encrypted secrets using AES-256-GCM with authenticated encryption.
- **Transit Cryptography Service** – Perform encryption, decryption, digital signing, and signature verification without exposing cryptographic keys.
- **Vault Lifecycle Management** – Initialize, seal, and unseal the vault using a passphrase-derived master key to protect the Data Encryption Key (DEK).
- **Authentication, Authorization & Audit Logging** – Secure access with bearer-token authentication, ownership-based authorization, and immutable audit trails.
- **Production Observability** – Built-in Prometheus metrics, health/readiness endpoints, structured logging, and request tracing for operational monitoring.

---

## Architecture

![architecture](images/architecture.png)

---

## Getting Started

### Installation

Clone the repository:

```bash
git clone https://github.com/ngthdong/aegis.git
cd aegis
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -e ".[dev]"
```

### Running the Service

Start the API server:

```bash
uvicorn aegis.api.main:app --reload
```

The service will be available at:

```
http://127.0.0.1:8000
```
---

## API Documentation

Interactive Swagger UI is available at:

```bash
http://127.0.0.1:8000/docs
```

## Running Tests

Run all tests:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=aegis
```

Static analysis:

```bash
ruff check .
ruff format .
mypy aegis
```

---

## Running with Docker

Build and start the service:

```bash
docker compose up --build
```

The API will be available at:

```
http://localhost:8000
```
