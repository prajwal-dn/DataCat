# AGENTS.md — DataCat Hackathon

## Project Overview
DataCat is a privacy-first observability platform.
Telemetry collectors run on-device, enforce privacy policies locally,
cryptographically sign every transmission, and forward verified receipts
to this central SaaS platform for storage, audit, and visualization.

---

## Team Split

| Owner       | Scope                                                      | Branch            |
|-------------|------------------------------------------------------------|-------------------|
| Prajwal DN  | Backend (FastAPI), Verification, DB, Dashboard, Integration | `backend-dashboard` |
| Teammate    | Collector, Privacy Engine, Signing Module                  | `collector-privacy` |

---

## Ownership Rules

- **Never** edit files in `collector/` without a coordinated PR reviewed by both.
- **Never** edit files in `backend/`, `dashboard/`, `tests/` without Prajwal's review.
- Shared files (`docs/api-contract.md`, `AGENTS.md`) require both parties to agree before changes.

---

## Shared Contracts

All inter-component communication is defined in `docs/api-contract.md`.
Neither party modifies this file unilaterally.

---

## Security Rules

- **Never** commit private signing keys, secrets, or credentials.
- Public keys are stored in `keys/` (gitignored private halves).
- Environment variables via `.env` (gitignored).

---

## Git Workflow

```
main                  ← stable, merged after review
backend-dashboard     ← Prajwal's working branch
collector-privacy     ← Teammate's working branch
```

Merge to `main` only after both parties confirm integration tests pass.

---

## Run Commands

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Tests
```bash
cd backend
pytest tests/ -v
```

### Dashboard
Open `http://localhost:8000/dashboard` after backend is running.

