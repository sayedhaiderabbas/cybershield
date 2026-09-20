# Day 3 Backend Architecture

## System scope

CyberShield uses a modular monolith for the MVP. A single backend service owns authentication, business logic, scan orchestration, reporting, and monitoring interfaces, but each subsystem remains isolated behind explicit boundaries.

### Layering

```text
Frontend
  ↓
API Layer
  ↓
Authentication and Authorization
  ↓
Business Services
  ↓
Scan Job System
  ↓
Scanner
  ↓
Finding Normalization and Risk Engine
  ↓
Database
```

### Module structure

```text
backend/
├── app/
│   ├── main.py
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   ├── logging.py
│   │   └── errors.py
│   ├── api/
│   │   ├── deps.py
│   │   └── routes/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── repositories/
│   ├── db/
│   ├── workers/
│   └── utils/
├── migrations/
├── tests/
├── requirements.txt
├── .env.example
└── README.md
```

## Responsibilities

### API Layer
- Serve the versioned contract under `/api/v1`
- Validate request payloads
- Normalize errors
- Serialize deterministic API responses

### Authentication and Authorization
- Verify identity for protected resources
- Enforce ownership through `User -> Business -> Website -> Scan -> Finding -> Report`
- Do not trust frontend route protection alone

### Business Services
- Manage business records and website registration
- Coordinate scan creation, lookup, and result processing
- Provide report generation preparation and monitoring configuration

### Scan Job System
- Accept a website ID and create an async-ready scan job
- Track state transitions without exposing scanner internals directly to API clients

### Scanner Subsystem
- Only scan registered and authorized assets
- Use read-only checks and explicit target validation
- Never direct database writes or business decisions without normalized findings

### Findings and Risk Engine
- Convert raw observations into structured findings
- Calculate deterministic risk using severity, confidence, asset impact, and status
- Keep the score explainable and transparent

## Future scalability

If the product grows, the monolith can later split into separate areas such as scan orchestration, reporting, and AI context services without changing the API contract.

## Non-goals for this phase

This stage does not implement a real scanner, AI provider, scheduler, or production deployment. It focuses on a safe, extensible shell that will support those additions later.
