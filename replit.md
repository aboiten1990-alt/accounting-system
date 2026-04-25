# Tourism Company Management System

Multi-tenant management system for tourism/travel agencies, with Arabic RTL UI.

## Features

- **Multi-tenant**: each company has its own users, clients and operations (isolated by `company_id`).
- **Authentication**: session-based (express-session), bcrypt-hashed passwords, four roles.
- **Clients**: name, phone, email, passport number, nationality, address, agent name, notes.
- **Operations**: linked to a client, with operation type, description, amount (income), cost (expense), payment status, and date.
- **Dashboard**: per-tenant totals (clients, operations, income, expenses, profit, due).
- **Payments tab**: dedicated finance view with per-service categorization.
- **Admin panel**: manage companies and users (admin-only).

## Roles & Permissions (server-enforced)

| Role           | Clients      | Operations                                       | Finance/Dashboard | Admin |
|----------------|--------------|--------------------------------------------------|-------------------|-------|
| `admin`        | Full         | Full                                             | Full              | Full  |
| `company_user` | Full         | Full (in own company)                            | Full              | —     |
| `employee`     | Full         | CRUD only for operations in their `department`   | —                 | —     |
| `accountant`   | Read-only    | Full CRUD (used in Finance/Payments tab)         | Full              | —     |

Employee `department` values: `flights`, `visas`, `umrah_hajj`, `internal_services`. Each maps to a fixed set of `operation_type` values (server-side `SERVICE_TYPES_BY_DEPT`).

## Operation Types

- `flight` (dept: flights)
- `visa_tourist`, `visa_family`, `visa_business` (dept: visas)
- `umrah`, `hajj` (dept: umrah_hajj)
- `internal_service` (dept: internal_services)

## Tech Stack

- **Backend**: Node.js + Express (ES modules), `pg` driver, `express-session`, `bcryptjs`.
- **Database**: PostgreSQL via `DATABASE_URL`.
- **Frontend**: Vanilla HTML/CSS/JS, Arabic RTL.
- **Port**: 5000.

## File Structure

```
.
├── server.js              # Express server, REST API, auth, role middleware
├── package.json
├── public/
│   ├── index.html         # Single-page UI (RTL Arabic)
│   ├── styles.css
│   └── app.js             # Frontend logic, API calls, role-aware UI
└── replit.md
```

## API Endpoints (selection)

- `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET/POST/PUT/DELETE /api/clients` — accountants are read-only.
- `GET/POST/PUT/DELETE /api/operations` — employees scoped to their department.
- `GET /api/summary` — dashboard totals (scoped per role/department).
- `GET/POST /api/companies`, `GET/POST/DELETE /api/users` — admin only.

## Database Schema

`users(id, username UNIQUE, password_hash, role, department, company_id, created_at)`
- `role` ∈ {admin, company_user, employee, accountant}
- `department` set only for employees.

`companies(id, name, created_at)`

`clients(id, name, phone, email, passport_number, nationality, address, agent_name, notes, company_id, created_at)`

`operations(id, client_id, operation_type, description, amount, cost, payment_status, operation_date, company_id, created_at)`

## Default Demo Accounts

- `admin / admin123` — system administrator
- `user / user123` — company user (full access within company)
- Employees / accountants are created from the Admin → Users panel.

## Workflow

`Start application` → `node server.js` on port 5000.
