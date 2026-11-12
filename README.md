# 🚑 Bucks EMS Cloud Hub

**Bucks EMS Cloud Hub** is a full-stack, mobile-responsive Emergency Medical Services (EMS) operations, clinical care, fleet maintenance, and compliance management platform built with **Node.js**, **Express**, **SQLite (`node:sqlite`)**, and **Tesseract.js**.

## ✨ Key Features

- **🔐 Backend-Enforced RBAC (8 Official Positions + Fleet Profile)**
  - Enforces least-privilege permissions (`view`, `create`, `edit`, `delete`, `approve`, `export`, `manage_permissions`) on every API endpoint via JWT authentication.
  - Supports **Doctor / Medical Director**, **Emergency / Training Nurse**, **Field Medic**, **Flight Paramedic**, **Station Manager**, **QA Clinical / Clinical Audit**, **EMS Dispatcher**, and **IT Admin** — plus a configurable **Fleet Management** permission profile assignable without creating extra job titles.
- **📡 Emergency Dispatch & Chronological Incident Timeline**
  - Unique Incident IDs (`INC-YYYYMMDD-XXXX`) linking calls, ambulances, crews, ePCRs, and response events.
  - One-tap Field Medic buttons with automatic timestamps, optional GPS-assisted arrival verification, Doctor/Nurse handover confirmation, and documented historical timestamp corrections.
- **🩺 5-Section Electronic Patient Care Record (ePCR)**
  - Structured clinical workflow covering Demographics & Triage, Clinical History & Allergies, Vitals & GCS, Interventions & 12-Lead ECG, and Hospital Handover.
- **📷 Staff Compliance, Camera Capture & OCR**
  - Upload or photograph licences, medical certificates, and training documents using the in-app camera (preview, retake, 90° rotate, center crop, multi-page capture).
  - Local **Tesseract.js** OCR extracts document type, licence/cert number, issue date, and expiry date for human confirmation before saving, with configurable expiry reminders (`30, 14, 7, 0` days).
- **🚐 Fleet Servicing & Vehicle Compliance**
  - Track ambulance profiles, chronological service history (with optional verified mileage), service receipts/invoices, licence discs, and roadworthiness expiries.
- **📊 Operational Analytics & Reporting**
  - Live aggregated statistics (patients, staff, emergency response intervals, fleet readiness, and compliance) with date filtering and CSV export — without exposing PHI.
- **🔒 Private Document Storage & Immutable Audit Logs**
  - Validates file magic bytes, stores documents outside public static routes using UUID filenames, enforces authenticated access, and protects `audit_logs` with database-level triggers.
- **📶 Offline Queue & Idempotent Sync + Mobile UI**
  - Queues supported field records and timeline events offline with duplicate-safe synchronisation and a slide-out mobile navigation drawer.

## 🛠️ Tech Stack
- **Backend:** Node.js, Express 5, `node:sqlite`, `jsonwebtoken`, `bcryptjs`, `multer`, `tesseract.js`
- **Frontend:** Vanilla HTML5, CSS3 (mobile-responsive drawer & touch targets), JavaScript

## 🚀 Local Setup
```bash
npm install
node server.js
# Open http://localhost:3000
```
