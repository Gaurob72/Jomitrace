# JomiTrace — Land Record Verification Prototype

JomiTrace is an educational prototype for screening supplied land-record information for inconsistencies. **All sample data must be fictional.** It does not connect to official government systems, determine legal ownership, or prove fraud.

## Included features

- Login and registration for demo users, with salted PBKDF2 password hashing and session cookies.
- Buyer and Officer demo roles.
- Dashboard statistics, case search, and risk-status filters.
- Case creation with two records and up to three registration transactions.
- Rule-based checks for:
  - Plot-number mismatch
  - Land-area mismatch after assumed unit conversion
  - Possible broken ownership chain
  - Potential duplicate sale indicator
  - Rapid transfers
  - Registration-versus-mutation mismatch
  - Missing survey-chain steps
- Side-by-side record comparison.
- Evidence-based findings explaining the rule, reason, and supplied evidence.
- Ownership timeline for supplied registration transactions.
- Persistent verification checklist for each case.
- Officer review workflow: Pending Review, Under Review, More Documents Required, and Review Completed, with a note.
- Downloadable PDF screening report including findings, evidence, supplied records, timeline, checklist, officer review, and SHA-256 hash.
- SHA-256 integrity seal and officer-only tampering demonstration on seeded demo cases.
- Officer-only audit log of key actions.
- Responsive dashboard and case-analysis pages.

## Easiest way to run on Windows

1. Install Python 3.10 or newer.
2. Extract the ZIP file into a normal folder.
3. Double-click `START_JOMITRACE.bat`.
4. The first run creates a local `.venv` and installs the packages. Internet access is required for installation.
5. Keep the terminal window open while using the website.
6. Open `http://127.0.0.1:8001` if the browser does not open automatically.

If you prefer to run it manually from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --port 8001
```

## Demo accounts

- Buyer: `buyer` / `BuyerDemo123!`
- Officer: `officer` / `OfficerDemo123!`

New demo accounts can also be registered. Role selection is for local demonstration only; never let public users self-assign privileged roles in a production system.

## How to demo the added features

1. Log in as `buyer` and open a case.
2. Review the side-by-side Record A / Record B comparison and the findings evidence.
3. Complete and save the verification checklist.
4. Open the ownership timeline and download the PDF screening report.
5. Log out and sign in as `officer`.
6. Open the same case, set a review status, add a fictional note, and save.
7. Open **Audit log** to see the recorded actions.
8. On an original seeded case only, use **Simulate tampering (demo)** to demonstrate a hash mismatch. Reset the seeded case afterwards. A hash mismatch intentionally blocks checklist/review edits until reset so ordinary workflow updates cannot hide the demo tampering.

## Important limitations and safety

- The prototype uses synthetic/demo records and is not connected to official Bangladesh government land databases.
- A warning is not proof of fraud; a clear result is not proof of legal ownership or authenticity.
- SHA-256 can reveal a change relative to the stored hash, but does not prove the original data was authentic.
- Unit conversion assumptions (`katha=1.65 decimals`, `bigha=33 decimals`, `acre=100 decimals`) are simplified demo assumptions and vary by region.
- Registration lets demo users choose a role for convenience. This is unsafe for production.
- Before any public deployment, add CSRF protection, rate limiting, secure role provisioning, HTTPS, a strong `JOMITRACE_SECRET`, secure cookies, backups, and a professional security review.
- Do not enter real personal data or private land-record information.

## AI tool disclosure

Update this section to accurately disclose any AI tools used and describe what you personally reviewed, modified, tested, and learned. Do not claim work you did not do.
