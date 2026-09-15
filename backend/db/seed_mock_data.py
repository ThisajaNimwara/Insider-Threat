# backend/db/seed_mock_data.py
"""
Seed script — initialises and populates both SQLite databases.

  mock_hr.db          : employee HR metadata (PIP, resignation, role, dept)
  incident_history.db : past anomaly records + analysis audit log

Usage:
    # First run — create and seed everything
    python backend/db/seed_mock_data.py

    # Re-seed employee/incident data without wiping the audit log
    python backend/db/seed_mock_data.py --reset

    # Only create tables if they don't exist yet (safe to re-run)
    python backend/db/seed_mock_data.py --skip-if-exists
"""

import sqlite3
import os
import sys
import random
from datetime import datetime, timedelta

HR_DB_PATH       = os.path.join(os.path.dirname(__file__), "mock_hr.db")
INCIDENT_DB_PATH = os.path.join(os.path.dirname(__file__), "incident_history.db")

# ── CLI flags ──────────────────────────────────────────────────────────────────
RESET         = "--reset"         in sys.argv   # drop + recreate employee/incident tables
SKIP_IF_EXISTS = "--skip-if-exists" in sys.argv  # no-op if tables already populated


# ══════════════════════════════════════════════════════════════════════════════
# SEED DATA
# ══════════════════════════════════════════════════════════════════════════════

# Columns: employee_id, on_pip, resigned, role, department,
#          termination_date, hire_date, manager_id, clearance_level, remote_worker
EMPLOYEES = [
    ("EMP_001", 0, 0, "Software Engineer",      "Engineering",     None,         "2021-03-15", "EMP_010", "standard",  0),
    ("EMP_002", 0, 0, "IT Administrator",        "IT Operations",   None,         "2019-07-01", "EMP_013", "elevated",  0),
    ("EMP_003", 1, 0, "Data Analyst",            "Business Intel",  None,         "2022-01-10", "EMP_007", "standard",  1),
    ("EMP_004", 0, 1, "Senior Developer",        "Engineering",     "2024-07-15", "2020-05-20", "EMP_010", "standard",  0),
    ("EMP_005", 1, 1, "Finance Analyst",         "Finance",         "2024-06-30", "2021-11-03", "EMP_014", "elevated",  0),
    ("EMP_006", 0, 0, "DevOps Engineer",         "IT Operations",   None,         "2020-09-14", "EMP_013", "elevated",  1),
    ("EMP_007", 0, 0, "Product Manager",         "Product",         None,         "2018-02-28", None,      "standard",  0),
    ("EMP_008", 1, 0, "Sales Executive",         "Sales",           None,         "2022-06-01", None,      "standard",  1),
    ("EMP_009", 0, 0, "Backup Operator",         "IT Operations",   None,         "2017-04-11", "EMP_013", "standard",  0),
    ("EMP_010", 0, 0, "Security Analyst",        "InfoSec",         None,         "2016-08-22", None,      "admin",     0),
    ("EMP_011", 0, 1, "Database Administrator",  "Engineering",     "2024-08-01", "2019-12-01", "EMP_010", "elevated",  0),
    ("EMP_012", 1, 0, "QA Engineer",             "Engineering",     None,         "2023-03-07", "EMP_010", "standard",  1),
    ("EMP_013", 0, 0, "Network Engineer",        "IT Operations",   None,         "2015-06-30", None,      "elevated",  0),
    ("EMP_014", 0, 0, "HR Coordinator",          "Human Resources", None,         "2020-01-15", None,      "elevated",  0),
    ("EMP_015", 1, 1, "Systems Architect",       "Engineering",     "2024-09-01", "2018-10-10", "EMP_010", "elevated",  0),
    # IDs used directly in mock alert JSON files
    ("EMP_042", 0, 1, "Senior Developer",        "Engineering",     "2024-07-20", "2021-05-17", "EMP_010", "standard",  0),
    ("EMP_099", 1, 0, "Data Analyst",            "Business Intel",  None,         "2022-08-29", "EMP_007", "standard",  1),
    ("EMP_777", 0, 0, "IT Administrator",        "IT Operations",   None,         "2020-03-03", "EMP_013", "elevated",  0),
    ("EMP_SVC", 0, 0, "Service Account",         "Automation",      None,         "2019-01-01", None,      "standard",  0),
]


def _random_ts(days_back_max: int = 180) -> str:
    """Generate a random ISO timestamp within the last N days."""
    delta = timedelta(
        days=random.randint(1, days_back_max),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    return (datetime.now() - delta).isoformat()


# Columns: employee_id, severity, incident_type, description
INCIDENTS_TEMPLATE = [
    ("EMP_003", 0.55, "bulk_download",     "Unusual volume of internal reports downloaded to local drive outside normal pattern."),
    ("EMP_004", 0.80, "usb_transfer",      "Large USB transfer of 340MB detected 3 days before confirmed resignation date."),
    ("EMP_005", 0.90, "email_forwarding",  "Auto-forwarding rule created to personal Gmail for all internal finance emails."),
    ("EMP_005", 0.75, "after_hours_logon", "VPN login at 02:30 AM on Saturday with no on-call ticket or manager approval."),
    ("EMP_008", 0.45, "policy_violation",  "Attempted installation of unauthorised remote-access software — blocked by DLP."),
    ("EMP_011", 0.70, "db_dump",           "Full production database schema exported to personal home directory."),
    ("EMP_012", 0.35, "failed_logins",     "Six consecutive failed login attempts within a 10-minute window on a Tuesday morning."),
    ("EMP_015", 0.88, "usb_transfer",      "Source code repository cloned and transferred to USB one day before resignation effective date."),
    ("EMP_042", 0.92, "usb_transfer",      "487MB USB transfer of proprietary ML models and datasets after 11 PM — confirmed exfil pattern."),
    ("EMP_099", 0.60, "bulk_download",     "Bulk export of customer PII dataset without a logged business justification or ticket reference."),
    # Additional lower-severity incidents to populate baseline history
    ("EMP_003", 0.40, "after_hours_logon", "Login at 21:45 on a Sunday — no incident ticket. Second occurrence this quarter."),
    ("EMP_008", 0.38, "bulk_download",     "Downloaded full Q2 client list to local machine without CRM export approval."),
    ("EMP_012", 0.30, "policy_violation",  "Attempted to access /admin portal — access denied. Logged as probing behaviour."),
]


# ══════════════════════════════════════════════════════════════════════════════
# TABLE CREATION
# ══════════════════════════════════════════════════════════════════════════════

def _create_hr_tables(cursor: sqlite3.Cursor, drop_first: bool = False) -> None:
    if drop_first:
        cursor.execute("DROP TABLE IF EXISTS employees")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            employee_id         TEXT    PRIMARY KEY,
            on_pip              INTEGER NOT NULL DEFAULT 0,
            resigned            INTEGER NOT NULL DEFAULT 0,
            role                TEXT    NOT NULL DEFAULT 'Unknown',
            department          TEXT    NOT NULL DEFAULT 'Unknown',
            termination_date    TEXT,
            hire_date           TEXT,
            manager_id          TEXT,
            clearance_level     TEXT    DEFAULT 'standard',
            remote_worker       INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_employees_department ON employees (department)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_employees_resigned ON employees (resigned)"
    )


def _create_incident_tables(cursor: sqlite3.Cursor, drop_first: bool = False) -> None:
    if drop_first:
        cursor.execute("DROP TABLE IF EXISTS incidents")
        # Never drop analysis_audit_log on reset — preserve history

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id     TEXT    NOT NULL,
            severity        REAL    NOT NULL DEFAULT 0.5,
            incident_type   TEXT    NOT NULL,
            description     TEXT,
            incident_ts     TEXT    NOT NULL,
            reviewed        INTEGER NOT NULL DEFAULT 0,
            false_positive  INTEGER NOT NULL DEFAULT 0,
            analyst_notes   TEXT,
            report_id       TEXT,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_employee_id ON incidents (employee_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents (incident_ts DESC)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity DESC)"
    )
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_emp_reviewed_ts
        ON incidents (employee_id, reviewed, incident_ts DESC)
    """)

    # Audit log — always CREATE IF NOT EXISTS, never dropped
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_audit_log (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id            TEXT    NOT NULL UNIQUE,
            employee_id          TEXT    NOT NULL,
            event_type           TEXT    NOT NULL,
            unified_threat_index REAL    NOT NULL,
            risk_level           TEXT    NOT NULL,
            ml_core_score        REAL,
            ml_dfuse_score       REAL,
            llm_mistral_score    REAL,
            llm_gemini_score     REAL,
            is_false_positive    INTEGER DEFAULT 0,
            verdict              TEXT,
            processing_ms        INTEGER,
            analyzed_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_employee ON analysis_audit_log (employee_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_risk_level ON analysis_audit_log (risk_level)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_analyzed_at ON analysis_audit_log (analyzed_at DESC)"
    )


# ==============================================================================
# SEED FUNCTIONS
# ==============================================================================

def seed_hr_db(reset: bool = False, skip_if_exists: bool = False) -> None:
    print(f"\n[seed] {'Re-creating' if reset else 'Initialising'} HR database -> {HR_DB_PATH}")
    conn   = sqlite3.connect(HR_DB_PATH)
    cursor = conn.cursor()

    _create_hr_tables(cursor, drop_first=reset)

    if skip_if_exists:
        existing = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
        if existing > 0:
            print(f"[seed] [SKIP] Skipped - {existing} employees already present.")
            conn.close()
            return

    cursor.executemany(
        """
        INSERT OR REPLACE INTO employees
            (employee_id, on_pip, resigned, role, department,
             termination_date, hire_date, manager_id, clearance_level, remote_worker)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        EMPLOYEES,
    )

    conn.commit()
    conn.close()
    print(f"[seed] [OK] Inserted {len(EMPLOYEES)} employee records.")


def seed_incident_db(reset: bool = False, skip_if_exists: bool = False) -> None:
    print(f"[seed] {'Re-creating' if reset else 'Initialising'} incident database -> {INCIDENT_DB_PATH}")
    conn   = sqlite3.connect(INCIDENT_DB_PATH)
    cursor = conn.cursor()

    _create_incident_tables(cursor, drop_first=reset)

    if skip_if_exists:
        existing = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if existing > 0:
            print(f"[seed] [SKIP] Skipped - {existing} incidents already present.")
            conn.close()
            return

    rows = [
        (emp_id, severity, inc_type, desc, _random_ts())
        for emp_id, severity, inc_type, desc in INCIDENTS_TEMPLATE
    ]

    cursor.executemany(
        """
        INSERT INTO incidents
            (employee_id, severity, incident_type, description, incident_ts)
        VALUES (?, ?, ?, ?, ?)
        """,
        rows,
    )

    conn.commit()
    conn.close()
    print(f"[seed] [OK] Inserted {len(rows)} incident records.")


# ==============================================================================
# VERIFICATION
# ==============================================================================

def verify_databases() -> None:
    """Print row counts and a sample of high-risk employees for a sanity check."""
    print("\n[verify] -- Database row counts -------------------------")

    with sqlite3.connect(HR_DB_PATH) as conn:
        emp_count  = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
        pip_count  = conn.execute("SELECT COUNT(*) FROM employees WHERE on_pip = 1").fetchone()[0]
        res_count  = conn.execute("SELECT COUNT(*) FROM employees WHERE resigned = 1").fetchone()[0]
        print(f"  mock_hr.db          -> {emp_count:>3} employees  "
              f"({pip_count} on PIP, {res_count} resigned)")

    with sqlite3.connect(INCIDENT_DB_PATH) as conn:
        inc_count   = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        audit_count = conn.execute("SELECT COUNT(*) FROM analysis_audit_log").fetchone()[0]
        print(f"  incident_history.db -> {inc_count:>3} incidents, {audit_count:>3} audit log entries")

    print("\n[verify] -- High-risk employees (PIP or resigned + incidents) --")
    with sqlite3.connect(HR_DB_PATH) as hr_conn:
        with sqlite3.connect(INCIDENT_DB_PATH) as inc_conn:
            # Attach HR db to incident connection for cross-db query
            inc_conn.execute(f"ATTACH DATABASE '{HR_DB_PATH}' AS hr")
            rows = inc_conn.execute("""
                SELECT   e.employee_id, e.role, e.department,
                         e.on_pip, e.resigned,
                         COUNT(i.id)     AS incidents,
                         MAX(i.severity) AS peak_severity
                FROM     hr.employees e
                JOIN     incidents i ON i.employee_id = e.employee_id
                WHERE    e.on_pip = 1 OR e.resigned = 1
                GROUP BY e.employee_id
                ORDER BY peak_severity DESC
            """).fetchall()

            if rows:
                print(f"  {'ID':<10} {'Role':<24} {'Dept':<18} {'PIP':>4} {'RES':>4} {'INC':>4} {'PEAK':>6}")
                print(f"  {'-'*10} {'-'*24} {'-'*18} {'-'*4} {'-'*4} {'-'*4} {'-'*6}")
                for r in rows:
                    print(
                        f"  {r[0]:<10} {r[1]:<24} {r[2]:<18} "
                        f"{'Y' if r[3] else 'N':>4} {'Y' if r[4] else 'N':>4} "
                        f"{r[5]:>4} {r[6]:>6.2f}"
                    )
            else:
                print("  (no matches - ensure both databases are seeded)")


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Insider Threat Detector - Database Seed Script")
    print("=" * 60)

    if RESET:
        print("[mode] RESET - employee + incident tables will be dropped and recreated.")
        print("       analysis_audit_log is preserved.\n")
    elif SKIP_IF_EXISTS:
        print("[mode] SKIP-IF-EXISTS - tables already populated will be left untouched.\n")
    else:
        print("[mode] DEFAULT - CREATE IF NOT EXISTS + INSERT OR REPLACE.\n")

    seed_hr_db(reset=RESET, skip_if_exists=SKIP_IF_EXISTS)
    seed_incident_db(reset=RESET, skip_if_exists=SKIP_IF_EXISTS)
    verify_databases()

    print("\n[seed] [SUCCESS] Done. You can now run: uvicorn backend.app:app --reload")