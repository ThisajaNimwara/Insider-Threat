# backend/db/db_utils.py
"""
Database utility layer.
All reusable SQLite query helpers consumed by enrichment.py, app.py,
and the audit logging system.  No raw SQL lives outside this module.

Usage:
    from backend.db.db_utils import (
        get_employee, get_incident_summary, log_analysis,
        get_high_risk_employees, mark_false_positive
    )
"""

import sqlite3
import os
import contextlib
from datetime import datetime, timezone
from typing import Optional, Generator

# ── Path resolution ────────────────────────────────────────────────────────────
_DB_DIR          = os.path.dirname(__file__)
HR_DB_PATH       = os.path.join(_DB_DIR, "mock_hr.db")
INCIDENT_DB_PATH = os.path.join(_DB_DIR, "incident_history.db")

# ── Connection helpers ─────────────────────────────────────────────────────────

@contextlib.contextmanager
def _hr_conn() -> Generator[sqlite3.Connection, None, None]:
    """Context-managed HR DB connection with row_factory set."""
    conn = sqlite3.connect(HR_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def _incident_conn() -> Generator[sqlite3.Connection, None, None]:
    """Context-managed incident/audit DB connection with row_factory set."""
    conn = sqlite3.connect(INCIDENT_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# HR DATABASE QUERIES
# ══════════════════════════════════════════════════════════════════════════════

def get_employee(employee_id: str) -> Optional[dict]:
    """
    Fetch a single employee record by ID.

    Returns:
        dict of employee fields, or None if not found.
    """
    with _hr_conn() as conn:
        row = conn.execute(
            """
            SELECT employee_id, on_pip, resigned, role, department,
                   termination_date, hire_date, manager_id,
                   clearance_level, remote_worker
            FROM   employees
            WHERE  employee_id = ?
            """,
            (employee_id,),
        ).fetchone()

    if row:
        return dict(row)
    return None


def get_employees_by_department(department: str) -> list[dict]:
    """Return all employees in a given department."""
    with _hr_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM employees WHERE department = ? ORDER BY employee_id",
            (department,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_high_risk_hr_employees() -> list[dict]:
    """
    Return employees with active PIP or resignation flag.
    Used for batch monitoring dashboards.
    """
    with _hr_conn() as conn:
        rows = conn.execute(
            """
            SELECT employee_id, role, department, on_pip, resigned, termination_date
            FROM   employees
            WHERE  on_pip = 1 OR resigned = 1
            ORDER  BY resigned DESC, on_pip DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_employee(record: dict) -> bool:
    """
    Insert or replace an employee record.
    Useful for syncing HR system updates.

    Args:
        record: dict with keys matching the employees table columns.

    Returns:
        True on success, False on failure.
    """
    required = {"employee_id", "role", "department"}
    if not required.issubset(record.keys()):
        raise ValueError(f"Employee record missing required keys: {required - record.keys()}")

    try:
        with _hr_conn() as conn:
            conn.execute(
                """
                INSERT INTO employees
                    (employee_id, on_pip, resigned, role, department,
                     termination_date, hire_date, manager_id, clearance_level,
                     remote_worker, updated_at)
                VALUES
                    (:employee_id, :on_pip, :resigned, :role, :department,
                     :termination_date, :hire_date, :manager_id, :clearance_level,
                     :remote_worker, datetime('now'))
                ON CONFLICT(employee_id) DO UPDATE SET
                    on_pip           = excluded.on_pip,
                    resigned         = excluded.resigned,
                    role             = excluded.role,
                    department       = excluded.department,
                    termination_date = excluded.termination_date,
                    updated_at       = datetime('now')
                """,
                {
                    "employee_id":      record["employee_id"],
                    "on_pip":           int(record.get("on_pip", 0)),
                    "resigned":         int(record.get("resigned", 0)),
                    "role":             record["role"],
                    "department":       record["department"],
                    "termination_date": record.get("termination_date"),
                    "hire_date":        record.get("hire_date"),
                    "manager_id":       record.get("manager_id"),
                    "clearance_level":  record.get("clearance_level", "standard"),
                    "remote_worker":    int(record.get("remote_worker", 0)),
                },
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"[db_utils] upsert_employee failed for {record.get('employee_id')}: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT DATABASE QUERIES
# ══════════════════════════════════════════════════════════════════════════════

def get_incident_summary(employee_id: str) -> dict:
    """
    Return aggregated incident metrics for one employee.
    Used directly by enrichment.py.

    Returns dict with:
        prior_incidents, confirmed_incidents, avg_severity, peak_severity,
        last_incident_ts, unreviewed_count, known_baseline_deviation
    """
    default = {
        "prior_incidents":          0,
        "confirmed_incidents":      0,
        "avg_severity":             0.0,
        "peak_severity":            0.0,
        "last_incident_ts":         None,
        "unreviewed_count":         0,
        "known_baseline_deviation": False,
    }

    try:
        with _incident_conn() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*)                                            AS total,
                    SUM(CASE WHEN false_positive = 0 THEN 1 ELSE 0 END) AS confirmed,
                    ROUND(AVG(severity), 3)                             AS avg_sev,
                    MAX(severity)                                       AS peak_sev,
                    MAX(incident_ts)                                    AS last_ts,
                    SUM(CASE WHEN reviewed = 0 THEN 1 ELSE 0 END)      AS unreviewed
                FROM incidents
                WHERE employee_id = ?
                """,
                (employee_id,),
            ).fetchone()

        if row and row["total"]:
            confirmed = row["confirmed"] or 0
            return {
                "prior_incidents":          row["total"],
                "confirmed_incidents":      confirmed,
                "avg_severity":             row["avg_sev"] or 0.0,
                "peak_severity":            row["peak_sev"] or 0.0,
                "last_incident_ts":         row["last_ts"],
                "unreviewed_count":         row["unreviewed"] or 0,
                "known_baseline_deviation": confirmed >= 2,
            }
    except sqlite3.Error as e:
        print(f"[db_utils] get_incident_summary error for {employee_id}: {e}")

    return default


def get_recent_incidents(employee_id: str, limit: int = 5) -> list[dict]:
    """
    Return the N most recent incident records for an employee.
    Used by the executive report page.
    """
    try:
        with _incident_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, incident_type, severity, description,
                       incident_ts, reviewed, false_positive, analyst_notes
                FROM   incidents
                WHERE  employee_id = ?
                ORDER  BY incident_ts DESC
                LIMIT  ?
                """,
                (employee_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        print(f"[db_utils] get_recent_incidents error for {employee_id}: {e}")
        return []


def insert_incident(
    employee_id: str,
    severity: float,
    incident_type: str,
    description: str = "",
    incident_ts: Optional[str] = None,
    report_id: Optional[str] = None,
) -> Optional[int]:
    """
    Insert a new incident record.

    Returns:
        The new row ID, or None on failure.
    """
    ts = incident_ts or datetime.now(timezone.utc).isoformat()
    try:
        with _incident_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO incidents
                    (employee_id, severity, incident_type, description,
                     incident_ts, report_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (employee_id, severity, incident_type, description, ts, report_id),
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"[db_utils] insert_incident error: {e}")
        return None


def mark_false_positive(incident_id: int, analyst_notes: str = "") -> bool:
    """
    Mark an incident as a confirmed false positive.
    Called by SOC analysts via the dashboard or API.
    """
    try:
        with _incident_conn() as conn:
            conn.execute(
                """
                UPDATE incidents
                SET    false_positive = 1,
                       reviewed       = 1,
                       analyst_notes  = ?
                WHERE  id = ?
                """,
                (analyst_notes, incident_id),
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"[db_utils] mark_false_positive error for id={incident_id}: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG QUERIES
# ══════════════════════════════════════════════════════════════════════════════

def log_analysis(
    report_id: str,
    employee_id: str,
    event_type: str,
    scorer_result: dict,
    agent_scores: dict,
    verdict: str,
    is_false_positive: bool = False,
    processing_ms: Optional[int] = None,
) -> bool:
    """
    Append one row to the analysis_audit_log table.
    Called at the end of every /analyze request.

    Args:
        report_id       : unique report ID from report_builder
        employee_id     : subject employee
        event_type      : logon | usb_insert | file_access | etc.
        scorer_result   : full dict from scorer.compute_threat_index()
        agent_scores    : dict of {agent_key: score}
        verdict         : THREAT | BENIGN | INCONCLUSIVE
        is_false_positive: Gemini's FP flag
        processing_ms   : optional API latency in ms
    """
    try:
        with _incident_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO analysis_audit_log
                    (report_id, employee_id, event_type,
                     unified_threat_index, risk_level,
                     ml_core_score, ml_dfuse_score,
                     llm_mistral_score, llm_gemini_score,
                     is_false_positive, verdict, processing_ms)
                VALUES
                    (:report_id, :employee_id, :event_type,
                     :unified_threat_index, :risk_level,
                     :ml_core_score, :ml_dfuse_score,
                     :llm_mistral_score, :llm_gemini_score,
                     :is_false_positive, :verdict, :processing_ms)
                """,
                {
                    "report_id":            report_id,
                    "employee_id":          employee_id,
                    "event_type":           event_type,
                    "unified_threat_index": scorer_result.get("unified_threat_index", 0.0),
                    "risk_level":           scorer_result.get("risk_level", "low"),
                    "ml_core_score":        agent_scores.get("ml_core"),
                    "ml_dfuse_score":       agent_scores.get("ml_dfuse"),
                    "llm_mistral_score":    agent_scores.get("llm_mistral"),
                    "llm_gemini_score":     agent_scores.get("llm_gemini"),
                    "is_false_positive":    int(is_false_positive),
                    "verdict":              verdict,
                    "processing_ms":        processing_ms,
                },
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"[db_utils] log_analysis error for report {report_id}: {e}")
        return False


def get_audit_log(
    limit: int = 50,
    risk_level_filter: Optional[str] = None,
    employee_id_filter: Optional[str] = None,
) -> list[dict]:
    """
    Return recent audit log entries, optionally filtered.
    Used by the Score Breakdown dashboard and executive report.
    """
    filters = []
    params  = []

    if risk_level_filter:
        filters.append("risk_level = ?")
        params.append(risk_level_filter)
    if employee_id_filter:
        filters.append("employee_id = ?")
        params.append(employee_id_filter)

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""
    params.append(limit)

    try:
        with _incident_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT report_id, employee_id, event_type,
                       unified_threat_index, risk_level, verdict,
                       ml_core_score, ml_dfuse_score,
                       llm_mistral_score, llm_gemini_score,
                       is_false_positive, processing_ms, analyzed_at
                FROM   analysis_audit_log
                {where_clause}
                ORDER  BY analyzed_at DESC
                LIMIT  ?
                """,
                params,
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        print(f"[db_utils] get_audit_log error: {e}")
        return []


def get_risk_trend(employee_id: str, days: int = 30) -> list[dict]:
    """
    Return daily average threat index for an employee over the last N days.
    Used for trend charts in the executive report.
    """
    try:
        with _incident_conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    DATE(analyzed_at)               AS day,
                    ROUND(AVG(unified_threat_index), 4) AS avg_score,
                    COUNT(*)                        AS event_count,
                    MAX(risk_level)                 AS peak_risk
                FROM   analysis_audit_log
                WHERE  employee_id = ?
                  AND  analyzed_at >= datetime('now', ?)
                GROUP  BY DATE(analyzed_at)
                ORDER  BY day ASC
                """,
                (employee_id, f"-{days} days"),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        print(f"[db_utils] get_risk_trend error for {employee_id}: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

def health_check_dbs() -> dict:
    """
    Verify both databases are reachable and return row counts.
    Called from GET /health in app.py.
    """
    result = {
        "mock_hr_db":       {"status": "error", "employee_count": 0},
        "incident_history_db": {"status": "error", "incident_count": 0, "audit_count": 0},
    }

    try:
        with _hr_conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
            result["mock_hr_db"] = {"status": "ok", "employee_count": count}
    except sqlite3.Error as e:
        result["mock_hr_db"]["error"] = str(e)

    try:
        with _incident_conn() as conn:
            inc_count   = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM analysis_audit_log"
            ).fetchone()[0]
            result["incident_history_db"] = {
                "status":        "ok",
                "incident_count": inc_count,
                "audit_count":   audit_count,
            }
    except sqlite3.Error as e:
        result["incident_history_db"]["error"] = str(e)

    return result