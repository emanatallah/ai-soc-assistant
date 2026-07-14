SCANS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    scan_results TEXT NOT NULL,
    risk_score REAL NOT NULL,
    severity TEXT NOT NULL,
    ai_report TEXT NOT NULL,
    mitre TEXT NOT NULL
);
"""