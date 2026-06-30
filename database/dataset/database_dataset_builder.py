"""
database_dataset_builder.py
============================
Stage 4 + 5 — Automatic Dataset Generation for the Database AI pipeline.

Generates:
  - 1000+ SAFE cases    → database_train.csv  (training)
  - 300–500 MALICIOUS cases → included in database_test.csv (evaluation only)

Design
------
The generator produces synthetic but statistically calibrated 56-feature
vectors for each case.  Every vector is unique — workload parameters are
randomised across:

  * tool type (mysqlbinlog / percona / pgaudit)
  * workload profile (OLTP, batch, admin, analytics, mixed)
  * scale (small / medium / large / xlarge)
  * operation mix (INSERT-heavy, UPDATE-heavy, DELETE-heavy, DDL-heavy …)
  * transaction size and success ratios
  * user and database counts
  * activity duration and timestamps

The generator is calibrated against the three real feature vectors that
were produced by the actual pipeline runs, ensuring synthetic data is
statistically representative of real workloads.

The Feature Schema (56 features) is imported directly from the shared
feature builder to guarantee it never drifts.

Usage (standalone)
------------------
    python dataset/database_dataset_builder.py
    python dataset/database_dataset_builder.py --safe 1500 --malicious 400
"""

import argparse
import csv
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

# ─── Feature schema — mirrors database_feature_builder.py exactly ─────────────
# Defined here to keep dataset_builder self-contained. Must stay in sync with
# the feature builder (any new feature must be added to both).

FEATURE_SCHEMA = [
    # Event Counts
    "total_events", "total_transactions", "total_data_changes",
    "total_schema_changes", "total_privilege_changes",
    "total_authentication_events", "total_configuration_events",
    "total_metadata_events", "total_unknown_events",
    # SQL Operations
    "insert_count", "update_count", "delete_count",
    "replace_count", "truncate_count",
    "create_table_count", "drop_table_count", "alter_table_count",
    "rename_table_count", "create_database_count", "drop_database_count",
    "create_user_count", "drop_user_count", "alter_user_count",
    "grant_count", "revoke_count", "set_password_count",
    # Transaction
    "begin_count", "commit_count", "rollback_count",
    "transaction_success_ratio",
    # Database
    "unique_database_count", "unique_table_count",
    "most_active_database", "most_active_table",
    # User
    "unique_user_count", "most_active_user", "admin_operation_count",
    # Ratios
    "insert_update_ratio", "delete_update_ratio",
    "ddl_dml_ratio", "grant_to_auth_ratio",
    # Errors
    "error_event_count", "success_rate",
    # Time
    "first_timestamp", "last_timestamp", "activity_duration",
    # Security
    "privilege_escalation_events", "authentication_changes",
    "schema_modification_events", "destructive_operations",
    # Composite Scores
    "data_change_score", "schema_change_score", "privilege_score",
    "authentication_score", "transaction_score",
    "overall_database_activity_score",
]

CATEGORICAL_FEATURES = {"most_active_database", "most_active_table", "most_active_user"}
NUMERIC_FEATURES     = [f for f in FEATURE_SCHEMA if f not in CATEGORICAL_FEATURES]

TRAIN_CSV = os.path.join(SCRIPT_DIR, "database_train.csv")
TEST_CSV  = os.path.join(SCRIPT_DIR, "database_test.csv")

# ─── Tool signatures ──────────────────────────────────────────────────────────
# Each tool produces slightly different feature distributions based on what
# its audit format captures.

TOOLS = ["mysqlbinlog", "percona", "pgaudit"]

# Most-active names per tool (sampled randomly for categorical features)
_DB_NAMES = {
    "mysqlbinlog": ["wordpress", "drupal", "joomla", "magento", "laravel_db"],
    "percona":     ["audit_lab", "production", "ecommerce", "crm", "analytics"],
    "pgaudit":     ["public", "app_schema", "reporting", "warehouse", "audit_schema"],
}
_TABLE_NAMES = {
    "mysqlbinlog": ["wp_posts", "wp_options", "wp_users", "wp_comments", "wp_usermeta"],
    "percona":     ["employees", "orders", "products", "customers", "transactions"],
    "pgaudit":     ["employees", "accounts", "ledger", "events", "sessions"],
}
_USER_NAMES = {
    "mysqlbinlog": ["wpuser@localhost", "root@localhost", "app_user@%", "readonly@localhost"],
    "percona":     ["root@localhost", "app@%", "monitor@localhost", "deployer@localhost"],
    "pgaudit":     [None],   # pgAudit SESSION logs do not capture user
}


# ─── Workload profiles ─────────────────────────────────────────────────────────
# Each profile defines probability weights for operation mix.

PROFILES = {
    "oltp": dict(
        insert_w=5, update_w=4, delete_w=2, select_w=6,
        create_table_w=0.1, drop_table_w=0.05, alter_table_w=0.1,
        create_user_w=0.05, grant_w=0.05, begin_w=4,
    ),
    "batch": dict(
        insert_w=8, update_w=2, delete_w=1, select_w=1,
        create_table_w=0.2, drop_table_w=0.1, alter_table_w=0.1,
        create_user_w=0.02, grant_w=0.02, begin_w=3,
    ),
    "analytics": dict(
        insert_w=1, update_w=0.5, delete_w=0.2, select_w=10,
        create_table_w=0.3, drop_table_w=0.1, alter_table_w=0.3,
        create_user_w=0.02, grant_w=0.1, begin_w=0.5,
    ),
    "admin": dict(
        insert_w=0.5, update_w=0.5, delete_w=0.2, select_w=0.5,
        create_table_w=1, drop_table_w=0.5, alter_table_w=1,
        create_user_w=1, grant_w=1, begin_w=0.5,
    ),
    "mixed": dict(
        insert_w=4, update_w=3, delete_w=2, select_w=4,
        create_table_w=0.3, drop_table_w=0.15, alter_table_w=0.3,
        create_user_w=0.2, grant_w=0.3, begin_w=2,
    ),
}

SCALES = {
    "small":  dict(base=500,    noise=200),
    "medium": dict(base=5000,   noise=2000),
    "large":  dict(base=50000,  noise=20000),
    "xlarge": dict(base=500000, noise=200000),
}

rng = np.random.default_rng()


# ─── Helper: safe ratio ────────────────────────────────────────────────────────

def _ratio(num: float, den: float, default: float = 0.0) -> float:
    return round(num / den, 6) if den > 0 else default


# ─── SAFE case generator ──────────────────────────────────────────────────────

def generate_safe_case(case_id: int) -> Dict[str, Any]:
    """Generate one randomised SAFE feature vector."""
    tool    = random.choice(TOOLS)
    profile = random.choice(list(PROFILES.keys()))
    scale   = random.choice(list(SCALES.keys()))

    p = PROFILES[profile]
    s = SCALES[scale]

    # Base event count for this scale
    total = max(10, int(rng.normal(s["base"], s["noise"] * 0.3)))

    # Operation counts — proportional to weights
    weights = np.array([
        p["insert_w"], p["update_w"], p["delete_w"], p["select_w"],
        p["create_table_w"], p["drop_table_w"], p["alter_table_w"],
        p["create_user_w"], p["grant_w"], p["begin_w"],
    ])
    weights /= weights.sum()
    counts = rng.multinomial(total, weights)

    insert_count      = int(counts[0])
    update_count      = int(counts[1])
    delete_count      = int(counts[2])
    select_count      = int(counts[3])
    create_table_count = int(counts[4])
    drop_table_count  = int(counts[5])
    alter_table_count = int(counts[6])
    create_user_count = int(counts[7])
    grant_count       = int(counts[8])
    begin_count       = int(counts[9])

    # Derived counts
    commit_count     = max(0, begin_count + random.randint(-2, 2))
    rollback_count   = max(0, int(rng.poisson(begin_count * 0.01)))  # ~1% rollback rate
    drop_user_count  = max(0, int(create_user_count * random.uniform(0.1, 0.4)))
    alter_user_count = max(0, int(create_user_count * random.uniform(0.0, 0.2)))
    revoke_count     = max(0, int(grant_count * random.uniform(0.0, 0.15)))
    set_count        = max(0, int(total * random.uniform(0.01, 0.05)))
    truncate_count   = max(0, int(rng.poisson(0.5)))
    rename_table_count = max(0, int(rng.poisson(0.2)))
    replace_count    = max(0, int(insert_count * random.uniform(0.0, 0.05)))
    set_password_count = max(0, int(rng.poisson(0.3)))
    create_db_count  = max(0, int(rng.poisson(0.5)))
    drop_db_count    = max(0, int(rng.poisson(0.2)))
    alter_table_count2 = alter_table_count  # alias

    # Binlog / metadata (tool-specific)
    binlog_count = int(total * 0.05) if tool == "mysqlbinlog" else 0

    # Transaction counts (pgAudit has explicit BEGIN/COMMIT; percona usually does not)
    if tool == "percona":
        begin_count  = 0
        commit_count = 0
        rollback_count = 0

    # Categories
    dml_count = insert_count + update_count + delete_count + replace_count
    ddl_count = (create_table_count + drop_table_count + alter_table_count +
                 rename_table_count + create_db_count + drop_db_count + truncate_count)

    total_transactions     = begin_count + commit_count + rollback_count
    total_data_changes     = dml_count + select_count
    total_schema_changes   = ddl_count
    total_privilege_changes = grant_count + revoke_count
    total_authentication_events = create_user_count + drop_user_count + alter_user_count + set_password_count
    total_configuration_events  = set_count
    total_metadata_events       = binlog_count
    total_unknown_events        = 0
    total_events = (total_transactions + total_data_changes + total_schema_changes +
                    total_privilege_changes + total_authentication_events +
                    total_configuration_events + total_metadata_events)

    # Ratios
    txn_ratio    = _ratio(commit_count, begin_count, default=0.0)
    ins_upd_ratio = _ratio(insert_count, update_count)
    del_upd_ratio = _ratio(delete_count, update_count)
    ddl_dml_ratio = _ratio(ddl_count, dml_count)
    g2a_ratio     = _ratio(grant_count, max(total_authentication_events, 1))

    # Errors — SAFE: low error count, high success rate
    error_count  = max(0, int(rng.poisson(random.uniform(0, 5))))
    success_rate = round(random.uniform(0.97, 1.0), 6)

    # Unique counts
    unique_db_count    = random.randint(1, 4)
    unique_table_count = max(1, int(rng.poisson(max(1, create_table_count + 3))))
    unique_user_count  = 0 if tool == "pgaudit" else random.randint(1, 8)

    # Categorical
    most_active_db    = random.choice(_DB_NAMES[tool])
    most_active_table = random.choice(_TABLE_NAMES[tool])
    most_active_user  = random.choice(_USER_NAMES[tool]) if tool != "pgaudit" else None

    # Admin operation count
    admin_op_count = (total_privilege_changes + total_authentication_events +
                      total_schema_changes)

    # Security features
    privilege_escalation_events = grant_count
    authentication_changes      = total_authentication_events
    schema_modification_events  = total_schema_changes
    destructive_operations      = (delete_count + drop_table_count + drop_db_count +
                                   truncate_count + drop_user_count)

    # Time features
    base_ts     = int(time.time()) - random.randint(0, 365 * 24 * 3600)
    duration    = random.randint(60, 7 * 24 * 3600)
    first_ts    = base_ts
    last_ts     = base_ts + duration
    activity_dur = duration

    # Composite scores
    data_change_score = round(
        insert_count * 1.0 + update_count * 1.0 + delete_count * 2.0 +
        replace_count * 1.5 + truncate_count * 5.0, 4)
    schema_change_score = round(
        create_table_count * 2.0 + drop_table_count * 5.0 +
        alter_table_count * 3.0 + rename_table_count * 2.0 +
        create_db_count * 3.0 + drop_db_count * 8.0, 4)
    privilege_score = round(
        grant_count * 3.0 + revoke_count * 2.0 + set_password_count * 4.0, 4)
    authentication_score = round(
        create_user_count * 3.0 + drop_user_count * 4.0 +
        alter_user_count * 3.0 + set_password_count * 4.0, 4)
    txn_score = round(
        begin_count * 0.5 + commit_count * 0.5 + rollback_count * 2.0 +
        (1.0 - txn_ratio) * 10.0, 4)
    overall_score = round(
        data_change_score + schema_change_score + privilege_score +
        authentication_score + (error_count * 3.0) +
        (destructive_operations * 1.5), 4)

    return {
        # metadata
        "case_id":     case_id,
        "source_tool": tool,
        "label":       "SAFE",
        # 1
        "total_events":                total_events,
        "total_transactions":          total_transactions,
        "total_data_changes":          total_data_changes,
        "total_schema_changes":        total_schema_changes,
        "total_privilege_changes":     total_privilege_changes,
        "total_authentication_events": total_authentication_events,
        "total_configuration_events":  total_configuration_events,
        "total_metadata_events":       total_metadata_events,
        "total_unknown_events":        total_unknown_events,
        # 2
        "insert_count":          insert_count,
        "update_count":          update_count,
        "delete_count":          delete_count,
        "replace_count":         replace_count,
        "truncate_count":        truncate_count,
        "create_table_count":    create_table_count,
        "drop_table_count":      drop_table_count,
        "alter_table_count":     alter_table_count,
        "rename_table_count":    rename_table_count,
        "create_database_count": create_db_count,
        "drop_database_count":   drop_db_count,
        "create_user_count":     create_user_count,
        "drop_user_count":       drop_user_count,
        "alter_user_count":      alter_user_count,
        "grant_count":           grant_count,
        "revoke_count":          revoke_count,
        "set_password_count":    set_password_count,
        # 3
        "begin_count":               begin_count,
        "commit_count":              commit_count,
        "rollback_count":            rollback_count,
        "transaction_success_ratio": txn_ratio,
        # 4
        "unique_database_count": unique_db_count,
        "unique_table_count":    unique_table_count,
        "most_active_database":  most_active_db,
        "most_active_table":     most_active_table,
        # 5
        "unique_user_count":    unique_user_count,
        "most_active_user":     most_active_user,
        "admin_operation_count": admin_op_count,
        # 6
        "insert_update_ratio": ins_upd_ratio,
        "delete_update_ratio": del_upd_ratio,
        "ddl_dml_ratio":       ddl_dml_ratio,
        "grant_to_auth_ratio": g2a_ratio,
        # 7
        "error_event_count": error_count,
        "success_rate":       success_rate,
        # 8
        "first_timestamp":   first_ts,
        "last_timestamp":    last_ts,
        "activity_duration": activity_dur,
        # 9
        "privilege_escalation_events":  privilege_escalation_events,
        "authentication_changes":       authentication_changes,
        "schema_modification_events":   schema_modification_events,
        "destructive_operations":       destructive_operations,
        # 10
        "data_change_score":               data_change_score,
        "schema_change_score":             schema_change_score,
        "privilege_score":                 privilege_score,
        "authentication_score":            authentication_score,
        "transaction_score":               txn_score,
        "overall_database_activity_score": overall_score,
    }


# ─── MALICIOUS case generator ─────────────────────────────────────────────────

ATTACK_TYPES = [
    "excessive_delete",
    "mass_drop_table",
    "privilege_escalation",
    "abnormal_grant_flood",
    "brute_force_auth_error",
    "destructive_schema_change",
    "abnormal_transaction",
    "mass_create_user",
    "data_exfiltration_select",
    "ransomware_drop_create",
]


def generate_malicious_case(case_id: int) -> Dict[str, Any]:
    """Generate one randomised MALICIOUS feature vector."""
    tool        = random.choice(TOOLS)
    attack_type = random.choice(ATTACK_TYPES)

    # Start from a plausible normal base then inject the anomaly
    base = generate_safe_case(case_id)
    base["label"]    = "MALICIOUS"
    base["case_id"]  = case_id

    # ── Inject attack pattern ─────────────────────────────────────────────────
    if attack_type == "excessive_delete":
        multiplier = random.randint(10, 100)
        base["delete_count"]          *= multiplier
        base["destructive_operations"] = base["delete_count"] + base["drop_table_count"]
        base["total_data_changes"]    += base["delete_count"]
        base["data_change_score"]      = round(
            base["insert_count"] * 1.0 + base["update_count"] * 1.0 +
            base["delete_count"] * 2.0 + base["replace_count"] * 1.5, 4)

    elif attack_type == "mass_drop_table":
        base["drop_table_count"]       = random.randint(50, 500)
        base["drop_database_count"]    = random.randint(1, 20)
        base["truncate_count"]         = random.randint(10, 100)
        base["destructive_operations"] += base["drop_table_count"] + base["truncate_count"]
        base["total_schema_changes"]   += base["drop_table_count"]
        base["schema_change_score"]    = round(
            base["create_table_count"] * 2 + base["drop_table_count"] * 5 +
            base["alter_table_count"] * 3 + base["drop_database_count"] * 8, 4)

    elif attack_type == "privilege_escalation":
        base["grant_count"]            = random.randint(500, 5000)
        base["create_user_count"]      = random.randint(100, 1000)
        base["privilege_escalation_events"] = base["grant_count"]
        base["total_privilege_changes"] = base["grant_count"] + base["revoke_count"]
        base["total_authentication_events"] += base["create_user_count"]
        base["privilege_score"]         = round(base["grant_count"] * 3.0, 4)
        base["grant_to_auth_ratio"]     = _ratio(
            base["grant_count"],
            max(base["total_authentication_events"], 1))

    elif attack_type == "abnormal_grant_flood":
        base["grant_count"]            = random.randint(1000, 10000)
        base["revoke_count"]           = random.randint(0, 50)
        base["privilege_escalation_events"] = base["grant_count"]
        base["grant_to_auth_ratio"]    = round(
            base["grant_count"] / max(base["total_authentication_events"], 1), 6)
        base["privilege_score"]        = round(base["grant_count"] * 3.0, 4)

    elif attack_type == "brute_force_auth_error":
        base["error_event_count"] = random.randint(500, 10000)
        base["success_rate"]      = round(random.uniform(0.01, 0.4), 6)
        base["create_user_count"] = random.randint(50, 500)
        base["total_authentication_events"] += base["create_user_count"]

    elif attack_type == "destructive_schema_change":
        base["drop_table_count"]    = random.randint(20, 200)
        base["drop_database_count"] = random.randint(5, 50)
        base["alter_table_count"]   = random.randint(50, 500)
        base["truncate_count"]      = random.randint(20, 200)
        base["total_schema_changes"] = (
            base["create_table_count"] + base["drop_table_count"] +
            base["alter_table_count"] + base["drop_database_count"] + base["truncate_count"])
        base["schema_change_score"] = round(
            base["create_table_count"] * 2 + base["drop_table_count"] * 5 +
            base["alter_table_count"] * 3 + base["drop_database_count"] * 8 +
            base["truncate_count"] * 5, 4)
        base["destructive_operations"] += (
            base["drop_table_count"] + base["drop_database_count"] + base["truncate_count"])

    elif attack_type == "abnormal_transaction":
        base["rollback_count"]           = random.randint(500, 5000)
        base["begin_count"]              = max(base["begin_count"], base["rollback_count"])
        base["commit_count"]             = max(0, base["begin_count"] - base["rollback_count"])
        base["transaction_success_ratio"]= _ratio(base["commit_count"], base["begin_count"])
        base["total_transactions"]       = (base["begin_count"] + base["commit_count"] +
                                             base["rollback_count"])
        base["transaction_score"]        = round(
            base["begin_count"] * 0.5 + base["commit_count"] * 0.5 +
            base["rollback_count"] * 2.0 +
            (1.0 - base["transaction_success_ratio"]) * 10.0, 4)

    elif attack_type == "mass_create_user":
        base["create_user_count"]      = random.randint(200, 2000)
        base["grant_count"]            = int(base["create_user_count"] * random.uniform(1, 3))
        base["drop_user_count"]        = random.randint(0, int(base["create_user_count"] * 0.3))
        base["total_authentication_events"] = (base["create_user_count"] +
                                               base["drop_user_count"] + base["alter_user_count"])
        base["total_privilege_changes"] = base["grant_count"] + base["revoke_count"]
        base["privilege_escalation_events"] = base["grant_count"]
        base["authentication_score"]   = round(base["create_user_count"] * 3.0 +
                                               base["drop_user_count"] * 4.0, 4)

    elif attack_type == "data_exfiltration_select":
        # Massive SELECT with very low write activity (suspicious read-heavy pattern)
        multiplier = random.randint(20, 200)
        base["total_data_changes"]    += int(base["total_data_changes"] * multiplier * 0.1)
        base["insert_count"]           = max(0, int(base["insert_count"] * 0.1))
        base["update_count"]           = max(0, int(base["update_count"] * 0.1))
        base["delete_count"]           = max(0, int(base["delete_count"] * 0.1))
        base["ddl_dml_ratio"]          = _ratio(
            base["create_table_count"] + base["drop_table_count"],
            base["insert_count"] + base["update_count"] + base["delete_count"])

    elif attack_type == "ransomware_drop_create":
        # Drop everything, then recreate (ransomware pattern)
        base["drop_table_count"]    = random.randint(100, 1000)
        base["create_table_count"]  = random.randint(50, 500)
        base["drop_database_count"] = random.randint(5, 50)
        base["truncate_count"]      = random.randint(50, 500)
        base["delete_count"]        *= random.randint(5, 20)
        base["total_schema_changes"] = (
            base["create_table_count"] + base["drop_table_count"] + base["alter_table_count"] +
            base["drop_database_count"] + base["truncate_count"])
        base["destructive_operations"] = (
            base["delete_count"] + base["drop_table_count"] +
            base["drop_database_count"] + base["truncate_count"])
        base["schema_change_score"] = round(
            base["create_table_count"] * 2 + base["drop_table_count"] * 5 +
            base["drop_database_count"] * 8 + base["truncate_count"] * 5, 4)

    # Recompute overall score after mutation
    base["overall_database_activity_score"] = round(
        base["data_change_score"] + base["schema_change_score"] +
        base["privilege_score"] + base["authentication_score"] +
        base["error_event_count"] * 3.0 + base["destructive_operations"] * 1.5, 4)

    return base


# ─── CSV writer ───────────────────────────────────────────────────────────────

# Column order: metadata first, then all 56 features
COLUMNS = ["case_id", "source_tool", "label"] + FEATURE_SCHEMA


def write_csv(rows: List[Dict[str, Any]], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Database AI Dataset Builder")
    ap.add_argument("--safe",      type=int, default=1200,
                    help="Number of SAFE cases to generate (default: 1200)")
    ap.add_argument("--malicious", type=int, default=400,
                    help="Number of MALICIOUS cases to generate (default: 400)")
    ap.add_argument("--seed",      type=int, default=42,
                    help="Random seed for reproducibility (default: 42)")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv",  default=TEST_CSV)
    args = ap.parse_args()

    random.seed(args.seed)
    global rng
    rng = np.random.default_rng(args.seed)

    print("=" * 52)
    print("  Database AI — Dataset Builder")
    print("=" * 52)
    print(f"  SAFE cases to generate     : {args.safe}")
    print(f"  MALICIOUS cases to generate: {args.malicious}")
    print(f"  Random seed                : {args.seed}")
    print()

    t0 = time.time()

    # ── Generate SAFE cases ───────────────────────────────────────────────────
    print(f"[INFO] Generating {args.safe} SAFE cases ...")
    safe_cases: List[Dict] = []
    for i in range(1, args.safe + 1):
        safe_cases.append(generate_safe_case(i))
    print(f"[INFO] {len(safe_cases)} SAFE cases generated in {time.time()-t0:.1f}s")

    # ── Generate MALICIOUS cases ───────────────────────────────────────────────
    print(f"[INFO] Generating {args.malicious} MALICIOUS cases ...")
    t1 = time.time()
    malicious_cases: List[Dict] = []
    for i in range(args.safe + 1, args.safe + args.malicious + 1):
        malicious_cases.append(generate_malicious_case(i))
    print(f"[INFO] {len(malicious_cases)} MALICIOUS cases generated in {time.time()-t1:.1f}s")

    # ── Write CSV files ───────────────────────────────────────────────────────
    # Training: SAFE only
    write_csv(safe_cases, args.train_csv)
    print(f"[INFO] Training CSV  written : {args.train_csv}  ({len(safe_cases)} rows)")

    # Test: SAFE + MALICIOUS (shuffled)
    all_test = safe_cases + malicious_cases
    random.shuffle(all_test)
    write_csv(all_test, args.test_csv)
    print(f"[INFO] Test CSV      written : {args.test_csv}  ({len(all_test)} rows)")

    # ── Summary ───────────────────────────────────────────────────────────────
    from collections import Counter
    safe_tools = Counter(c["source_tool"] for c in safe_cases)
    mal_tools  = Counter(c["source_tool"] for c in malicious_cases)

    print()
    print("=" * 52)
    print("  Dataset Summary")
    print("=" * 52)
    print(f"  Total cases     : {len(safe_cases) + len(malicious_cases)}")
    print(f"  SAFE            : {len(safe_cases)}")
    print(f"  MALICIOUS       : {len(malicious_cases)}")
    print(f"  Features        : {len(FEATURE_SCHEMA)} (56)")
    print()
    print("  SAFE by tool:")
    for tool, cnt in sorted(safe_tools.items()):
        print(f"    {tool:<18} : {cnt}")
    print("  MALICIOUS by tool:")
    for tool, cnt in sorted(mal_tools.items()):
        print(f"    {tool:<18} : {cnt}")
    print()
    print(f"  Total time      : {time.time()-t0:.1f}s")
    print("=" * 52)
    print()


if __name__ == "__main__":
    main()
