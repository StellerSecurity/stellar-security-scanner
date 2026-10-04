#!/usr/bin/env python3
"""Combine sanitized posture collector reports; optionally probe owned App hosts.

Local report mode is the default. No notification or cloud mutation is performed.
Input reports are treated as untrusted data and reduced to identifier metadata.
The enclosing workflow must persist next_state before delivering its digests and
must impose a hard job timeout (the OS DNS resolver is not fully time bounded).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
import uuid

import exposure_probe
import reporting


ORGANIZATIONS = ("StellerSecurity", "Stellar-seo-websites", "StellarMail", "StellarSecurity-Packages")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TOTAL_HOSTS = 600
_PROBE_RULES = {"/.git/HEAD": "public_git_metadata", "/.env": "public_environment_file",
                "/backup.sql": "public_database_dump", "/database.sql": "public_database_dump"}
_PLAN_TYPES = {
    "AppServices": {"microsoft.web/sites"},
    "SqlServers": {"microsoft.sql/servers"},
    "StorageAccounts": {"microsoft.storage/storageaccounts"},
    "OpenSourceRelationalDatabases": {"microsoft.dbformysql/flexibleservers", "microsoft.dbforpostgresql/flexibleservers",
                                        "microsoft.dbformysql/servers", "microsoft.dbforpostgresql/servers"},
    "CosmosDbs": {"microsoft.documentdb/databaseaccounts"},
}


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _id(value, resource=False):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("invalid_collector_identifier")
    try:
        return reporting._identifier(value, resource=resource)
    except reporting.ReportingError:
        # Preserve identity for legitimate non-ASCII/cloud resource names without
        # copying untrusted punctuation, control characters or arbitrary text.
        return "resource:" + _hash(value) if resource else "scope:" + _hash(value)


def _subscription(resource_id, expected):
    match = re.match(r"^/subscriptions/([0-9a-fA-F-]{36})(?:/|$)", resource_id or "")
    if not match or str(uuid.UUID(match[1])) not in expected:
        raise ValueError("azure_resource_outside_expected_subscriptions")
    return str(uuid.UUID(match[1]))


def _resource_scope(resource_id):
    return "azure:resource:" + _hash(resource_id.lower())[:32]


def _repo_scope(repo):
    return _id("github:repository:" + repo.lower())


def _probe_scope(host, path):
    return _id("probe:" + host + ":" + path)


def _rows(report, key):
    value = report.get(key, [])
    if not isinstance(value, list) or len(value) > 25000 or any(not isinstance(item, dict) for item in value):
        raise ValueError("invalid_collector_rows")
    return value


def owned_probe_hosts(azure_report, expected_subscriptions):
    """Only ARM-owned App defaultHostName, never arbitrary URLs from findings."""
    expected = {str(uuid.UUID(value)) for value in expected_subscriptions}
    result = set()
    if not azure_report:
        return []
    for resource in _rows(azure_report, "inventory"):
        _subscription(resource.get("resource_id"), expected)
        if resource.get("type", "").lower() != "microsoft.web/sites" or resource.get("assessed") is not True:
            continue
        for endpoint in _rows(resource, "endpoints"):
            if (endpoint.get("kind") == "app" and endpoint.get("source_property") == "defaultHostName"
                    and endpoint.get("https_probe_candidate") is True):
                host = exposure_probe._valid_host(endpoint.get("host"))
                if not host.endswith(".azurewebsites.net"):
                    raise ValueError("unexpected_azure_default_hostname")
                result.add(host)
    if len(result) > MAX_TOTAL_HOSTS:
        raise ValueError("total_owned_host_limit_exceeded")
    return sorted(result)


def run_owned_probes(azure_report, expected_subscriptions, budget_seconds=300, probe=None, clock=time.monotonic):
    """At most 60 hosts per batch and four workers, within a shared time budget."""
    if type(budget_seconds) not in (int, float) or not 1 <= budget_seconds <= 600:
        raise ValueError("invalid_total_probe_budget")
    hosts = owned_probe_hosts(azure_report, expected_subscriptions)
    probe = exposure_probe.probe_hosts if probe is None else probe
    deadline = clock() + budget_seconds
    results = []
    for start in range(0, len(hosts), exposure_probe.MAX_HOSTS):
        batch = hosts[start:start + exposure_probe.MAX_HOSTS]
        remaining = deadline - clock()
        if remaining < 1:
            results.extend({"resource_host": host, "coverage": "unavailable", "findings": [], "checks": [],
                            "reason": "total_time_budget_exhausted"} for host in batch)
            continue
        results.extend(probe(batch, budget_seconds=min(300, remaining), max_workers=4))
    return results


def normalize_reports(azure_report, github_report, probe_results, expected_subscriptions,
                      expected_organizations=ORGANIZATIONS, observed_at=None):
    expected = {str(uuid.UUID(value)) for value in expected_subscriptions}
    github_owners = {value.lower() for value in expected_organizations}
    if not expected or not set(expected_organizations).issubset(ORGANIZATIONS):
        raise ValueError("explicit_approved_scope_required")
    observed_at = observed_at or dt.datetime.now(dt.timezone.utc).isoformat()
    reporting._time(observed_at)
    snapshot = {"observed_at": observed_at, "coverage": {}, "findings": []}
    coverage, findings = snapshot["coverage"], snapshot["findings"]

    def add(scope, resource, rule, severity, kind):
        if severity == "info":
            return
        if severity not in reporting.SEVERITIES:
            severity = "medium"  # Provider unknown severity still requires review.
        findings.append(reporting.normalize_finding({"scope": scope, "resource_id": _id(resource, True),
            "rule_id": _id(rule), "severity": severity, "kind": kind}))

    # Inventory and per-resource scopes remain independent: an unrelated failed
    # check cannot incorrectly resolve another resource's still-open finding.
    if azure_report is None:
        for sub in sorted(expected):
            coverage["azure:inventory:" + sub] = "unavailable"
            coverage["azure:defender:" + sub] = "unavailable"
    else:
        if (not isinstance(azure_report, dict) or not isinstance(azure_report.get("coverage"), dict)
                or azure_report["coverage"].get("scope") not in reporting.COVERAGE):
            raise ValueError("invalid_azure_report")
        declared = {str(uuid.UUID(value)) for value in azure_report.get("subscriptions", [])}
        if not declared.issubset(expected):
            raise ValueError("azure_report_outside_expected_subscriptions")
        gaps = _rows(azure_report, "coverage_gaps")
        inventory = _rows(azure_report, "inventory")
        entries = {}
        for item in inventory:
            rid = item.get("resource_id")
            _subscription(rid, expected)
            entries[rid.lower()] = item
        for sub in sorted(expected):
            inventory_gaps = [g for g in gaps if g.get("check") == "resource_inventory"
                              and str(g.get("resource_id", "")).lower().startswith("/subscriptions/" + sub)]
            status = azure_report.get("coverage", {}).get("scope")
            coverage["azure:inventory:" + sub] = ("unavailable" if sub not in declared or status == "unavailable"
                                                  else "partial" if inventory_gaps else "complete")
            alert_gaps = [g for g in gaps if g.get("check") == "defender_alert_inventory"
                          and str(g.get("resource_id", "")).lower().startswith("/subscriptions/" + sub)]
            coverage["azure:defender:" + sub] = ("unavailable" if sub not in declared or alert_gaps
                or not isinstance(azure_report.get("defender_alerts"), list) else "complete")
        for rid, item in entries.items():
            matching = [g for g in gaps if str(g.get("resource_id", "")).lower() == rid
                        or str(g.get("resource_id", "")).lower().startswith(rid + "/")]
            coverage[_resource_scope(rid)] = ("unavailable" if item.get("assessed") is not True
                                               else "partial" if matching else "complete")
        for raw in _rows(azure_report, "findings"):
            rid = raw.get("resource_id")
            sub = _subscription(rid, expected)
            scope = "azure:defender:" + sub if raw.get("kind") == "defender_alert" else _resource_scope(rid)
            coverage.setdefault(scope, "partial")
            finding_resource = rid
            if raw.get("rule_id") == "ANONYMOUS_BLOB_ACCESS_CONFIGURED":
                container = raw.get("evidence", {}).get("container_name")
                if not isinstance(container, str) or not re.fullmatch(r"\$root|\$web|[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", container):
                    raise ValueError("invalid_anonymous_container_identifier")
                # Keep account coverage (ACL enumeration may have failed) while
                # distinguishing each container's independently changing access.
                finding_resource += "/blobServices/default/containers/" + container
            add(scope, finding_resource, raw.get("rule_id"), raw.get("severity"),
                "monitoring" if raw.get("kind") in {"monitoring", "monitoring-gap"} else "exposure")
        for plan in _rows(azure_report, "defender_plans"):
            name, sub = plan.get("name"), plan.get("subscription_id")
            if sub not in expected or name not in _PLAN_TYPES:
                continue
            applicable = any(_subscription(item["resource_id"], expected) == sub
                             and item.get("type", "").lower() in _PLAN_TYPES[name] for item in inventory)
            if not applicable:
                continue
            scope = "azure:runtime-plan:" + sub + ":" + name
            tier = plan.get("pricing_tier")
            coverage[scope] = "complete" if tier in {"Free", "Standard"} else "partial"
            if tier == "Free":
                add(scope, "azure:" + sub + ":" + name, "runtime_coverage_missing", "medium", "monitoring")

    if github_report is None:
        for org in expected_organizations:
            coverage["github:inventory:" + org] = "unavailable"
    else:
        if not isinstance(github_report, dict):
            raise ValueError("invalid_github_report")
        observed_orgs = {row.get("organization"): row for row in _rows(github_report, "organizations")}
        if not set(observed_orgs).issubset(expected_organizations):
            raise ValueError("github_report_outside_expected_organizations")
        attested = github_report.get("coverage", {}).get("all_repository_access_attested") is True
        for org in expected_organizations:
            entry = observed_orgs.get(org, {})
            coverage["github:inventory:" + org] = ("unavailable" if entry.get("inventory_status") != "OBSERVED"
                                                    else "complete" if attested else "partial")
        coverage["github:inventory-attestation"] = "complete" if attested else "partial"
        for row in _rows(github_report, "repositories"):
            name = row.get("repository")
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name)
                    or name.split("/")[0].lower() not in github_owners):
                raise ValueError("github_repository_outside_expected_organizations")
            coverage[_repo_scope(name)] = "complete" if row.get("unknown") == [] else "partial"
        for raw in _rows(github_report, "findings"):
            rid = raw.get("resource_id")
            if rid == "organizations":
                scope = "github:inventory-attestation"
            elif rid in expected_organizations:
                scope = "github:inventory:" + rid
            elif (isinstance(rid, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", rid)
                    and rid.split("/")[0].lower() in github_owners):
                scope = _repo_scope(rid)
                coverage.setdefault(scope, "unavailable")
            else:
                raise ValueError("github_finding_outside_expected_organizations")
            add(scope, rid, raw.get("rule_id"), raw.get("severity"),
                "exposure" if raw.get("kind") == "credential-exposure" else "monitoring")

    expected_hosts = owned_probe_hosts(azure_report, expected)
    indexed = {}
    for result in probe_results or []:
        host = result.get("resource_host")
        if host not in expected_hosts or host in indexed:
            raise ValueError("unexpected_or_duplicate_probe_host")
        indexed[host] = result
    for host in expected_hosts:
        result = indexed.get(host, {})
        checks = {c.get("path"): c for c in _rows(result, "checks")}
        if not set(checks).issubset(exposure_probe.PATHS):
            raise ValueError("unexpected_probe_path")
        for path in exposure_probe.PATHS:
            check = checks.get(path, {})
            outcome = check.get("result")
            coverage[_probe_scope(host, path)] = ("complete" if outcome in {
                "not_public_at_checked_path", "strong_exposure_indicator"}
                else "partial" if check.get("status") else "unavailable")
        for raw in _rows(result, "findings"):
            path = raw.get("path")
            if (path not in _PROBE_RULES or raw.get("rule_id") != _PROBE_RULES[path]
                    or raw.get("resource_host") != host or raw.get("status") != 200
                    or raw.get("confidence") != "high"
                    or checks.get(path, {}).get("result") != "strong_exposure_indicator"):
                raise ValueError("invalid_probe_finding")
            add(_probe_scope(host, path), host + path, raw["rule_id"], "high", "exposure")
    return snapshot


def build_digests(alerts):
    """At most two messages per invocation, irrespective of estate/finding size."""
    groups = {"exposure": [], "monitoring": []}
    for alert in alerts:
        reporting._validate_alert(alert)
        groups[alert["finding"]["kind"]].append(alert)
    digests = []
    for kind, rows in groups.items():
        if not rows:
            continue
        rows = sorted(rows, key=lambda row: row["event_id"])
        identifiers = sorted({row["event_id"] for row in rows})
        unique = {row["event_id"]: row for row in rows}
        rows = list(unique.values())
        counts = {change: sum(row["change"] == change for row in rows) for change in ("new", "worsened", "resolved")}
        label = "SECURITY EXPOSURE" if kind == "exposure" else "SECURITY MONITORING"
        title = label + " — " + ", ".join(f"{counts[change]} {change.upper()}" for change in counts if counts[change])
        text = ["Changes since the previous recorded check:"]
        ordered = sorted(rows, key=lambda row: (row["change"] == "resolved", -reporting.SEVERITIES[row["finding"]["severity"]], row["event_id"]))
        for row in ordered[:5]:
            finding = row["finding"]
            resource = finding["resource_id"].rstrip("/").split("/")[-1]
            resource = resource[:70]
            text.append(f"{row['change'].upper()} {finding['severity'].upper()}: {finding['rule_id'][:80]} — {resource}")
        if len(rows) > 5:
            text.append(f"{len(rows) - 5} additional changes are in the private report.")
        text.append("Incomplete checks are reported separately; they never resolve exposure findings.")
        body = "\n".join(text)
        if len(body) > 1024 or len(title) > 250:
            raise ValueError("digest_size_exceeded")
        digests.append({"event_id": "posture-digest:v1:" + _hash(identifiers), "event_ids": identifiers,
            "destination": "github-security", "kind": kind, "title": title, "text": body, "counts": counts})
    return digests


def prepare_report(previous_state, azure_report, github_report, probe_results, expected_subscriptions,
                   expected_organizations=ORGANIZATIONS, observed_at=None):
    snapshot = normalize_reports(azure_report, github_report, probe_results, expected_subscriptions,
                                 expected_organizations, observed_at)
    comparison = reporting.compare_snapshots(previous_state, snapshot)
    state = comparison["state"]
    return {"schema_version": 1, "observed_at": snapshot["observed_at"], "snapshot": snapshot,
            "new_alerts": comparison["alerts"], "digests": build_digests(comparison["alerts"]),
            "pending_digests": build_digests(list(state["pending"].values())),
            "counts": {"active": len(state["active"]), "new_changes": len(comparison["alerts"]),
                       "pending_events": len(state["pending"]), "coverage_scopes": len(snapshot["coverage"])},
            "next_state": state}


def _read_json(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("json_input_too_large")
    return json.loads(raw)


def _write_json(path, value):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("output_symlink_rejected")
    body = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(body) > MAX_JSON_BYTES:
        raise ValueError("json_output_too_large")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure-report", type=Path)
    parser.add_argument("--github-report", type=Path)
    parser.add_argument("--probe-report", type=Path)
    parser.add_argument("--probe-owned-hosts", action="store_true")
    parser.add_argument("--probe-budget-seconds", type=float, default=300)
    parser.add_argument("--subscription", action="append", required=True)
    parser.add_argument("--organization", action="append", choices=ORGANIZATIONS)
    initial = parser.add_mutually_exclusive_group(required=True)
    initial.add_argument("--state-in", type=Path)
    initial.add_argument("--initialize-state", action="store_true")
    parser.add_argument("--state-out", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.probe_report and args.probe_owned_hosts:
        parser.error("Choose probe report input or an owned-host probe, not both.")
    azure = _read_json(args.azure_report) if args.azure_report else None
    github = _read_json(args.github_report) if args.github_report else None
    previous = _read_json(args.state_in) if args.state_in else reporting.empty_state()
    probes = (_read_json(args.probe_report) if args.probe_report else
              run_owned_probes(azure, args.subscription, args.probe_budget_seconds) if args.probe_owned_hosts else [])
    result = prepare_report(previous, azure, github, probes, args.subscription, args.organization or ORGANIZATIONS)
    # Root's workflow owns external persistence and per-provider acknowledgement.
    _write_json(args.state_out, result["next_state"])
    _write_json(args.output, result)
    print(json.dumps({"result": "local_report_written", **result["counts"], "digests": len(result["digests"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
