#!/usr/bin/env python3
"""Read-only GitHub security posture collector. Python standard library only.

No repository code is executed. Only the fixed first-party workflow paths below
are read. Secret-alert bodies are projected to numeric IDs at the transport
boundary and never included in reports or error text. The token needs repository
Metadata, Actions, Contents, Checks, and Secret scanning alerts read permissions.
Viewing security_and_analysis also needs suitable repository admin/security
manager privileges and the relevant GitHub product entitlement.

The inventory is credential-visible, not proof that an organization has no
inaccessible repositories. Set inventory_attested only after independently
verifying all-repository installation access; optionally supply expected_repos.
Workflow success proves execution, not the absence of malware or credential leaks.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

ORGANIZATIONS = ("StellerSecurity", "Stellar-seo-websites", "StellarMail", "StellarSecurity-Packages")
WORKFLOW_PATHS = {
    "source": ".github/workflows/stellar-source-guard.yml",
    "collector": ".github/workflows/stellar-commit-trigger.yml",
    "worker": ".github/workflows/stellar-commit-guard.yml",
}
CHECK_NAMES = {"Repository source guard", "Repository commit guard", "Repository dependency content guard"}
UTC = dt.timezone.utc
MAX_BODY = 16 * 1024 * 1024
MAX_WORKFLOW = 512 * 1024
MAX_PAGES = 1000
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
SHA = re.compile(r"^[a-f0-9]{40}$")


@dataclass
class Response:
    status: int
    data: Any = None


def _safe_api_path(path: str) -> str:
    if not path.startswith(("/orgs/", "/repos/")) or any(c in path for c in "\r\n\\") or ".." in path:
        raise ValueError("Unsupported GitHub API path")
    parts = urllib.parse.urlsplit(path)
    if parts.scheme or parts.netloc or parts.fragment:
        raise ValueError("Unsupported GitHub API URL")
    return path


def _project_response(path: str, body: Any) -> Any:
    if "/secret-scanning/alerts" in path:
        # Never return secret values, locations, or server-provided free text.
        if not isinstance(body, list):
            return None
        return [{"number": item.get("number")} for item in body if isinstance(item, dict)]
    return body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpApi:
    """Suitable for an existing approved runtime. Token is never printed/stored."""
    def __init__(self, token: str, timeout: int = 30):
        self._token = token
        self.timeout = timeout
        # Never let an ambient proxy setting redirect authenticated API traffic.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def get(self, path: str) -> Response:
        path = _safe_api_path(path)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Stellar-Cloud-Posture"}
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        req = urllib.request.Request("https://api.github.com" + path, headers=headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                raw = response.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    return Response(0)
                data = _project_response(path, json.loads(raw))
                del raw
                return Response(response.status, data)
        except urllib.error.HTTPError as exc:
            return Response(exc.code)  # Never log potentially sensitive error bodies.
        except (OSError, ValueError, TimeoutError):
            return Response(0)


class GhApi:
    """Uses the already installed/authenticated gh CLI; does not extract tokens."""
    def get(self, path: str) -> Response:
        path = _safe_api_path(path)
        args = ["gh", "api", "--method", "GET", path, "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if "/secret-scanning/alerts" in path:
            args += ["--jq", "[.[] | {number: .number}]"]
        try:
            result = subprocess.run(args, capture_output=True, timeout=45, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return Response(0)
        if result.returncode:
            match = re.search(rb"\(HTTP (\d{3})\)", result.stderr)
            return Response(int(match.group(1)) if match else 0)
        if len(result.stdout) > MAX_BODY:
            return Response(0)
        try:
            return Response(200, _project_response(path, json.loads(result.stdout)))
        except (ValueError, UnicodeError):
            return Response(0)


def _date(value: Any):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except ValueError:
        return None


def _error(status: int) -> str:
    return {401: "authentication_failed", 403: "denied_or_rate_limited", 404: "not_found_or_not_authorized", 429: "rate_limited"}.get(status, "unavailable")


def paginate(client, path: str, key: str | None = None, *, identity="id", max_pages=MAX_PAGES):
    """Numeric pagination with deduplication and explicit partial results."""
    found, seen = [], set()
    for page in range(1, max_pages + 1):
        sep = "&" if "?" in path else "?"
        response = client.get(f"{path}{sep}per_page=100&page={page}")
        if response.status != 200:
            return found, _error(response.status)
        data = response.data
        rows = data.get(key) if key and isinstance(data, dict) else data
        if not isinstance(rows, list):
            return found, "invalid_response"
        new = 0
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get(identity), int) or isinstance(row[identity], bool):
                return found, "invalid_response"
            if row[identity] not in seen:
                seen.add(row[identity]); found.append(row); new += 1
        if len(rows) < 100:
            if key and isinstance(data.get("total_count"), int) and len(found) < data["total_count"]:
                return found, "inconsistent_pagination"
            return found, None
        if not new:
            return found, "pagination_did_not_advance"
    return found, "pagination_limit"


def workflow_schedule(content: str):
    """Read only the simple top-level on/schedule YAML form used by our callers.

    This is deliberately not a general YAML parser. Unsupported expressions,
    aliases, inline schedules or complex cron get UNKNOWN, never a healthy pass.
    """
    in_on, in_schedule, on_indent, schedule_indent, crons = False, False, 0, 0, []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if re.fullmatch(r"(?:on|'on'|\"on\"):\s*(?:#.*)?", line):
            in_on, on_indent = True, indent
            continue
        if in_on and indent <= on_indent:
            in_on = in_schedule = False
        if not in_on:
            continue
        if re.fullmatch(r"schedule:\s*(?:#.*)?", stripped):
            in_schedule, schedule_indent = True, indent
            continue
        if in_schedule and indent <= schedule_indent:
            in_schedule = False
        if in_schedule:
            match = re.fullmatch(r"-\s+cron:\s*(['\"])([^'\"]+)\1\s*(?:#.*)?", stripped)
            if not match:
                return {"status": "UNKNOWN", "reason": "unsupported_schedule_syntax"}
            crons.append(match[2])
            if len(crons) > 32 or len(match[2]) > 128:
                return {"status": "UNKNOWN", "reason": "schedule_complexity_limit"}
    if not crons:
        return {"status": "UNKNOWN", "reason": "schedule_missing_or_unsupported"}
    # Derive the largest gap for the actual schedule over 15 months. This handles
    # monthly/weekday schedules without labelling a weekly source scan overdue.
    intervals = []
    for cron in crons:
        fields = cron.split()
        if len(fields) != 5:
            return {"status": "UNKNOWN", "reason": "unsupported_cron"}
        try:
            minutes = _cron_values(fields[0], 0, 59)
            hours = _cron_values(fields[1], 0, 23)
            days = _cron_values(fields[2], 1, 31)
            months = _cron_values(fields[3], 1, 12)
            weekdays = {v % 7 for v in _cron_values(fields[4], 0, 7)}
        except ValueError:
            return {"status": "UNKNOWN", "reason": "unsupported_cron"}
        previous, max_gap = None, 0.0
        start = dt.datetime(2024, 1, 1, tzinfo=UTC)
        for offset in range(457):
            day = start + dt.timedelta(days=offset)
            dom_match, dow_match = day.day in days, ((day.weekday() + 1) % 7) in weekdays
            # GitHub uses POSIX cron: when both fields are constrained, either
            # day of month OR day of week can match.
            match = (dom_match or dow_match) if fields[2] != "*" and fields[4] != "*" else dom_match and dow_match
            if day.month not in months or not match:
                continue
            for hour in sorted(hours):
                for minute in sorted(minutes):
                    point = day.replace(hour=hour, minute=minute)
                    if previous:
                        max_gap = max(max_gap, (point - previous).total_seconds())
                    previous = point
        if not max_gap:
            return {"status": "UNKNOWN", "reason": "schedule_interval_not_established"}
        intervals.append(max_gap)
    return {"status": "OBSERVED", "cron": crons, "max_interval_seconds": min(intervals)}


def _cron_values(field: str, lower: int, upper: int):
    values = set()
    for item in field.split(","):
        base, slash, step_text = item.partition("/")
        step = int(step_text) if slash else 1
        if step < 1:
            raise ValueError("invalid step")
        if base == "*":
            lo, hi = lower, upper
        elif re.fullmatch(r"\d+-\d+", base):
            lo, hi = map(int, base.split("-"))
        elif base.isdigit() and not slash:
            lo = hi = int(base)
        else:
            raise ValueError("unsupported field")
        if lo < lower or hi > upper or lo > hi:
            raise ValueError("invalid range")
        values.update(range(lo, hi + 1, step))
    return values


def _finding(repo, rule, severity, description, kind="monitoring-gap", **evidence):
    return {"scope": "github", "resource_id": repo, "rule_id": rule, "severity": severity,
            "kind": kind, "description": description, "evidence": evidence}


def _run_metadata(run):
    return {k: run.get(k) for k in ("id", "status", "conclusion", "event", "created_at", "updated_at", "head_sha")}


def audit_repository(client, repo: dict, now: dt.datetime):
    full_name = repo.get("full_name", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
        raise ValueError("Invalid repository name")
    prefix = "/repos/" + full_name
    findings, unknown = [], []
    result = {"repository": full_name, "id": repo["id"], "visibility": repo.get("visibility", "unknown"),
              "archived": bool(repo.get("archived")), "disabled": bool(repo.get("disabled"))}
    details = client.get(prefix)
    if details.status != 200 or not isinstance(details.data, dict):
        unknown.append("repository_security_metadata:" + _error(details.status))
        metadata = {}
    else:
        metadata = details.data
    security = metadata.get("security_and_analysis") or {}
    result["security"] = {}
    for feature in ("secret_scanning", "secret_scanning_push_protection"):
        feature_metadata = security.get(feature) if isinstance(security, dict) else None
        status = feature_metadata.get("status") if isinstance(feature_metadata, dict) else None
        result["security"][feature] = status if status in ("enabled", "disabled") else "UNKNOWN"
        if status == "disabled":
            findings.append(_finding(full_name, "github_" + feature + "_disabled", "medium", feature.replace("_", " ") + " is disabled.", kind="configuration"))
        elif status != "enabled":
            unknown.append(feature + ":not_visible_or_not_available")
    alerts, err = paginate(client, prefix + "/secret-scanning/alerts?state=open", identity="number")
    result["open_secret_alerts"] = {"status": "UNKNOWN" if err else "OBSERVED", "count": None if err else len(alerts), "observed_lower_bound": len(alerts)}
    # Only an aggregate count survives; no secrets, URLs, types or alert locations.
    if err:
        unknown.append("secret_alert_count:" + err)
    if alerts:
        findings.append(_finding(full_name, "github_open_secret_alerts", "high", "GitHub reports open secret-scanning alerts; review and rotate confirmed exposures.", "credential-exposure", count=len(alerts), count_complete=not bool(err)))
    del alerts
    if result["archived"] or result["disabled"]:
        result["scanning"] = {"status": "NOT_RUNNING", "reason": "repository_archived_or_disabled"}
        # Historical credentials still matter; scheduled Actions cannot run here.
        result["unknown"] = unknown
        return result, findings
    workflows, err = paginate(client, prefix + "/actions/workflows", "workflows")
    if err:
        unknown.append("workflow_inventory:" + err)
    by_path = {item.get("path"): item for item in workflows}
    result["scanning"] = {"inventory_complete": not bool(err), "known_workflows": {},
                          "workflow_inventory": [{"id": w["id"], "path": w.get("path"), "state": w.get("state")} for w in workflows]}
    for role, path in WORKFLOW_PATHS.items():
        workflow = by_path.get(path)
        if not workflow:
            result["scanning"]["known_workflows"][role] = {"status": "UNKNOWN" if err else "MISSING"}
            if not err:
                findings.append(_finding(full_name, "github_scan_" + role + "_missing", "high", "Required scanner workflow is missing.", path=path))
            continue
        wf = {"id": workflow["id"], "path": path, "state": workflow.get("state", "unknown")}
        result["scanning"]["known_workflows"][role] = wf
        if wf["state"] != "active":
            findings.append(_finding(full_name, "github_scan_" + role + "_inactive", "high", "Scanner workflow is not active.", state=wf["state"]))
        if role == "worker":
            continue  # Dispatch-driven: inactivity alone is not evidence of failure.
        response = client.get(prefix + "/contents/" + path)
        try:
            if response.status != 200 or response.data.get("encoding") != "base64" or response.data.get("type") != "file":
                raise ValueError()
            encoded = response.data["content"]
            if len(encoded) > MAX_WORKFLOW * 2:
                raise ValueError()
            raw = base64.b64decode("".join(encoded.split()), validate=True)
            if len(raw) > MAX_WORKFLOW:
                raise ValueError()
            schedule = workflow_schedule(raw.decode("utf-8"))
            wf["content_sha256"] = hashlib.sha256(raw).hexdigest()
            del raw
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            schedule = {"status": "UNKNOWN", "reason": "workflow_content_unavailable"}
        wf["schedule"] = schedule
        if schedule["status"] == "UNKNOWN":
            unknown.append(role + ":" + schedule["reason"])
        run_response = client.get(prefix + f"/actions/workflows/{workflow['id']}/runs?event=schedule&per_page=1&page=1")
        rows = run_response.data.get("workflow_runs") if isinstance(run_response.data, dict) else None
        if run_response.status != 200 or not isinstance(rows, list):
            unknown.append(role + "_scheduled_runs:" + _error(run_response.status))
            wf["latest_scheduled_run"] = {"status": "UNKNOWN"}
        elif not rows:
            wf["latest_scheduled_run"] = None
            findings.append(_finding(full_name, "github_scan_" + role + "_never_scheduled", "medium", "No scheduled run is visible for this scanner workflow; onboarding or workflow changes may explain this."))
        elif not isinstance(rows[0], dict):
            unknown.append(role + "_scheduled_runs:invalid_response")
            wf["latest_scheduled_run"] = {"status": "UNKNOWN"}
        else:
            latest = _run_metadata(rows[0])
            wf["latest_scheduled_run"] = latest
            created = _date(latest["created_at"])
            if not created or created > now + dt.timedelta(minutes=5):
                unknown.append(role + "_run_timestamp:invalid")
            elif schedule["status"] != "UNKNOWN":
                # Allow two hours of GitHub scheduling delay in addition to cadence.
                limit = schedule["max_interval_seconds"] + 7200
                age = (now - created).total_seconds()
                if age > limit:
                    findings.append(_finding(full_name, "github_scan_" + role + "_overdue", "high", "Scheduled scan collection is overdue.", age_hours=round(age / 3600, 1), allowed_hours=round(limit / 3600, 1), run_id=latest["id"]))
            if latest["status"] == "completed" and latest["conclusion"] != "success":
                findings.append(_finding(full_name, "github_scan_" + role + "_failed", "high", "Latest scheduled scanner run did not succeed.", run_id=latest["id"], conclusion=latest["conclusion"]))
    branch = metadata.get("default_branch", repo.get("default_branch"))
    if isinstance(branch, str) and branch:
        # The branch endpoint has no commit patch/file content. Do not use the
        # commits/{ref} endpoint, which unnecessarily returns application code.
        head_response = client.get(prefix + "/branches/" + urllib.parse.quote(branch, safe=""))
        commit = head_response.data.get("commit") if isinstance(head_response.data, dict) else None
        head = commit.get("sha") if isinstance(commit, dict) else None
        if head_response.status == 200 and isinstance(head, str) and SHA.fullmatch(head):
            checks, check_err = paginate(client, prefix + "/commits/" + head + "/check-runs?filter=latest", "check_runs")
            ours = [{"name": c.get("name"), "id": c["id"], "status": c.get("status"), "conclusion": c.get("conclusion")}
                    for c in checks if c.get("name") in CHECK_NAMES]
            result["default_head"] = {"sha": head, "checks_complete": not bool(check_err), "scanner_checks": ours}
            if check_err:
                unknown.append("default_head_checks:" + check_err)
            elif not ours:
                commit_detail = commit.get("commit")
                committer = commit_detail.get("committer") if isinstance(commit_detail, dict) else None
                committed_at = _date(committer.get("date")) if isinstance(committer, dict) else None
                if committed_at and now - dt.timedelta(hours=8) <= committed_at <= now + dt.timedelta(minutes=5):
                    result["default_head"]["status"] = "PENDING_WITHIN_COLLECTION_GRACE"
                else:
                    result["default_head"]["status"] = "MISSING"
                    findings.append(_finding(full_name, "github_head_scanner_checks_missing", "medium", "No recognized scanner check is visible on the default-branch HEAD after the collection grace period, or its age could not be established.", head_sha=head))
        else:
            unknown.append("default_head:" + _error(head_response.status))
    else:
        unknown.append("default_branch:missing")
    result["unknown"] = unknown
    return result, findings


def audit_organizations(client, organizations=ORGANIZATIONS, now=None, *, inventory_attested=False, expected_repos=None, workers=1):
    now = now or dt.datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    report = {"schema_version": 1, "observed_at": now.astimezone(UTC).isoformat(),
              "coverage": {"scope": "complete", "inventory": "credential-visible", "all_repository_access_attested": bool(inventory_attested)},
              "organizations": [], "repositories": [], "findings": []}
    seen = set()
    if not inventory_attested:
        report["coverage"]["scope"] = "partial"
        report["findings"].append(_finding("organizations", "github_inventory_visibility_unattested", "medium", "Credential-visible inventory cannot establish coverage of inaccessible repositories."))
    for org in organizations:
        if org not in ORGANIZATIONS:
            raise ValueError("Organization outside approved scope")
        repos, err = paginate(client, "/orgs/" + org + "/repos?type=all&sort=full_name&direction=asc")
        entry = {"organization": org, "inventory_status": "UNKNOWN" if err else "OBSERVED", "repository_count": len(repos)}
        report["organizations"].append(entry)
        if err:
            report["coverage"]["scope"] = "partial"
            entry["reason"] = err
            report["findings"].append(_finding(org, "github_inventory_incomplete", "high", "Organization repository inventory is incomplete or unavailable.", reason=err))
        selected = []
        for repo in repos:
            if repo["id"] in seen:
                continue
            if not isinstance(repo.get("full_name"), str) or repo["full_name"].split("/")[0].lower() != org.lower():
                report["coverage"]["scope"] = "partial"
                report["findings"].append(_finding(org, "github_inventory_invalid", "high", "Repository inventory included an invalid owner; entry skipped."))
                continue
            seen.add(repo["id"])
            selected.append(repo)
        def inspect(repo):
            try:
                return audit_repository(client, repo, now)
            except (TypeError, ValueError, KeyError, AttributeError):
                return ({"repository": repo["full_name"], "id": repo["id"], "unknown": ["invalid_api_metadata"]}, [])
        with ThreadPoolExecutor(max_workers=workers) as pool:
            completed = list(pool.map(inspect, selected))
        for result, findings in completed:
            report["repositories"].append(result)
            report["findings"].extend(findings)
            if result["unknown"]:
                report["coverage"]["scope"] = "partial"
                report["findings"].append(_finding(result["repository"], "github_security_posture_unknown", "medium", "One or more security checks could not be verified.", unavailable=result["unknown"]))
    if expected_repos is not None:
        actual = {r["repository"].lower() for r in report["repositories"]}
        missing = sorted(set(r.lower() for r in expected_repos) - actual)
        for name in missing:
            report["findings"].append(_finding(name, "github_expected_repository_not_visible", "high", "A previously inventoried repository is not visible; verify access, transfer or deletion."))
        if missing:
            report["coverage"]["scope"] = "partial"
    if not report["repositories"]:
        report["coverage"]["scope"] = "unavailable"
    report["limitations"] = ["Only credential-visible repositories are inventoried.", "Scheduled-run health and default-HEAD checks do not prove every branch/commit was scanned.", "Secret-scanning alert counts do not cover unsupported secret formats or unscanned external systems.", "Workflow files are read statically and never executed. No package contents are downloaded."]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--organization", choices=ORGANIZATIONS, action="append")
    parser.add_argument("--transport", choices=("gh", "http"), default="gh")
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 5))
    args = parser.parse_args()
    if args.transport == "http" and not os.environ.get("GITHUB_TOKEN"):
        parser.error("HTTP transport requires an existing approved GITHUB_TOKEN")
    client = HttpApi(os.environ.get("GITHUB_TOKEN", "")) if args.transport == "http" else GhApi()
    result = audit_organizations(client, args.organization or ORGANIZATIONS, workers=args.workers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"coverage": result["coverage"]["scope"], "repositories": len(result["repositories"]), "findings": len(result["findings"])}))
    return 2 if result["coverage"]["scope"] != "complete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
