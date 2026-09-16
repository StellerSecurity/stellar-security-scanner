"""Inspect locked dependency archives as data before any package installation.

Only the reviewed acquisition adapter contacts public registries. This wrapper
never installs, extracts, imports or executes acquired package bytes.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import unicodedata


LIMITS = {"files": 200000, "depth": 128, "lock_bytes": 16 * 1024 * 1024,
          "packages": 10000, "download_bytes": 1024 * 1024 * 1024,
          "requests": 20000, "seconds": 600, "gaps": 1000,
          "manifest_bytes": 64 * 1024 * 1024, "manifest_files": 1000,
          "manifest_bundle_bytes": 96 * 1024 * 1024}
LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "composer.lock"}
MANIFESTS = {"package.json", "composer.json"}
UNSUPPORTED = {"yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "poetry.lock", "uv.lock",
               "Pipfile", "Pipfile.lock", "pyproject.toml", "requirements.txt", "requirements.in",
               "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "Gemfile", "Gemfile.lock",
               "build.gradle", "build.gradle.kts", "gradle.lockfile", "pom.xml", "packages.config",
               "packages.lock.json", "Package.swift", "Package.resolved", "Podfile", "Podfile.lock",
               "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock", "build.sbt", ".gitmodules"}
SKIP_DIRECTORIES = {".git", "node_modules", "vendor"}


class Incomplete(Exception):
    pass


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def load_reviewed(name, expected):
    path = Path(__file__).with_name(name + ".py")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise Incomplete("reviewed-module-integrity")
        raw = stream.read(8 * 1024 * 1024 + 1)
    if not re.fullmatch(r"[0-9a-f]{64}", expected or "") or sha256(raw) != expected:
        raise Incomplete("reviewed-module-integrity")
    module = types.ModuleType("stellar_package_guard_" + name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def recognized(name):
    return name in LOCKS | MANIFESTS | UNSUPPORTED or bool(re.search(r"\.(?:csproj|fsproj|vbproj|nuspec)$", name, re.I)) or bool(re.fullmatch(r"requirements[^/]*\.(?:txt|in)", name))


def discover(root, check_budget, limits=None):
    """Read only dependency manifest/lock files, without following symlinks."""
    limits = dict(LIMITS if limits is None else limits)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Incomplete("invalid-dependency-root")
    result, gaps, count, manifest_bytes = {}, [], 0, 0
    def gap(path, reason):
        if len(gaps) >= limits["gaps"]:
            raise Incomplete("dependency-gap-limit")
        gaps.append({"path": path, "reason": reason})
    def visit(descriptor, prefix="", depth=0):
        nonlocal count, manifest_bytes
        check_budget()
        if depth > limits["depth"]:
            raise Incomplete("dependency-directory-depth-limit")
        before = stable(os.fstat(descriptor))
        with os.scandir(descriptor) as entries:
            names = []
            for entry in entries:
                count += 1
                if count > limits["files"]:
                    raise Incomplete("dependency-file-count-limit")
                names.append(entry.name)
        for name in sorted(names):
            check_budget()
            relative = prefix + name
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                # A link can hide a dependency subtree or redirect a lock read.
                gap(relative, "dependency-symbolic-link-not-followed")
            elif stat.S_ISDIR(info.st_mode):
                if name in SKIP_DIRECTORIES:
                    continue
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    if stable(os.fstat(child)) != stable(info):
                        raise Incomplete("dependency-directory-changed")
                    visit(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            elif recognized(name):
                if not stat.S_ISREG(info.st_mode) or info.st_size > limits["lock_bytes"]:
                    gap(relative, "invalid-or-oversized-dependency-manifest")
                    continue
                if manifest_bytes + info.st_size > limits["manifest_bytes"] or len(result) >= limits["manifest_files"]:
                    raise Incomplete("dependency-manifest-aggregate-limit")
                file_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                with os.fdopen(file_descriptor, "rb") as stream:
                    if stable(os.fstat(stream.fileno())) != stable(info):
                        raise Incomplete("dependency-manifest-changed")
                    raw = stream.read(limits["lock_bytes"] + 1)
                    if len(raw) != info.st_size or stable(os.fstat(stream.fileno())) != stable(info):
                        raise Incomplete("dependency-manifest-changed")
                result[relative] = raw
                manifest_bytes += len(raw)
        if stable(os.fstat(descriptor)) != before:
            raise Incomplete("dependency-directory-changed")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(descriptor)
    finally:
        os.close(descriptor)
    return result, gaps


def manifest_bundle(value, source_sha, limits):
    """Validate bytes supplied by the isolated exact-commit GitHub bridge."""
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("source_sha") != source_sha:
        raise Incomplete("dependency-bundle-source-identity")
    if (not re.fullmatch(r"(?:StellerSecurity|Stellar-seo-websites|StellarMail|StellarSecurity-Packages)/[A-Za-z0-9_.-]+", value.get("repository", ""))
            or type(value.get("repository_id")) is not int or value["repository_id"] <= 0
            or not re.fullmatch(r"[0-9a-f]{40}", value.get("tree_sha", ""))):
        raise Incomplete("dependency-bundle-repository-identity")
    rows, prior_gaps = value.get("files"), value.get("gaps")
    if not isinstance(rows, list) or len(rows) > limits["manifest_files"] or not isinstance(prior_gaps, list) or len(prior_gaps) > limits["gaps"]:
        raise Incomplete("dependency-bundle-shape")
    gaps = []
    if value.get("complete") is not True:
        gaps.append({"path": "dependencies", "reason": "dependency-bundle-incomplete"})
    for item in prior_gaps:
        if not isinstance(item, dict):
            raise Incomplete("dependency-bundle-gap-shape")
        gaps.append({"path": "dependencies", "reason": "upstream-dependency-coverage-gap"})
    found, seen, total = {}, set(), 0
    for row in rows:
        if not isinstance(row, dict):
            raise Incomplete("dependency-bundle-file-shape")
        path = row.get("path")
        if (not isinstance(path, str) or not path or len(path) > 4096 or "\\" in path
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or any(part in ("", ".", "..") or part in SKIP_DIRECTORIES for part in path.split("/"))
                or not recognized(path.rsplit("/", 1)[-1])):
            raise Incomplete("dependency-bundle-file-path")
        canonical = unicodedata.normalize("NFC", path).casefold()
        if canonical in seen:
            raise Incomplete("dependency-bundle-duplicate-path")
        seen.add(canonical)
        size = row.get("bytes")
        if (row.get("mode") not in ("100644", "100755") or type(size) is not int or not 0 <= size <= limits["lock_bytes"]
                or not re.fullmatch(r"[0-9a-f]{40}", row.get("blob_sha", ""))
                or not isinstance(row.get("content_base64"), str)
                or len(row["content_base64"]) > ((size + 2) // 3) * 4):
            raise Incomplete("dependency-bundle-file-metadata")
        total += size
        if total > limits["manifest_bytes"]:
            raise Incomplete("dependency-manifest-aggregate-limit")
        try:
            raw = base64.b64decode(row["content_base64"], validate=True)
        except ValueError:
            raise Incomplete("dependency-bundle-file-encoding")
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if len(raw) != size or actual != row["blob_sha"]:
            raise Incomplete("dependency-bundle-git-blob-mismatch")
        found[path] = raw
    return found, gaps


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Incomplete("duplicate-dependency-json-key")
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise Incomplete("invalid-dependency-json")
    if not isinstance(value, dict):
        raise Incomplete("invalid-dependency-manifest")
    return value


def check_npm_graph(path, manifest, lock, gap):
    packages = lock.get("packages")
    fields = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    if not isinstance(packages, dict):
        gap(path, "npm-package-map-missing")
        return
    for field in fields:
        declaration = manifest.get(field, {})
        if not isinstance(declaration, dict):
            raise Incomplete("invalid-dependency-declaration")
        for name in declaration:
            if not isinstance(packages.get("node_modules/" + name), dict):
                gap(path, "npm-declared-direct-package-not-locked")
    for package_path, row in packages.items():
        if package_path == "" or not isinstance(row, dict):
            continue
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            declared = row.get(field, {})
            if not isinstance(declared, dict):
                raise Incomplete("invalid-lock-dependency-edges")
            for name in declared:
                # Resolve the lockfile's nested node_modules ancestry as data.
                candidates = [package_path + "/node_modules/" + name]
                ancestor = package_path
                while "/node_modules/" in ancestor:
                    ancestor = ancestor.rsplit("/node_modules/", 1)[0]
                    candidates.append(ancestor + "/node_modules/" + name)
                candidates.append("node_modules/" + name)
                if not any(isinstance(packages.get(candidate), dict) for candidate in candidates):
                    gap(path, "npm-transitive-dependency-edge-not-locked")


def check_composer_graph(path, manifest, lock, gap):
    rows = lock.get("packages", []) + lock.get("packages-dev", [])
    if not all(isinstance(row, dict) for row in rows):
        raise Incomplete("invalid-composer-package-list")
    names = {row.get("name") for row in rows if isinstance(row.get("name"), str)}
    declarations = [(manifest, ("require", "require-dev"))] + [(row, ("require",)) for row in rows]
    for declaration, fields in declarations:
        for field in fields:
            requirements = declaration.get(field, {})
            if not isinstance(requirements, dict):
                raise Incomplete("invalid-composer-dependency-edges")
            for name in requirements:
                if "/" in name and name not in names:
                    # Composer provide/replace can satisfy virtual packages, but
                    # trusting arbitrary aliases needs a separate reviewed resolver.
                    gap(path, "composer-required-package-or-virtual-binding-not-locked")


def inspect(root, source_sha, acquisition, content, fetch=None, limits=None, manifests_input=None, advisories=None, advisory_request=None):
    limits = dict(LIMITS if limits is None else limits)
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise Incomplete("invalid-source-sha")
    started = time.monotonic()
    scanner_limits = dict(content.LIMITS)
    scanner_limits["seconds"] = limits["seconds"]
    scanner = content.Inspector(limits=scanner_limits)
    records, manifests, plans, downloaded_bytes, requests = [], {}, {}, 0, 0
    bundle_validated = False
    public_packages = []
    advisory = None
    advisory_response_bytes_reserved = 0
    def check_budget():
        if time.monotonic() - started > limits["seconds"]:
            raise Incomplete("dependency-time-limit")
        scanner.check_budget()
    def gap(path, reason):
        scanner.gap(path, reason)
    def bounded_fetch(url, max_bytes):
        nonlocal downloaded_bytes, requests
        check_budget()
        requests += 1
        if requests > limits["requests"]:
            raise Incomplete("dependency-request-limit")
        remaining = limits["download_bytes"] - downloaded_bytes - advisory_response_bytes_reserved
        if remaining <= 0:
            raise Incomplete("dependency-download-byte-limit")
        raw = (fetch or acquisition.public_fetch)(url, min(max_bytes, remaining))
        if not isinstance(raw, bytes) or len(raw) > min(max_bytes, remaining):
            raise Incomplete("dependency-download-byte-limit")
        downloaded_bytes += len(raw)
        check_budget()
        return raw
    def bounded_advisory_request(method, url, data, max_bytes):
        nonlocal advisory_response_bytes_reserved, requests
        check_budget()
        requests += 1
        remaining = limits["download_bytes"] - downloaded_bytes - advisory_response_bytes_reserved
        if requests > limits["requests"] or remaining <= 0:
            raise Incomplete("dependency-advisory-budget-limit")
        allowance = min(max_bytes, remaining)
        advisory_response_bytes_reserved += allowance
        response = (advisory_request or advisories.public_request)(method, url, data, allowance)
        if not isinstance(response, tuple) or len(response) != 2:
            raise Incomplete("dependency-advisory-byte-limit")
        check_budget()
        return response
    try:
        manifests, discovery_gaps = manifest_bundle(manifests_input, source_sha, limits) if manifests_input is not None else discover(root, check_budget, limits)
        bundle_validated = manifests_input is not None
        for item in discovery_gaps:
            gap(item["path"], item["reason"])
        for path, raw in sorted(manifests.items()):
            check_budget()
            name = path.rsplit("/", 1)[-1]
            prefix = path[:-len(name)]
            if name in LOCKS:
                if name != "composer.lock":
                    manifest_raw = manifests.get(prefix + "package.json")
                    if manifest_raw is None:
                        gap(path, "npm-root-manifest-missing")
                    else:
                        manifest, lock = strict_json(manifest_raw), strict_json(raw)
                        if lock.get("lockfileVersion") in (2, 3):
                            lock_root = lock.get("packages", {}).get("")
                            if not isinstance(lock_root, dict) or any(manifest.get(field, {}) != lock_root.get(field, {}) for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")):
                                gap(path, "npm-lock-and-manifest-declarations-differ")
                            check_npm_graph(path, manifest, lock, gap)
                        else:
                            gap(path, "npm-v1-manifest-binding-needs-review")
                else:
                    manifest_raw = manifests.get(prefix + "composer.json")
                    if manifest_raw is not None:
                        check_composer_graph(path, strict_json(manifest_raw), strict_json(raw), gap)
                planned = acquisition.plan_packages(path, raw, composer_manifest=manifests.get(prefix + "composer.json"))
                for item in planned["gaps"]:
                    gap(path, item["reason"])
                for package in planned["packages"]:
                    identity = json.dumps(package, sort_keys=True, separators=(",", ":"))
                    if identity not in plans:
                        plans[identity] = {"plan": package, "lockfiles": []}
                    plans[identity]["lockfiles"].append(path)
                    if len(plans) > limits["packages"]:
                        raise Incomplete("dependency-package-count-limit")
            elif name in MANIFESTS:
                manifest = strict_json(raw)
                if name == "package.json":
                    dependency_fields = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                    for field in dependency_fields:
                        if field in manifest and not isinstance(manifest[field], dict):
                            raise Incomplete("invalid-dependency-declaration")
                    has_dependencies = any(manifest.get(field) for field in dependency_fields)
                    if manifest.get("workspaces"):
                        gap(path, "npm-workspaces-require-explicit-coverage-review")
                    if has_dependencies and not any(prefix + lock in manifests for lock in ("package-lock.json", "npm-shrinkwrap.json")):
                        gap(path, "npm-lockfile-missing")
                else:
                    for field in ("require", "require-dev"):
                        if field in manifest and not isinstance(manifest[field], dict):
                            raise Incomplete("invalid-dependency-declaration")
                    has_packages = any("/" in name for field in ("require", "require-dev") for name in manifest.get(field, {}))
                    if has_packages and prefix + "composer.lock" not in manifests:
                        gap(path, "composer-lockfile-missing")
            else:
                gap(path, "unsupported-dependency-ecosystem")
        for index, value in enumerate(plans.values()):
            check_budget()
            package = value["plan"]
            logical = "package-" + str(index + 1)
            record = {"ecosystem": package["ecosystem"], "name": package["name"],
                      "version": package["version"], "reference": package.get("reference"),
                      "lockfiles": value["lockfiles"], "status": "incomplete"}
            records.append(record)
            before_gaps, before_findings, before_files = len(scanner.gaps), len(scanner.findings), scanner.files_scanned
            try:
                result = acquisition.acquire(package, fetch=bounded_fetch)
                raw = result["data"]
                if not isinstance(raw, bytes) or sha256(raw) != result.get("sha256"):
                    raise Incomplete("dependency-archive-digest-mismatch")
                provenance = result.get("provenance")
                if not isinstance(provenance, dict) or provenance.get("registry_identity_verified") is not True or provenance.get("name") != package["name"] or provenance.get("version") != package["version"]:
                    raise Incomplete("dependency-provenance-incomplete")
                if not re.fullmatch(r"[0-9a-f]{64}", provenance.get("metadata_sha256", "")):
                    raise Incomplete("dependency-provenance-incomplete")
                public_packages.append({"ecosystem": package["ecosystem"], "name": package["name"], "version": package["version"],
                                        "public_registry_verified": True})
                record.update(archive_sha256=result["sha256"], provenance=provenance,
                              integrity_verified=result.get("integrity_verified") is True)
                if result.get("integrity_verified") is not True:
                    gap(logical, "dependency-integrity-not-verified")
                if not isinstance(result.get("gaps"), list):
                    raise Incomplete("dependency-acquisition-report-invalid")
                for item in result["gaps"]:
                    gap(logical, item["reason"])
                scanner.archive(logical, raw)
                if scanner.files_scanned == before_files:
                    gap(logical, "dependency-package-has-no-inspected-text")
                blockers = [x for x in scanner.findings[before_findings:] if x["severity"] in ("error", "review") or x["malware"]]
                record.update(status="blocked" if blockers else "incomplete" if len(scanner.gaps) > before_gaps else "passed",
                              files_scanned=scanner.files_scanned - before_files,
                              blocking_findings=len(blockers), coverage_gaps=len(scanner.gaps) - before_gaps)
            except (acquisition.AcquisitionError, Incomplete) as exc:
                gap(logical, str(exc))
                record["status"] = "incomplete"
        if advisories is None:
            gap("dependencies", "known-malware-advisory-check-unavailable")
        else:
            check_budget()
            advisory = advisories.check_packages(public_packages, request=bounded_advisory_request)
            if (not isinstance(advisory, dict) or advisory.get("complete") is not True or advisory.get("gaps") != []
                    or advisory.get("advisory_module_sha256") != sha256(Path(advisories.__file__).read_bytes())):
                gap("dependencies", "known-malware-advisory-check-incomplete")
            if not isinstance(advisory, dict) or not isinstance(advisory.get("malicious"), list):
                raise Incomplete("known-malware-advisory-result-invalid")
            public_identities = {(p["ecosystem"], p["name"], p["version"]) for p in public_packages}
            for finding in advisory["malicious"]:
                identity = (finding.get("ecosystem"), finding.get("name"), finding.get("version"))
                if identity not in public_identities:
                    raise Incomplete("known-malware-advisory-identity-mismatch")
                scanner.finding("dependencies", "known-malicious-dependency", "error", True)
                for record in records:
                    if (record["ecosystem"], record["name"], record["version"]) == identity:
                        record["status"] = "blocked"
                        record.setdefault("malware_advisories", []).append(finding.get("id"))
    except (Incomplete, content.Incomplete, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        reason = str(exc) if isinstance(exc, (Incomplete, content.Incomplete)) else "dependency-inspection-failed"
        if len(scanner.gaps) < scanner.limits["findings"]:
            gap("dependencies", reason)
    empty_dependency_inventory = not plans and not records and not scanner.gaps
    result = scanner.report(source_sha, "dependency-archives")
    if empty_dependency_inventory:
        # No declared packages is a complete empty dependency inventory, not a
        # source-content clean claim. Keep files_scanned=0; never fabricate a scan.
        result["gaps"] = []
        result["status"] = "passed"
    manifest = [{"path": path, "sha256": sha256(raw)} for path, raw in sorted(manifests.items())]
    result.update(scanner_sha256=sha256(Path(__file__).read_bytes()), dependency_guard_version="1.0.0",
                  content_scanner_sha256=sha256(Path(content.__file__).read_bytes()),
                  acquisition_sha256=sha256(Path(acquisition.__file__).read_bytes()),
                  advisory_sha256=sha256(Path(advisories.__file__).read_bytes()) if advisories is not None else None,
                  malware_advisory_result=advisory,
                  input={"kind": "dependency-lock-manifest", "sha256": sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
                         "digest_scope": "inspected-dependency-manifests"},
                  packages=records, dependency_manifest_count=len(manifests), dependency_manifests=manifest,
                  dependency_inventory_complete=not result["gaps"],
                  downloads_as_data_only=True, installed_or_executed_packages=False,
                  network_requests=requests, downloaded_bytes=downloaded_bytes,
                  advisory_response_bytes_reserved=advisory_response_bytes_reserved,
                  dependency_limits=limits)
    if bundle_validated:
        result.update(repository=manifests_input.get("repository"), repository_id=manifests_input.get("repository_id"),
                      tree_sha=manifests_input.get("tree_sha"))
    if any(row["status"] != "passed" for row in records) and result["status"] == "passed":
        result["status"] = "incomplete"
    return result


def main():
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--directory", "--root", dest="directory", type=Path)
    choice.add_argument("--manifest-bundle", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--content-scanner-sha256", required=True)
    parser.add_argument("--acquisition-sha256", required=True)
    parser.add_argument("--advisory-sha256", required=True)
    args = parser.parse_args()
    try:
        content = load_reviewed("content_guard", args.content_scanner_sha256)
        previous = sys.modules.get("content_guard")
        sys.modules["content_guard"] = content
        try:
            acquisition = load_reviewed("package_acquisition", args.acquisition_sha256)
        finally:
            if previous is None:
                sys.modules.pop("content_guard", None)
            else:
                sys.modules["content_guard"] = previous
        advisories = load_reviewed("malware_advisories", args.advisory_sha256)
        supplied = None
        if args.manifest_bundle:
            descriptor = os.open(args.manifest_bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > LIMITS["manifest_bundle_bytes"]:
                    raise Incomplete("dependency-bundle-file-size")
                raw = stream.read(LIMITS["manifest_bundle_bytes"] + 1)
                if len(raw) != before.st_size or stable(os.fstat(stream.fileno())) != stable(before):
                    raise Incomplete("dependency-bundle-file-changed")
            supplied = strict_json(raw)
        result = inspect(args.directory, args.source_sha, acquisition, content, manifests_input=supplied, advisories=advisories)
        if supplied is not None:
            result["manifest_bundle_sha256"] = sha256(raw)
    except (Incomplete, OSError, ValueError):
        print('{"status":"incomplete","reason":"dependency-check-could-not-start"}')
        return 2
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, ensure_ascii=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "source_sha": result["source_sha"],
                      "packages": len(result["packages"]), "coverage_gaps": len(result["gaps"])}))
    return {"passed": 0, "blocked": 1, "incomplete": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
