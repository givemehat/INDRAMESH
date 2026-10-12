"""SARIF 2.1.0 emitter -- the format GitHub code scanning, GitLab and any SARIF viewer reads.

Why this exists: `cli.py` could emit a CBOM and a text report, but neither lands in a pull
request. A CI gate whose findings live in a log line is a gate nobody sees until something is
already broken; SARIF turns each finding into an annotation on the diff, on the Security tab,
and on the file itself.

Three properties matter more than the JSON plumbing:

1. RELATIVE URIs. GitHub rejects absolute paths in `artifactLocation.uri`, and an absolute
   path also leaks the builder's directory layout into a public artefact. Paths are made
   relative to the scan root and slash-normalised before they are written.

2. A RULE PER ARTEFACT, NOT PER FINDING. 400 findings from 30 rules must not become 400
   rules; `driver.rules` is the de-duplicated rule table, each result references it by id.

3. LEVEL IS RISK, NOT SEVERITY THEATRE. CRITICAL and HIGH are `error` (act now), MEDIUM is
   `warning`, LOW is `note`. Mapping everything to `error` trains reviewers to ignore the
   whole file; mapping CRITICAL to `warning` hides the one thing that must not be hidden.

A finding with no usable line is still emitted, with the location attached to the file
rather than dropped: losing a finding because its line number was absent is exactly the
silent-undercount this project exists to argue against.
"""
import json
import os

SARIF_VERSION = "2.1.0"

# Risk tier -> SARIF level. See the module docstring for why the mapping is not flat.
_LEVEL_BY_TIER = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _relative_uri(path, root):
    """A POSIX-style URI relative to the scan root, never absolute."""
    if not path:
        return None
    try:
        if root:
            real_root = os.path.realpath(root)
            real_path = os.path.realpath(path)
            if real_path.startswith(real_root):
                path = os.path.relpath(real_path, real_root)
    except (OSError, ValueError):
        pass  # keep the original path; a strange path is better than no result
    return str(path).replace("\\", "/").lstrip("./") or None


def _rule_metadata(finding):
    """The de-duplicated rule entry for one rule id."""
    return {
        "id": finding.get("rule_id") or "UNKNOWN",
        "name": finding.get("name") or "unknown",
        "shortDescription": {"text": f"{finding.get('name', 'unknown')} "
                                     f"({finding.get('primitive', 'unspecified primitive')})"},
        "properties": {
            "primitive": finding.get("primitive"),
            "artefact_class": finding.get("artefact_class"),
            "evidence_class": finding.get("evidence_class"),
        },
    }


def generate_sarif(findings, root=None, tool_name="IndraMesh",
                   tool_version="2.0.0", sarif_uri="https://github.com/givemehat/INDRAMESH"):
    """Return a SARIF 2.1.0 document (as a JSON string) for `findings`.

    `root` is the directory the scan was pointed at; relative URIs are computed against it.
    Each finding may carry `risk` (from engine.mosca); a finding without one degrades to a
    `warning` result rather than being dropped.
    """
    findings = list(findings or [])

    rules, seen_ids, results = [], set(), []
    for f in findings:
        rule_id = f.get("rule_id") or "UNKNOWN"
        if rule_id not in seen_ids:
            seen_ids.add(rule_id)
            rules.append(_rule_metadata(f))

        risk = f.get("risk") or {}
        tier = risk.get("tier") or "MEDIUM"
        level = _LEVEL_BY_TIER.get(tier, "warning")
        rec = f.get("recommendation") or {}
        target = rec.get("algorithm", "see rule trace")

        message = (f"{f.get('name', 'unknown')} ({f.get('primitive', '?')}) is exposed to a "
                   f"future quantum attacker: {risk.get('break_model', 'see evidence')} at "
                   f"tier {tier} (X+Y={risk.get('x_y', '?')} vs Z={risk.get('z', '?')}). "
                   f"Recommended PQC target: {target}.")
        if risk.get("hndl_exposed"):
            message += " Harvest-now-decrypt-later: data captured today is readable later."

        uri = _relative_uri(f.get("file"), root)
        physical = {"artifactLocation": {"uri": uri}} if uri else {}
        line = f.get("line")
        if isinstance(line, int) and line > 0 and physical:
            physical["region"] = {"startLine": line}

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            # Stable across re-runs of the same tree: path + rule + line. Lets a viewer track
            # one finding across runs instead of re-reporting the world each time.
            "partialFingerprints": {"indramesh/v1": f"{uri or ''}|{rule_id}|{line or 0}"},
            "properties": {
                "tier": tier,
                "hndl_exposed": bool(risk.get("hndl_exposed")),
                "scanner": f.get("scanner"),
                "evidence_class": f.get("evidence_class"),
                "target_algorithm": target,
            },
        }
        if physical:
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": sarif_uri,
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "indramesh/findings_total": len(results),
                "indramesh/rules_exercised": len(rules),
            },
        }],
    }
    return json.dumps(doc, indent=2)


