# analyzer/scanner.py
import os
import json
import shutil
import subprocess

def load_abap_file(path):
    """
    Läser in en enskild ABAP-fil på ett säkert sätt.
    Krävs av main.py och beroendeparsern.
    """
    if os.path.isdir(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    except PermissionError:
        return []


def map_abaplint_issue_to_rule(issue):
    """Map a single abaplint issue object to the matching internal R00X rule ID."""
    if not isinstance(issue, dict):
        return None

    key = str(issue.get("key", "")).lower()
    message = str(issue.get("message", "")).upper()

    if "obsolete_statement" in key:
        return "R008"
    if "db_operation_in_loop" in key or ("loop" in key and "select" in message):
        return "R001"
    if "select_star" in key or "SELECT *" in message:
        return "R002"
    if "hardcoded_org_value" in key or "org_value" in key or "hardcoded" in key:
        return "R003"
    if "modify_only_own_db_tables" in key or ("UPDATE " in message and "BSEG" in message):
        return "R006"
    if "cds_legacy_view" in key or any(token in message for token in ["BSEG", "MSEG", "BKPF", "MKPF", "GLT0", "FAGLFLEXT"]):
        return "R004"
    if "obsolete_function" in key or any(token in message for token in ["WS_DOWNLOAD", "WS_UPLOAD", "GUI_DOWNLOAD"]):
        return "R005"
    if "select_add_order_by" in key or ("ORDER BY" not in message and "SELECT" in message and "FROM" in message):
        return "R007"
    if "native_sql" in key or "EXEC SQL" in message:
        return "R009"
    if "call_transaction_authority_check" in key or ("AUTHORITY" in message and "CALL TRANSACTION" in message):
        return "R010"
    if "select_single_full_key" in key:
        return "R011"
    if "sql_escape_host_variables" in key:
        return "R012"
    if "form_tables_obsolete" in key:
        return "R013"
    return None


def _build_abaplint_command(executable, file_path, platform_name=None):
    """Build a direct command for abaplint's config-plus-file CLI syntax."""
    if platform_name is None:
        platform_name = os.name

    normalized_file_path = file_path.replace(os.sep, "/")
    command_args = ["-f", "json", "--file", f"/{normalized_file_path.lstrip('/')}" ]

    if platform_name == "nt" and executable.lower().endswith((".cmd", ".bat")):
        npm_directory = os.path.dirname(executable)
        cli_entrypoint = os.path.join(npm_directory, "node_modules", "@abaplint", "cli", "abaplint")
        node_executable = shutil.which("node")
        if node_executable is None or not os.path.isfile(cli_entrypoint):
            return None
        return [node_executable, cli_entrypoint, "abaplint.json", *command_args]

    return [executable, "abaplint.json", *command_args]


def analyze_file(file_path):
    """
    Kör den officiella abaplint-motorn i bakgrunden via systemet
    och mappar om dess JavaScript-resultat till dina Python-regler.
    """
    findings = []

    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return {"findings": findings, "engine": "none", "fallback_reason": "invalid-path"}

    executable = shutil.which("abaplint")
    if executable is None:
        from analyzer.rules import scan_code
        return {
            "findings": scan_code(load_abap_file(file_path)),
            "engine": "python-fallback",
            "fallback_reason": "abaplint-not-found",
        }

    command = _build_abaplint_command(executable, file_path)
    if command is None:
        from analyzer.rules import scan_code
        return {
            "findings": scan_code(load_abap_file(file_path)),
            "engine": "python-fallback",
            "fallback_reason": "abaplint-windows-entrypoint-not-found",
        }

    try:
        # Starta den officiella abaplint CLI-motorn i bakgrunden och be om JSON-utdata.
        # Använd shell=False för att undvika osäkerhetsproblem på Windows och andra miljöer.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            check=False
        )

        if result.returncode not in (0, 1):
            from analyzer.rules import scan_code
            return {
                "findings": scan_code(load_abap_file(file_path)),
                "engine": "python-fallback",
                "fallback_reason": f"abaplint-exit-{result.returncode}",
            }

        if not result.stdout.strip():
            from analyzer.rules import scan_code
            return {
                "findings": scan_code(load_abap_file(file_path)),
                "engine": "python-fallback",
                "fallback_reason": "abaplint-empty-output",
            }

        try:
            sap_issues = json.loads(result.stdout)
        except json.JSONDecodeError:
            from analyzer.rules import scan_code
            return {
                "findings": scan_code(load_abap_file(file_path)),
                "engine": "python-fallback",
                "fallback_reason": "abaplint-invalid-json",
            }

        for issue in sap_issues:
            abaplint_rule = issue.get("key", "unknown").lower()
            message = issue.get("message", "")
            line_num = issue.get("start", {}).get("row", 1)

            mapped_rule = map_abaplint_issue_to_rule(issue)
            from analyzer.rules import RULES

            if mapped_rule and mapped_rule in RULES:
                finding = dict(RULES[mapped_rule])
                finding["line"] = line_num
                finding["code"] = message
                findings.append(finding)
                continue

            findings.append({
                "id": f"ABAPLINT-{abaplint_rule.upper()}",
                "title": f"Community Rule: {abaplint_rule}",
                "category": "Maintainability",
                "severity": "MEDIUM",
                "weight": 3,
                "rationale": "This issue was raised by the core abaplint engine framework definitions.",
                "description": message,
                "recommendation": "Refactor code to align with standard abaplint/abapGit linter guidelines.",
                "line": line_num,
                "code": "Violation detected by abaplint engine."
            })

        # abaplint does not cover every project-specific R00X risk pattern.
        # Supplement its output so a successful lint run cannot hide custom findings.
        from analyzer.rules import scan_code
        custom_findings = scan_code(load_abap_file(file_path))
        existing_findings = {(finding["id"], finding["line"]) for finding in findings}
        for finding in custom_findings:
            identity = (finding["id"], finding["line"])
            if identity not in existing_findings:
                findings.append(finding)
                existing_findings.add(identity)

    except Exception:
        from analyzer.rules import scan_code
        lines = load_abap_file(file_path)
        return {
            "findings": scan_code(lines),
            "engine": "python-fallback",
            "fallback_reason": "abaplint-execution-failed",
        }

    engine = "abaplint+python-rules" if custom_findings and findings else "abaplint"
    return {"findings": findings, "engine": engine, "fallback_reason": None}


def run_analysis(file_path):
    """Return findings only for callers that use the original API."""
    return analyze_file(file_path)["findings"]

def scan_package(folder_path):
    """
    Samma paketstruktur som förr, men som nu använder abaplint-motorn för varje fil.
    """
    package_results = {}
    if not os.path.isdir(folder_path):
        return package_results

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith('.abap'):
                full_path = os.path.join(root, file)
                if file.startswith('~$'):
                    continue
                try:
                    analysis = analyze_file(full_path)
                    package_results[file] = {
                        "path": full_path,
                        "findings": analysis["findings"],
                        "engine": analysis["engine"],
                        "fallback_reason": analysis["fallback_reason"],
                    }
                except Exception:
                    continue
                    
    return package_results
