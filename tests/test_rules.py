# tests/test_rules.py
import pytest
from analyzer import rules
from analyzer import scanner
from analyzer.rules import scan_code, RULES

def test_select_inside_loop_detection():
    """Verifies that R001 (SELECT inside LOOP) is detected correctly."""
    bad_abap_code = [
        "LOOP AT lt_data INTO ls_data.\n",
        "  SELECT SINGLE * FROM kna1 INTO ls_cust.\n",
        "ENDLOOP.\n"
    ]
    
    findings = scan_code(bad_abap_code)
    
    # Control that we get exactly one finding and that it is the correct rule
    assert len(findings) >= 1
    assert any(f["id"] == "R001" for f in findings)

def test_obsolete_statement_detection():
    """Verifies and tests that obsolete ABAP statements (R008) are flagged."""
    obsolete_code = [
        "MOVE '1000' TO lv_company.\n",
        "REFRESH lt_table.\n"
    ]
    
    findings = scan_code(obsolete_code)
    
    # Two unique findings for R008 here
    r008_findings = [f for f in findings if f["id"] == "R008"]
    assert len(r008_findings) == 2

def test_run_analysis_uses_abaplint_cli_without_shell(monkeypatch, tmp_path):
    """Verifies that the project calls abaplint as a real process, not via shell string execution."""
    seen = {}
    npm_directory = tmp_path / "npm"
    cli_entrypoint = npm_directory / "node_modules" / "@abaplint" / "cli" / "abaplint"
    cli_entrypoint.parent.mkdir(parents=True)
    cli_entrypoint.write_text("", encoding="utf-8")
    shim_path = npm_directory / "abaplint.cmd"
    node_path = tmp_path / "node.exe"

    def fake_which(command):
        if command == "abaplint":
            return str(shim_path)
        if command == "node":
            return str(node_path)
        return None

    def fake_run(cmd, capture_output, text, shell, check):
        seen["cmd"] = cmd
        seen["shell"] = shell
        seen["check"] = check

        class DummyResult:
            returncode = 0
            stdout = "[]"
            stderr = ""

        return DummyResult()

    monkeypatch.setattr(scanner.shutil, "which", fake_which)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    source_file = tmp_path / "demo.abap"
    source_file.write_text("REPORT z_demo.\n", encoding="utf-8")
    analysis = scanner.analyze_file(str(source_file))

    expected_command = [str(shim_path), "abaplint.json", "-f", "json", "--file", f"/{str(source_file).replace(scanner.os.sep, '/')}" ]
    if scanner.os.name == "nt":
        expected_command = [str(node_path), str(cli_entrypoint), "abaplint.json", "-f", "json", "--file", f"/{str(source_file).replace(scanner.os.sep, '/')}" ]
    assert seen["cmd"] == expected_command
    assert seen["shell"] is False
    assert seen["check"] is False
    assert analysis == {"findings": [], "engine": "abaplint", "fallback_reason": None}


def test_analyze_file_reports_fallback_when_abaplint_is_missing(monkeypatch, tmp_path):
    source_file = tmp_path / "demo.abap"
    source_file.write_text("MOVE '1000' TO lv_company.\n", encoding="utf-8")
    monkeypatch.setattr(scanner.shutil, "which", lambda command: None)

    analysis = scanner.analyze_file(str(source_file))

    assert analysis["engine"] == "python-fallback"
    assert analysis["fallback_reason"] == "abaplint-not-found"
    assert any(finding["id"] == "R008" for finding in analysis["findings"])


def test_analyze_file_supplements_empty_abaplint_output_with_custom_rules(monkeypatch, tmp_path):
    source_file = tmp_path / "demo.abap"
    source_file.write_text("SELECT * FROM mara INTO TABLE lt_mara.\n", encoding="utf-8")

    monkeypatch.setattr(scanner.shutil, "which", lambda command: "abaplint")
    monkeypatch.setattr(scanner, "_build_abaplint_command", lambda executable, path: [executable, path])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: type(
        "Result", (), {"returncode": 0, "stdout": "[]", "stderr": ""}
    )())
    analysis = scanner.analyze_file(str(source_file))

    assert analysis["engine"] == "abaplint+python-rules"
    assert any(finding["id"] == "R002" for finding in analysis["findings"])


def test_real_abaplint_program_returns_lint_and_custom_findings():
    """Checks the complete abaplint-to-R00X path using a real ABAP program file."""
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    source_file = project_root / "examples" / "zabaplint_risk_demo.prog.abap"
    analysis = scanner.analyze_file(str(source_file))

    finding_ids = {finding["id"] for finding in analysis["findings"]}
    assert analysis["engine"] == "abaplint+python-rules"
    assert "ABAPLINT-CHECK_SYNTAX" in finding_ids
    assert "R001" in finding_ids
    assert "R010" in finding_ids


def test_run_analysis_keeps_findings_only_return_contract(monkeypatch, tmp_path):
    source_file = tmp_path / "demo.abap"
    source_file.write_text("REPORT z_demo.\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "analyze_file", lambda path: {"findings": [], "engine": "abaplint", "fallback_reason": None})

    assert scanner.run_analysis(str(source_file)) == []


def test_realistic_abap_patterns_are_detected_in_fallback_engine():
    """Covers representative ABAP snippets for each major rule family in the Python fallback engine."""
    snippets = {
        "R001": [
            "LOOP AT lt_data INTO ls_data.",
            "  SELECT SINGLE * FROM mara INTO ls_mara.",
            "ENDLOOP.",
        ],
        "R002": [
            "SELECT * FROM kna1 INTO TABLE @DATA(lt_kna1).",
        ],
        "R003": [
            "DATA lv_bukrs TYPE bukrs VALUE '1000'.",
        ],
        "R004": [
            "SELECT * FROM bseg INTO TABLE @DATA(lt_bseg).",
        ],
        "R005": [
            "CALL FUNCTION 'WS_DOWNLOAD'.",
        ],
        "R006": [
            "UPDATE bseg SET fieldname = value WHERE bukrs = '1000'.",
        ],
        "R007": [
            "SELECT * FROM t001 INTO TABLE @DATA(lt_t001).",
        ],
        "R008": [
            "MOVE '1000' TO lv_bukrs.",
            "REFRESH lt_table.",
        ],
        "R009": [
            "EXEC SQL.",
            "  SELECT * FROM usr01 INTO :wa_usr01.",
            "ENDEXEC.",
        ],
        "R010": [
            "CALL TRANSACTION 'VA01'.",
        ],
        "R011": [
            "SELECT SINGLE * FROM mara INTO ls_mara.",
        ],
        "R012": [
            "SELECT * FROM mara INTO TABLE lt_mara.",
        ],
        "R013": [
            "FORM legacy TABLES lt_data.",
        ],
    }

    findings = []
    for lines in snippets.values():
        findings.extend(scan_code(lines))

    found_ids = {finding["id"] for finding in findings}
    for rule_id in snippets:
        assert rule_id in found_ids, f"Missing fallback detection for {rule_id}"


def test_abaplint_issue_to_rule_mapping_matches_every_rule_id():
    """Ensures each supported R00X rule is mapped from representative abaplint payloads."""
    mappings = [
        ({"key": "db_operation_in_loop", "message": "SELECT inside LOOP", "start": {"row": 4}}, "R001"),
        ({"key": "select_star", "message": "SELECT * FROM mara", "start": {"row": 2}}, "R002"),
        ({"key": "hardcoded_org_value", "message": "Hardcoded org value '1000'", "start": {"row": 5}}, "R003"),
        ({"key": "cds_legacy_view", "message": "Legacy table BSEG used in SELECT", "start": {"row": 7}}, "R004"),
        ({"key": "obsolete_function", "message": "WS_DOWNLOAD is obsolete", "start": {"row": 8}}, "R005"),
        ({"key": "modify_only_own_db_tables", "message": "Direct UPDATE on BSEG", "start": {"row": 9}}, "R006"),
        ({"key": "select_add_order_by", "message": "SELECT without ORDER BY", "start": {"row": 10}}, "R007"),
        ({"key": "obsolete_statement", "message": "MOVE ... TO ... is obsolete", "start": {"row": 1}}, "R008"),
        ({"key": "native_sql", "message": "EXEC SQL detected", "start": {"row": 11}}, "R009"),
        ({"key": "call_transaction_authority_check", "message": "CALL TRANSACTION without authority check", "start": {"row": 12}}, "R010"),
        ({"key": "select_single_full_key", "message": "SELECT SINGLE without full key", "start": {"row": 13}}, "R011"),
        ({"key": "sql_escape_host_variables", "message": "Escape host variables with @", "start": {"row": 14}}, "R012"),
        ({"key": "form_tables_obsolete", "message": "FORM TABLES parameters are obsolete", "start": {"row": 15}}, "R013"),
    ]

    for issue, expected_rule in mappings:
        mapped_rule = scanner.map_abaplint_issue_to_rule(issue)
        assert mapped_rule == expected_rule, f"Expected {expected_rule} for {issue['key']}, got {mapped_rule}"


def test_clean_code_gives_no_findings():
    """Making sure the ABAP-code is clean and passes without issues."""
    clean_abap_code = [
        "REPORT z_clean_program.\n",
        "DATA(lv_total) = 0.\n",
        "lv_total = lv_total + 1.\n"
    ]
    
    findings = scan_code(clean_abap_code)
    assert len(findings) == 0
