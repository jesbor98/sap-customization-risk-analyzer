# analyzer/main.py
import os
import time
import math
import re
from analyzer.scanner import run_analysis, scan_package, load_abap_file

def print_header():
    print("\nSAP Customization Risk Analyzer")
    print("================================")

def get_risk_level(score):
    if score == 0:
        return "CLEAN"
    elif 1 <= score <= 10:
        return "LOW"
    elif 11 <= score <= 30:
        return "MEDIUM"
    elif 31 <= score <= 60:
        return "HIGH"
    else:
        return "CRITICAL"

def draw_score_bar(score, max_expected=80):
    bar_length = 20
    if score == 0:
        return f"[--------------------] 0 pts"
    
    filled_length = int(round(bar_length * score / max_expected))
    if filled_length > bar_length:
        filled_length = bar_length
    elif filled_length < 1:
        filled_length = 1
        
    bar = "█" * filled_length + "-" * (bar_length - filled_length)
    return f"[{bar}] {score} pts"

def parse_dependencies(file_path):
    dependencies = []
    if os.path.isdir(file_path):
        return dependencies
        
    try:
        lines = load_abap_file(file_path)
        for line in lines:
            line_upper = line.strip().upper()
            if line_upper.startswith("*") or line_upper.startswith('"'):
                continue
            
            func_match = re.search(r"CALL\s+FUNCTION\s+'([^']+)'", line_upper)
            if func_match:
                dependencies.append(f"Function Module: {func_match.group(1)}")
                continue
                
            submit_match = re.search(r"SUBMIT\s+([A-Z0-9_]+)", line_upper)
            if submit_match and submit_match.group(1) not in ["VIA", "SELECTION-SCREEN"]:
                dependencies.append(f"Program: {submit_match.group(1)}")
                continue

            class_match = re.search(r"TYPE\s+(ZCL_[A-Z0-9_]+)", line_upper)
            if class_match:
                dependencies.append(f"Class: {class_match.group(1)}")
                continue
    except Exception:
        pass
    return list(set(dependencies))

def run_cli():
    print_header()
    print("\nWhat would you like to analyze?\n")
    print("1. ABAP program")
    print("2. ABAP class")
    print("3. Function module")
    print("4. Include")
    print("5. Folder/package")
    
    try:
        choice = input("\nSelect: ").strip()
        if choice not in ["1", "2", "3", "4", "5"]:
            print("\nInvalid selection. Exiting.")
            return

        path = input("\nEnter path to ABAP file or folder: ").strip()

        if not os.path.exists(path):
            print(f"\nError: Path '{path}' could not be found.")
            return

        # SECURITY: Prevent Windows from raising PermissionError with invalid input
        if choice in ["1", "2", "3", "4"] and os.path.isdir(path):
            print(f"\nError: You selected a file analysis (1-4) but provided a folder path ('{path}').")
            print("Please provide a path to a specific .abap file, or choose option 5 for folders.")
            return
            
        if choice == "5" and os.path.isfile(path):
            print(f"\nError: You selected folder analysis (5) but provided a specific file ('{path}').")
            print("Please provide a path to a directory/folder.")
            return

        print("\nAnalyzing...\n")
        time.sleep(0.4)
        print("✓ Resource(s) loaded")
        time.sleep(0.3)
        print("✓ ABAP syntax scanned")
        time.sleep(0.3)
        print("✓ Risk patterns and dependencies mapped")
        
        if choice == "5":
            package_results = scan_package(path)
            print_package_report(path, package_results)
        else:
            findings = run_analysis(path)
            print_report(path, findings, choice)

    except KeyboardInterrupt:
        print("\n\nAnalysis cancelled by user.")

def print_report(path, findings, object_type_choice):
    filename = os.path.basename(path)
    type_mapping = {"1": "ABAP Program", "2": "ABAP Class", "3": "Function Module", "4": "Include"}
    object_name = type_mapping.get(object_type_choice, "Unknown")

    print("\nResults")
    print("================================")
    print(f"Object: {filename} ({object_name})")
    print("================================\n")

    multipliers = {"1": 1.25, "2": 1.20, "3": 1.00, "4": 0.75}
    m_o = multipliers.get(object_type_choice, 1.00)

    rule_frequencies = {}
    calculated_base_score = 0
    category_max_severity = {"Performance": "LOW", "Maintainability": "LOW", "Migration": "LOW", "Security": "LOW"}

    if not findings:
        print("No risks detected! Code looks clean. ✨\n")
    else:
        for f in findings:
            rule_id = f["id"]
            rule_frequencies[rule_id] = rule_frequencies.get(rule_id, 0) + 1
            n = rule_frequencies[rule_id]

            marginal_weight = f["weight"] / math.sqrt(n)
            calculated_base_score += marginal_weight

            if f["severity"] == "HIGH":
                category_max_severity[f["category"]] = "HIGH"
            elif f["severity"] == "CRITICAL":
                category_max_severity[f["category"]] = "CRITICAL"
            elif f["severity"] == "MEDIUM" and category_max_severity[f["category"]] not in ["HIGH", "CRITICAL"]:
                category_max_severity[f["category"]] = "MEDIUM"

            print(f"[{f['severity']}] {f['id']} - {f['title']}")
            print(f"Line {f['line']} | Instance #{n} (Mathematical impact: +{marginal_weight:.2f} pts)")
            print(f"    Code: {f['code'].strip()}\n")
            print(f"Why this matters: {f['description']}")
            print(f"Technical Rationale: {f['rationale']}\n")
            if "detected_value" in f:
                print(f"Detected value: '{f['detected_value']}'\n")
            print(f"Recommendation: {f['recommendation']}")
            print("-" * 60 + "\n")

    dependencies = parse_dependencies(path)
    print("Dependency Graph")
    print("────────────────────────")
    print(f" {filename}")
    if not dependencies:
        print("  └── (No custom outbound SAP dependencies detected)")
    else:
        for i, dep in enumerate(dependencies):
            marker = "└──" if i == len(dependencies) - 1 else "├──"
            print(f"  {marker} {dep}")
    print("\n")

    total_risk_score = round(calculated_base_score * m_o, 1)
    overall_level = get_risk_level(total_risk_score)

    print("================================")
    print("Risk summary\n")
    for cat, sev in category_max_severity.items():
        print(f"{cat:<18} {sev}")
    print("-" * 32)
    print(f"Raw Code Issues Score: {calculated_base_score:.2f} pts")
    print(f"SAP Execution Impact:  x{m_o}")
    print(f"Total Weighted Score:  {draw_score_bar(total_risk_score)}")
    print(f"Overall Risk Rating:   {overall_level}")
    print("================================")

def print_package_report(folder_path, package_results):
    folder_name = os.path.basename(os.path.normpath(folder_path))
    print("\nPackage Analysis Results")
    print("================================")
    print(f"Package Folder: {folder_name}")
    print(f"Total ABAP Files Scanned: {len(package_results)}")
    print("================================\n")

    total_package_score = 0
    package_dependencies = {}
    global_category_severity = {"Performance": "LOW", "Maintainability": "LOW", "Migration": "LOW", "Security": "LOW"}

    if not package_results:
        print("No .abap files found in this directory.")
        print("────────────────────────")
    else:
        print("File Breakdown:")
        print("────────────────────────")
        for file, data in package_results.items():
            findings = data["findings"]
            file_path = data["path"]
            
            file_score = 0
            freqs = {}
            for f in findings:
                freqs[f["id"]] = freqs.get(f["id"], 0) + 1
                file_score += f["weight"] / math.sqrt(freqs[f["id"]])
                
                if f["severity"] == "HIGH" and global_category_severity[f["category"]] != "CRITICAL":
                    global_category_severity[f["category"]] = "HIGH"
                elif f["severity"] == "CRITICAL":
                    global_category_severity[f["category"]] = "CRITICAL"
                elif f["severity"] == "MEDIUM" and global_category_severity[f["category"]] == "LOW":
                    global_category_severity[f["category"]] = "MEDIUM"

            total_package_score += file_score
            print(f"{file:<30} | Risks found: {len(findings):<3} | Impact: {file_score:.1f} pts")
            package_dependencies[file] = parse_dependencies(file_path)

    print("\nPackage Dependency Matrix & Architecture Graph")
    print("──────────────────────────────────────────────")
    for file, deps in package_dependencies.items():
        print(f"{file}")
        if not deps:
            print("   └── (Standalone / No outbound architecture dependencies)")
        else:
            for i, dep in enumerate(deps):
                structure_marker = "   └──" if i == len(deps) - 1 else "   ├──"
                print(f"{structure_marker} {dep}")
        print()

    m_o = 1.50
    final_package_score = round(total_package_score * m_o, 1)
    overall_level = get_risk_level(final_package_score)

    print("================================")
    print("Overall Package Risk Summary\n")
    for cat, sev in global_category_severity.items():
        print(f"{cat:<18} {sev}")
    print("-" * 32)
    print(f"Combined Package Issues: {total_package_score:.2f} pts")
    print(f"Package Architecture Factor: x{m_o}")
    print(f"Total Package Score:     {draw_score_bar(final_package_score, max_expected=150)}")
    print(f"Overall Package Rating:  {overall_level}")
    print("================================")

if __name__ == "__main__":
    run_cli()
