import os
import sys

# Find search path for the map above 'analyzer'
current_dir = os.path.dirname(os.path.abspath(__file__)) 
project_root = os.path.dirname(current_dir)

# Add rootmap first to 'analyzer' can be found
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import streamlit as st
import math
import re
from analyzer.scanner import analyze_file, scan_package
from analyzer.main import parse_dependencies, get_risk_level


# Forcing python to find the 'analyzer'-package without relying on the current working directory
# Crucial for Streamlit deployments where the working directory may not be the project root.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Title and layout for webpage
st.set_page_config(page_title="SAP Customization Risk Analyzer", layout="wide")

st.title("SAP Customization Risk Analyzer")
st.markdown("Automated Static Code Analysis (SCA) & S/4HANA Migration Readiness Assessment")
st.write("---")

# Generate HTML report function
# --- RAPPORTMOTOR 2: HTML REPORT FOR FOLDER ---
def generate_package_html_report(folder_name, package_results, final_score, overall_level, global_severities):
    severity_colors = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#fd7e14", "CRITICAL": "#dc3545", "CLEAN": "#17a2b8"}
    overall_color = severity_colors.get(overall_level.split()[0] if overall_level else "CLEAN", "#6c757d")
    
    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; line-height: 1.6; }}
            .header {{ background-color: #1a365d; color: white; padding: 20px; border-radius: 5px; }}
            .badge {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; display: inline-block; }}
            .file-header {{ background: #edf2f7; padding: 12px; margin-top: 40px; border-left: 6px solid #1a365d; border-radius: 0 4px 4px 0; }}
            .card {{ border: 1px solid #e2e8f0; padding: 15px; margin: 15px 0; border-radius: 5px; background: #f7fafc; }}
            .matrix {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            .matrix th, .matrix td {{ border: 1px solid #cbd5e0; padding: 10px; text-align: left; }}
            .matrix th {{ background-color: #edf2f7; }}
            pre {{ background: #eee; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SAP Customization Comprehensive Package Risk Report</h1>
            <p><b>Package Folder Analyzed:</b> {folder_name}</p>
            <p><b>Overall Cumulative Package Rating:</b> <span style="background-color: {overall_color};" class="badge">{overall_level}</span> ({final_score} pts)</p>
        </div>
        
        <h2>Global Risk Summary Matrix</h2>
        <table class="matrix">
            <tr><th>SAP Risk Dimension</th><th>Vulnerability Level</th></tr>
            {"".join([f"<tr><td>{cat}</td><td><span style='background-color:{severity_colors.get(sev, '#6c757d')};' class='badge'>{sev}</span></td></tr>" for cat, sev in global_severities.items()])}
        </table>

        <h2>Detailed File breakdown & Recommended Action Items</h2>
    """
    
    for file, data in package_results.items():
        findings = data["findings"]
        html += f"""
        <div class="file-header">
            <h2>Object: {file} ({len(findings)} issues detected)</h2>
            <p>Analysis engine: {data.get('engine', 'unknown')}{f" (fallback: {data.get('fallback_reason')})" if data.get('fallback_reason') else ""}</p>
        </div>
        """
        if not findings:
            html += "<p style='color: #28a745; font-style: italic; margin-left: 10px;'>✓ No risks detected in this object. Code meets quality gate criteria.</p>"
        else:
            for f in findings:
                html += f"""
                <div class="card">
                    <h3><span style="background-color: {severity_colors.get(f['severity'], '#6c757d')};" class="badge">[{f['severity']}]</span> {f['id']} - {f['title']}</h3>
                    <p><b>Line:</b> {f['line']}</p>
                    <pre><code>{f['code']}</code></pre>
                    <p><b>Why this matters:</b> {f['description']}</p>
                    <p><b>Technical Rationale:</b> {f['rationale']}</p>
                    <p><b>Required Action / Recommendation:</b> <br><span style="color:#1a365d; font-weight:bold;">{f['recommendation']}</span></p>
                </div>
                """
    html += "</body></html>"
    return html


# ----------------- WEBSITE GUI  -----------------

# Menu Choice in sidebar
analysis_type = st.sidebar.selectbox(
    "What would you like to analyze?",
    ["Single ABAP File", "Folder / Package"]
)

# Drag-and-Drop in side panel
uploaded_file = None
if analysis_type == "Single ABAP File":
    uploaded_file = st.sidebar.file_uploader("Upload an ABAP file directly:", type=["abap"])

path = st.sidebar.text_input("Or enter path to file or folder:", value="examples")

if st.sidebar.button("Run Risk Analysis"):
    # SECURITY: Do Drag-and-Drop if an uploaded file is detected
    if analysis_type == "Single ABAP File" and uploaded_file is not None:
        with st.spinner("Processing uploaded file from desktop..."):
            filename = uploaded_file.name
            
            # Read source code directly from memory and decode the binary data to lines
            file_bytes = uploaded_file.read()
            lines = [line.decode("utf-8", errors="ignore") for line in file_bytes.splitlines(keepends=True)]
            
            # Run the scan directly against the memory lines via the rule function
            from analyzer.rules import scan_code
            findings = scan_code(lines)
            dependencies = [] # Isolated files missing local folder dependencies
            
            # Count points and risks
            rule_frequencies = {}
            calculated_base_score = 0
            category_severities = {"Performance": "LOW", "Maintainability": "LOW", "Migration": "LOW", "Security": "LOW"}
            
            for f in findings:
                rule_id = f["id"]
                rule_frequencies[rule_id] = rule_frequencies.get(rule_id, 0) + 1
                calculated_base_score += f["weight"] / math.sqrt(rule_frequencies[rule_id])
                
                if f["severity"] == "HIGH":
                    category_severities[f["category"]] = "HIGH"
                elif f["severity"] == "CRITICAL":
                    category_severities[f["category"]] = "CRITICAL"
                elif f["severity"] == "MEDIUM" and category_severities[f["category"]] not in ["HIGH", "CRITICAL"]:
                    category_severities[f["category"]] = "MEDIUM"
                    
            total_score = round(calculated_base_score * 1.25, 1) 
            overall_level = get_risk_level(total_score)
            
            # Render GUI-paneler for the uploaded file
            col1, col2 = st.columns([2, 1])
            with col1:
                st.subheader(f"Analysis Results for Uploaded File: {filename}")
                st.warning("Analysis engine: Python fallback. Uploaded files are scanned in memory and are not passed to the abaplint CLI.")
                if not findings:
                    st.success("No risks detected! Code looks clean.")
                else:
                    for f in findings:
                        with st.expander(f"[{f['severity']}] {f['id']} - {f['title']} (Rad {f['line']})"):
                            st.code(f['code'], language="abap")
                            st.markdown(f"**Why this matters:** {f['description']}")
                            st.markdown(f"*Technical Rationale:* {f['rationale']}")
                            st.info(f"**Recommendation:** {f['recommendation']}")
            with col2:
                st.subheader("Executive Risk Score")
                st.metric("Overall Rating", overall_level)
                st.metric("Total Weighted Score", f"{total_score} pts")
                
                st.subheader("Dimension Checklist")
                for cat, sev in category_severities.items():
                    st.write(f"• **{cat}:** {sev}")
                    
                st.subheader("Outbound Dependencies")
                st.caption("Standalone object (No local calls mapped for dropped assets)")
                
            st.write("---")
            
            # LÖSNING: Anpassa datastrukturen och anropa generate_package_html_report istället
            single_file_payload = {filename: {"findings": findings}}
            report_html = generate_package_html_report(filename, single_file_payload, total_score, overall_level, category_severities)
            
            st.download_button(
                label="Download Complete Report (HTML)",
                data=report_html,
                file_name=f"SAP_Risk_Report_{filename}.html",
                mime="text/html"
            )

    # Standard fallback on local paths if no file is uploaded, drag-and-drop
    elif not os.path.exists(path):
        st.error(f"Path '{path}' does not exist. Please check the spelling.")
    else:
        with st.spinner("Scanning code structures and computing risk matrices..."):
            
            # --- SCENARIO A: ANALYZE ONE FILE  ---
            if analysis_type == "Single ABAP File":
                if os.path.isdir(path):
                    st.error("You chose file analysis but specified a folder. Please change the selection in the sidebar.")
                else:
                    filename = os.path.basename(path)
                    analysis = analyze_file(path)
                    findings = analysis["findings"]
                    dependencies = parse_dependencies(path)
                    
                    # Count the points and risks
                    rule_frequencies = {}
                    calculated_base_score = 0
                    category_severities = {"Performance": "LOW", "Maintainability": "LOW", "Migration": "LOW", "Security": "LOW"}
                    
                    for f in findings:
                        rule_id = f["id"]
                        rule_frequencies[rule_id] = rule_frequencies.get(rule_id, 0) + 1
                        calculated_base_score += f["weight"] / math.sqrt(rule_frequencies[rule_id])
                        
                        if f["severity"] == "HIGH":
                            category_severities[f["category"]] = "HIGH"
                        elif f["severity"] == "CRITICAL":
                            category_severities[f["category"]] = "CRITICAL"
                        elif f["severity"] == "MEDIUM" and category_severities[f["category"]] not in ["HIGH", "CRITICAL"]:
                            category_severities[f["category"]] = "MEDIUM"
                            
                    total_score = round(calculated_base_score * 1.25, 1) # Multiplikator för Program
                    overall_level = get_risk_level(total_score)
                    
                    # --- GUI-PANELS ---
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.subheader(f"Analysis Results for: {filename}")
                        if analysis["engine"].startswith("abaplint"):
                            st.caption(f"Analysis engine: {analysis['engine']}")
                        else:
                            st.warning(f"Analysis engine: Python fallback ({analysis['fallback_reason']}).")
                        if not findings:
                            st.success("No risks detected! Code looks clean.")
                        else:
                            for f in findings:
                                with st.expander(f"[{f['severity']}] {f['id']} - {f['title']} (Rad {f['line']})"):
                                    st.code(f['code'], language="abap")
                                    st.markdown(f"**Why this matters:** {f['description']}")
                                    st.markdown(f"*Technical Rationale:* {f['rationale']}")
                                    st.info(f"**Recommendation:** {f['recommendation']}")
                                    
                    with col2:
                        st.subheader("Executive Risk Score")
                        st.metric("Overall Rating", overall_level)
                        st.metric("Total Weighted Score", f"{total_score} pts")
                        
                        st.subheader("Dimension Checklist")
                        for cat, sev in category_severities.items():
                            st.write(f"• **{cat}:** {sev}")
                            
                        st.subheader("Outbound Dependencies")
                        if not dependencies:
                            st.caption("Standalone object (No custom calls detected)")
                        else:
                            for dep in dependencies:
                                st.text(f" └── {dep}")
                                
                                        # Button for HTML Report Download
                    st.write("---")
                    
                    # LÖSNING: Anpassa datastrukturen till din befintliga paket-rapportmotor
                    single_file_payload = {filename: {
                        "findings": findings,
                        "engine": analysis["engine"],
                        "fallback_reason": analysis["fallback_reason"],
                    }}
                    report_html = generate_package_html_report(filename, single_file_payload, total_score, overall_level, category_severities)
                    
                    st.download_button(
                        label="Download Complete Report (HTML)",
                        data=report_html,
                        file_name=f"SAP_Risk_Report_{filename}.html",
                        mime="text/html"
                    )


            # --- SCENARIO B: ANALYZE FOLER/MAP ---
            else:
                if os.path.isfile(path):
                    st.error("You chose package analysis but specified a specific file.")
                else:
                    package_results = scan_package(path)
                    st.subheader(f"Package Summary: {os.path.basename(os.path.normpath(path))}")
                    
                    total_package_score = 0
                    global_category_severity = {"Performance": "LOW", "Maintainability": "LOW", "Migration": "LOW", "Security": "LOW"}
                    
                    col1, col2 = st.columns([3, 2])
                    
                    with col1:
                        st.write("### File Breakdown")
                        for file, data in package_results.items():
                            file_score = 0
                            freqs = {}
                            for f in data["findings"]:
                                freqs[f["id"]] = freqs.get(f["id"], 0) + 1
                                file_score += f["weight"] / math.sqrt(freqs[f["id"]])
                                
                                if f["severity"] == "HIGH" and global_category_severity[f["category"]] != "CRITICAL":
                                    global_category_severity[f["category"]] = "HIGH"
                                elif f["severity"] == "CRITICAL":
                                    global_category_severity[f["category"]] = "CRITICAL"
                                elif f["severity"] == "MEDIUM" and global_category_severity[f["category"]] == "LOW":
                                    global_category_severity[f["category"]] = "MEDIUM"
                                    
                            total_package_score += file_score
                            engine_status = data["engine"]
                            if data["fallback_reason"]:
                                engine_status += f" ({data['fallback_reason']})"
                            st.text(f"{file:<25} | Risks: {len(data['findings']):<3} | Impact: {file_score:.1f} pts | {engine_status}")
                            
                    with col2:
                        final_score = round(total_package_score * 1.50, 1)
                        st.write("### Cumulative Package Score")
                        st.metric("Overall Package Rating", get_risk_level(final_score))
                        st.metric("Total Combined Score", f"{final_score} pts")
                        
                        st.write("Package Architecture Matrix:")
                        for cat, sev in global_category_severity.items():
                            st.write(f"• {cat}: {sev}")

                    # RENDER THE DEPENDANCY FOR THE PACKAGE
                    st.write("### Package Architecture Graph")
                    for file, data in package_results.items():
                        deps = parse_dependencies(data["path"])
                        st.markdown(f"Object: {file}")
                        if not deps:
                            st.caption("  └── Standalone object")
                        else:
                            for d in deps:
                                st.markdown(f"  * └── {d}")

                    # BUTTON FOR HTML REPORT DOWNLOAD
                    st.write("---")
                    st.subheader("Export Package Report")
                    
                    pkg_html_report = generate_package_html_report(
                        os.path.basename(os.path.normpath(path)),
                        package_results,
                        final_score,
                        get_risk_level(final_score),
                        global_category_severity
                    )
                    
                    st.download_button(
                        label="Download Full Package Analysis & Recommendations (HTML)",
                        data=pkg_html_report,
                        file_name=f"SAP_Full_Package_Report_{os.path.basename(os.path.normpath(path))}.html",
                        mime="text/html"
                    )
