# SAP Customization Risk Analyzer

An automated, non-linear **Static Code Analysis (SCA)** platform built in Python to evaluate the technical debt, security anomalies, and S/4HANA migration readiness of custom (`Z*` & `Y*`) ABAP assets.

## Mathematical Framework vs. Native SAP Tools

Traditional SAP utilities (such as `ATC`, `SLIN`, or `RS_ABAP_SOURCE_SCAN`) operate on a linear binary methodology. They flag an issue, and each issue adds up sequentially. This creates major gaps when assessing risk in enterprise environments.

This tool uses a **Dimension Matrix Model** utilizing non-linear mathematical formulas to bridge these gaps:

1. **Logarithmic Frequency Damping (\(\frac{W}{\sqrt{n}}\)):** In native SAP scans, a file with 50 instances of a minor bug looks 50x worse than a file with one catastrophic flaw. This engine applies an evaluation where the mathematical impact of a specific rule decays with successive occurrences (n). The first strike hits with 100% weight, while repetitive instances are damped, preventing a single redundant pattern from skewing the executive dashboard.
2. **Context-Aware Execution Multipliers (\(M_o\)):** Enterprise impact is asymmetric. A vulnerable database modification inside an active ABAP Class (\(M_o = 1.20\)) or a core Transaction Report (\(M_o = 1.25\)) poses a higher operational risk than the same statement embedded inside an inactive code fragment or Include (\(M_o = 0.75\)).
3. **Hard-Coded Isolation Vulnerability Floor (Short-Circuit Logic):** The math does not let massive amounts of clean code hide a critical risk. If a single flaw designated as `CRITICAL` (e.g., direct standard database modifications) or `HIGH` is captured, the engine automatically forces an escalation floor, overriding low base-scores to project a true representation of compliance risk.

## Core Features
- **Multi-Engine Ingestion:** Uses the local abaplint CLI as the primary engine and supplements its output with project-specific R00X rules. Uploaded files use the Python rules because they exist only in memory.
- **S/4HANA Readiness Scanning:** Catches direct accesses to simplified legacy indexes (e.g., `BSIS`, `BSEG`), out-of-date functions (`WS_DOWNLOAD`), and native database hints.
- **ABAP Quality Rules:** Includes R001-R013 for performance, security, migration, maintainability, SQL usage, and legacy ABAP patterns.
- **Dependency Graph Mapping (Phase 5):** Parses outbound structural hooks (`CALL FUNCTION`, `SUBMIT`, object instantiation) to map coupling topologies.
- **Portable Compliance Assets:** Outputs portable, standalone HTML executive summaries embedded with clean UI matrices and structured action items for engineering teams.

## Installation & Execution
The analyzer requires Python, Node.js, the abaplint CLI, and the Python packages used by the UI and tests.

```bash
# Optional: activate your Python environment
conda activate "myEnvironment"

# Install Python dependencies
pip install streamlit pytest

# Install the primary ABAP analysis engine
npm install --global @abaplint/cli

# Start the graphical server
streamlit run analyzer/app.py
```

The scanner reads [abaplint.json](abaplint.json) from the project root. This file defines the ABAP version, the files to scan, and the enabled abaplint rules. No GitHub or other network configuration is required during analysis.

## Analysis Flow

For local files, the scanner follows this flow:

1. Run the installed abaplint CLI with JSON output.
2. Map supported abaplint issues to R00X rules.
3. Run the local Python R00X rules to cover project-specific risks that abaplint does not report.
4. Deduplicate findings by rule and source line.

The UI displays `abaplint`, `abaplint+python-rules`, or `python-fallback` as the active engine status.

## ABAP Example Files

abaplint identifies ABAP object types from file suffixes. Use SAP-style names such as:

```text
zabaplint_risk_demo.prog.abap
zcl_example.clas.abap
zfi_payment_run.prog.abap
```

The examples folder contains both ordinary `.abap` samples for the Python rules and a `.prog.abap` file that produces real abaplint findings.

## Tests

Run the complete regression suite from the project root:

```bash
pytest -q
```
