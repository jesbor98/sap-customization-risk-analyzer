import re

RULES = {
    "R001": {
        "id": "R001",
        "title": "SELECT inside LOOP",
        "category": "Performance",
        "severity": "HIGH",
        "weight": 5,
        "rationale": "Database access inside a loop triggers multiple network round-trips (N+1 query problem), which is the leading cause of performance degradation in SAP systems.",
        "description": "Database access inside a loop can cause performance problems when processing large datasets.",
        "recommendation": "Consider retrieving the required data before the loop (e.g., using FOR ALL ENTRIES or JOIN).",
    },
    "R002": {
        "id": "R002",
        "title": "SELECT *",
        "category": "Maintainability",
        "severity": "MEDIUM",
        "weight": 2,
        "rationale": "Selecting all columns bypasses SAP database optimizations (like columnar storage indexing in HANA) and unnecessarily inflates application server memory usage.",
        "description": "Selecting all database fields may increase data transfer and make the code more dependent on the underlying structure.",
        "recommendation": "Select only the database fields that are required.",
    },
    "R003": {
        "id": "R003",
        "title": "Hard-coded organizational value",
        "category": "Migration",
        "severity": "MEDIUM",
        "weight": 2,
        "rationale": "Hard-coded values create rigid dependencies on specific organizational structures (e.g., Company Code 1000). This complicates S/4HANA conversion and landscape consolidation.",
        "description": "Hard-coded organizational values (like company codes, plants, or clients) hinder system flexibility and S/4HANA migration.",
        "recommendation": "Consider using configuration tables, TVARVC, or a parameter instead.",
    },
    "R004": {
        "id": "R004",
        "title": "S/4HANA Legacy Table Dependency",
        "category": "Migration",
        "severity": "CRITICAL",  # Höjd till CRITICAL på grund av prestanda- och stabilitetsrisk i HANA
        "weight": 15,            # Höjd vikt för att spegla allvaret i en S/4HANA-migration
        "rationale": "S/4HANA förenklar datamodellen dramatiskt. Gamla index- och totalsummetabeller (BSIS/BSAS/BSIK/BSAK/BSID/BSAD/GLT0/FAGLFLEXT) samt kärntabeller (BSEG/MSEG/MKPF) är antingen raderade eller ersatta med Compatibility Views. Att läsa direkt från dem bypassar det optimerade ACDOCA/MATDOC-kärnan och orsakar massiva prestandatapp.",
        "description": "Direkt SELECT-anrop mot föråldrade finansiella tabeller eller logistiska index-tabeller upptäckt.",
        "recommendation": "Granska SAP S/4HANA Simplification Item List. Styr om arkitekturen till att använda Universal Journal (ACDOCA för finans), MATDOC (för logistik) eller standard-CDS-vyer.",
    },
    "R005": {
        "id": "R005",
        "title": "Deprecated Functionality (Obsolete Function Call)",
        "category": "Migration",
        "severity": "MEDIUM",
        "weight": 2,
        "rationale": "Legacy function modules like WS_DOWNLOAD, WS_UPLOAD, or GUI_DOWNLOAD are obsolete and incompatible with modern NetWeaver/HANA application servers or web-based environments.",
        "description": "Obsolete function modules hinder system upgrades and unicode/cloud readiness.",
        "recommendation": "Replace legacy WS_* or GUI_* function calls with modern Object-Oriented equivalents like CL_GUI_FRONTEND_SERVICES.",
    },
    "R006": {
        "id": "R006",
        "title": "Direct Database Modification on Standard Table",
        "category": "Migration",
        "severity": "CRITICAL",
        "weight": 20,            # Höjd vikt då detta blockerar en S/4HANA-konvertering helt och hållet
        "rationale": "Att förbigå SAP:s standardapplikationslager via direkt UPDATE, INSERT eller DELETE på standardtabeller (t.ex. BSEG eller MARA) saboterar dataintegriteten och blockerar S/4HANA-konverteringen helt. Compatibility Views är Read-Only och kommer att krascha direkt vid skrivförsök.",
        "description": "Direkt modifiering (skrivning/ändring) av en standard SAP-databas-tabell upptäckt utan tillåtet API.",
        "recommendation": "Refaktorera koden omedelbart till att använda SAP:s officiella BAPIs, standard-funktionsmoduler eller moderna RAP (ABAP RESTful Application Programming) affärsobjekt.",
    },
    "R007": {
        "id": "R007",
        "title": "Missing ORDER BY in SELECT (HANA Sorting Risk)",
        "category": "Performance",
        "severity": "HIGH",
        "weight": 4,
        "rationale": "In SAP HANA (column-based DB), data rows are returned in a non-deterministic (random) order unless ORDER BY is explicit. Legacy databases often returned them sorted by primary key implicitly.",
        "description": "A SELECT statement without an ORDER BY clause might return rows in an unexpected sequence on a HANA database, breaking legacy application logic.",
        "recommendation": "Add an explicit ORDER BY clause if the subsequent application logic relies on a specific data sequence.",
    },
    "R008": {
        "id": "R008",
        "title": "Obsolete ABAP Language Statement",
        "category": "Maintainability",
        "severity": "LOW",
        "weight": 1,
        "rationale": "Statements like MOVE, REFRESH, or COMPUTE are deprecated in modern ABAP. They hinder Cloud-readiness (BTP/Steampunk) and break Clean ABAP standards.",
        "description": "Outdated ABAP syntax keywords detected in the source code.",
        "recommendation": "Replace 'MOVE x TO y' with 'y = x'. Replace 'REFRESH x' with 'CLEAR x'. Remove 'COMPUTE' keywords entirely.",
    },
    "R009": {
        "id": "R009",
        "title": "Native SQL or Database Hint Detected",
        "category": "Performance",
        "severity": "HIGH",
        "weight": 5,
        "rationale": "Native SQL (EXEC SQL) or DB Hints (%_HINTS) target specific legacy database platforms (e.g., Oracle). During an S/4HANA migration, these statements will either cause short dumps or severely degrade execution speeds.",
        "description": "Database-specific native code bypassing Open SQL standard boundaries.",
        "recommendation": "Remove database hints completely as HANA optimizes queries natively. Refactor Native SQL into standard Open SQL or AMDP (ABAP Managed Database Procedures).",
    },
    "R010": {
        "id": "R010",
        "title": "Missing Authority Check Before Transactional Context",
        "category": "Security",
        "severity": "HIGH",
        "weight": 5,
        "rationale": "Executing critical database operations, file access, or custom calculations without validation leaves the custom transaction open to authorization bypass exploits.",
        "description": "Potential lack of an AUTHORITY-CHECK statement before critical processing logic.",
        "recommendation": "Ensure an explicit AUTHORITY-CHECK OBJECT statement is executed and sy-subrc is validated before performing restricted business logic.",
    },
    "R011": {
        "id": "R011",
        "title": "SELECT SINGLE Without Full Key",
        "category": "Performance",
        "severity": "MEDIUM",
        "weight": 3,
        "rationale": "A SELECT SINGLE without a complete key can scan multiple database rows and return an arbitrary match.",
        "description": "SELECT SINGLE appears without a WHERE clause that identifies a complete database key.",
        "recommendation": "Use the complete primary key or a deterministic ORDER BY with an explicit result limit.",
    },
    "R012": {
        "id": "R012",
        "title": "Unescaped SQL Host Variable",
        "category": "Maintainability",
        "severity": "MEDIUM",
        "weight": 2,
        "rationale": "Modern Open SQL requires escaped host variables to make the boundary between database expressions and ABAP variables explicit.",
        "description": "An Open SQL host variable is used without the modern @ escape syntax.",
        "recommendation": "Use @ before ABAP host variables in Open SQL statements.",
    },
    "R013": {
        "id": "R013",
        "title": "Obsolete FORM TABLES Interface",
        "category": "Maintainability",
        "severity": "MEDIUM",
        "weight": 2,
        "rationale": "FORM TABLES parameters rely on legacy procedural interfaces and make typing and data flow harder to verify.",
        "description": "A procedural FORM routine declares TABLES parameters.",
        "recommendation": "Replace the FORM interface with a typed method or explicitly typed USING/CHANGING parameters.",
    }
}

def scan_code(lines):
    """
    Kör lokala mönsterigenkänningar på rå ABAP-kod.
    """
    findings = []
    in_loop = False
    has_authority_check = False

    legacy_tables = [
        "BSIS", "BSAS", "BSIK", "BSAK", "BSID", "BSAD",  
        "BSEG", "GLT0", "FAGLFLEXT",                    
        "MSEG", "MKPF",                                 
        "MARD", "MARCD"                                 
    ]

    for i, line_raw in enumerate(lines, start=1):
        clean_line = line_raw.strip().upper()
        
        # Ignorera tomma rader samt kommentarer
        if not clean_line or clean_line.startswith("*") or clean_line.startswith('"'):
            continue

        # Spåra loop-block för R001
                # Spåra loop-block för R001
        if "LOOP " in clean_line or "DO " in clean_line or "WHILE " in clean_line:
            in_loop = True
        if "ENDLOOP" in clean_line or "ENDDO" in clean_line or "ENDWHILE" in clean_line:
            in_loop = False

        # Spåra Authority Checks för R010
        if "AUTHORITY-CHECK " in clean_line:
            has_authority_check = True

        if "CALL TRANSACTION" in clean_line and "AUTHORITY-CHECK " not in clean_line:
            findings.append({**RULES["R010"], "line": i, "code": line_raw.strip()})

        # --- R011: SELECT SINGLE without a complete key ---
        if "SELECT SINGLE " in clean_line and "WHERE " not in clean_line:
            findings.append({**RULES["R011"], "line": i, "code": line_raw.strip()})

        # --- R012: Unescaped Open SQL host variables ---
        if "SELECT " in clean_line and "INTO " in clean_line and "@" not in clean_line:
            findings.append({**RULES["R012"], "line": i, "code": line_raw.strip()})

        # --- R013: Obsolete FORM TABLES interface ---
        if clean_line.startswith("FORM ") and " TABLES " in f" {clean_line} ":
            findings.append({**RULES["R013"], "line": i, "code": line_raw.strip()})

        # --- R001: SELECT inside LOOP ---
        if in_loop and "SELECT " in clean_line and "ENDSELECT" not in clean_line:
            findings.append({**RULES["R001"], "line": i, "code": line_raw.strip()})

        # --- R002: SELECT * ---
        if "SELECT *" in clean_line:
            findings.append({**RULES["R002"], "line": i, "code": line_raw.strip()})

        # --- R003: Hardcoded Org Values ---
        if "BUKRS" in clean_line or "WERKS" in clean_line:
            if re.search(r"=\s*'Value'", clean_line) or re.search(r"'\d{4}'", clean_line):
                findings.append({**RULES["R003"], "line": i, "code": line_raw.strip()})

        # --- S/4HANA-KONTROLLER (R004 & R006) ---
        for table in legacy_tables:
            if re.search(r"\b" + table + r"\b", clean_line):
                # R006: Om de försöker modifiera/skriva i tabellen (Kritiskt!)
                if any(x in clean_line for x in ["UPDATE ", "INSERT ", "DELETE ", "MODIFY "]):
                    findings.append({**RULES["R006"], "line": i, "code": line_raw.strip()})
                # R004: Om de gör en SELECT/läsning från den föråldrade tabellen
                elif "FROM " in clean_line or "SELECT " in clean_line:
                    findings.append({**RULES["R004"], "line": i, "code": line_raw.strip()})

        # --- R005: Obsolete Function Call ---
        if "CALL FUNCTION" in clean_line:
            if any(func in clean_line for func in ["WS_DOWNLOAD", "WS_UPLOAD", "GUI_DOWNLOAD"]):
                findings.append({**RULES["R005"], "line": i, "code": line_raw.strip()})

        # --- R007: Missing ORDER BY ---
        if "SELECT " in clean_line and "FROM " in clean_line and "ORDER BY" not in clean_line:
            if "SINGLE " not in clean_line:  # Undvik falsklarm på singelradsläsningar
                findings.append({**RULES["R007"], "line": i, "code": line_raw.strip()})

        # --- R008: Obsolete Syntax ---
        if any(k in clean_line for k in ["MOVE ", "REFRESH ", "COMPUTE "]):
            if " TO " in clean_line or "COMPUTE " in clean_line or clean_line.startswith("REFRESH "):
                findings.append({**RULES["R008"], "line": i, "code": line_raw.strip()})

        # --- R009: Native SQL / Hints ---
        if "EXEC SQL" in clean_line or "%_HINTS" in clean_line:
            findings.append({**RULES["R009"], "line": i, "code": line_raw.strip()})

    return findings
