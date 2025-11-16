"""Educational guidance system for HIPAA Query Validator.

This module provides educational responses for each error type, helping users
understand WHY their queries were rejected and HOW to fix them. This follows
the principle of "educate, don't auto-fix."
"""

from typing import Dict, Optional, Tuple


def get_educational_guidance(error_code: str) -> Tuple[str, Optional[str]]:
    """Get educational guidance and correct pattern for an error code.

    Args:
        error_code: Error code (e.g., 'E001', 'E201')

    Returns:
        Tuple of (educational_guidance, correct_pattern)
    """
    guidance_map: Dict[str, Tuple[str, Optional[str]]] = {
        # Layer 0: ASCII Input Validation (E001-E099)
        "E001": (
            "Your query contains non-ASCII characters, which are prohibited for security "
            "reasons (Unicode-based SQL injection prevention). Please use only standard "
            "ASCII characters (letters, numbers, common punctuation). If you need to "
            "represent special characters, use SQL string functions or escape sequences.",
            "SELECT * FROM person WHERE name = 'Smith'  -- ASCII only",
        ),
        "E002": (
            "Your query contains control characters that are not allowed. Only newline (\\n), "
            "carriage return (\\r), and tab (\\t) are permitted for formatting. Remove any "
            "other control characters from your query.",
            "SELECT person_id,\n       gender_concept_id\nFROM person  -- Newlines OK",
        ),
        "E003": (
            "Your query is empty or contains only whitespace. Please provide a valid SQL query.",
            "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person",
        ),
        # Layer 1: Schema Validation (E101-E199)
        "E101": (
            "The table you referenced is not in the approved OMOP CDM schema. Please verify "
            "the table name against the OMOP CDM documentation. Common tables include: "
            "person, condition_occurrence, drug_exposure, measurement, observation, visit_occurrence.",
            "SELECT COUNT(DISTINCT person_id) AS Count_Patients\nFROM condition_occurrence",
        ),
        "E102": (
            "The column you referenced does not exist in the specified table according to "
            "the OMOP CDM schema. Please verify column names against the OMOP CDM documentation "
            "for your table.",
            "SELECT gender_concept_id  -- Valid OMOP column\nFROM person",
        ),
        # Layer 2: PHI Column Validation (E201-E299)
        "E201": (
            "Your query references a column containing Protected Health Information (PHI) "
            "as defined by HIPAA 45 CFR § 164.514(b)(2). Direct identifiers like names, "
            "SSNs, MRNs, addresses, and similar fields cannot be queried under Safe Harbor "
            "de-identification rules. You must use only aggregate, de-identified data.\n\n"
            "The 18 HIPAA identifiers that must be removed are:\n"
            "1. Names  2. Geographic subdivisions smaller than state  3. Dates (except year)\n"
            "4. Telephone numbers  5. Fax numbers  6. Email addresses  7. SSN  8. MRN\n"
            "9. Health plan numbers  10. Account numbers  11. Certificate/license numbers\n"
            "12. Vehicle identifiers  13. Device identifiers/serial numbers  14. Web URLs\n"
            "15. IP addresses  16. Biometric identifiers  17. Full-face photos  18. Other unique IDs",
            "SELECT state_code,  -- OK: state-level geography\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY state_code",
        ),
        "E202": (
            "Your query references geographic information smaller than state-level, which "
            "violates HIPAA Safe Harbor requirements (45 CFR § 164.514(b)(2)(i)(B)). "
            "You may only use state-level or larger geographic divisions. ZIP codes are "
            "prohibited unless aggregated to 3-digit ZIP with populations >20,000.\n\n"
            "Allowed: state, state_code, region, country\n"
            "Prohibited: street_address, city, county, zip_code (5-digit), latitude, longitude",
            "SELECT state_code,  -- OK: state-level\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY state_code",
        ),
        "E203": (
            "Your query references date elements more specific than year, which violates "
            "HIPAA Safe Harbor requirements (45 CFR § 164.514(b)(2)(i)(C)). You may only "
            "use year; month and day must be excluded for individuals over 89 years old.\n\n"
            "Allowed: year_of_birth, year columns\n"
            "Prohibited: birth_date, month_of_birth, day_of_birth, full dates",
            "SELECT year_of_birth,  -- OK: year only\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY year_of_birth",
        ),
        "E204": (
            "SELECT * is prohibited because it returns all columns, including potential PHI. "
            "You must explicitly list only the non-PHI columns you need. This ensures you "
            "consciously select only de-identified, aggregate data.\n\n"
            "This is a critical HIPAA compliance requirement - you must know exactly what "
            "data you are accessing.",
            "SELECT gender_concept_id,  -- Explicit columns only\n"
            "       race_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id, race_concept_id",
        ),
        # Layer 3: Aggregation Validation (E301-E399)
        "E301": (
            "Your query is missing a GROUP BY clause. HIPAA compliance requires aggregation "
            "to prevent identification of individuals. You must group by at least one "
            "non-PHI dimension (e.g., gender, race, year, state) unless performing a "
            "global aggregate across the entire dataset.\n\n"
            "Aggregation is the primary mechanism for de-identification in this system.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id  -- Required",
        ),
        "E302": (
            "Your query is missing the required patient count column. You must include "
            "'COUNT(DISTINCT person_id) AS Count_Patients' in your SELECT clause. This "
            "is required for the 20,000 patient minimum threshold enforcement.\n\n"
            "The exact syntax is required for proper wrapper enforcement.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients  -- Required\n"
            "FROM person\nGROUP BY gender_concept_id",
        ),
        "E303": (
            "Your patient count syntax is incorrect. You must use the exact syntax:\n"
            "COUNT(DISTINCT person_id) AS Count_Patients\n\n"
            "This exact syntax is required for:\n"
            "- Proper threshold enforcement (≥20,000 patients per cell)\n"
            "- Consistent audit logging\n"
            "- Prevention of circumvention attempts\n\n"
            "The column name must be 'person_id' (OMOP standard), DISTINCT is required "
            "to avoid double-counting, and the alias must be exactly 'Count_Patients'.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients  -- Exact syntax required\n"
            "FROM person\nGROUP BY gender_concept_id",
        ),
        "E304": (
            "Your query contains an aggregate function outside the SELECT clause. Aggregate "
            "functions (COUNT, SUM, AVG, MIN, MAX) are only allowed in the SELECT clause. "
            "They cannot be used in WHERE, GROUP BY, or other clauses.\n\n"
            "If you need to filter on aggregated values, this would require a HAVING clause, "
            "but HAVING is currently not supported to prevent threshold circumvention.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients  -- Aggregate in SELECT only\n"
            "FROM person\nGROUP BY gender_concept_id",
        ),
        "E305": (
            "Your GROUP BY clause contains an invalid column. GROUP BY columns must be:\n"
            "- Non-PHI columns (no direct identifiers)\n"
            "- Actual columns from the schema (not expressions or aggregates)\n"
            "- Not geographic subdivisions smaller than state\n"
            "- Not date elements more specific than year",
            "SELECT gender_concept_id,\n"
            "       race_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id, race_concept_id  -- Valid non-PHI columns",
        ),
        # Layer 4: SQL Enforcement (E401-E499)
        "E401": (
            "Subqueries are not allowed because they can be used to circumvent the minimum "
            "patient count threshold. All aggregation must occur in a single, top-level query "
            "that can be properly wrapped with the ≥20,000 patient enforcement.\n\n"
            "This is a critical anti-circumvention control.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id  -- Single-level query only",
        ),
        "E402": (
            "Common Table Expressions (WITH clauses / CTEs) are not allowed because they "
            "can be used to circumvent security controls and the minimum patient count "
            "threshold. All logic must be in a single, top-level query.\n\n"
            "This is a critical anti-circumvention control.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id  -- No CTEs allowed",
        ),
        # System Errors (E801-E899)
        "E801": (
            "There is an error in the system configuration file. Please contact your "
            "system administrator to resolve this issue. This is not a problem with "
            "your query.",
            None,
        ),
        "E802": (
            "The SQL parser encountered an error while analyzing your query. This could be "
            "due to invalid SQL syntax. Please verify your query syntax is correct.\n\n"
            "Common issues: missing semicolons, unbalanced parentheses, invalid keywords, "
            "typos in table/column names.",
            "SELECT gender_concept_id,\n"
            "       COUNT(DISTINCT person_id) AS Count_Patients\n"
            "FROM person\nGROUP BY gender_concept_id",
        ),
    }

    return guidance_map.get(error_code, ("Unknown error code", None))


def get_documentation_link(error_code: str) -> str:
    """Get documentation URL for an error code.

    Args:
        error_code: Error code (e.g., 'E201')

    Returns:
        URL to relevant documentation
    """
    # Map error code ranges to documentation sections
    if error_code.startswith("E0"):  # ASCII validation
        return "https://docs.example.com/validation/ascii-input"
    elif error_code.startswith("E1"):  # Schema validation
        return "https://docs.example.com/validation/schema"
    elif error_code.startswith("E2"):  # PHI validation
        return "https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html"
    elif error_code.startswith("E3"):  # Aggregation validation
        return "https://docs.example.com/validation/aggregation"
    elif error_code.startswith("E4"):  # Enforcement
        return "https://docs.example.com/validation/enforcement"
    elif error_code.startswith("E8"):  # System errors
        return "https://docs.example.com/troubleshooting/system-errors"
    else:
        return "https://docs.example.com/validation/overview"


def format_educational_response(
    error_code: str, message: str, details: Optional[Dict] = None
) -> Dict[str, str]:
    """Format a complete educational response for an error.

    Args:
        error_code: Error code
        message: Error message
        details: Optional additional details

    Returns:
        Dictionary with formatted educational response
    """
    guidance, pattern = get_educational_guidance(error_code)
    doc_link = get_documentation_link(error_code)

    response = {
        "error_code": error_code,
        "message": message,
        "educational_guidance": guidance,
        "documentation": doc_link,
    }

    if pattern:
        response["correct_pattern"] = pattern

    if details:
        response["details"] = str(details)

    return response
