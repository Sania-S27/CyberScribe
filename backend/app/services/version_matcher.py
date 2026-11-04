# backend/app/services/version_matcher.py
import re
from typing import Tuple, List, Optional
from packaging.version import parse as parse_version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier


# Common package name normalizations and aliases
PACKAGE_ALIASES = {
    "python-jose": ["python-jose", "jose", "python_jose"],
    "python-levenshtein": ["python-levenshtein", "levenshtein", "python_levenshtein"],
    "thefuzz": ["thefuzz", "fuzzywuzzy"],
    "pymysql": ["pymysql", "py-mysql"],
    "react-map-gl": ["react-map-gl", "react_map_gl"],
    "mapbox-gl": ["mapbox-gl", "mapbox_gl"],
    "react-router-dom": ["react-router-dom", "react_router_dom"],
}

# Authoritative distinct product rules to prevent false positive matching on derivative
# packages, database adapters, plugins, extensions, or similarly named software.
DISTINCT_PRODUCT_RULES = {
    "sqlalchemy": [
        (re.compile(r"\b(?:products\.)?sqlalchemyda\b", re.IGNORECASE), "SQLAlchemyDA", "Zope database adapter for ZSQL methods"),
        (re.compile(r"\bflask-sqlalchemy\b", re.IGNORECASE), "Flask-SQLAlchemy", "Flask framework database integration"),
        (re.compile(r"\bsqlalchemy-utils\b", re.IGNORECASE), "SQLAlchemy-Utils", "Community utility package for SQLAlchemy"),
        (re.compile(r"\bsqlalchemy-migrate\b", re.IGNORECASE), "SQLAlchemy-Migrate", "Database schema migration library"),
        (re.compile(r"\bmarshmallow-sqlalchemy\b", re.IGNORECASE), "Marshmallow-SQLAlchemy", "Marshmallow integration"),
    ],
    "fastapi": [
        (re.compile(r"\bfastapi-admin\b", re.IGNORECASE), "fastapi-admin", "Administrative interface extension for FastAPI"),
        (re.compile(r"\bfastapi-users\b", re.IGNORECASE), "fastapi-users", "User authentication extension for FastAPI"),
    ],
    "react": [
        (re.compile(r"\breactos\b", re.IGNORECASE), "ReactOS", "Open-source operating system"),
        (re.compile(r"\breactions\b", re.IGNORECASE), "J! Reactions", "Joomla reaction extension"),
    ],
    "bcrypt": [
        (re.compile(r"\bopencast\b", re.IGNORECASE), "Opencast", "Video capture and management platform"),
    ],
    "httpx": [
        (re.compile(r"\bpraisonai(?:agents)?\b", re.IGNORECASE), "PraisonAI", "Multi-agent framework using HTTPX"),
    ],
    "aws": [
        (re.compile(r"\bawstats\b", re.IGNORECASE), "AWStats", "Web log analysis software"),
    ],
}


def normalize_package_name(name: str) -> str:
    """Normalizes package names by replacing underscores with hyphens and lowercasing."""
    return name.strip().lower().replace("_", "-")


def check_product_identity_mismatch(norm_pkg: str, threat_text: str) -> Optional[Tuple[str, str]]:
    """
    Checks if an advisory targets a distinct derivative, adapter, plugin, or separate product
    rather than the base package.
    
    Returns:
        Optional[(distinct_product_name, product_description)]
    """
    if not threat_text:
        return None

    # 1. Evaluate explicit distinct product rules (fast path for known high-profile derivatives)
    rules = DISTINCT_PRODUCT_RULES.get(norm_pkg, [])
    for pattern, product_name, desc in rules:
        if pattern.search(threat_text):
            return product_name, desc

    # 2. Generalized check for ANY package across all future reports:
    # Detect compound package/product names in threat_text that contain norm_pkg as a sub-token
    # (e.g. prefix-{norm_pkg}, {norm_pkg}-{suffix}, {norm_pkg}DA, products.{norm_pkg}, {norm_pkg}Plugin, etc.)
    aliases = PACKAGE_ALIASES.get(norm_pkg, [norm_pkg])
    alias_patterns = "|".join([re.escape(a) for a in aliases])

    # Find compound tokens that contain norm_pkg or its aliases
    generic_compounds = re.findall(
        rf"\b([a-zA-Z0-9_\-\.]*(?:{alias_patterns})[a-zA-Z0-9_\-\.]*)\b",
        threat_text,
        re.IGNORECASE
    )
    for c in generic_compounds:
        c_norm = normalize_package_name(c)
        if c_norm != norm_pkg and len(c_norm) > len(norm_pkg) + 1:
            if c_norm not in aliases:
                # Check for derivative/relationship indicators:
                is_derivative_context = bool(re.search(
                    rf"\b(?:adapter|plugin|extension|module|wrapper|connector|library|package|tool)\s+(?:for|to|with)\s+(?:{alias_patterns})\b",
                    threat_text,
                    re.IGNORECASE
                ) or re.search(
                    rf"\b(?:for|with|on|to)\s+(?:{alias_patterns})\b",
                    threat_text,
                    re.IGNORECASE
                ))

                # Check if compound `c` is described as having the vulnerability or version constraint
                compound_has_flaw = bool(re.search(
                    rf"\b{re.escape(c)}\b[^\.\n]*?(?:vulnerab|flaw|exploit|before|prior to|through|<=|<|fixed in|patched in|allows)",
                    threat_text,
                    re.IGNORECASE
                ))

                # Check if base package is separately and explicitly asserted to have the vulnerability
                base_pkg_explicitly_vulnerable = bool(re.search(
                    rf"\b(?:{alias_patterns})\b\s*(?:itself)?\s*(?:[<>=]|before|prior to|through|is vulnerable|has a vulnerability)",
                    re.sub(rf"\b{re.escape(c)}\b", "", threat_text, flags=re.IGNORECASE),
                    re.IGNORECASE
                ))

                if (compound_has_flaw or is_derivative_context) and not base_pkg_explicitly_vulnerable:
                    return c, f"Distinct derivative, plugin, or adapter associated with {norm_pkg}"

    return None


def extract_version_constraints(text: str, pkg_name: str) -> List[str]:
    """
    Extracts authoritative version constraints from threat advisories for a specific package.
    Supports operators (<, <=, >, >=, ==), natural language expressions ('before X', 'through X', 'fixed in X'),
    and handles punctuation/formatting cleanly. Strictly associates constraints with pkg_name.
    """
    if not text or not pkg_name:
        return []

    norm_pkg = normalize_package_name(pkg_name)
    
    # If the text targets a distinct derivative product, do not attribute its version bounds to the base package
    if check_product_identity_mismatch(norm_pkg, text):
        return []

    constraints = []
    aliases = PACKAGE_ALIASES.get(norm_pkg, [norm_pkg])
    alias_patterns = "|".join([re.escape(a) for a in aliases])

    # Pattern 1: Direct operators after package name e.g. 'FastAPI < 0.65.0', 'httpx <= 0.23.0'
    p1 = re.findall(
        rf"\b(?:{alias_patterns})\b\s*([<>=!~]=?\s*\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
        text,
        re.IGNORECASE,
    )
    for c in p1:
        clean_c = c.strip().rstrip(".,;:!)'\"")
        if clean_c:
            constraints.append(clean_c)

    # Pattern 2: Package name followed closely by 'before / prior to / earlier than / less than'
    # e.g. "FastAPI before 0.65.2", "FastAPI versions before 0.65.2", "FastAPI prior to 0.65"
    p2 = re.findall(
        rf"\b(?:{alias_patterns})\b\s*(?:versions?|releases?|packages?|components?)?\s*(?:before|prior to|earlier than|lower than|less than|below)\s+(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
        text,
        re.IGNORECASE,
    )
    for v in p2:
        clean_v = v.strip().rstrip(".,;:!)'\"")
        if clean_v:
            constraints.append(f"< {clean_v}")

    # Pattern 3: Package name followed closely by 'through / up to / <= '
    # e.g. "PyMySQL through 1.1.0", "python-jose versions up to 3.3.0"
    p3 = re.findall(
        rf"\b(?:{alias_patterns})\b\s*(?:versions?|releases?|packages?|components?)?\s*(?:through|up to)\s+(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
        text,
        re.IGNORECASE,
    )
    for v in p3:
        clean_v = v.strip().rstrip(".,;:!)'\"")
        if clean_v:
            constraints.append(f"<= {clean_v}")

    # Pattern 4: Sentence-level constraint extraction when sentence references package
    sentences = re.split(r"[\n\.\?!]", text)
    for s in sentences:
        s_clean = s.strip()
        if not s_clean:
            continue
        if re.search(rf"\b(?:{alias_patterns})\b", s_clean, re.IGNORECASE):
            # Prior to / before / earlier than in sentence referencing package
            m_prior = re.findall(
                rf"(?:in\s+)?(?:versions?|releases?|packages?|components?)?\s*(?:before|prior to|earlier than|lower than|less than|below)\s+(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
                s_clean,
                re.IGNORECASE
            )
            for v in m_prior:
                clean_v = v.strip().rstrip(".,;:!)'\"")
                if clean_v:
                    constraints.append(f"< {clean_v}")

            # Through / up to in sentence referencing package
            m_through = re.findall(
                rf"(?:in\s+)?(?:versions?|releases?|packages?|components?)?\s*(?:through|up to)\s+(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
                s_clean,
                re.IGNORECASE
            )
            for v in m_through:
                clean_v = v.strip().rstrip(".,;:!)'\"")
                if clean_v:
                    constraints.append(f"<= {clean_v}")

            # Fix/patch statements within sentence referencing package
            fix_matches = re.findall(
                rf"(?:fixed in|patched in)\s+(?:(?:{alias_patterns})\s+)?(?:\bversion\s+)?(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
                s_clean,
                re.IGNORECASE
            )
            for v in fix_matches:
                clean_v = v.strip().rstrip(".,;:!)'\"")
                if clean_v:
                    constraints.append(f"< {clean_v}")

    # Pattern 5: Advisory-wide single-subject fix/patch statements
    # If the text identifies pkg_name and contains explicit 'fixed in / patched in' statements
    if re.search(rf"\b(?:{alias_patterns})\b", text, re.IGNORECASE):
        advisory_fixes = re.findall(
            rf"(?:fixed in|patched in)\s+(?:(?:{alias_patterns})\s+)?(?:\bversion\s+)?(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
            text,
            re.IGNORECASE
        )
        for v in advisory_fixes:
            clean_v = v.strip().rstrip(".,;:!)'\"")
            if clean_v:
                constraints.append(f"< {clean_v}")

    # Pattern 6: Direct specifiers in sentences referencing package
    for s in sentences:
        s_clean = s.strip()
        if re.search(rf"\b(?:{alias_patterns})\b", s_clean, re.IGNORECASE):
            direct_ops = re.findall(
                rf"\b(?:{alias_patterns})\b\s*(?:version|release|package|core|component)?\s*([<>=!~]=?\s*\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]*)?)",
                s_clean,
                re.IGNORECASE
            )
            for d in direct_ops:
                clean_d = d.strip().rstrip(".,;:!)'\"")
                if any(op in clean_d for op in ["<", ">", "=", "~"]) and clean_d not in constraints:
                    constraints.append(clean_d)

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for c in constraints:
        try:
            SpecifierSet(c)
            if c not in seen:
                seen.add(c)
                deduped.append(c)
        except InvalidSpecifier:
            pass

    return deduped


def evaluate_version_applicability(
    installed_version: Optional[str],
    threat_text: str,
    pkg_name: str
) -> Tuple[str, float, str]:
    """
    Evaluates whether an installed software version is Affected, Not Affected, or Needs Review.
    
    Returns:
        (classification, confidence_score, detailed_reason)
        classification: 'AFFECTED' | 'NOT_AFFECTED' | 'NEEDS_REVIEW'
        confidence_score: Heuristic match rule confidence score (0.0 - 100.0). Note that confidence
                          scores are deterministic heuristic indicators, not measured statistical probabilities.
    """
    norm_pkg = normalize_package_name(pkg_name)

    # 1. Product Identity Verification:
    # Detect if the advisory describes a distinct derivative, adapter, or separate product.
    mismatch = check_product_identity_mismatch(norm_pkg, threat_text)
    if mismatch:
        distinct_prod, prod_desc = mismatch
        clean_v = (installed_version or "").strip().lower().lstrip("v") or "unspecified"
        return (
            "NEEDS_REVIEW",
            50.0,
            f"[NEEDS REVIEW] Advisory targets distinct component '{distinct_prod}' ({prod_desc}); mismatch with installed '{pkg_name}' ({clean_v}). Product applicability unverified - manual review required. (Heuristic score: 50.0% - not a measured probability)"
        )

    # 2. Check if package is actually mentioned in the text
    aliases = PACKAGE_ALIASES.get(norm_pkg, [norm_pkg])
    alias_patterns = "|".join([re.escape(a) for a in aliases])
    if not re.search(rf"\b(?:{alias_patterns})\b", threat_text, re.IGNORECASE):
        return "NOT_AFFECTED", 0.0, f"Component {pkg_name} not referenced in advisory."

    # 3. If installed version is missing, unpinned or 'latest', we cannot guarantee safety
    if not installed_version or installed_version.strip().lower() in ["latest", "*", "unknown", ""]:
        return "NEEDS_REVIEW", 65.0, f"[NEEDS REVIEW] Component '{pkg_name}' matched, but installed version is unpinned ('{installed_version}'). Verification required. (Heuristic score: 65.0% - not a measured probability)"

    clean_installed = installed_version.strip().lower().lstrip("v")
    
    try:
        inst_v = parse_version(clean_installed)
    except InvalidVersion:
        return "NEEDS_REVIEW", 60.0, f"[NEEDS REVIEW] Installed version '{installed_version}' for '{pkg_name}' could not be parsed as semantic version. (Heuristic score: 60.0% - not a measured probability)"

    constraints = extract_version_constraints(threat_text, pkg_name)

    if not constraints:
        # Check if the installed version is explicitly named in connection with the package as vulnerable in the advisory text
        version_in_pkg_context = False
        sentences = re.split(r"[\n\.\?!]", threat_text)
        for s in sentences:
            s_lower = s.lower()
            if re.search(rf"\b(?:{alias_patterns})\b", s_lower):
                if re.search(rf"\b(?:version|v|release)?\s*{re.escape(clean_installed)}\b", s_lower):
                    if any(w in s_lower for w in ["vulnerab", "affect", "flaw", "exploit", "issue", "bug"]):
                        version_in_pkg_context = True
                        break

        if version_in_pkg_context:
            return "AFFECTED", 95.0, f"[AFFECTED] Component '{pkg_name}' version {clean_installed} is explicitly identified as vulnerable in the threat advisory. (Heuristic score: 95.0% - not a measured probability)"

        # No version bounds given in text: Do NOT assume safe!
        return "NEEDS_REVIEW", 70.0, f"[NEEDS REVIEW] Component '{pkg_name}' ({clean_installed}) matched, but advisory does not state authoritative version range bounds. (Heuristic score: 70.0% - not a measured probability)"

    # 4. Evaluate against extracted constraints
    all_spec_str = ",".join(constraints)
    try:
        spec = SpecifierSet(all_spec_str)
        if inst_v in spec:
            return "AFFECTED", 95.0, f"[AFFECTED] Installed '{pkg_name}' {clean_installed} satisfies vulnerable constraint: {all_spec_str} (Heuristic score: 95.0% - not a measured probability)"
        else:
            return "NOT_AFFECTED", 92.0, f"[NOT AFFECTED] Installed '{pkg_name}' {clean_installed} is outside vulnerable range: {all_spec_str} (Heuristic score: 92.0% - not a measured probability)"
    except Exception:
        # Fallback to evaluating individual specifier clauses
        is_affected = False
        clauses_matched = []
        for c in constraints:
            try:
                s = SpecifierSet(c)
                if inst_v in s:
                    is_affected = True
                    clauses_matched.append(c)
            except Exception:
                pass
        
        if is_affected:
            return "AFFECTED", 90.0, f"[AFFECTED] Installed '{pkg_name}' {clean_installed} matches vulnerable clause ({', '.join(clauses_matched)}) (Heuristic score: 90.0% - not a measured probability)"
        elif constraints:
            return "NOT_AFFECTED", 90.0, f"[NOT AFFECTED] Installed '{pkg_name}' {clean_installed} is outside vulnerable constraints ({all_spec_str}) (Heuristic score: 90.0% - not a measured probability)"
        
        return "NEEDS_REVIEW", 65.0, f"[NEEDS REVIEW] Ambiguous version constraint evaluation for '{pkg_name}' ({all_spec_str}) (Heuristic score: 65.0% - not a measured probability)"
