"""
analytics/mitre_mapper.py
-------------------------
MITRE ATT&CK technique distribution mapping and frequency calculations.

FIX (Issue #19, #20, #21): MITRE counts are now derived from the IOC registry.
MITRE analytics and Threat Hunt use the same underlying technique set.
"""

from src.marlon.mitre_mapper import map_attack_to_mitre


def get_dominant_technique(technique_counts: dict) -> str:
    """
    Returns the most frequent technique in technique_counts, or "N/A" if none.
    """
    if not technique_counts or not any(technique_counts.values()):
        return "N/A"
    return max(technique_counts, key=technique_counts.get)


def calculate_mitre_frequencies(events: list) -> dict:
    """
    Calculates technique counts from a list of structured events.
    FIX #21: Only counts real MITRE technique IDs (T#### format), not DEFENSIVE-OPS
    or other synthetic values. This ensures MITRE chart matches IOC registry.
    """
    import re
    TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
    counts = {}
    for e in events:
        # Only process attacker events for MITRE technique counting
        actor = str(e.get("actor", "")).lower()
        if actor == "defender":
            continue  # FIX: skip defender events — MITRE is for attack techniques

        tech = e.get("technique") or e.get("mitre_id") or ""
        tech_key = str(tech).strip().upper()

        # FIX #21: Only accept valid T#### formatted technique IDs
        if not TECH_RE.match(tech_key):
            continue
        counts[tech_key] = counts.get(tech_key, 0) + 1
    return counts


def get_mitre_frequencies_from_ioc_registry(ioc_df) -> dict:
    """
    FIX #21: Derive MITRE technique counts from the IOC registry DataFrame
    (the authoritative source) rather than re-counting from raw events.
    This guarantees MITRE Analytics, Threat Hunt, and IOC Registry are in sync.
    """
    import re
    TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
    counts = {}
    if ioc_df is None or ioc_df.empty:
        return counts

    try:
        # Only use base technique rows (not "Technique on Asset" / "Technique on Port")
        tech_rows = ioc_df[
            (ioc_df["Type"] == "Adversary Technique") &
            ioc_df["IOC"].str.match(r"T\d{4}", na=False)
        ]
        for _, row in tech_rows.iterrows():
            tech = str(row.get("IOC", "")).strip().upper()
            if TECH_RE.match(tech):
                counts[tech] = int(row.get("Count", 1))
    except Exception:
        pass

    return counts
