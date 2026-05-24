"""
analytics/mitre_mapper.py
-------------------------
MITRE ATT&CK technique distribution mapping and frequency calculations.
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
    """
    counts = {}
    for e in events:
        tech = e.get("technique") or e.get("mitre_name") or "DEFENSIVE-OPS"
        # Normalize to string key
        tech_key = str(tech).upper()
        counts[tech_key] = counts.get(tech_key, 0) + 1
    return counts
