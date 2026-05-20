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
    counts = {
        "T1190": 0,
        "T1021": 0,
        "T1046": 0,
        "T1595": 0
    }
    for e in events:
        tech = e.get("technique")
        if tech in counts:
            counts[tech] += 1
    return counts
