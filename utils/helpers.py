"""
utils/helpers.py
----------------
General helper functions, safe type conversion, and dict merge guards.
"""

def safe_int(val, default=0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def safe_float(val, default=0.0) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def safe_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]
