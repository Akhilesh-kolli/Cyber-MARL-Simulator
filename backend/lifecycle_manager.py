"""
backend/lifecycle_manager.py
----------------------------
Enforces the strict, single-occupancy lifecycle state machine:
INITIALIZED -> READY -> RUNNING -> COMPLETED -> RESET -> READY.
"""

VALID_LIFECYCLE_STATES = {"initialized", "ready", "running", "completed", "reset"}

def get_current_lifecycle(state: dict) -> str:
    """Returns the current simulation lifecycle status."""
    return state.get("simulation", {}).get("status", "initialized")

def transition_to(state: dict, next_status: str) -> bool:
    """
    Attempts to transition the simulation lifecycle to the next_status.
    Ensures transitions conform to:
    INITIALIZED -> READY -> RUNNING -> COMPLETED -> RESET -> READY
    """
    current_status = get_current_lifecycle(state)
    
    if next_status not in VALID_LIFECYCLE_STATES:
        return False
        
    allowed = False
    
    if current_status == "initialized":
        # Initialized can move to ready or reset
        allowed = (next_status in ("ready", "reset"))
    elif current_status == "ready":
        # Ready can move to running or reset
        allowed = (next_status in ("running", "reset"))
    elif current_status == "running":
        # Running can move to completed or reset
        allowed = (next_status in ("completed", "reset"))
    elif current_status == "completed":
        # Completed must transition through reset
        allowed = (next_status in ("reset", "ready"))
    elif current_status == "reset":
        # Reset must transition to ready
        allowed = (next_status == "ready")
        
    if allowed:
        state["simulation"]["status"] = next_status
        # Sync simple flags
        state["simulation"]["running"] = (next_status == "running")
        state["simulation"]["completed"] = (next_status == "completed")
        return True
        
    return False
