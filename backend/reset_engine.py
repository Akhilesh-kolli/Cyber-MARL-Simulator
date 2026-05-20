"""
backend/reset_engine.py
----------------------
Thoroughly flushes all simulation graphs, telemetry variables, cached lists,
metrics, and narratives. Ensures zero stale leakages survive reset.
"""

from backend.state_manager import get_initial_state

def reset_entire_simulation(st):
    """
    Completely flushes all states in session state.
    """
    # 1. Reset simulation state object to default initial state
    st.session_state.simulation_state = get_initial_state()
    
    # 2. Reset aliases and helper keys
    st.session_state.simulation_data = st.session_state.simulation_state
    st.session_state.simulation_started = False
    st.session_state.simulation_complete = False
    
    # 3. Reset network visual cache
    st.session_state.network_graph_fig = None
    st.session_state.alert_fatigue_score = 0
    
    # 4. If we have any custom threat hunt filters or timelines in streamlit, reset them
    if "threat_filter" in st.session_state:
        st.session_state.threat_filter = "ALL"
    if "soc_workspace" in st.session_state:
        st.session_state.soc_workspace = "Overview"
