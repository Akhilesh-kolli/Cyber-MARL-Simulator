"""
backend/reset_engine.py
----------------------
Thoroughly flushes simulation graphs, telemetry variables, cached lists,
metrics, and narratives so stale UI state cannot survive reset.
"""

from backend.state_manager import get_initial_state


DEFAULT_SIDEBAR_SUMMARY = {
    "step": 0,
    "risk": 0.0,
    "reward": 0.0,
    "threat": "LOW",
}


def reset_entire_simulation(st, rerun=True):
    """
    Completely reset canonical simulation state and all derived UI artifacts.
    """
    fresh_state = get_initial_state()

    keys_to_clear = [
        "topology_positions",
        "topology_fig",
        "topology_fig_json",
        "topology_nodes_snapshot",
        "network_graph_fig",
        "network_graph_bytes",
        "node_labels",
        "attack_df",
        "timeline_df",
        "timeline_events",
        "live_feed",
        "event_feed",
        "feed_logs",
        "soc_trend_fig",
        "soc_trend_fig_json",
        "trend_data",
        "soc_metrics",
        "sidebar_summary",
        "mitre_df",
        "mitre_data",
        "ioc_df",
        "ioc_data",
        "simulation_started",
        "simulation_complete",
        "current_step",
        "sim_obs",
        "step_history",
        "alert_fatigue_score",
        "compromised_nodes",
        "attack_history",
        "risk_score",
        "risk",
        "total_reward",
        "reward",
        "threat_level",
        "threat",
        "topology_instance_id",
        "overview_topology",
        "overview_soc_trend",
    ]

    for key in keys_to_clear:
        if key in st.session_state:
            try:
                del st.session_state[key]
            except Exception:
                st.session_state[key] = None

    for key in list(st.session_state.keys()):
        if key.startswith(("tmp_", "_tmp", "widget_")):
            try:
                del st.session_state[key]
            except Exception:
                st.session_state[key] = None

    st.session_state.simulation_state = fresh_state
    st.session_state.simulation_data = fresh_state
    st.session_state.simulation_started = False
    st.session_state.simulation_complete = False
    st.session_state.current_step = 0
    st.session_state.sim_obs = None
    st.session_state.sidebar_summary = DEFAULT_SIDEBAR_SUMMARY.copy()
    st.session_state.soc_metrics = fresh_state["metrics"].copy()
    st.session_state.live_feed = []
    st.session_state.event_feed = []
    st.session_state.feed_logs = []
    st.session_state.attack_df = None
    st.session_state.timeline_df = None
    st.session_state.timeline_events = []
    st.session_state.mitre_df = None
    st.session_state.mitre_data = None
    st.session_state.ioc_df = None
    st.session_state.ioc_data = None
    st.session_state.trend_data = None
    st.session_state.attack_history = []
    st.session_state.compromised_nodes = []
    st.session_state.topology_positions = None
    st.session_state.topology_fig = None
    st.session_state.topology_fig_json = None
    st.session_state.topology_nodes_snapshot = None
    st.session_state.network_graph_fig = None
    st.session_state.alert_fatigue_score = 0

    if rerun:
        try:
            if hasattr(st, "rerun"):
                st.rerun()
            else:
                st.experimental_rerun()
        except Exception:
            try:
                st.experimental_rerun()
            except Exception:
                pass
