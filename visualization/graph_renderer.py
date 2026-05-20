"""
visualization/graph_renderer.py
-------------------------------
De-couples NetworkX Matplotlib drawing and buffer generation.
"""

import streamlit as st
from backend.graph_engine import generate_network_graph

def render_network_graph(nodes_state: dict, env_graph, env_node_types, env_node_count) -> bytes:
    """
    Wraps the backend graph engine to draw the network graph and return PNG bytes.
    """
    return generate_network_graph(nodes_state, env_graph, env_node_types, env_node_count)

def display_network_graph(graph_bytes: bytes, placeholder=None):
    """
    Displays the generated network graph bytes in a custom CSS styled container in Streamlit.
    """
    if not graph_bytes:
        return
        
    container = placeholder if placeholder else st
    
    with container.container():
        st.markdown('<div class="graph-card">', unsafe_allow_html=True)
        st.image(graph_bytes, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
