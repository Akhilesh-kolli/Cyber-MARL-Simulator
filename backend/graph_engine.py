"""
backend/graph_engine.py
----------------------
Synchronizes network graph rendering strictly with simulation_state["nodes"] status.
Zero local widgets or cached calculations.
"""

import networkx as nx
import matplotlib.pyplot as plt
import io

def generate_network_graph(nodes_state: dict, env_graph, env_node_types, env_node_count) -> bytes:
    """
    Creates and draws the NetworkX graph in a dark-theme, returning a byte buffer of the PNG image.
    Uses states from nodes_state to determine node colors.
    """
    G = nx.Graph()
    for i in range(env_node_count):
        G.add_node(i)

    for i in range(env_node_count):
        for j in range(i + 1, env_node_count):
            if env_graph[i, j] == 1:
                G.add_edge(i, j)

    # 1. Labels
    labels = {}
    for i in range(env_node_count):
        node_name = env_node_types[i]
        if node_name == "DomainController":
            node_name = "Domain\nController"
        labels[i] = f"{i}\n{node_name}"

    # 2. Layout
    pos = nx.spring_layout(G, seed=42, k=1.3)

    # 3. Colors strictly derived from canonical states
    def get_color(node_id):
        node_info = nodes_state.get(node_id, {})
        status = node_info.get("status", "healthy")
        if status == "compromised":
            return "#ef4444"
        elif status == "contained":
            return "#facc15"
        elif node_info.get("defender_action") != "None":
            return "#38bdf8"
        return "#22c55e"

    def get_size(node_id):
        node_info = nodes_state.get(node_id, {})
        status = node_info.get("status", "healthy")
        base = 2200
        if status == "compromised":
            return base + 900
        if status == "contained":
            return base + 450
        return base

    colors = [get_color(i) for i in range(env_node_count)]
    sizes = [get_size(i) for i in range(env_node_count)]
    edge_colors = []
    edge_widths = []
    for u, v in G.edges():
        if nodes_state.get(u, {}).get("status") == "compromised" or nodes_state.get(v, {}).get("status") == "compromised":
            edge_colors.append("#f97316")
            edge_widths.append(3.2)
        elif nodes_state.get(u, {}).get("status") == "contained" or nodes_state.get(v, {}).get("status") == "contained":
            edge_colors.append("#fde047")
            edge_widths.append(2.5)
        else:
            edge_colors.append("#64748b")
            edge_widths.append(1.8)

    # 4. Draw Figure
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor("#071028")
    ax.set_facecolor("#071028")

    nx.draw_networkx_nodes(
        G, pos, node_color=colors,
        node_size=sizes, edgecolors="#0ea5e9",
        linewidths=2.5, ax=ax
    )

    nx.draw_networkx_edges(
        G, pos, edge_color=edge_colors,
        width=edge_widths, ax=ax, alpha=0.9
    )

    nx.draw_networkx_labels(
        G, pos, labels=labels,
        font_size=10,
        font_weight="bold",
        font_color="white",
        ax=ax
    )

    ax.axis("off")
    plt.tight_layout()

    # Save to buffer
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), edgecolor='none')
    buf.seek(0)
    img_data = buf.getvalue()
    
    plt.close(fig)  # Prevent leaks
    return img_data
