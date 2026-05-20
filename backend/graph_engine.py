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
        # Fallback to healthy if node_id not found
        node_info = nodes_state.get(node_id, {})
        status = node_info.get("status", "healthy")
        if status == "compromised":
            return "#ef4444"
        elif status == "contained":
            return "#eab308"
        else:
            return "#22c55e"

    colors = [get_color(i) for i in range(env_node_count)]

    # 4. Draw Figure
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor("#071028")
    ax.set_facecolor("#071028")

    nx.draw_networkx_nodes(
        G, pos, node_color=colors,
        node_size=2600, edgecolors="#0ea5e9",
        linewidths=2, ax=ax
    )

    nx.draw_networkx_edges(
        G, pos, edge_color="#334155",
        width=2, ax=ax
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
