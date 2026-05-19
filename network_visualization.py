import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from pathlib import Path
import sys

# allow imports from src/
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from stable_baselines3 import PPO
from marlon.graph_env import GraphCyberEnv


def main():

    model_dir = Path("models")

    attacker = PPO.load(str(model_dir / "ppo_attacker_graph"))
    defender = PPO.load(str(model_dir / "ppo_defender_graph"))

    env = GraphCyberEnv()

    # build network graph
    G = nx.Graph()
    for i in range(env.node_count):
        G.add_node(i)

    for i in range(env.node_count):
        for j in range(i+1, env.node_count):
            if env.graph[i, j] == 1:
                G.add_edge(i, j)

    # run one episode
    obs, _ = env.reset()
    done = False

    while not done:

        action, _ = attacker.predict(obs, deterministic=True)
        obs, _, done, truncated, _ = env.step(action)

        if done:
            break

        action, _ = defender.predict(obs, deterministic=True)
        obs, _, done, _ = env.step(action)

    # final compromised state
    compromised = obs

    # color nodes
    colors = ["red" if compromised[i] == 1 else "lightgreen"
              for i in range(env.node_count)]

    # draw graph
    plt.figure(figsize=(6,6))
    pos = nx.spring_layout(G, seed=42)

    nx.draw(G, pos,
            with_labels=True,
            node_color=colors,
            node_size=800,
            font_weight="bold")

    plt.title("Final Network Compromise State")
    plt.savefig("network_state.png")
    plt.show()

    print("\n Saved: network_state.png")


if __name__ == "__main__":
    main()
