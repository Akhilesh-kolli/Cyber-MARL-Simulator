import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
import imageio
from pathlib import Path
import sys
import os

# allow imports from src/
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from stable_baselines3 import PPO
from marlon.graph_env import GraphCyberEnv


def draw_state(G, pos, state, step, filename):
    colors = ["red" if state[i] == 1 else "lightgreen" for i in range(len(state))]

    plt.figure(figsize=(6,6))
    nx.draw(G, pos,
            with_labels=True,
            node_color=colors,
            node_size=800,
            font_weight="bold")

    plt.title(f"Step {step}")
    plt.savefig(filename)
    plt.close()


def main():

    model_dir = Path("models")

    attacker = PPO.load(str(model_dir / "ppo_attacker_graph"))
    defender = PPO.load(str(model_dir / "ppo_defender_graph"))

    env = GraphCyberEnv()

    # ---- build graph ----
    G = nx.Graph()
    for i in range(env.node_count):
        G.add_node(i)

    for i in range(env.node_count):
        for j in range(i+1, env.node_count):
            if env.graph[i, j] == 1:
                G.add_edge(i, j)

    pos = nx.spring_layout(G, seed=42)

    # ---- simulate episode ----
    obs, _ = env.reset()
    done = False

    frames = []
    temp_dir = Path("gif_frames")
    temp_dir.mkdir(exist_ok=True)

    step = 0

    while not done:

        # save frame before action
        filename = temp_dir / f"frame_{step}.png"
        draw_state(G, pos, obs, step, filename)
        frames.append(filename)
        step += 1

        # attacker
        action, _ = attacker.predict(obs, deterministic=True)
        obs, _, done, truncated, _ = env.step(action)
        if done:
            break

        # defender
        action, _ = defender.predict(obs, deterministic=True)
        obs, _, done, _ = env.step(action)

    # ---- final frame ----
    filename = temp_dir / f"frame_{step}.png"
    draw_state(G, pos, obs, step, filename)
    frames.append(filename)

    # ---- build GIF ----
    images = [imageio.imread(f) for f in frames]
    imageio.mimsave("attack_progress.gif", images, duration=2.0)

    print("\n Saved: attack_progress.gif")

    # optional cleanup
    for f in frames:
        os.remove(f)
    temp_dir.rmdir()


if __name__ == "__main__":
    main()
