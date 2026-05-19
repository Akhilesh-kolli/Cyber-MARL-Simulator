import numpy as np
import matplotlib.pyplot as plt
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

    obs, _ = env.reset()
    done = False

    compromised_counts = []
    steps = []

    step = 0

    while not done:

        # attacker move
        action, _ = attacker.predict(obs, deterministic=True)
        obs, reward, done, truncated, _ = env.step(action)

        compromised_counts.append(np.sum(obs))
        steps.append(step)
        step += 1

        if done:
            break

        # defender move
        action, _ = defender.predict(obs, deterministic=True)
        obs, reward, done, _ = env.step(action)

        compromised_counts.append(np.sum(obs))
        steps.append(step)
        step += 1

    # ---- plot ----
    plt.figure(figsize=(8,5))
    plt.plot(steps, compromised_counts, marker="o")
    plt.xlabel("Simulation Step")
    plt.ylabel("Compromised Nodes")
    plt.title("Cyber Attack Progression Over Time")
    plt.grid()

    plt.savefig("episode_progression.png")
    plt.show()

    print("\n✅ Saved: episode_progression.png")


if __name__ == "__main__":
    main()
