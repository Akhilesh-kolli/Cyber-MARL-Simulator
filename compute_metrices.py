import numpy as np
from pathlib import Path
import sys

# ---- allow imports from src/ ----
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from stable_baselines3 import PPO
from marlon.graph_env import GraphCyberEnv


# --------------------------------------------------
# Run one attacker vs defender episode
# --------------------------------------------------
def run_episode(env, attacker, defender):

    obs, _ = env.reset()
    done = False

    total_reward = 0
    steps = 0

    while not done:

        # ---- attacker step ----
        action, _ = attacker.predict(obs, deterministic=True)
        obs, reward, done, truncated, _ = env.step(action)

        total_reward += reward
        steps += 1

        if done:
            break

        # ---- defender step ----
        action, _ = defender.predict(obs, deterministic=True)
        obs, reward, done, _ = env.step(action)

        total_reward += reward
        steps += 1

    compromised_nodes = int(np.sum(obs))
    return total_reward, steps, compromised_nodes


# --------------------------------------------------
# Main evaluation loop
# --------------------------------------------------
def main():

    root = Path(__file__).resolve().parent
    model_dir = root / "models"

    attacker_path = model_dir / "ppo_attacker_graph"
    defender_path = model_dir / "ppo_defender_graph"

    print("\nLoading models...")
    print("Attacker:", attacker_path)
    print("Defender:", defender_path)

    attacker = PPO.load(str(attacker_path))
    defender = PPO.load(str(defender_path))

    env = GraphCyberEnv()

    episodes = 100

    rewards = []
    lengths = []
    compromised = []

    for _ in range(episodes):
        r, l, c = run_episode(env, attacker, defender)
        rewards.append(r)
        lengths.append(l)
        compromised.append(c)

    rewards = np.array(rewards)
    lengths = np.array(lengths)
    compromised = np.array(compromised)

    print("\n=== EVALUATION METRICS ===")
    print(f"Episodes: {episodes}")
    print(f"Avg Reward: {rewards.mean():.2f}")
    print(f"Avg Episode Length: {lengths.mean():.2f}")
    print(f"Avg Compromised Nodes: {compromised.mean():.2f}")

    attacker_wins = np.mean(compromised > env.node_count / 2)
    defender_wins = 1 - attacker_wins

    print(f"\nAttacker Win Rate: {attacker_wins*100:.1f}%")
    print(f"Defender Win Rate: {defender_wins*100:.1f}%")
    print("==========================\n")


if __name__ == "__main__":
    main()
