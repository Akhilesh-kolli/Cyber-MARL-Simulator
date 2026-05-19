from stable_baselines3 import PPO
from pathlib import Path
import numpy as np
import sys

sys.path.append(str(Path(__file__).resolve().parent))

from marlon.graph_env import GraphCyberEnv


def main():

    print("\n=== ATTACKER vs DEFENDER SIMULATION ===\n")

    env = GraphCyberEnv()

    # ---- load models from ROOT models folder ----
    model_dir = Path(__file__).resolve().parents[1] / "models"

    attacker_path = model_dir / "ppo_attacker_graph"
    defender_path = model_dir / "ppo_defender_graph"

    print("Loading attacker:", attacker_path)
    print("Loading defender:", defender_path)

    attacker = PPO.load(str(attacker_path), env=env)
    defender = PPO.load(str(defender_path), env=env)

    state, _ = env.reset()
    done = False
    step = 0

    while not done:

        # ---------- ATTACKER ----------
        a_action, _ = attacker.predict(state, deterministic=False)
        state, reward, done, truncated, _ = env.step(int(a_action))

        print(f"[Step {step}] Attacker -> Node {a_action} | Reward {reward:.2f} | State {state}")

        if done:
            break

        # ---------- DEFENDER ----------
        d_action, _ = defender.predict(state, deterministic=False)
        state, reward, done, truncated, _ = env.step(int(d_action))

        print(f"[Step {step}] Defender -> Action {d_action} | Reward {reward:.2f} | State {state}")

        step += 1


if __name__ == "__main__":
    main()
