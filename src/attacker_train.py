from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from pathlib import Path
import sys

# allow imports from src/
sys.path.append(str(Path(__file__).resolve().parent))

from marlon.attacker_env import AttackerEnv


def main():

    print("\n=== TRAINING ATTACKER ===\n")

    # ---- create logs folder ----
    root_dir = Path(__file__).resolve().parents[1]
    log_dir = root_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    # ---- environment with logging enabled ----
    env = AttackerEnv()
    env = Monitor(env, str(log_dir / "attacker_monitor.csv"))

    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        learning_rate=0.0003,
        n_steps=512,
        batch_size=64,
        gamma=0.99,
    )

    model.learn(total_timesteps=60000)

    # ---- save model ----
    model_dir = root_dir / "models"
    model_dir.mkdir(exist_ok=True)

    save_path = model_dir / "ppo_attacker_graph"
    model.save(str(save_path))

    print("\n Attacker saved to:", save_path)
    print("Logs saved to:", log_dir / "attacker_monitor.csv")


if __name__ == "__main__":
    main()
