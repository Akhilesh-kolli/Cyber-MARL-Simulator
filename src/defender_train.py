from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parent))
from marlon.graph_env import GraphCyberEnv

def main():
    root_dir = Path(__file__).resolve().parents[1]
    log_dir = root_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    env = GraphCyberEnv()
    env = Monitor(env, str(log_dir / "defender_monitor.csv"))

    model = PPO(
        "MlpPolicy", env,
        verbose=1,
        learning_rate=0.0003,
        n_steps=512,
        batch_size=64,
        gamma=0.99,
    )
    model.learn(total_timesteps=100000)

    model_dir = root_dir / "models"
    model_dir.mkdir(exist_ok=True)
    model.save(str(model_dir / "ppo_defender_graph"))
    print("Defender saved to:", model_dir / "ppo_defender_graph")

if __name__ == "__main__":
    main()