from stable_baselines3 import PPO
from pathlib import Path
import sys

# --------------------------------------------------
# IMPORT ENV
# --------------------------------------------------
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from marlon.graph_env import GraphCyberEnv

# --------------------------------------------------
# CREATE ENVIRONMENT
# --------------------------------------------------
env = GraphCyberEnv()

# --------------------------------------------------
# ATTACKER MODEL
# --------------------------------------------------
print("\nTraining Attacker Agent...\n")

attacker_model = PPO(
    "MlpPolicy",
    env,
    verbose=1,
    tensorboard_log="./logs/attacker/"
)

attacker_model.learn(
    total_timesteps=30000
)

attacker_model.save(
    "models/ppo_attacker_graph"
)

print("\nAttacker Training Complete\n")

# --------------------------------------------------
# DEFENDER MODEL
# --------------------------------------------------
print("\nTraining Defender Agent...\n")

defender_model = PPO(
    "MlpPolicy",
    env,
    verbose=1,
    tensorboard_log="./logs/defender/"
)

defender_model.learn(
    total_timesteps=30000
)

defender_model.save(
    "models/ppo_defender_graph"
)

print("\nDefender Training Complete\n")
print("Models saved successfully.")
