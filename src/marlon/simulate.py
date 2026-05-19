from stable_baselines3 import PPO
from marlon.dummy_env import DummyCyberEnv


class SimulationCache:
    def __init__(self):
        self.value = None


def simulate(timesteps, attacker_option, defender_option, attacker_file=None, defender_file=None):
    env = DummyCyberEnv(node_count=5, max_steps=20)

    attacker = PPO.load("models/ppo_attacker_dummy", env=env)
    defender = PPO.load("models/ppo_defender_dummy", env=env)

    logs = []
    state, _ = env.reset()
    done = False
    step = 0

    while not done:
        # Attacker turn
        a_action, _ = attacker.predict(state, deterministic=True)
        state, a_reward, done, truncated, _ = env.step(a_action)

        logs.append({
            "step": step,
            "agent": "attacker",
            "action": int(a_action),
            "reward": float(a_reward),
            "state": state.tolist()
        })

        if done:
            break

        # Defender turn
        d_action = env.node_count
        state, d_reward, done, truncated, _ = env.step(d_action)

        logs.append({
            "step": step,
            "agent": "defender",
            "action": "recover",
            "reward": float(d_reward),
            "state": state.tolist()
        })

        step += 1

    return logs
