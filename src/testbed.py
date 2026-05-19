from stable_baselines3 import PPO
from marlon.dummy_env import DummyCyberEnv
from marlon.graph_utils import plot_network_state
import numpy as np
import matplotlib.pyplot as plt
import os


def main():
    # ======================
    # ENVIRONMENT SETUP
    # ======================
    env = DummyCyberEnv(node_count=5, max_steps=20)

    # ======================
    # TRAINING PHASE
    # ======================
    model = PPO(
        policy="MlpPolicy",
        env=env,
        verbose=1
    )

    print("Training attacker using PPO...")
    model.learn(total_timesteps=5000)
    print("Training complete.\n")

    # Save trained model
    os.makedirs("models", exist_ok=True)
    model.save("models/ppo_attacker_dummy")

    # ======================
    # EVALUATION PHASE
    # ======================
    episode_rewards = []

    for episode in range(20):
        obs, _ = env.reset()
        done = False
        total_reward = 0.0

        while not done:
            action, _ = model.predict(obs)
            obs, reward, done, truncated, _ = env.step(action)
            total_reward += reward

        episode_rewards.append(total_reward)
        print(f"Episode {episode} | Total Reward: {total_reward}")

    # ======================
    # PLOT REWARDS
    # ======================
    os.makedirs("results", exist_ok=True)

    episodes = list(range(len(episode_rewards)))
    plt.figure()
    plt.plot(episodes, episode_rewards, marker='o')
    plt.xlabel("Episode")
    plt.ylabel("Total Reward")
    plt.title("Attacker Learning Performance")
    plt.grid(True)
    plt.savefig("results/attacker_learning.png")
    plt.close()

    # ======================
    # METRICS SUMMARY
    # ======================
    avg = np.mean(episode_rewards)
    mx = np.max(episode_rewards)
    mn = np.min(episode_rewards)

    print("\nEvaluation Summary")
    print("------------------")
    print("Average reward:", avg)
    print("Max reward:", mx)
    print("Min reward:", mn)

    with open("results/metrics.txt", "w") as f:
        f.write(f"Average reward: {avg}\n")
        f.write(f"Max reward: {mx}\n")
        f.write(f"Min reward: {mn}\n")

    # ======================
    # GRAPH VISUALIZATION
    # ======================
    print("\nFinal Network State Visualization")
    plot_network_state(env.state)


if __name__ == "__main__":
    main()
