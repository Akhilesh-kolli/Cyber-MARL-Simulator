"""
src/marlon/marl_env.py
----------------------
Shared Multi-Agent RL environment for adversarial co-training.

Both agents observe the same 6-feature-per-node network state.
On each episode step the attacker acts FIRST, then the defender responds.

This module provides two thin wrappers around the shared state so each
agent gets a standard Gym-compatible interface:
  - MARLAttackerView  (wraps shared env, exposes attacker actions)
  - MARLDefenderView  (wraps shared env, exposes defender actions)

Usage
-----
    shared = MARLSharedEnv()
    att_env = MARLAttackerView(shared)
    def_env = MARLDefenderView(shared)

    attacker_model = PPO("MlpPolicy", att_env, ...)
    defender_model = PPO("MlpPolicy", def_env, ...)

    # Self-play training loop
    marl_train(attacker_model, defender_model, shared, total_rounds=200)
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces

from marlon.defender_env import (
    DefenderEnv,
    DEFENDER_ACTIONS,
    NUM_ACTION_TYPES,
    OBS_FEATURES,
    MAX_BLOCKED_EDGES,
)

NODE_TYPES = {
    0: "Workstation", 1: "Firewall",    2: "Database",
    3: "Server",      4: "DomainCtrl",  5: "Workstation",
}


# ─────────────────────────────────────────────────────────────────────────────
class MARLSharedEnv:
    """
    Non-Gym container holding the true shared simulation state.
    Both MARLAttackerView and MARLDefenderView hold a reference to this.
    """

    def __init__(self, node_count: int = 6, max_steps: int = 50):
        self.node_count  = node_count
        self.max_steps   = max_steps
        self.current_step = 0

        self.graph = np.array([
            [0, 1, 1, 0, 0, 0],
            [1, 0, 1, 1, 0, 0],
            [1, 1, 0, 1, 1, 0],
            [0, 1, 1, 0, 1, 1],
            [0, 0, 1, 1, 0, 1],
            [0, 0, 0, 1, 1, 0],
        ], dtype=np.int32)

        self.critical_nodes = {0, 1, 2}
        self.cvss_scores    = np.array(
            [8.5, 9.5, 9.2, 7.8, 9.8, 4.5], dtype=np.float32
        )

        self.reset()

    # ── State ─────────────────────────────────────────────────────────────
    def reset(self):
        self.compromised    = np.zeros(self.node_count, dtype=np.int32)
        self.isolated       = np.zeros(self.node_count, dtype=np.int32)
        self.blocked        = np.zeros(self.node_count, dtype=np.int32)
        self.priority       = np.zeros(self.node_count, dtype=np.int32)
        self.blocked_count  = 0
        self.current_step   = 0

        entry = int(np.random.randint(self.node_count))
        self.compromised[entry] = 1

        self.last_attacker_reward = 0.0
        self.last_defender_reward = 0.0
        self.done                 = False

        return self._build_obs()

    def _build_obs(self) -> np.ndarray:
        obs = np.zeros(self.node_count * OBS_FEATURES, dtype=np.float32)
        for i in range(self.node_count):
            base = i * OBS_FEATURES
            obs[base + 0] = float(self.compromised[i])
            obs[base + 1] = float(self.isolated[i])
            obs[base + 2] = float(self.blocked[i])
            obs[base + 3] = float(self.priority[i])
            obs[base + 4] = self.cvss_scores[i] / 10.0
            obs[base + 5] = float(i in self.critical_nodes)
        return obs

    def _active_graph(self) -> np.ndarray:
        g = self.graph.copy()
        for i in range(self.node_count):
            if self.blocked[i]:
                g[i, :] = 0
                g[:, i] = 0
        return g

    # ── Attacker step ─────────────────────────────────────────────────────
    def attacker_step(self, action: int) -> float:
        """
        Process attacker action, return reward for the attacker.
        Does NOT advance current_step (defender does that).
        """
        reward = 0.0
        node   = int(action) % self.node_count

        if self.isolated[node] or self.blocked[node]:
            return -1.0

        if self.compromised[node] == 1:
            return -0.3

        g    = self._active_graph()
        comp = np.where(self.compromised == 1)[0]
        reachable = any(g[c, node] == 1 for c in comp)

        if not reachable:
            return -0.5

        p = float(np.clip(0.2 + self.cvss_scores[node] / 20.0, 0.05, 0.95))
        if np.random.rand() < p:
            self.compromised[node] = 1
            reward += 2.0
            if node in self.critical_nodes:
                reward += 3.0
        else:
            reward -= 0.5

        self.last_attacker_reward = reward
        return reward

    # ── Defender step ─────────────────────────────────────────────────────
    def defender_step(self, action: int) -> float:
        """
        Process defender action, return reward for the defender.
        Advances current_step and computes done.
        """
        action_type = int(action) // self.node_count
        node        = int(action) %  self.node_count

        reward = 0.0

        if action_type == DEFENDER_ACTIONS["ISOLATE"]:
            reward = self._isolate(node)
        elif action_type == DEFENDER_ACTIONS["RECOVER"]:
            reward = self._recover(node)
        elif action_type == DEFENDER_ACTIONS["BLOCK"]:
            reward = self._block(node)
        elif action_type == DEFENDER_ACTIONS["PRIORITIZE"]:
            reward = self._prioritize(node)

        # Shaping
        clean_ratio = 1.0 - (self.compromised.sum() / self.node_count)
        reward += clean_ratio * 0.5
        if self.compromised.sum() == 0:
            reward += 5.0

        self.current_step += 1
        all_comp = bool(self.compromised.sum() == self.node_count)
        self.done = all_comp or (self.current_step >= self.max_steps)

        self.last_defender_reward = reward
        return reward

    # ── Defender sub-actions ─────────────────────────────────────────────
    def _isolate(self, node: int) -> float:
        if self.compromised[node]:
            self.compromised[node] = 0
            self.isolated[node]    = 1
            return 2.0 + (1.0 if node in self.critical_nodes else 0.0)
        return -1.5 if self.isolated[node] else -1.0   # heavy penalty for spam

    def _recover(self, node: int) -> float:
        if self.isolated[node]:
            self.isolated[node] = 0
            return 2.5 + (1.5 if node in self.critical_nodes else 0.0)
        if self.compromised[node]:
            if np.random.rand() < 0.4:
                self.compromised[node] = 0
                return 3.0
            return -0.3
        return -0.5

    def _block(self, node: int) -> float:
        if self.blocked[node]:
            return -1.0                             # heavy penalty for re-block
        if self.blocked_count >= MAX_BLOCKED_EDGES:
            return -0.5
        self.blocked[node]  = 1
        self.blocked_count += 1
        if self.compromised[node]:
            return 3.0
        comp_nbrs = sum(
            1 for nbr in range(self.node_count)
            if self.graph[node, nbr] == 1 and self.compromised[nbr] == 1
        )
        return 1.5 + comp_nbrs * 1.0

    def _prioritize(self, node: int) -> float:
        if self.priority[node]:
            return -1.0                             # heavy penalty for re-flag
        self.priority[node] = 1
        if self.compromised[node]:
            return 2.5 + (1.5 if node in self.critical_nodes else 0.0)
        return 0.5

    def obs(self) -> np.ndarray:
        return self._build_obs()


# ─────────────────────────────────────────────────────────────────────────────
# Gym-compatible views
# ─────────────────────────────────────────────────────────────────────────────

class MARLAttackerView(gym.Env):
    """Gym wrapper giving the attacker agent a standard interface."""

    def __init__(self, shared: MARLSharedEnv):
        super().__init__()
        self.shared = shared
        n = shared.node_count
        self.action_space = spaces.Discrete(n + 1)   # N attack + 1 wait
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(n * OBS_FEATURES,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        obs = self.shared.reset()
        return obs, {}

    def step(self, action: int):
        r      = self.shared.attacker_step(int(action))
        obs    = self.shared.obs()
        done   = self.shared.done
        trunc  = False
        return obs, r, done, trunc, {}


class MARLDefenderView(gym.Env):
    """Gym wrapper giving the defender agent a standard interface."""

    def __init__(self, shared: MARLSharedEnv):
        super().__init__()
        self.shared = shared
        n = shared.node_count
        self.action_space = spaces.Discrete(NUM_ACTION_TYPES * n)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(n * OBS_FEATURES,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        obs = self.shared.reset()
        return obs, {}

    def step(self, action: int):
        r     = self.shared.defender_step(int(action))
        obs   = self.shared.obs()
        done  = self.shared.done
        trunc = (self.shared.current_step >= self.shared.max_steps
                 and not done)
        return obs, r, done, trunc, {}