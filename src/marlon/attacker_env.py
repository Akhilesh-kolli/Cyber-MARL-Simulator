"""
src/marlon/attacker_env.py
--------------------------
Attacker-side Gym environment for PPO training, upgraded to work
against the RL Defender instead of a rule-based counterpart.

The attacker observes the same 6-feature-per-node observation as the
defender (shared network state) and picks a target node to attack.

Actions: 0 .. N-1  → attempt to compromise node i
         N          → WAIT / re-scan (no-op, small penalty)
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces

OBS_FEATURES = 6   # features per node (must match defender_env.py)


class AttackerEnv(gym.Env):
    """
    Attacker-side Gym environment.

    For solo attacker training the defender is a lightweight heuristic
    (prioritises highest CVSS compromised node).  For adversarial co-training
    a shared MARLEnv is used instead.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, node_count: int = 6, max_steps: int = 50):
        super().__init__()

        self.node_count = node_count
        self.max_steps  = max_steps

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

        # node i  = attack node i;  node_count = wait
        self.action_space = spaces.Discrete(node_count + 1)

        obs_dim = node_count * OBS_FEATURES
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(obs_dim,), dtype=np.float32
        )

        self.reset()

    # ──────────────────────────────────────────────────────────────────────
    def _build_obs(self) -> np.ndarray:
        obs = np.zeros(self.node_count * OBS_FEATURES, dtype=np.float32)
        for i in range(self.node_count):
            base = i * OBS_FEATURES
            obs[base + 0] = float(self.compromised[i])
            obs[base + 1] = float(self.isolated[i])
            obs[base + 2] = float(self.blocked[i])
            obs[base + 3] = 0.0                            # priority not visible to attacker
            obs[base + 4] = self.cvss_scores[i] / 10.0
            obs[base + 5] = float(i in self.critical_nodes)
        return obs

    def _heuristic_defender_step(self):
        """
        Lightweight rule-based defender used during solo attacker training.
        Targets the highest CVSS compromised node with 35 % success probability.
        """
        comp = np.where(self.compromised == 1)[0]
        if len(comp) == 0:
            return
        target = int(max(comp, key=lambda x: self.cvss_scores[x]))
        if np.random.rand() < 0.35:
            self.compromised[target] = 0
            self.isolated[target]    = 1

    # ──────────────────────────────────────────────────────────────────────
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)

        self.compromised = np.zeros(self.node_count, dtype=np.int32)
        self.isolated    = np.zeros(self.node_count, dtype=np.int32)
        self.blocked     = np.zeros(self.node_count, dtype=np.int32)

        entry = int(np.random.randint(self.node_count))
        self.compromised[entry] = 1

        self.current_step = 0
        return self._build_obs(), {}

    def step(self, action: int):
        action = int(action)
        self.current_step += 1
        reward = 0.0
        info   = {}

        # ── Attacker action ──────────────────────────────────────────────
        if action < self.node_count:
            node = action

            # Cannot attack isolated/blocked nodes
            if self.isolated[node] or self.blocked[node]:
                reward -= 1.0
                info["attack"] = f"Node {node} unreachable (isolated/blocked)"
            elif self.compromised[node] == 1:
                reward -= 0.3   # already owned
                info["attack"] = f"Node {node} already compromised"
            else:
                # Reachability via adjacency
                comp = np.where(self.compromised == 1)[0]
                reachable = any(
                    self.graph[c, node] == 1 for c in comp
                )
                if reachable:
                    p = float(np.clip(
                        0.2 + self.cvss_scores[node] / 20.0, 0.05, 0.95
                    ))
                    if np.random.rand() < p:
                        self.compromised[node] = 1
                        reward += 2.0
                        if node in self.critical_nodes:
                            reward += 3.0   # critical node bonus
                        info["attack"] = f"Node {node} COMPROMISED"
                    else:
                        reward -= 0.5
                        info["attack"] = f"Node {node} exploit failed"
                else:
                    reward -= 0.5
                    info["attack"] = f"Node {node} unreachable from foothold"
        else:
            # WAIT action
            reward -= 0.2
            info["attack"] = "WAIT"

        # ── Heuristic defender responds ──────────────────────────────────
        prev_comp = int(self.compromised.sum())
        self._heuristic_defender_step()
        after_comp = int(self.compromised.sum())
        if after_comp < prev_comp:
            reward -= 2.0       # defender recovered a node

        # ── Shaping rewards ──────────────────────────────────────────────
        reward += float(self.compromised.sum()) * 0.3

        # ── Termination ──────────────────────────────────────────────────
        all_compromised = bool(self.compromised.sum() == self.node_count)
        time_up         = (self.current_step >= self.max_steps)
        done            = all_compromised or time_up
        truncated       = time_up and not all_compromised

        info["compromised"] = int(self.compromised.sum())
        info["step"]        = self.current_step

        return self._build_obs(), float(reward), done, truncated, info

    def render(self):
        node_types = {
            0: "Nginx",           1: "DVWA",              2: "MySQL",
            3: "Server",          4: "Domain-Controller",  5: "Workstation"
        }
        print("\n" + "─" * 55)
        print(f"  Attacker Env  |  Step {self.current_step}/{self.max_steps}")
        print("─" * 55)
        for i in range(self.node_count):
            status = "COMPROMISED" if self.compromised[i] else (
                     "ISOLATED"    if self.isolated[i]    else "SAFE")
            crit = " [CRITICAL]" if i in self.critical_nodes else ""
            print(f"  Node {i} | {node_types[i]:<14} | CVSS {self.cvss_scores[i]:.1f}{crit} | {status}")
        print("─" * 55)