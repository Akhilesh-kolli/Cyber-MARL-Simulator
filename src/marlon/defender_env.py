"""
src/marlon/defender_env.py
--------------------------
Defender-side Gym environment for PPO training.

The defender observes the full network state and has 4 action categories:
  0 .. N-1   → ISOLATE node i           (removes attacker presence, blocks paths)
  N .. 2N-1  → RECOVER node i           (restores a clean/contained node to healthy)
  2N .. 3N-1 → BLOCK path from node i   (raises edge cost to reduce lateral movement)
  3N .. 4N-1 → PRIORITIZE node i        (marks node as high-priority alert focus)

Observation vector (per node × N nodes):
  - compromised      [0,1]
  - isolated         [0,1]
  - blocked          [0,1]  (outgoing edges blocked)
  - priority_flag    [0,1]
  - cvss_norm        [0,1]  (CVSS / 10)
  - is_critical      [0,1]

Total obs dim = N * 6
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces


# ─────────────────────────────────────────────────────────────────────────────
# Defender Action Categories
# ─────────────────────────────────────────────────────────────────────────────
DEFENDER_ACTIONS = {
    "ISOLATE":    0,   # offset 0*N
    "RECOVER":    1,   # offset 1*N
    "BLOCK":      2,   # offset 2*N
    "PRIORITIZE": 3,   # offset 3*N
}
NUM_ACTION_TYPES = 4

OBS_FEATURES = 6           # features per node
MAX_BLOCKED_EDGES = 3      # cap to prevent total network freeze


class DefenderEnv(gym.Env):
    """
    Standalone Gym environment for the PPO Defender agent.

    The attacker is simulated as a stochastic adversary using CVSS-based
    probabilities and the adjacency graph — the defender must learn to
    outmanoeuvre it.
    """

    metadata = {"render_modes": ["human"]}

    # ──────────────────────────────────────────────────────────────────────
    def __init__(self, node_count: int = 6, max_steps: int = 50):
        super().__init__()

        self.node_count  = node_count
        self.max_steps   = max_steps

        # ── Static topology ─────────────────────────────────────────────
        self.graph = np.array([
            [0, 1, 1, 0, 0, 0],
            [1, 0, 1, 1, 0, 0],
            [1, 1, 0, 1, 1, 0],
            [0, 1, 1, 0, 1, 1],
            [0, 0, 1, 1, 0, 1],
            [0, 0, 0, 1, 1, 0],
        ], dtype=np.int32)

        self.critical_nodes = {0, 1, 2}          # high-value targets

        self.cvss_scores = np.array(
            [8.5, 9.5, 9.2, 7.8, 9.8, 4.5], dtype=np.float32
        )

        # ── Action / Observation Spaces ──────────────────────────────────
        self.action_space = spaces.Discrete(NUM_ACTION_TYPES * node_count)

        obs_dim = node_count * OBS_FEATURES
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(obs_dim,), dtype=np.float32
        )

        self.reset()

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
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
        """Adjacency matrix with blocked edges zeroed out."""
        g = self.graph.copy()
        for i in range(self.node_count):
            if self.blocked[i]:
                g[i, :] = 0
                g[:, i] = 0
        return g

    def _attacker_step(self):
        """
        Simulated stochastic attacker: picks a reachable uncompromised node
        and attempts exploitation using CVSS probability.
        """
        g = self._active_graph()
        comp = np.where(self.compromised == 1)[0]
        if len(comp) == 0:
            # plant initial foothold
            entry = int(np.random.randint(self.node_count))
            if not self.isolated[entry]:
                self.compromised[entry] = 1
            return

        reachable = set()
        for c in comp:
            for nbr in range(self.node_count):
                if g[c, nbr] == 1 and self.compromised[nbr] == 0 and not self.isolated[nbr]:
                    reachable.add(nbr)

        if not reachable:
            return

        target = int(np.random.choice(list(reachable)))
        p = float(np.clip(0.2 + self.cvss_scores[target] / 20.0, 0.05, 0.95))
        if np.random.rand() < p:
            self.compromised[target] = 1

    # ──────────────────────────────────────────────────────────────────────
    # Gym Interface
    # ──────────────────────────────────────────────────────────────────────
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)

        self.compromised = np.zeros(self.node_count, dtype=np.int32)
        self.isolated    = np.zeros(self.node_count, dtype=np.int32)
        self.blocked     = np.zeros(self.node_count, dtype=np.int32)
        self.priority    = np.zeros(self.node_count, dtype=np.int32)

        # Attacker starts with one foothold
        entry = int(np.random.randint(self.node_count))
        self.compromised[entry] = 1

        self.current_step   = 0
        self.blocked_count  = 0   # track cap

        return self._build_obs(), {}

    def step(self, action: int):
        action      = int(action)
        action_type = action // self.node_count
        node        = action  % self.node_count

        self.current_step += 1
        reward = 0.0
        info   = {}

        # ── Attacker moves first ─────────────────────────────────────────
        before = int(self.compromised.sum())
        self._attacker_step()
        after  = int(self.compromised.sum())

        if after > before:
            # reward penalty for every newly compromised node
            reward -= 2.0 * (after - before)
            if any(n in self.critical_nodes for n in
                   np.where(self.compromised == 1)[0]):
                reward -= 3.0   # extra penalty for critical nodes

        # ── Defender action ──────────────────────────────────────────────
        if action_type == DEFENDER_ACTIONS["ISOLATE"]:
            reward += self._action_isolate(node)
            info["action"] = f"ISOLATE node {node}"

        elif action_type == DEFENDER_ACTIONS["RECOVER"]:
            reward += self._action_recover(node)
            info["action"] = f"RECOVER node {node}"

        elif action_type == DEFENDER_ACTIONS["BLOCK"]:
            reward += self._action_block(node)
            info["action"] = f"BLOCK node {node}"

        elif action_type == DEFENDER_ACTIONS["PRIORITIZE"]:
            reward += self._action_prioritize(node)
            info["action"] = f"PRIORITIZE node {node}"

        # ── Shaping rewards ──────────────────────────────────────────────
        # Reward for keeping nodes clean
        clean_ratio = 1.0 - (self.compromised.sum() / self.node_count)
        reward += clean_ratio * 0.5

        # Bonus for zero compromised nodes
        if self.compromised.sum() == 0:
            reward += 5.0

        # ── Termination ──────────────────────────────────────────────────
        all_compromised = bool(self.compromised.sum() == self.node_count)
        time_up         = (self.current_step >= self.max_steps)
        done            = all_compromised or time_up
        truncated       = time_up and not all_compromised

        info["compromised"] = int(self.compromised.sum())
        info["isolated"]    = int(self.isolated.sum())
        info["blocked"]     = int(self.blocked.sum())
        info["priority"]    = int(self.priority.sum())
        info["step"]        = self.current_step

        return self._build_obs(), float(reward), done, truncated, info

    # ──────────────────────────────────────────────────────────────────────
    # Defender Action Implementations
    # ──────────────────────────────────────────────────────────────────────
    def _action_isolate(self, node: int) -> float:
        """
        ISOLATE: removes attacker from node, marks it isolated.
        Penalised heavily for repeated isolations of already-clean nodes.
        """
        if self.compromised[node] == 1:
            self.compromised[node] = 0
            self.isolated[node]    = 1
            reward = 2.0                            # reduced from 4.0
            if node in self.critical_nodes:
                reward += 1.0                       # reduced from 3.0
            return reward
        elif self.isolated[node] == 1:
            return -1.5         # heavy penalty — stop spamming already-isolated
        else:
            return -1.0         # penalise isolating healthy nodes

    def _action_recover(self, node: int) -> float:
        """
        RECOVER: restores an isolated node back to healthy.
        Boosted reward to make it competitive with ISOLATE.
        """
        if self.isolated[node] == 1:
            self.isolated[node] = 0
            reward = 2.5                            # boosted from 1.5
            if node in self.critical_nodes:
                reward += 1.5                       # boosted from 1.0
            return reward
        elif self.compromised[node] == 1:
            if np.random.rand() < 0.4:
                self.compromised[node] = 0
                return 3.0
            else:
                return -0.3
        else:
            return -0.5         # already healthy — wasteful

    def _action_block(self, node: int) -> float:
        """
        BLOCK: severs edges to cut lateral movement.
        Boosted reward to make it competitive with ISOLATE.
        """
        if self.blocked[node] == 1:
            return -1.0         # heavy penalty — stop re-blocking

        if self.blocked_count >= MAX_BLOCKED_EDGES:
            return -0.5

        self.blocked[node]  = 1
        self.blocked_count += 1

        if self.compromised[node] == 1:
            reward = 3.0                            # boosted from 2.5
        else:
            comp_neighbours = sum(
                1 for nbr in range(self.node_count)
                if self.graph[node, nbr] == 1 and self.compromised[nbr] == 1
            )
            reward = 1.5 + comp_neighbours * 1.0   # boosted from 0.5 + *0.8

        return reward

    def _action_prioritize(self, node: int) -> float:
        """
        PRIORITIZE: flags node as high-priority SOC alert.
        Boosted reward to make it competitive with ISOLATE.
        """
        if self.priority[node] == 1:
            return -1.0         # heavy penalty — stop re-flagging

        self.priority[node] = 1

        if self.compromised[node] == 1:
            reward = 2.5                            # boosted from 1.2
            if node in self.critical_nodes:
                reward += 1.5                       # boosted from 0.8
            return reward
        else:
            return 0.5                              # boosted from 0.2

    # ──────────────────────────────────────────────────────────────────────
    # Render
    # ──────────────────────────────────────────────────────────────────────
    def render(self):
        node_types = {
            0: "Nginx",           1: "DVWA",              2: "MySQL",
            3: "Server",          4: "Domain-Controller",  5: "Workstation"
        }
        print("\n" + "=" * 60)
        print(f"  Defender Env  |  Step {self.current_step}/{self.max_steps}")
        print("=" * 60)
        for i in range(self.node_count):
            flags = []
            if self.compromised[i]: flags.append("COMPROMISED")
            if self.isolated[i]:    flags.append("ISOLATED")
            if self.blocked[i]:     flags.append("BLOCKED")
            if self.priority[i]:    flags.append("PRIORITY")
            status = ", ".join(flags) if flags else "HEALTHY"
            crit   = " [CRITICAL]" if i in self.critical_nodes else ""
            print(f"  Node {i} | {node_types[i]:<14} | CVSS {self.cvss_scores[i]:.1f}{crit} | {status}")
        print("=" * 60)