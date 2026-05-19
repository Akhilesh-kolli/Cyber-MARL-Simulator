import numpy as np
import gym
from gym import spaces


class DummyCyberEnv(gym.Env):
    """
    FINAL stable dummy cyber environment
    Compatible with Stable-Baselines3 + Gym
    """

    metadata = {"render.modes": ["human"]}

    def __init__(self, node_count=5, max_steps=25):
        super(DummyCyberEnv, self).__init__()

        self.node_count = node_count
        self.max_steps = max_steps

        # Actions:
        # 0..node_count-1  -> attack node
        # node_count       -> defender recover action
        self.action_space = spaces.Discrete(self.node_count + 1)

        # State = compromised nodes vector
        self.observation_space = spaces.Box(
            low=0,
            high=1,
            shape=(self.node_count,),
            dtype=np.float32
        )

        self.state = np.zeros(self.node_count, dtype=np.float32)
        self.current_step = 0

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.state = np.zeros(self.node_count, dtype=np.float32)
        self.current_step = 0
        return self.state.copy(), {}

    def step(self, action):

        self.current_step += 1
        reward = 0.0

        # ---------- ATTACK ----------
        if action < self.node_count:

            if self.state[action] == 0:
                # successful compromise
                self.state[action] = 1
                reward = 1.0
            else:
                # attacking same node again
                reward = -0.3

        # ---------- DEFENDER ----------
        else:

            compromised = np.where(self.state == 1)[0]

            if len(compromised) > 0:
                node = np.random.choice(compromised)
                self.state[node] = 0
                reward = 0.6
            else:
                reward = -0.2

        done = self.current_step >= self.max_steps

        return self.state.copy(), reward, done, False, {}

    def render(self, mode="human"):
        print(f"Step {self.current_step}: {self.state}")
