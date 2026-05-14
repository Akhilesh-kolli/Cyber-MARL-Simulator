import numpy as np
import gym
from gym import spaces
from marlon.real_scan import scan_local_services


class GraphCyberEnv(gym.Env):
    """
    Advanced Cyber MARL Environment
    Real-service-aware attacker vs defender simulation
    """

    def __init__(self, node_count=6, max_steps=25):
        super(GraphCyberEnv, self).__init__()

        self.node_count = node_count
        self.max_steps = max_steps

        # ==================================================
        # NETWORK TOPOLOGY
        # ==================================================
        self.graph = np.array([
            [0,1,1,0,0,0],
            [1,0,1,1,0,0],
            [1,1,0,1,1,0],
            [0,1,1,0,1,1],
            [0,0,1,1,0,1],
            [0,0,0,1,1,0],
        ], dtype=np.int32)

        # ==================================================
        # CRITICAL NODES
        # ==================================================
        self.critical_nodes = {0,1,2}

        # ==================================================
        # NODE TYPES
        # ==================================================
        self.node_types = {
            0: "Workstation",
            1: "Firewall",
            2: "Database",
            3: "Server",
            4: "DomainController",
            5: "Workstation"
        }

        # ==================================================
        # REAL SERVICE MAPPING
        # ==================================================
        self.real_services = {
            0: "Nginx",
            1: "DVWA",
            2: "MySQL"
        }

        # ==================================================
        # SECURITY LEVELS
        # ==================================================
        self.security_levels = {
            0: 0.4,
            1: 0.9,
            2: 0.8,
            3: 0.7,
            4: 0.95,
            5: 0.5
        }

        # ==================================================
        # CVSS SCORES
        # ==================================================
        self.cvss_scores = {
            0: 8.5,
            1: 9.5,
            2: 9.2,
            3: 7.8,
            4: 9.8,
            5: 4.5
        }

        # ==================================================
        # ACTION SPACE
        # ==================================================
        self.action_space = spaces.Discrete(self.node_count + 1)

        self.observation_space = spaces.Box(
            low=0,
            high=1,
            shape=(self.node_count,),
            dtype=np.float32
        )

        self.reset()

    # ======================================================
    # RESET
    # ======================================================
    def reset(self, seed=None, options=None):

        super().reset(seed=seed)

        self.state = np.zeros(self.node_count, dtype=np.float32)

        # initial foothold
        entry = np.random.randint(0, self.node_count)
        self.state[entry] = 1

        self.current_step = 0

        # ==================================================
        # REAL SERVICE DISCOVERY
        # ==================================================
        self.service_status = scan_local_services()

        return self.state.copy()

    # ======================================================
    # STEP
    # ======================================================
    def step(self, action):

        action = int(action)

        self.current_step += 1
        reward = 0.0

        # ==================================================
        # ATTACKER ACTION
        # ==================================================
        if action < self.node_count:

            compromised = np.where(self.state == 1)[0]

            # lateral movement connectivity
            reachable = False

            for node in compromised:
                if self.graph[node, action] == 1:
                    reachable = True
                    break

            # ==================================================
            # CHECK REAL SERVICE AVAILABILITY
            # ==================================================
            service_available = True

            if action in self.real_services:
                service_name = self.real_services[action]
                service_available = self.service_status.get(
                    service_name,
                    False
                )

            # ==================================================
            # ATTACK ATTEMPT
            # ==================================================
            if (
                reachable
                and self.state[action] == 0
                and service_available
            ):

                # CVSS-based compromise probability
                success_prob = 0.2 + (
                    self.cvss_scores[action] / 20
                )

                # exploration randomness
                success_prob += np.random.uniform(-0.05, 0.05)

                # valid probability bounds
                success_prob = np.clip(
                    success_prob,
                    0.05,
                    0.95
                )

                # successful compromise
                if np.random.rand() < success_prob:

                    self.state[action] = 1

                    # base reward
                    reward = 1.0

                    # vulnerability severity reward

                    # Real infrastructure bonus
                    if action in self.real_services:
                        reward += 4.0
                    else:
                        reward += 0.2
                    # critical infrastructure bonus
                    if action in self.critical_nodes:
                        reward += 2.0
                    # Penalize simulated-only nodes
                    if action not in self.real_services:
                        reward -= 2.5
                else:
                    reward = -0.5

            else:
                reward = -0.3

        # ==================================================
        # DEFENDER ACTION
        # ==================================================
        else:

            compromised = np.where(self.state == 1)[0]

            if len(compromised) > 0:

                # prioritize high-risk systems
                node = max(
                    compromised,
                    key=lambda x: self.cvss_scores[x]
                )

                # probabilistic recovery
                if np.random.rand() < 0.35:

                    self.state[node] = 0
                    reward = 0.8

                else:
                    reward = -0.2

            else:
                reward = -0.1

        # ==================================================
        # TERMINATION
        # ==================================================
        done = self.current_step >= self.max_steps

        return self.state.copy(), reward, done, {}

    # ======================================================
    # RENDER
    # ======================================================
    def render(self):

        print("\n==============================")
        print(f"Step: {self.current_step}")

        for i in range(self.node_count):

            status = (
                "COMPROMISED"
                if self.state[i] == 1
                else "SAFE"
            )

            service = self.real_services.get(
                i,
                "Simulated"
            )

            print(
                f"Node {i} | "
                f"{self.node_types[i]} | "
                f"Service={service} | "
                f"CVSS={self.cvss_scores[i]} | "
                f"{status}"
            )

        print("==============================")
