# Multi Agent Cyber Defense and SOC simluation Platform


<p align="center">
  <img src="https://img.shields.io/badge/CYMARL-Cyber%20Defense-darkred">
  <img src="https://img.shields.io/badge/MARL-Multi--Agent%20RL-blue">
  <img src="https://img.shields.io/badge/PPO-Attacker%20%26%20Defender-purple">
  <img src="https://img.shields.io/badge/CVE-CVSS-orange">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red">
  <img src="https://img.shields.io/badge/Threat-Intelligence-black">
  <img src="https://img.shields.io/badge/SOC-Analytics-green">
  <img src="https://img.shields.io/badge/Risk-Assessment-yellowgreen">
  <img src="https://img.shields.io/badge/Environment-Enterprise%20Graph-lightgrey">
  <img src="https://img.shields.io/badge/Dashboard-Streamlit-ff4b4b">
  <img src="https://img.shields.io/badge/Python-Framework-yellow">
  <img src="https://img.shields.io/badge/Platform-Windows-red">
  <img src="https://img.shields.io/badge/Research-Cybersecurity-blueviolet">
  <img src="https://img.shields.io/badge/Status-Active-success">
  <img src="https://img.shields.io/badge/License-Academic-lightgrey">
  <img src="https://img.shields.io/badge/Domain-SOC%20Intelligence-darkgreen">
  <img src="https://img.shields.io/badge/Framework-CYMARL-darkred">
</p>

---

# Cymarl-Framework

Cymarl-Framework is a Cybersecurity Multi-Agent Reinforcement Learning (MARL) framework designed for attacker–defender simulations in graph-based cyber environments.

The framework models interactions between intelligent attacker and defender agents where both learn adaptive strategies using Proximal Policy Optimization (PPO). The project focuses on cyber attack path traversal, dynamic defense decisions, reward optimization, and reinforcement learning–based cybersecurity experimentation.

The environment simulates cyber conflict scenarios where attackers attempt to compromise network nodes while defenders attempt to secure critical assets and minimize attack success.

---

# Core Features

- Multi-Agent Reinforcement Learning (MARL)
- PPO-based attacker and defender training
- Graph-based cyber environment
- Attack path simulation
- Dynamic reward engineering
- Cyber node compromise simulation
- Defender response mechanisms
- Training metric visualization
- GIF-based environment rendering
- Research-focused cyber experimentation

---

# Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | Python |
| RL Algorithm | PPO |
| Environment Modeling | Graph-based Simulation |
| Visualization | Matplotlib |
| Numerical Computing | NumPy |
| Data Handling | Pandas |
| Platform | Kali Linux |

---

# Framework Workflow

```text
Attacker Agent
       ↓
Graph-Based Cyber Environment
       ↓
Defender Agent
       ↓
State Transition & Rewards
       ↓
PPO Training Process
       ↓
Metrics & Visualization
```

---

# Project Structure

```text
Cymarl-Framework/
│
├── src/
├── models/
├── plots/
├── gifs/
├── metrics/
├── compute_metrics.py
├── plot_training.py
├── generate_gif.py
├── requirements.txt
└── README.md
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Akhilesh-kolli/Cymarl-Framework-.git
```

Move into the project directory:

```bash
cd Cymarl-Framework-
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Framework

Run training:

```bash
python train.py
```

Generate metrics:

```bash
python compute_metrics.py
```

Plot training graphs:

```bash
python plot_training.py
```

Generate environment GIF:

```bash
python generate_gif.py
```

---

# Generated Outputs

The framework generates:

- PPO training metrics
- Reward convergence graphs
- Attack success analysis
- Defender efficiency metrics
- Training visualizations
- Animated cyber environment simulations
- Graph traversal analysis

---

# Research Applications

- Cybersecurity reinforcement learning
- Autonomous cyber defense research
- Attacker–defender simulations
- Graph-based threat modeling
- Adaptive defense strategy analysis
- AI-driven cyber experimentation

---

# Future Enhancements

- Multi-defender coordination
- Advanced adversarial RL algorithms
- Real-time simulation dashboards
- Scalable distributed training
- Explainable AI for cyber decisions
- Dynamic network topology generation

---

# Author

## Akhilesh Kolli

Cybersecurity Research | Reinforcement Learning | Threat Simulation

GitHub:
https://github.com/Akhilesh-kolli

---

# License

This project is intended for academic and cybersecurity research purposes.
