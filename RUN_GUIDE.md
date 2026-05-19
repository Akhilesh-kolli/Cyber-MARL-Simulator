# Cyber MARL SOC Simulator - Run Guide

This guide will help you set up and run the Cyber-MARL simulator successfully.

## 1. Prerequisites
- **Python 3.8+** (Tested on 3.9 and 3.10)
- **Virtual Environment** (Recommended)
- **Nmap** (Optional: Required only for real-service scanning features)

## 2. Setting Up the Environment

Open your terminal in the project root and run:

```bash
# Create a virtual environment
python -m venv venv

# Activate it
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies using the minimal requirements file
pip install -r requirements_mini.txt
```

## 3. Training the Agents
Before running the dashboard, you need to train the Attacker and Defender agents. This script will train models using PPO and save them to the `models/` folder.

```bash
python train_graph_marl.py
```
*Note: This might take a few minutes depending on your hardware. It saves models at `models/ppo_attacker_graph` and `models/ppo_defender_graph`.*

## 4. Running the SOC Dashboard
The dashboard is built with Streamlit. It provides a real-time visualization of the simulation.

```bash
streamlit run dashboard.py
```
*Once started, open the URL provided in the terminal (usually `http://localhost:8501`).*

## 5. Main Components
- **`train_graph_marl.py`**: The training script for both agents.
- **`dashboard.py`**: The main GUI for monitoring simulations.
- **`src/`**: Contains the core logic for the graph environment (`marlon/graph_env.py`).
- **`models/`**: Stores your trained agents.

## Troubleshooting
- **Missing Models error**: Ensure you ran `train_graph_marl.py` first so the trained models exist in the `models/` directory.
- **Gym/NumPy Compatibility**: If you see NumPy 2.0 warnings, use the `requirements_mini.txt` which pins `numpy<2.0.0` for compatibility with `gym`.
- **Nmap Not Found**: If you don't have Nmap installed, the simulation will still run, but real-service detection will be disabled.
