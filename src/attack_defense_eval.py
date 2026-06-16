"""
attack_defense_eval.py
----------------------
Evaluate trained PPO Attacker vs PPO Defender on the shared MARL env.
Loads models saved by train_graph_marl.py and runs a full episode.
"""

from stable_baselines3 import PPO
from pathlib import Path
import sys
import numpy as np

sys.path.append(str(Path(__file__).resolve().parent))

from marlon.marl_env import MARLSharedEnv, MARLAttackerView, MARLDefenderView

ACTION_LABELS = {0: "ISOLATE", 1: "RECOVER", 2: "BLOCK", 3: "PRIORITIZE"}
NODE_TYPES    = {
    0: "Nginx",           1: "DVWA",              2: "MySQL",
    3: "Server",          4: "Domain-Controller",  5: "Workstation",
}


def main():
    model_dir = Path(__file__).resolve().parents[1] / "models"

    print("\n" + "="*60)
    print("  PPO ATTACKER vs PPO DEFENDER — Evaluation")
    print("="*60)

    shared   = MARLSharedEnv()
    att_view = MARLAttackerView(shared)
    def_view = MARLDefenderView(shared)

    # Load models (defender uses new rl model name, attacker unchanged)
    att_path = model_dir / "ppo_attacker_graph"
    def_path = model_dir / "ppo_defender_graph"

    print(f"  Loading attacker : {att_path}")
    print(f"  Loading defender : {def_path}\n")

    attacker = PPO.load(str(att_path), env=att_view)
    defender = PPO.load(str(def_path), env=def_view)

    obs_att, _ = att_view.reset()
    done        = False
    step        = 0

    att_total = 0.0
    def_total = 0.0

    while not done and step < shared.max_steps:
        step += 1
        print(f"\n--- Step {step} ---")

        # ── Attacker ────────────────────────────────────────────────
        att_action, _ = attacker.predict(obs_att, deterministic=False)
        att_r         = shared.attacker_step(int(att_action))
        att_total    += att_r
        node          = int(att_action) % shared.node_count
        print(f"  [ATTACKER] Targeted node {node} ({NODE_TYPES[node]}) "
              f"| Reward {att_r:+.2f}")

        if shared.done:
            print("  → Attacker achieved full compromise!")
            break

        # ── Defender ────────────────────────────────────────────────
        obs_def       = shared.obs()
        def_action, _ = defender.predict(obs_def, deterministic=False)
        def_r         = shared.defender_step(int(def_action))
        def_total    += def_r

        action_type = int(def_action) // shared.node_count
        node_target = int(def_action) %  shared.node_count
        label       = ACTION_LABELS.get(action_type, "?")
        print(f"  [DEFENDER] {label} node {node_target} ({NODE_TYPES[node_target]}) "
              f"| Reward {def_r:+.2f}")

        # ── Network state ───────────────────────────────────────────
        comp = int(shared.compromised.sum())
        iso  = int(shared.isolated.sum())
        blk  = int(shared.blocked.sum())
        pri  = int(shared.priority.sum())
        print(f"  Network: Compromised={comp} | Isolated={iso} "
              f"| Blocked={blk} | Priority={pri}")

        obs_att = shared.obs()
        done    = shared.done

    print("\n" + "="*60)
    print("  EPISODE COMPLETE")
    print(f"  Steps played        : {step}")
    print(f"  Attacker total rwd  : {att_total:+.2f}")
    print(f"  Defender total rwd  : {def_total:+.2f}")
    print(f"  Nodes compromised   : {int(shared.compromised.sum())}/{shared.node_count}")
    print(f"  Nodes isolated      : {int(shared.isolated.sum())}")
    winner = "DEFENDER" if shared.compromised.sum() == 0 else \
             "ATTACKER" if shared.compromised.sum() == shared.node_count else "DRAW"
    print(f"  Result              : {winner} wins")
    print("="*60)


if __name__ == "__main__":
    main()