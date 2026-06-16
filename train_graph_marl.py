"""
train_graph_marl.py
-------------------
True PPO Attacker vs PPO Defender adversarial self-play training.

Flow per round:
  1. Attacker acts  -> gets reward from shared env
  2. Defender acts  -> gets reward from shared env (ISOLATE / RECOVER / BLOCK / PRIORITIZE)
  3. Repeat until episode done
  4. Every N rounds, update both PPO policies
"""

from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from pathlib import Path
import sys
import numpy as np

# ── paths ──────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.append(str(ROOT / "src"))

from marlon.marl_env import MARLSharedEnv, MARLAttackerView, MARLDefenderView

# ── config ─────────────────────────────────────────────────────────────────
WARMUP_STEPS    = 20_000  # solo warm-up per agent before self-play
SELFPLAY_ROUNDS = 200     # adversarial rounds
STEPS_PER_ROUND = 512     # timesteps each agent trains per round
EVAL_EVERY      = 25      # print stats every N rounds

# ── directories ────────────────────────────────────────────────────────────
log_dir   = ROOT / "logs"
model_dir = ROOT / "models"
log_dir.mkdir(exist_ok=True)
model_dir.mkdir(exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1 — WARM-UP (solo training so each agent starts with some policy)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("  PHASE 1 — Warm-up: solo attacker training")
print("="*60)

warmup_shared_att = MARLSharedEnv()
att_warmup_env    = Monitor(MARLAttackerView(warmup_shared_att),
                            str(log_dir / "attacker_warmup.csv"))

attacker_model = PPO(
    "MlpPolicy", att_warmup_env,
    verbose=0,
    learning_rate=3e-4,
    n_steps=256,
    batch_size=64,
    gamma=0.99,
    ent_coef=0.05,              # forces attacker to keep exploring nodes
    tensorboard_log=str(log_dir / "attacker_tb"),
)
attacker_model.learn(total_timesteps=WARMUP_STEPS)
print(f"  Attacker warm-up complete ({WARMUP_STEPS} steps)")

# ─────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("  PHASE 1 — Warm-up: solo defender training")
print("="*60)

warmup_shared_def = MARLSharedEnv()
def_warmup_env    = Monitor(MARLDefenderView(warmup_shared_def),
                            str(log_dir / "defender_warmup.csv"))

defender_model = PPO(
    "MlpPolicy", def_warmup_env,
    verbose=0,
    learning_rate=3e-4,
    n_steps=256,
    batch_size=64,
    gamma=0.99,
    ent_coef=0.05,              # forces defender to keep using all 4 actions
    tensorboard_log=str(log_dir / "defender_tb"),
)
defender_model.learn(total_timesteps=WARMUP_STEPS)
print(f"  Defender warm-up complete ({WARMUP_STEPS} steps)")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2 — ADVERSARIAL SELF-PLAY (PPO Attacker vs PPO Defender)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("  PHASE 2 — Adversarial self-play: PPO Attacker vs PPO Defender")
print("="*60)

ACTION_LABELS = {0: "ISOLATE", 1: "RECOVER", 2: "BLOCK", 3: "PRIORITIZE"}

att_rewards_history = []
def_rewards_history = []

for round_num in range(1, SELFPLAY_ROUNDS + 1):

    # Fresh shared environment for this round
    shared     = MARLSharedEnv()
    att_view   = MARLAttackerView(shared)
    def_view   = MARLDefenderView(shared)

    # Swap the policy into the new env
    attacker_model.set_env(Monitor(att_view, str(log_dir / "att_selfplay.csv")))
    defender_model.set_env(Monitor(def_view, str(log_dir / "def_selfplay.csv")))

    # ── collect one episode manually (true turn-based) ─────────────────
    obs_att, _ = att_view.reset()
    obs_def    = shared.obs()

    ep_att_reward = 0.0
    ep_def_reward = 0.0
    done          = False
    step          = 0
    defender_actions_used = {k: 0 for k in ACTION_LABELS}

    while not done:
        # Attacker predicts and acts
        att_action, _ = attacker_model.predict(obs_att, deterministic=False)
        att_r         = shared.attacker_step(int(att_action))
        ep_att_reward += att_r

        if shared.done:
            break

        # Defender predicts and acts
        obs_def       = shared.obs()
        def_action, _ = defender_model.predict(obs_def, deterministic=False)
        def_r         = shared.defender_step(int(def_action))
        ep_def_reward += def_r

        # Track which defender action category was used
        action_type = int(def_action) // shared.node_count
        if action_type in defender_actions_used:
            defender_actions_used[action_type] += 1

        obs_att = shared.obs()
        done    = shared.done
        step   += 1

    att_rewards_history.append(ep_att_reward)
    def_rewards_history.append(ep_def_reward)

    # ── PPO update for both agents every round ─────────────────────────
    attacker_model.learn(total_timesteps=STEPS_PER_ROUND, reset_num_timesteps=False)
    defender_model.learn(total_timesteps=STEPS_PER_ROUND, reset_num_timesteps=False)

    # ── periodic stats ─────────────────────────────────────────────────
    if round_num % EVAL_EVERY == 0:
        last = min(EVAL_EVERY, len(att_rewards_history))
        avg_att = np.mean(att_rewards_history[-last:])
        avg_def = np.mean(def_rewards_history[-last:])
        comp    = int(shared.compromised.sum())
        iso     = int(shared.isolated.sum())

        def_breakdown = "  ".join(
            f"{ACTION_LABELS[k]}={v}"
            for k, v in defender_actions_used.items()
        )

        print(f"\n  Round {round_num}/{SELFPLAY_ROUNDS}")
        print(f"  Attacker avg reward : {avg_att:+.2f}")
        print(f"  Defender avg reward : {avg_def:+.2f}")
        print(f"  Last episode        : {step} steps | "
              f"Compromised={comp} | Isolated={iso}")
        print(f"  Defender actions    : {def_breakdown}")

# ══════════════════════════════════════════════════════════════════════════
# SAVE MODELS
# ══════════════════════════════════════════════════════════════════════════
attacker_model.save(str(model_dir / "ppo_attacker_graph"))
defender_model.save(str(model_dir / "ppo_defender_graph"))

print("\n" + "="*60)
print("  TRAINING COMPLETE")
print(f"  Attacker saved -> models/ppo_attacker_graph")
print(f"  Defender saved -> models/ppo_defender_graph")
print("="*60)

# ── final summary ──────────────────────────────────────────────────────────
print(f"\n  Total self-play rounds  : {SELFPLAY_ROUNDS}")
print(f"  Steps per round (each)  : {STEPS_PER_ROUND}")
print(f"  Defender capabilities   : ISOLATE | RECOVER | BLOCK | PRIORITIZE")
print(f"  Final attacker reward   : {att_rewards_history[-1]:+.2f}")
print(f"  Final defender reward   : {def_rewards_history[-1]:+.2f}")