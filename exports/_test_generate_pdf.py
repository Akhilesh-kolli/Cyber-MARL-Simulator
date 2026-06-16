import sys
import os

# Ensure repository root is on sys.path so `exports` package can be imported
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if repo_root not in sys.path:
	sys.path.insert(0, repo_root)

from exports.pdf_exporter import generate_soc_pdf_report

# Minimal dummy inputs
soc_metrics = {}
sidebar_summary = {}
attack_timeline_df = []
mitre_df = []
ioc_df = []
live_feed = []

pdf = generate_soc_pdf_report(soc_metrics, sidebar_summary, attack_timeline_df, mitre_df, ioc_df, live_feed)
print(len(pdf))
