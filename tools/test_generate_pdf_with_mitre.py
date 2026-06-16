import sys
import os
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from exports.pdf_exporter import generate_soc_pdf_report
import pandas as pd

soc_metrics = {}
sidebar_summary = {}
attack_timeline_df = []
mitre_df = pd.DataFrame({'Technique': ['T1547', 'T1486', 'T1078'], 'Count': [12, 7, 3]})
ioc_df = []
live_feed = []

pdf = generate_soc_pdf_report(soc_metrics, sidebar_summary, attack_timeline_df, mitre_df, ioc_df, live_feed)
print('PDF bytes:', len(pdf))
