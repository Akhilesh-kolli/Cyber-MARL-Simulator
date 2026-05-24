import importlib
import os
import sys

# Ensure repo root is on sys.path for package imports
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

mods = [
    'backend.risk_engine',
    'backend.simulation_engine',
    'visualization.timeline_renderer',
    'components.mitre_panels',
    'components.threat_panels',
    'components.executive_panels',
    'visualization.graph_renderer'
]
for m in mods:
    importlib.import_module(m)
print('SMOKE_OK')
