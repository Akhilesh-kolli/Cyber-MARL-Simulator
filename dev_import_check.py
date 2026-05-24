modules = [
    'backend.event_bus',
    'backend.simulation_engine',
    'analytics.anomaly_engine',
    'analytics.mitre_mapper',
    'analytics.executive_analytics',
]

import importlib
import sys

ok = True
for m in modules:
    try:
        importlib.import_module(m)
        print(f"OK: imported {m}")
    except Exception as e:
        ok = False
        print(f"ERROR importing {m}: {e}")

if not ok:
    sys.exit(2)
else:
    print("All modules imported successfully.")
