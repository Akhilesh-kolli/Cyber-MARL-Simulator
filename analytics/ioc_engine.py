"""
analytics/ioc_engine.py
-----------------------
IOC Engine to ingest canonical structured events and generate registry DataFrames.
"""

import pandas as pd

class IOCEngine:
    @staticmethod
    def generate_registry_df(structured_events: list) -> pd.DataFrame:
        """
        Ingests structured events and compiles a unified DataFrame of IOC records.
        """
        ioc_records = {}
        for e in structured_events:
            # Check for port IOC
            port = e.get("port")
            if port and port != "N/A" and port != None:
                ioc_name = f"Port {port}"
                conf = e.get("detection_confidence")
                conf_str = f"{conf}%" if conf else "N/A"
                if ioc_name not in ioc_records:
                    ioc_records[ioc_name] = {
                        "IOC": ioc_name,
                        "Type": "Network Port",
                        "Severity": e.get("threat", "LOW"),
                        "First Seen": e.get("timestamp", "00:00:00"),
                        "Count": 1,
                        "Confidence": conf_str
                    }
                else:
                    ioc_records[ioc_name]["Count"] += 1

            # Check for technique IOC
            tech = e.get("technique")
            if tech and tech != "N/A" and tech != None:
                mitre_name = e.get("mitre_name", "Unknown Technique")
                ioc_name = f"{tech} - {mitre_name}"
                conf = e.get("detection_confidence")
                conf_str = f"{conf}%" if conf else "N/A"
                if ioc_name not in ioc_records:
                    ioc_records[ioc_name] = {
                        "IOC": ioc_name,
                        "Type": "Adversary Technique",
                        "Severity": e.get("threat", "LOW"),
                        "First Seen": e.get("timestamp", "00:00:00"),
                        "Count": 1,
                        "Confidence": conf_str
                    }
                else:
                    ioc_records[ioc_name]["Count"] += 1

        if not ioc_records:
            return pd.DataFrame(columns=["IOC", "Type", "Severity", "First Seen", "Count", "Confidence"])
            
        return pd.DataFrame(list(ioc_records.values()))
