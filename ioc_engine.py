"""
ioc_engine.py
-------------
Indicator of Compromise (IOC) aggregation.
Reads structured event dicts — no string parsing.

Tracks:
  - techniques  (only valid MITRE IDs)
  - ports
  - compromised assets (node_id + type)
  - CVEs
"""

from event_engine import VALID_TECHNIQUES, INVALID_TECHNIQUE_VALUES


class IOCEngine:
    """
    Aggregates IOCs from structured event dicts.
    All sets are keyed by structured fields, not strings.
    """

    def __init__(self):
        self.techniques:         set  = set()   # valid MITRE IDs only
        self.ports:              set  = set()   # int port numbers
        self.compromised_assets: set  = set()   # (node_id, node_type) tuples
        self.cves:               set  = set()   # CVE strings
        self.attacker_ips:       set  = set()   # future: real IPs

    # --------------------------------------------------
    def ingest(self, event: dict):
        """
        Process one structured event and update IOC sets.
        Only attacker events contribute IOCs.
        """
        if event.get("actor") != "attacker":
            return

        # Techniques — only valid MITRE IDs
        technique = event.get("technique", "")
        if technique and technique not in INVALID_TECHNIQUE_VALUES \
                and technique in VALID_TECHNIQUES:
            self.techniques.add(technique)

        # Ports
        port = event.get("port")
        if port and isinstance(port, int):
            self.ports.add(port)

        # Compromised assets
        if event.get("status") == "success":
            node_id   = event.get("node_id")
            node_type = event.get("node_type", "Unknown")
            if node_id is not None:
                self.compromised_assets.add((node_id, node_type))

        # CVEs
        cve = event.get("cve", "")
        if cve and cve not in ("N/A", "", None):
            self.cves.add(cve)

    # --------------------------------------------------
    # Convenience accessors
    # --------------------------------------------------
    def unique_technique_count(self) -> int:
        return len(self.techniques)

    def observed_port_count(self) -> int:
        return len(self.ports)

    def compromised_asset_count(self) -> int:
        return len(self.compromised_assets)

    def technique_list(self) -> list:
        return sorted(self.techniques)

    def port_list(self) -> list:
        return sorted(self.ports)

    def cve_list(self) -> list:
        return sorted(self.cves)

    def asset_list(self) -> list:
        """Return list of 'NodeID: NodeType' strings."""
        return [f"Node {nid}: {ntype}" for nid, ntype in sorted(self.compromised_assets)]

    def reset(self):
        self.__init__()
