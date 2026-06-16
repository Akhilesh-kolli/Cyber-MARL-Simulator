"""
analytics/ioc_engine.py
-----------------------
IOC Engine to ingest canonical structured events and generate a cleaned, audit-ready
IOC registry DataFrame suitable for downstream MITRE aggregation and dashboarding.

Behaviors:
- Only emit meaningful IOC rows (technique IDs, CVEs, ports). Do not create rows for
  metadata-only values (Service: SOC, Host: SOC, Asset: Defender, etc.).
- Create contextual correlation rows (Technique on Asset, Technique on Port) but
  these are for IOC Intelligence only; MITRE aggregation will normalize to base IDs.
- Compute deterministic confidence scores based on frequency, severity, correlation,
  and CVE enrichment.
"""

from typing import List
import re
import pandas as pd
from dateutil.parser import parse as dtparse
from utils.constants import ASSET_CRITICALITY, ATTACK_SEVERITY


class IOCEngine:
    @staticmethod
    def generate_registry_df(structured_events: List[dict]) -> pd.DataFrame:
        """
        Ingest structured events and return a cleaned IOC registry DataFrame.

        Output columns:
        IOC, Type, Severity, First Seen, Last Seen, Count, Confidence,
        Asset, Ports, Source, Destination, Evidence
        """

        cols = ["IOC", "Type", "Severity", "First Seen", "Last Seen", "Count", "Confidence", "Asset", "Ports", "Source", "Destination", "Evidence"]

        if not structured_events:
            return pd.DataFrame(columns=cols)

        # Regex helpers
        TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
        CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

        def is_valid_cve(val):
            if not val:
                return False
            return bool(CVE_RE.search(str(val)))

        def normalize_asset_name(a: str) -> str:
            if not a:
                return ""
            s = str(a).strip()
            sl = s.lower()
            if "mysql" in sl or "database" in sl or "db" in sl:
                return "MySQL"
            if "dvwa" in sl:
                return "DVWA"
            if "nginx" in sl or "web" in sl:
                return "Nginx"
            if "domain" in sl:
                return "Domain-Controller"
            if "server" in sl:
                return "Server"
            if "workstation" in sl:
                return "Workstation"
            return s

        def _update_first_last(rec: dict, ts: str):
            if not ts:
                return
            try:
                t_dt = dtparse(ts)
            except Exception:
                return
            fs = rec.get("First Seen")
            ls = rec.get("Last Seen")
            try:
                f_dt = dtparse(fs) if fs else None
            except Exception:
                f_dt = None
            try:
                l_dt = dtparse(ls) if ls else None
            except Exception:
                l_dt = None
            if not f_dt or t_dt < f_dt:
                rec["First Seen"] = ts
            if not l_dt or t_dt > l_dt:
                rec["Last Seen"] = ts

        def _merge_timestamps(rec: dict, other: dict):
            # Merge first/last seen from other into rec using datetime ordering
            of = other.get("First Seen")
            ol = other.get("Last Seen")
            if of:
                _update_first_last(rec, of)
            if ol:
                _update_first_last(rec, ol)

        def extract_techs(text):
            if not text:
                return []
            return [t.upper() for t in TECH_RE.findall(str(text))]

        def map_source(e):
            actor = str(e.get("actor", "") or "").lower()
            kc = str(e.get("kill_chain", "") or "").lower()
            msg = str(e.get("message", "") or "").lower()
            if "attacker" in actor:
                return "Attack Telemetry"
            if "defender" in actor:
                return "Defender Telemetry"
            if "persistence" in kc or "persistence" in msg:
                return "Persistence Detection"
            if any(k in kc for k in ["reconnaissance", "discovery", "scanning"]) or any(k in msg for k in ["scan", "port scan"]):
                return "Network Monitoring"
            if "ioc" in msg or "correlat" in msg:
                return "IOC Correlation"
            return "Threat Hunt"

        # canonical store
        ioc_map = {}

        def ensure_rec(key, ioc_name, ioc_type, severity, ts, src, dst, evidence):
            rec = ioc_map.get(key)
            if rec is None:
                rec = {
                    "IOC": ioc_name,
                    "Type": ioc_type,
                    "Severity": (severity or "LOW").upper(),
                    "First Seen": ts or "",
                    "Last Seen": ts or "",
                    "Count": 0,
                    "Sources": set(),
                    "Assets": set(),
                    "Ports": set(),
                    "SeverityVals": set(),
                    "Successes": 0,
                    "PrivilegeSeen": False,
                    "LateralSeen": False,
                    "Destination": normalize_asset_name(dst) if dst else "",
                    "Evidence": evidence or "",
                }
                ioc_map[key] = rec
            return rec

        # metadata values to ignore as IOC subjects
        META_IGNORE = {"SOC", "NOT-APPLICABLE", "DEFENDER", "DEFENDER-ACTION", "WORKSTATION"}

        for idx, e in enumerate(structured_events or []):
            ts = e.get("timestamp") or e.get("time") or ""
            sev = (e.get("threat") or e.get("severity") or "LOW").upper()
            src_label = map_source(e)
            dst = e.get("target") or e.get("destination") or e.get("node") or e.get("dest") or ""
            asset = e.get("asset") or e.get("node_type") or e.get("service") or dst or ""
            message = e.get("message") or e.get("event_summary") or ""
            # FIX: Build meaningful evidence when message is empty
            if not message:
                _tech = e.get("technique") or ""
                _stage = e.get("kill_chain") or e.get("event_type") or ""
                _node = e.get("node") or e.get("service") or ""
                _port = e.get("port") or ""
                _status = e.get("status") or ""
                parts = []
                if _stage:
                    parts.append(f"Stage: {_stage}")
                if _tech and not str(_tech).startswith("DEF:") and _tech != "DEFENSIVE-OPS":
                    parts.append(f"Technique: {_tech}")
                if _node:
                    parts.append(f"Target: {_node}")
                if _port:
                    parts.append(f"Port: {_port}")
                if _status:
                    parts.append(f"Status: {_status}")
                message = " | ".join(parts) if parts else "Observed during simulation"

            # Normalize asset: do not treat generic metadata as an asset for IOC rows
            if asset and str(asset).strip().upper() in META_IGNORE:
                asset = ""
            asset = normalize_asset_name(asset)

            # Determine success/privilege/lateral indicators from event
            success_flag = False
            try:
                if int(e.get("compromise_count") or e.get("compromised_count") or e.get("compromise_count_snapshot") or 0) > 0:
                    success_flag = True
            except Exception:
                success_flag = False
            status = str(e.get("status") or e.get("event_type") or "").lower()
            if "success" in status or "compromis" in status:
                success_flag = True
            priv_flag = "privilege" in str(e.get("kill_chain") or "").lower() or "privilege" in message.lower()
            lat_flag = "lateral" in str(e.get("kill_chain") or "").lower() or "lateral" in message.lower()

            # extract numeric port if present
            pnum = None
            port_val = e.get("port") or e.get("dport") or e.get("destination_port")
            try:
                if port_val is not None and str(port_val).strip() != "":
                    pnum = int(str(port_val))
            except Exception:
                pnum = None
            if not pnum:
                m = re.search(r"port\s*(?:[:=]?\s*)(\d{2,5})", str(message), re.IGNORECASE)
                if m:
                    try:
                        pnum = int(m.group(1))
                    except Exception:
                        pnum = None

            # CVE handling
            cve = e.get("cve") or e.get("vulnerability") or e.get("vuln")
            if not is_valid_cve(cve):
                m = CVE_RE.search(str(message) or "")
                cve = m.group(0).upper() if m else None

            # technique candidates
            techs = []
            for fld in [e.get("technique"), e.get("mitre_id"), e.get("mitre_name"), message]:
                techs += extract_techs(fld)
            # unique preserve order
            seen = set()
            techs_unique = []
            for t in techs:
                if t and t not in seen:
                    seen.add(t)
                    techs_unique.append(t)

            # Primary technique rows + correlated context rows
            for tech in techs_unique:
                key = f"TECH:{tech}"
                r = ensure_rec(key, tech, "Adversary Technique", sev, ts, src_label, dst, message)
                # update count and canonical timestamp bounds
                r["Count"] += 1
                # track observed severities for later canonicalization
                r.setdefault("SeverityVals", set()).add(sev)
                _update_first_last(r, ts)
                r["Sources"].add(src_label)
                if asset:
                    r["Assets"].add(normalize_asset_name(asset))
                if pnum:
                    r["Ports"].add(str(pnum))
                if success_flag:
                    r["Successes"] = r.get("Successes", 0) + 1
                if priv_flag:
                    r["PrivilegeSeen"] = True
                if lat_flag:
                    r["LateralSeen"] = True

                # correlated: technique on asset
                if asset:
                    k2 = f"T@A:{tech}@{asset}"
                    r2 = ensure_rec(k2, f"{tech} on {asset}", "Technique on Asset", sev, ts, src_label, dst, message)
                    r2["Count"] += 1
                    r2.setdefault("SeverityVals", set()).add(sev)
                    _update_first_last(r2, ts)
                    r2["Sources"].add(src_label)
                    if asset:
                        r2["Assets"].add(normalize_asset_name(asset))
                    if pnum:
                        r2["Ports"].add(str(pnum))
                    if success_flag:
                        r2["Successes"] = r2.get("Successes", 0) + 1
                    if priv_flag:
                        r2["PrivilegeSeen"] = True
                    if lat_flag:
                        r2["LateralSeen"] = True

                # correlated: technique on port
                if pnum:
                    k3 = f"T@P:{tech}@{pnum}"
                    r3 = ensure_rec(k3, f"{tech} on Port {pnum}", "Technique on Port", sev, ts, src_label, dst, message)
                    r3["Count"] += 1
                    r3.setdefault("SeverityVals", set()).add(sev)
                    _update_first_last(r3, ts)
                    r3["Sources"].add(src_label)
                    r3["Ports"].add(str(pnum))
                    if asset:
                        r3["Assets"].add(normalize_asset_name(asset))
                    if success_flag:
                        r3["Successes"] = r3.get("Successes", 0) + 1
                    if priv_flag:
                        r3["PrivilegeSeen"] = True
                    if lat_flag:
                        r3["LateralSeen"] = True

            # Port-only IOC
            if (not techs_unique) and pnum:
                key = f"PORT:{pnum}"
                r = ensure_rec(key, f"Port {pnum}", "Network Port", sev, ts, src_label, dst, message)
                r["Count"] += 1
                r.setdefault("SeverityVals", set()).add(sev)
                _update_first_last(r, ts)
                r["Sources"].add(src_label)
                if asset:
                    r["Assets"].add(normalize_asset_name(asset))
                # FIX #14: Map well-known ports to service names for Asset column
                _PORT_SERVICE_MAP = {
                    5000: "Nginx", 8080: "DVWA", 3307: "MySQL",
                    80: "HTTP", 443: "HTTPS", 22: "SSH", 3306: "MySQL",
                }
                if not asset and pnum in _PORT_SERVICE_MAP:
                    r["Assets"].add(_PORT_SERVICE_MAP[pnum])
                r["Ports"].add(str(pnum))
                if success_flag:
                    r["Successes"] = r.get("Successes", 0) + 1
                if priv_flag:
                    r["PrivilegeSeen"] = True
                if lat_flag:
                    r["LateralSeen"] = True

            # CVE rows — FIX: Link CVE to asset and enrich with CVSS from VULNERABILITY_DB
            if cve and str(cve).upper() not in META_IGNORE:
                key = f"CVE:{cve.upper()}"
                r = ensure_rec(key, cve.upper(), "CVE", sev, ts, src_label, dst, message)
                r["Count"] += 1
                r.setdefault("SeverityVals", set()).add(sev)
                _update_first_last(r, ts)
                r["Sources"].add(src_label)

                # FIX: Enrich CVE row with asset from event AND from VULNERABILITY_DB lookup
                cve_asset = normalize_asset_name(asset) if asset else ""
                if not cve_asset:
                    # Reverse lookup: find which asset has this CVE in VULNERABILITY_DB
                    try:
                        from utils.constants import VULNERABILITY_DB
                        for _asset_name, _vinfo in VULNERABILITY_DB.items():
                            if str(_vinfo.get("cve", "")).upper() == str(cve).upper():
                                cve_asset = _asset_name
                                break
                    except Exception:
                        pass
                if cve_asset:
                    r["Assets"].add(cve_asset)

                # FIX: Store CVSS score on CVE row for display
                try:
                    from utils.constants import VULNERABILITY_DB
                    for _asset_name, _vinfo in VULNERABILITY_DB.items():
                        if str(_vinfo.get("cve", "")).upper() == str(cve).upper():
                            r["CVSS"] = _vinfo.get("cvss", "")
                            r["MITRE"] = _vinfo.get("mitre", "")
                            break
                except Exception:
                    pass

                if pnum:
                    r["Ports"].add(str(pnum))
                if success_flag:
                    r["Successes"] = r.get("Successes", 0) + 1
                if priv_flag:
                    r["PrivilegeSeen"] = True
                if lat_flag:
                    r["LateralSeen"] = True

        # Propagate correlated asset/port info into primary technique records
        for key, rec in list(ioc_map.items()):
            if not key.startswith("TECH:"):
                continue
            tech = key.split(":", 1)[1]
            for k2, r2 in ioc_map.items():
                if k2.startswith(f"T@A:{tech}@") or k2.startswith(f"T@P:{tech}@"):
                    # merge asset/port/source sets
                    rec["Assets"].update(r2.get("Assets", set()))
                    rec["Ports"].update(r2.get("Ports", set()))
                    rec["Sources"].update(r2.get("Sources", set()))
                    # merge observed severities
                    if r2.get("SeverityVals"):
                        rec.setdefault("SeverityVals", set()).update(r2.get("SeverityVals", set()))
                    # merge timestamps using parser-aware helper
                    _merge_timestamps(rec, r2)
                    # merge success/privilege/lateral indicators and stats
                    if r2.get("Successes"):
                        rec["Successes"] = rec.get("Successes", 0) + int(r2.get("Successes", 0))
                    if r2.get("PrivilegeSeen"):
                        rec["PrivilegeSeen"] = True
                    if r2.get("LateralSeen"):
                        rec["LateralSeen"] = True

        # finalize: compute deterministic confidence and normalize
        severity_map = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5}
        out = []
        for rec in ioc_map.values():
            count = int(rec.get("Count", 0))

            # Determine observed severity vals and canonicalize using multiple signals
            sev_vals = rec.get("SeverityVals", set()) or set()
            severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            observed_max = None
            if sev_vals:
                observed_max = max(sev_vals, key=lambda s: severity_rank.get(str(s).upper(), 0))
            else:
                observed_max = rec.get("Severity", "LOW")

            # Attempt to extract base technique from IOC text for technique-driven severity
            base_tech = None
            m = TECH_RE.search(str(rec.get("IOC", "")))
            if m:
                base_tech = m.group(0).upper()

            # Base technique severity from mapping
            base_tech_label = ATTACK_SEVERITY.get(base_tech) if base_tech else None

            # numeric severity contribution (used in confidence)
            sev_score = severity_map.get(str(observed_max).upper(), 0)

            # frequency contribution
            freq_score = min(40, count * 4)

            # correlation strength: assets/ports diversity
            corr_bonus = 0
            assets_set = rec.get("Assets", set()) if isinstance(rec.get("Assets", set()), (set, list)) else set()
            assets_count = len(assets_set)
            ports_set = rec.get("Ports", set()) if isinstance(rec.get("Ports", set()), (set, list)) else set()
            ports_count = len(ports_set)
            if assets_count >= 2:
                corr_bonus += 6
            if ports_count >= 2:
                corr_bonus += 4

            # asset impact: use ASSET_CRITICALITY mapping (take max impacted asset weight)
            asset_crit_weight = 0
            try:
                weights = [ASSET_CRITICALITY.get(a, 1) for a in assets_set if a]
                asset_crit_weight = max(weights) if weights else 1
            except Exception:
                asset_crit_weight = 1
            asset_bonus = min(12, asset_crit_weight * 3)

            # enrichment bonus for CVEs
            enrich_bonus = 0
            if rec.get("Type") == "CVE":
                enrich_bonus += 10

            # success / privilege / lateral indicators
            success_count = int(rec.get("Successes", 0))
            success_bonus = min(20, success_count * 8) if success_count > 0 else 0
            priv_bonus = 10 if rec.get("PrivilegeSeen") else 0
            lat_bonus = 10 if rec.get("LateralSeen") else 0

            # incorporate base technique guidance into severity decision
            tech_base_score = 0
            if base_tech_label:
                tech_base_score = severity_rank.get(str(base_tech_label).upper(), 0) * 8

            # final risk value for severity classification
            risk_value = freq_score + sev_score + corr_bonus + enrich_bonus + asset_bonus + success_bonus + priv_bonus + lat_bonus + tech_base_score

            if risk_value >= 70:
                final_sev_label = "CRITICAL"
            elif risk_value >= 45:
                final_sev_label = "HIGH"
            elif risk_value >= 25:
                final_sev_label = "MEDIUM"
            else:
                final_sev_label = "LOW"

            # Deterministic confidence calculation enhanced with success/correlation/asset
            confidence = int(min(98, freq_score + severity_map.get(final_sev_label, 0) + corr_bonus + enrich_bonus + asset_bonus + (success_bonus // 2) + priv_bonus + lat_bonus))

            rec["Confidence"] = confidence
            rec["Severity"] = str(final_sev_label).upper()
            rec["Source"] = ", ".join(sorted(rec.get("Sources", []))) if rec.get("Sources") else ""
            # produce canonical Asset and Ports strings
            try:
                assets_list = sorted({a for a in (rec.get("Assets") or []) if a})
            except Exception:
                assets_list = [a for a in (rec.get("Assets") or []) if a]
            rec["Asset"] = ", ".join(assets_list) if assets_list else ""
            # FIX: Carry CVSS and related MITRE technique into final output for CVE rows
            if rec.get("Type") == "CVE":
                if "CVSS" not in rec:
                    rec["CVSS"] = ""
                if "MITRE" not in rec:
                    rec["MITRE"] = ""
            try:
                ports_list = sorted({p for p in (rec.get("Ports") or []) if p}, key=lambda x: int(x))
            except Exception:
                ports_list = sorted({p for p in (rec.get("Ports") or []) if p})
            rec["Ports"] = ",".join(ports_list) if ports_list else ""
            # cleanup helper sets
            rec.pop("Sources", None)
            rec.pop("Assets", None)
            rec.pop("Ports", None)
            rec.pop("SeverityVals", None)
            rec.pop("Successes", None)
            rec.pop("PrivilegeSeen", None)
            rec.pop("LateralSeen", None)
            # FIX: Keep CVSS and MITRE on CVE rows for display
            out.append(rec)

        df = pd.DataFrame(out)

        # Ensure consistent columns exist
        for c in ["First Seen", "Last Seen", "Evidence", "Asset", "Ports", "Source", "Destination", "CVSS", "MITRE"]:
            if c not in df.columns:
                df[c] = ""

        # FIX: Replace nan/None/NaN in CVSS column with empty string for all row types
        # Technique rows get nan because VULNERABILITY_DB lookup fails for unmapped techniques
        

        if "Count" in df.columns:
            df = df.sort_values("Count", ascending=False).reset_index(drop=True)

        # FIX: Replace nan in CVSS column with empty string
        if "CVSS" in df.columns:
            df["CVSS"] = df["CVSS"].astype(str).replace(
                {"nan": "", "NaN": "", "None": "", "none": ""}
            )

        return df