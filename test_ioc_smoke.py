from analytics.ioc_engine import IOCEngine

events = [
    {"timestamp":"2026-06-08T12:00:00","technique":"T1547","mitre_name":"Boot or Logon Autostart Execution","port":3307,"cve":"CVE-2016-6662","service":"mysql","node":"Database","source":"Attacker","detection_confidence":85,"actor":"attacker","message":"sample event 1"},
    {"timestamp":"2026-06-08T12:01:00","technique":"T1595","mitre_name":"Active Scanning","port":8080,"service":"nginx","node":"Webserver","source":"Attacker","detection_confidence":60,"actor":"attacker","message":"sample event 2"},
    {"timestamp":"2026-06-08T12:02:00","technique":"T1190","mitre_name":"Exploit Public-Facing Application","port":5000,"cve":"CVE-2021-23017","service":"dvwa","node":"Firewall / DVWA","source":"Attacker","detection_confidence":92,"actor":"attacker","message":"sample event 3"},
]

df = IOCEngine.generate_registry_df(events)
print('rows:', len(df))
print(df.head(20).to_string(index=False))
print('columns:', df.columns.tolist())
