import importlib
m = importlib.import_module('exports.pdf_exporter')
# representative session-like data
soc_metrics = {
    'incident_status': 'ACTIVE',
    'threat_level': 'HIGH',
    'risk_score': 78.5,
    'compromised_assets': ['host1', 'host2'],
    'defense_effectiveness': 'Moderate',
    'soc_recommendation': 'Isolate hosts',
    'tactical_recommendation': ['Isolate host1', 'Block IP 1.2.3.4'],
    'executive_response_strategy': 'Activate incident response'
}
sidebar_summary = {'status': 'OK'}
attack_timeline_df = [
    {'Time':'2026-05-24 10:00','Stage':'Initial Access','Severity':'High','Technique':'Phishing','Target Node':'host1','CVE':'','Event Summary':'Phishing link clicked'},
    {'Time':'2026-05-24 10:05','Stage':'Execution','Severity':'High','Technique':'Malware','Target Node':'host1','CVE':'','Event Summary':'Payload executed'}
]
mitre_df = [{'Technique':'Phishing','Count':5},{'Technique':'Malware','Count':2}]
ioc_df = [{'IOC':'1.2.3.4','Type':'IP','Severity':'High','First Seen':'2026-05-24','Count':3,'Confidence':90}]
live_feed = ['Alert 1', ['nested','list','entry'], {'msg':'dict entry'}]

pdf = m.generate_soc_pdf_report(soc_metrics, sidebar_summary, attack_timeline_df, mitre_df, ioc_df, live_feed)
print('PDF_LEN', len(pdf))
