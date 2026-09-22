"""Subconjunto de referencia de MITRE ATT&CK (Enterprise) usado para el
gap analysis de purple-service. Son solo METADATOS PUBLICOS (id, nombre,
tactica) tomados del framework -- no hay aca ni codigo de explotacion ni
logica de ejecucion de ninguna tecnica. La cobertura de deteccion se
calcula cruzando estos ids contra los tags de las reglas Sigma habilitadas
en siem-service (ver app/services.py: compute_coverage)."""

ATTACK_TECHNIQUES = [
    {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    {"technique_id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    {"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
]
