"""
MITRE ATT&CK technique library and mapping utilities.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


class Tactic(Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class Technique:
    technique_id: str
    name: str
    tactic: Tactic
    description: str = ""
    platforms: List[str] = field(default_factory=lambda: ["Windows", "Linux", "macOS"])
    data_sources: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    subtechniques: List[str] = field(default_factory=list)
    detection_priority: str = "medium"  # critical, high, medium, low
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.name,
            "tactic_id": self.tactic.value,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "detections": self.detections,
            "mitigations": self.mitigations,
            "detection_priority": self.detection_priority,
            "notes": self.notes,
        }

    def __str__(self):
        return f"{self.technique_id} — {self.name} [{self.tactic.name}]"


# Core high-value technique library (expandable)
_TECHNIQUES: Dict[str, Technique] = {}


def _reg(t: Technique):
    _TECHNIQUES[t.technique_id] = t
    return t


# --- Initial Access ---
_reg(Technique("T1566", "Phishing", Tactic.INITIAL_ACCESS,
    data_sources=["Email gateway", "User reports", "Web proxy"],
    detections=["Suspicious attachment / link", "First-time sender", "Lookalike domain"],
    mitigations=["User training", "Email filtering", "Attachment sandboxing"],
    detection_priority="high",
    subtechniques=["T1566.001", "T1566.002", "T1566.003"]))

_reg(Technique("T1190", "Exploit Public-Facing Application", Tactic.INITIAL_ACCESS,
    data_sources=["Web logs", "WAF", "IDS"],
    detections=["Exploit attempt signatures", "Unusual request patterns"],
    mitigations=["Patching", "WAF", "Network segmentation"],
    detection_priority="critical"))

_reg(Technique("T1078", "Valid Accounts", Tactic.INITIAL_ACCESS,
    data_sources=["Authentication logs", "Identity provider"],
    detections=["Impossible travel", "Unusual login time/location", "MFA fatigue"],
    mitigations=["MFA", "Conditional access", "Privileged access management"],
    detection_priority="critical"))

_reg(Technique("T1133", "External Remote Services", Tactic.INITIAL_ACCESS,
    data_sources=["VPN logs", "Firewall", "Identity"],
    detections=["Brute force", "Unusual source geo", "New device"],
    mitigations=["MFA", "Geo restrictions", "Device posture"],
    detection_priority="high"))

# --- Execution ---
_reg(Technique("T1059", "Command and Scripting Interpreter", Tactic.EXECUTION,
    data_sources=["Process creation", "Script block logging", "Command-line logging"],
    detections=["powershell -enc", "Unusual parent-child", "LOLBins"],
    mitigations=["Application control", "Constrained language mode", "Script block logging"],
    detection_priority="critical",
    subtechniques=["T1059.001", "T1059.003", "T1059.004"]))

_reg(Technique("T1047", "Windows Management Instrumentation", Tactic.EXECUTION,
    data_sources=["WMI logs", "Process creation"],
    detections=["wmic process call create", "Unusual WMI consumers"],
    mitigations=["WMI filtering", "Process monitoring"],
    detection_priority="high"))

_reg(Technique("T1204", "User Execution", Tactic.EXECUTION,
    data_sources=["Process creation", "File creation", "Email"],
    detections=["User opened attachment / link leading to process"],
    mitigations=["User training", "Attachment blocking", "Mark of the Web"],
    detection_priority="high"))

# --- Persistence ---
_reg(Technique("T1053", "Scheduled Task/Job", Tactic.PERSISTENCE,
    data_sources=["Scheduled task logs", "Process creation"],
    detections=["New scheduled task", "Task running from unusual path"],
    mitigations=["Audit task creation", "Restrict schtasks"],
    detection_priority="high",
    subtechniques=["T1053.005"]))

_reg(Technique("T1547", "Boot or Logon Autostart Execution", Tactic.PERSISTENCE,
    data_sources=["Registry", "File monitoring", "Process creation"],
    detections=["New Run key", "New service", "Startup folder write"],
    mitigations=["Registry auditing", "Application control"],
    detection_priority="high"))

_reg(Technique("T1136", "Create Account", Tactic.PERSISTENCE,
    data_sources=["Account management logs", "Directory service"],
    detections=["New local / domain account", "Account added to privileged group"],
    mitigations=["Privileged access management", "Account creation alerts"],
    detection_priority="high"))

# --- Privilege Escalation ---
_reg(Technique("T1068", "Exploitation for Privilege Escalation", Tactic.PRIVILEGE_ESCALATION,
    data_sources=["Process creation", "Kernel logs"],
    detections=["Exploit attempt", "Unusual process privileges"],
    mitigations=["Patching", "Exploit protection", "Least privilege"],
    detection_priority="critical"))

_reg(Technique("T1548", "Abuse Elevation Control Mechanism", Tactic.PRIVILEGE_ESCALATION,
    data_sources=["Process creation", "Token logs"],
    detections=["UAC bypass patterns", "token manipulation"],
    mitigations=["UAC highest", "Remove local admin rights"],
    detection_priority="high"))

# --- Defense Evasion ---
_reg(Technique("T1027", "Obfuscated Files or Information", Tactic.DEFENSE_EVASION,
    data_sources=["File", "Process", "Script logs"],
    detections=["High entropy", "Encoded PowerShell", "Packed binaries"],
    mitigations=["AMSI", "Script block logging", "EDR"],
    detection_priority="medium"))

_reg(Technique("T1070", "Indicator Removal", Tactic.DEFENSE_EVASION,
    data_sources=["File deletion", "Log clearing", "Process"],
    detections=["wevtutil cl", "log cleared", "timestomp"],
    mitigations=["Centralized logging", "Tamper protection", "SIEM"],
    detection_priority="critical"))

_reg(Technique("T1562", "Impair Defenses", Tactic.DEFENSE_EVASION,
    data_sources=["Process", "Service", "Registry"],
    detections=["Security tool stopped", "Defender disabled", "ETW tampering"],
    mitigations=["Tamper protection", "EDR self-protection", "Alert on security tool state"],
    detection_priority="critical"))

# --- Credential Access ---
_reg(Technique("T1003", "OS Credential Dumping", Tactic.CREDENTIAL_ACCESS,
    data_sources=["Process access", "LSASS access", "File"],
    detections=["LSASS memory access", "procdump", "mimikatz-like behavior", "ntdsutil"],
    mitigations=["Credential Guard", "LSA protection", "Privileged access workstations"],
    detection_priority="critical",
    subtechniques=["T1003.001", "T1003.002", "T1003.003"]))

_reg(Technique("T1110", "Brute Force", Tactic.CREDENTIAL_ACCESS,
    data_sources=["Authentication logs"],
    detections=["High failure rate", "Password spray patterns"],
    mitigations=["Account lockout", "MFA", "Smart lockout"],
    detection_priority="high"))

_reg(Technique("T1558", "Steal or Forge Kerberos Tickets", Tactic.CREDENTIAL_ACCESS,
    data_sources=["Kerberos logs", "Process"],
    detections=["Anomalous TGS requests", "Golden / Silver ticket indicators"],
    mitigations=["Protected Users group", "Tiered admin model", "Kerberos monitoring"],
    detection_priority="critical"))

# --- Discovery ---
_reg(Technique("T1082", "System Information Discovery", Tactic.DISCOVERY,
    data_sources=["Process creation", "Command-line"],
    detections=["systeminfo", "hostname", "uname patterns in suspicious context"],
    mitigations=["Process monitoring"],
    detection_priority="low"))

_reg(Technique("T1018", "Remote System Discovery", Tactic.DISCOVERY,
    data_sources=["Network flow", "Process", "Directory"],
    detections=["Network scans from workstation", "Unusual LDAP queries"],
    mitigations=["Network segmentation", "Monitor scanning"],
    detection_priority="medium"))

_reg(Technique("T1087", "Account Discovery", Tactic.DISCOVERY,
    data_sources=["Process", "Directory service"],
    detections=["net user / domain", "large LDAP queries"],
    mitigations=["Monitor directory enumeration"],
    detection_priority="medium"))

# --- Lateral Movement ---
_reg(Technique("T1021", "Remote Services", Tactic.LATERAL_MOVEMENT,
    data_sources=["Authentication", "Network", "Process"],
    detections=["RDP / SMB / WinRM from unusual source", "Lateral auth spikes"],
    mitigations=["Network segmentation", "Privileged access workstations", "MFA for remote"],
    detection_priority="critical",
    subtechniques=["T1021.001", "T1021.002", "T1021.006"]))

_reg(Technique("T1550", "Use Alternate Authentication Material", Tactic.LATERAL_MOVEMENT,
    data_sources=["Authentication", "Process"],
    detections=["Pass-the-hash", "Pass-the-ticket indicators"],
    mitigations=["Credential Guard", "Protected Users", "Restrict NTLM"],
    detection_priority="critical"))

_reg(Technique("T1570", "Lateral Tool Transfer", Tactic.LATERAL_MOVEMENT,
    data_sources=["File", "Network", "Process"],
    detections=["Tool staging on multiple hosts", "Unusual file copy patterns"],
    mitigations=["Application control", "Network monitoring"],
    detection_priority="high"))

# --- Collection ---
_reg(Technique("T1005", "Data from Local System", Tactic.COLLECTION,
    data_sources=["File access", "Process"],
    detections=["Mass file access", "Sensitive file reads"],
    mitigations=["DLP", "File auditing"],
    detection_priority="medium"))

_reg(Technique("T1560", "Archive Collected Data", Tactic.COLLECTION,
    data_sources=["Process", "File"],
    detections=["7z / rar / tar of sensitive paths"],
    mitigations=["Process monitoring", "DLP"],
    detection_priority="medium"))

# --- C2 ---
_reg(Technique("T1071", "Application Layer Protocol", Tactic.COMMAND_AND_CONTROL,
    data_sources=["Network flow", "Proxy", "DNS"],
    detections=["Unusual HTTP/S beaconing", "Long connections", "Domain fronting indicators"],
    mitigations=["Proxy inspection", "TLS inspection", "Beacon detection"],
    detection_priority="high"))

_reg(Technique("T1090", "Proxy", Tactic.COMMAND_AND_CONTROL,
    data_sources=["Network"],
    detections=["Internal proxying", "Unusual SOCKS / port forwarding"],
    mitigations=["Network segmentation", "Egress filtering"],
    detection_priority="high"))

_reg(Technique("T1573", "Encrypted Channel", Tactic.COMMAND_AND_CONTROL,
    data_sources=["Network", "TLS logs"],
    detections=["Encrypted beacons", "Certificate anomalies"],
    mitigations=["TLS inspection where appropriate", "JA3 / JA4"],
    detection_priority="medium"))

# --- Exfiltration ---
_reg(Technique("T1041", "Exfiltration Over C2 Channel", Tactic.EXFILTRATION,
    data_sources=["Network", "Proxy"],
    detections=["Large outbound over known C2", "Beacon size increase"],
    mitigations=["Egress filtering", "DLP", "Bandwidth anomaly detection"],
    detection_priority="high"))

_reg(Technique("T1048", "Exfiltration Over Alternative Protocol", Tactic.EXFILTRATION,
    data_sources=["Network", "DNS", "ICMP"],
    detections=["DNS tunneling", "ICMP exfil", "Unusual protocol volume"],
    mitigations=["Protocol filtering", "DNS monitoring", "DLP"],
    detection_priority="high"))

_reg(Technique("T1567", "Exfiltration Over Web Service", Tactic.EXFILTRATION,
    data_sources=["Proxy", "Cloud logs", "Network"],
    detections=["Upload to cloud storage / paste sites / Discord / Telegram"],
    mitigations=["Cloud DLP", "Proxy category blocking", "CASB"],
    detection_priority="high"))


class AttackLibrary:
    """Query and filter the ATT&CK technique library."""

    def __init__(self):
        self.techniques = dict(_TECHNIQUES)

    def get(self, technique_id: str) -> Optional[Technique]:
        return self.techniques.get(technique_id.upper())

    def by_tactic(self, tactic: Tactic) -> List[Technique]:
        return [t for t in self.techniques.values() if t.tactic == tactic]

    def by_priority(self, priority: str) -> List[Technique]:
        return [t for t in self.techniques.values() if t.detection_priority == priority.lower()]

    def search(self, keyword: str) -> List[Technique]:
        kw = keyword.lower()
        return [t for t in self.techniques.values()
                if kw in t.name.lower() or kw in t.technique_id.lower() or kw in t.description.lower()]

    def high_value(self) -> List[Technique]:
        return self.by_priority("critical") + self.by_priority("high")

    def all_ids(self) -> List[str]:
        return sorted(self.techniques.keys())

    def coverage_matrix(self, selected_ids: List[str]) -> Dict[str, List[str]]:
        """Return tactic -> list of technique IDs for a selected set."""
        matrix: Dict[str, List[str]] = {}
        for tid in selected_ids:
            t = self.get(tid)
            if t:
                key = t.tactic.name
                matrix.setdefault(key, []).append(tid)
        return matrix

    def summary(self) -> str:
        lines = [f"AttackLibrary: {len(self.techniques)} techniques loaded"]
        for tac in Tactic:
            count = len(self.by_tactic(tac))
            if count:
                lines.append(f"  {tac.name}: {count}")
        return "\n".join(lines)


def get_technique(technique_id: str) -> Optional[Technique]:
    return AttackLibrary().get(technique_id)
