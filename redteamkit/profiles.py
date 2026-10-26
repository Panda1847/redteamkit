"""
Adversary / APT profile library.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AdversaryProfile:
    name: str
    aliases: List[str] = field(default_factory=list)
    origin: str = ""
    motivation: str = ""
    target_sectors: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)          # ATT&CK technique IDs
    tools: List[str] = field(default_factory=list)
    infrastructure: List[str] = field(default_factory=list)
    operational_notes: str = ""
    fidelity_notes: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    generated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "aliases": self.aliases,
            "origin": self.origin,
            "motivation": self.motivation,
            "target_sectors": self.target_sectors,
            "ttps": self.ttps,
            "tools": self.tools,
            "infrastructure": self.infrastructure,
            "operational_notes": self.operational_notes,
            "fidelity_notes": self.fidelity_notes,
            "generated": self.generated,
        }

    def summary(self) -> str:
        lines = [
            f"=== {self.name} ===",
            f"Aliases: {', '.join(self.aliases) or '—'}",
            f"Origin: {self.origin or '—'}",
            f"Motivation: {self.motivation or '—'}",
            f"Sectors: {', '.join(self.target_sectors) or '—'}",
            f"Key TTPs ({len(self.ttps)}): {', '.join(self.ttps[:12])}{'...' if len(self.ttps) > 12 else ''}",
            f"Tools: {', '.join(self.tools) or '—'}",
            f"Infra patterns: {', '.join(self.infrastructure) or '—'}",
            f"Source: {'generated' if self.generated else 'hand-maintained'}",
        ]
        if self.operational_notes:
            lines.append(f"Ops notes: {self.operational_notes}")
        if self.fidelity_notes:
            lines.append(f"Fidelity: {self.fidelity_notes}")
        return "\n".join(lines)


# Built-in high-fidelity profiles
_PROFILES: Dict[str, AdversaryProfile] = {}
_GENERATED: Dict[str, AdversaryProfile] = {}
_LOADED = False


def _add(p: AdversaryProfile):
    key = p.name.lower().replace(" ", "")
    _PROFILES[key] = p
    for a in p.aliases:
        _PROFILES[a.lower().replace(" ", "")] = p
    return p


_add(AdversaryProfile(
    name="APT29",
    aliases=["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard"],
    origin="Russia (SVR)",
    motivation="Espionage, strategic intelligence",
    target_sectors=["Government", "Think tanks", "Technology", "Healthcare", "NGOs"],
    ttps=[
        "T1566", "T1078", "T1059", "T1053", "T1003", "T1021",
        "T1071", "T1041", "T1027", "T1070", "T1547", "T1082",
        "T1018", "T1550", "T1567"
    ],
    tools=["WellMess", "WellMail", "Cobalt Strike", "GoldMax", "Sunburst (historical)"],
    infrastructure=["Compromised websites", "Cloud services (Azure, AWS)", "Domain fronting", "Residential proxies"],
    operational_notes="Extremely patient, high OPSEC, prefers living-off-the-land and legitimate cloud services. Long dwell times.",
    fidelity_notes="Emulate slow, quiet progression. Heavy use of valid accounts and cloud. Avoid noisy tools early."
))

_add(AdversaryProfile(
    name="APT28",
    aliases=["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"],
    origin="Russia (GRU)",
    motivation="Espionage, influence operations",
    target_sectors=["Government", "Military", "Media", "Political organizations"],
    ttps=[
        "T1566", "T1190", "T1059", "T1003", "T1021", "T1071",
        "T1041", "T1027", "T1070", "T1547", "T1053", "T1082"
    ],
    tools=["X-Agent", "X-Tunnel", "Zebrocy", "Komplex", "Cannon"],
    infrastructure=["Bulletproof hosting", "Compromised sites", "Fast-flux"],
    operational_notes="More aggressive than APT29. Frequently uses zero-days and custom malware. Political targeting common.",
    fidelity_notes="Can be noisier. Credential dumping and lateral movement via RDP/SMB are signature."
))

_add(AdversaryProfile(
    name="APT41",
    aliases=["Double Dragon", "Barium", "Winnti"],
    origin="China",
    motivation="Espionage + financially motivated operations",
    target_sectors=["Healthcare", "Telecom", "High-tech", "Gaming", "Government"],
    ttps=[
        "T1190", "T1566", "T1078", "T1059", "T1003", "T1021",
        "T1053", "T1071", "T1041", "T1027", "T1562", "T1550"
    ],
    tools=["Cobalt Strike", "Custom backdoors", "Supply-chain implants"],
    infrastructure=["Supply-chain compromise", "Cloud", "Compromised software update channels"],
    operational_notes="Dual-use: state espionage and moonlighting criminal activity. Fast when needed.",
    fidelity_notes="Include supply-chain or software update themes for high fidelity."
))

_add(AdversaryProfile(
    name="FIN7",
    aliases=["Carbanak", "Navigator Group"],
    origin="Unknown (financially motivated)",
    motivation="Financial gain — payment card data, ransomware",
    target_sectors=["Retail", "Hospitality", "Restaurants", "Finance"],
    ttps=[
        "T1566", "T1059", "T1003", "T1021", "T1053", "T1071",
        "T1041", "T1027", "T1078", "T1550", "T1560"
    ],
    tools=["Carbanak", "Griffon", "Cobalt Strike", "POWERSOURCE", "BABYMETAL"],
    infrastructure=["Phishing infrastructure", "Compromised sites", "Bulletproof"],
    operational_notes="Highly professional, uses sophisticated social engineering and living-off-the-land. Often targets POS.",
    fidelity_notes="Strong phishing + rapid credential + lateral to payment systems. Avoid destructive unless scoped."
))

_add(AdversaryProfile(
    name="Lazarus",
    aliases=["Hidden Cobra", "Guardians of Peace", "ZINC"],
    origin="North Korea",
    motivation="Financial (crypto, banks) + espionage + destructive",
    target_sectors=["Finance", "Cryptocurrency", "Defense", "Media", "Critical infrastructure"],
    ttps=[
        "T1566", "T1190", "T1059", "T1003", "T1021", "T1486",
        "T1071", "T1041", "T1027", "T1562", "T1053"
    ],
    tools=["Custom loaders", "HOPLIGHT", "BLINDINGCAN", "Wiper variants"],
    infrastructure=["Compromised sites", "Cloud", "Cryptocurrency mixers"],
    operational_notes="Wide spectrum: theft, espionage, and destructive attacks. High risk of impact techniques.",
    fidelity_notes="Only include destructive (T1486) if explicitly authorized with full rollback. Otherwise stop at collection/exfil."
))

_add(AdversaryProfile(
    name="Turla",
    aliases=["Snake", "Uroburos", "Venomous Bear"],
    origin="Russia",
    motivation="Espionage",
    target_sectors=["Government", "Military", "Diplomacy", "Research"],
    ttps=[
        "T1566", "T1190", "T1059", "T1003", "T1021", "T1071",
        "T1041", "T1027", "T1070", "T1547", "T1090"
    ],
    tools=["Snake", "Carbon", "Gazer", "Mosquito", "ComRAT"],
    infrastructure=["Satellite links (historical)", "Compromised sites", "Complex multi-hop"],
    operational_notes="Extremely sophisticated C2, long-term presence, high OPSEC.",
    fidelity_notes="Focus on complex C2 and long dwell. Quiet persistence."
))

_add(AdversaryProfile(
    name="Custom",
    aliases=[],
    origin="Engagement-defined",
    motivation="Defined by campaign objectives",
    target_sectors=[],
    ttps=["T1566", "T1059", "T1003", "T1021", "T1071", "T1041"],
    tools=["Cobalt Strike", "Sliver", "Mythic", "Custom"],
    infrastructure=["Engagement-specific"],
    operational_notes="Generic advanced threat profile for when no specific actor is required.",
    fidelity_notes="Tune TTPs to the client's actual threat model."
))


def list_profiles() -> List[str]:
    registry = _build_registry()
    seen = set()
    names = []
    for p in registry.values():
        if p.name not in seen:
            seen.add(p.name)
            names.append(p.name)
    return sorted(names)


def load_profile(name: str) -> Optional[AdversaryProfile]:
    registry = _build_registry()
    key = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    return registry.get(key)


def search_profiles(keyword: str) -> List[AdversaryProfile]:
    registry = _build_registry()
    kw = keyword.lower()
    results = []
    seen = set()
    for p in registry.values():
        if p.name in seen:
            continue
        if (kw in p.name.lower() or any(kw in a.lower() for a in p.aliases)
                or kw in p.origin.lower() or kw in p.motivation.lower()):
            results.append(p)
            seen.add(p.name)
    return results


def load_generated_profiles(records: List[Dict[str, Any]]) -> None:
    """Load ATT&CK-derived profiles into a separate registry."""
    _GENERATED.clear()
    for record in records:
        name = record.get("name") or record.get("attack_id")
        if not name:
            continue
        profile = AdversaryProfile(
            name=name,
            aliases=list(record.get("aliases") or []),
            motivation="ATT&CK intrusion-set profile",
            ttps=list(record.get("ttps") or []),
            operational_notes=record.get("description", ""),
            generated=True,
        )
        key = name.lower().replace(" ", "").replace("-", "").replace("_", "")
        _GENERATED[key] = profile
        for alias in profile.aliases:
            _GENERATED[alias.lower().replace(" ", "").replace("-", "").replace("_", "")] = profile


def _ensure_generated_loaded() -> None:
    """Load ATT&CK-derived profiles once, tolerating a missing/seed index."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        from .attackdata import data_path, load_index
        index = load_index(data_path())
    except Exception:
        return
    records = []
    for gid, group in (index.get("groups") or {}).items():
        if not group.get("ttps") or group.get("deprecated") or group.get("revoked"):
            continue
        records.append({
            "attack_id": gid,
            "name": group.get("name", ""),
            "aliases": group.get("aliases") or [],
            "description": group.get("description", ""),
            "ttps": group["ttps"],
        })
    load_generated_profiles(records)


def _build_registry() -> Dict[str, AdversaryProfile]:
    _ensure_generated_loaded()
    registry = dict(_GENERATED)
    for key, profile in _PROFILES.items():
        registry[key] = profile
    return registry
