"""MITRE ATT&CK score table per classified attack class."""

SCORE_BY_LABEL: dict[str, int] = {
    "Etc": 0,
    "Recon": 32,
    "Brute Force": 65,
    "Intrusion": 85,
    "Malware": 92,
}

TECHNIQUE_BY_LABEL: dict[str, str] = {
    "Etc": "",
    "Recon": "T1046",
    "Brute Force": "T1110",
    "Intrusion": "T1059",
    "Malware": "T1105",
}


def score_for(label: str) -> int:
    return SCORE_BY_LABEL.get(label, 50)


def technique_for(label: str) -> str:
    return TECHNIQUE_BY_LABEL.get(label, "")
