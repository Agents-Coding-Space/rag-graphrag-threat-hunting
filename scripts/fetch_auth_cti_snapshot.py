"""Acquire the one additional authentication CTI report needed by the new study."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import fetch_cti_snapshots

fetch_cti_snapshots.SOURCES = ((
    "microsoft-password-spray",
    "https://www.microsoft.com/en-us/security/blog/2024/10/31/chinese-threat-actor-storm-0940-uses-credentials-from-password-spray-attacks-from-a-covert-network/",
    "Microsoft Threat Intelligence",
    "Chinese threat actor Storm-0940 uses credentials from password spray attacks from a covert network",
),)

if __name__ == "__main__":
    fetch_cti_snapshots.main()
