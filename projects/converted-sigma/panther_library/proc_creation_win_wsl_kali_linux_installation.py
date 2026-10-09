# Title: Installation of WSL Kali-Linux
# ID: eca8ae39-5c3c-4321-b538-9e64fe25822e
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-10-10
# Tags: attack.execution, attack.t1059
# Description: Detects installation of Kali Linux distribution through Windows Subsystem for Linux (WSL).
# Attackers may use Kali Linux WSL to leverage its penetration testing tools and capabilities for malicious purposes.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Installation of WSL Kali-Linux
def rule(event):
    # Detection Logic:
    # (((Image="*\\wsl.exe") OR (OriginalFileName="wsl")) AND ((CommandLine="* --install *" OR CommandLine="* -i *")) AND (CommandLine="*kali*"))
    return True

def title(event):
    return "Installation of WSL Kali-Linux"

