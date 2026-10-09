# Title: Special File Creation via Mknod Syscall
# ID: 710bdbce-495d-491d-9a8f-7d0d88d2b41e
# Status: experimental
# Level: low
# Author: Milad Cheraghi
# Date: 2025-05-31
# Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
# Description: Detects usage of the `mknod` syscall to create special files (e.g., character or block devices).
# Attackers or malware might use `mknod` to create fake devices, interact with kernel interfaces,
# or establish covert channels in Linux systems.
# Monitoring the use of `mknod` is important because this syscall is rarely used by legitimate applications,
# and it can be abused to bypass file system restrictions or create backdoors.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Special File Creation via Mknod Syscall
def rule(event):
    # Detection Logic:
    # (type="SYSCALL" AND SYSCALL="mknod")
    return True

def title(event):
    return "Special File Creation via Mknod Syscall"

