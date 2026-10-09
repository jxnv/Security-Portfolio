# Title: Persistence Via Sudoers Files
# ID: ddb26b76-4447-4807-871f-1b035b2bfa5d
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-05
# Tags: attack.privilege-escalation, attack.persistence, attack.t1548.003
# Description: Detects the creation or modification of the main "/etc/sudoers" file or files within the "/etc/sudoers.d/" directory on Linux systems.
# Adversaries may alter sudoers configuration to execute commands with elevated privileges without supplying a password.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Persistence Via Sudoers Files
def rule(event):
    # Detection Logic:
    # (((TargetFilename="/etc/sudoers") OR (TargetFilename="/etc/sudoers.d/*")) AND NOT ((Image="*/usr/bin/dpkg" AND TargetFilename="/etc/sudoers.d/README.dpkg-new")))
    return True

def title(event):
    return "Persistence Via Sudoers Files"

