# Title: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
# ID: a7c3d773-caef-227e-a7e7-c2f13c622329
# Status: test
# Level: high
# Author: Oleg Kolesnikov @securonix invrep_de, oscd.community, Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
# Date: 2020-10-23
# Tags: attack.stealth, attack.t1218.011
# Description: Detects attackers using tooling with bad opsec defaults.
# E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run.
# One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
def rule(event):
    # Detection Logic:
    # (((Image="*\\regasm.exe" AND CommandLine="*regasm.exe") OR (Image="*\\regsvcs.exe" AND CommandLine="*regsvcs.exe") OR (Image="*\\regsvr32.exe" AND CommandLine="*regsvr32.exe") OR (Image="*\\rundll32.exe" AND CommandLine="*rundll32.exe") OR (Image="*\\WerFault.exe" AND CommandLine="*WerFault.exe")) AND NOT ((((ParentImage="*\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\*" OR ParentImage="*\\AppData\\Local\\Google\\Chrome\\Application\\*") AND ParentImage="*\\Installer\\setup.exe" AND ParentCommandLine="*--uninstall *" AND Image="*\\rundll32.exe" AND CommandLine="*rundll32.exe") OR (ParentImage="*\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{*" AND Image="*\\rundll32.exe" AND CommandLine="*rundll32.exe"))))
    return True

def title(event):
    return "Bad Opsec Defaults Sacrificial Processes With Improper Arguments"

