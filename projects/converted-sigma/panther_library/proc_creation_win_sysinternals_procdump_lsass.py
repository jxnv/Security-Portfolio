# Title: Potential LSASS Process Dump Via Procdump
# ID: 5afee48e-67dd-4e03-a783-f74259dcf998
# Status: stable
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2018-10-30
# Tags: attack.stealth, attack.t1036, attack.credential-access, attack.t1003.001, car.2013-05-009
# Description: Detects potential credential harvesting attempts through LSASS memory dumps using ProcDump.
# This rule identifies suspicious command-line patterns that combine memory dump flags (-ma, -mm, -mp) with LSASS-related process markers.
# LSASS (Local Security Authority Subsystem Service) contains sensitive authentication data including plaintext passwords, NTLM hashes, and Kerberos tickets in memory.
# Attackers commonly dump LSASS memory to extract credentials for lateral movement and privilege escalation.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential LSASS Process Dump Via Procdump
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -ma *" OR CommandLine="* -mm *" OR CommandLine="* -mp *")) AND ((CommandLine="* ls*" OR CommandLine="* keyiso*" OR CommandLine="* samss*")))
    return True

def title(event):
    return "Potential LSASS Process Dump Via Procdump"

