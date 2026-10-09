# Title: Meterpreter or Cobalt Strike Getsystem Service Installation - Security
# ID: ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34
# Status: test
# Level: high
# Author: Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
# Date: 2019-10-26
# Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.002
# Description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Meterpreter or Cobalt Strike Getsystem Service Installation - Security
def rule(event):
    # Detection Logic:
    # ((EventID="4697") AND (((ServiceFileName="*/c*" AND ServiceFileName="*echo*" AND ServiceFileName="*\\pipe\\*") AND (ServiceFileName="*cmd*" OR ServiceFileName="*%COMSPEC%*")) OR ((ServiceFileName="*rundll32*" AND ServiceFileName="*.dll,a*" AND ServiceFileName="*/p:*")) OR (ServiceFileName="\\\\\\\\127.0.0.1\\\\ADMIN$\\*")))
    return True

def title(event):
    return "Meterpreter or Cobalt Strike Getsystem Service Installation - Security"

