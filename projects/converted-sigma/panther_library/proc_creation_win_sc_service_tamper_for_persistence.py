# Title: Potential Persistence Attempt Via Existing Service Tampering
# ID: 38879043-7e1e-47a9-8d46-6bec88e201df
# Status: test
# Level: medium
# Author: Sreeman
# Date: 2020-09-29
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1543.003, attack.t1574.011
# Description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Attempt Via Existing Service Tampering
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*sc *" AND CommandLine="*config *" AND CommandLine="*binpath=*")) OR ((CommandLine="*sc *" AND CommandLine="*failure*" AND CommandLine="*command=*"))) OR (((CommandLine="*.sh*" OR CommandLine="*.exe*" OR CommandLine="*.dll*" OR CommandLine="*.bin$*" OR CommandLine="*.bat*" OR CommandLine="*.cmd*" OR CommandLine="*.js*" OR CommandLine="*.msh$*" OR CommandLine="*.reg$*" OR CommandLine="*.scr*" OR CommandLine="*.ps*" OR CommandLine="*.vb*" OR CommandLine="*.jar*" OR CommandLine="*.pl*")) AND (((CommandLine="*reg *" AND CommandLine="*add *" AND CommandLine="*FailureCommand*")) OR ((CommandLine="*reg *" AND CommandLine="*add *" AND CommandLine="*ImagePath*")))))
    return True

def title(event):
    return "Potential Persistence Attempt Via Existing Service Tampering"

