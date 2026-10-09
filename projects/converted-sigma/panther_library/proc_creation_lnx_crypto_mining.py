# Title: Linux Crypto Mining Indicators
# ID: 9069ea3c-b213-4c52-be13-86506a227ab1
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-10-26
# Tags: attack.impact, attack.t1496
# Description: Detects command line parameters or strings often used by crypto miners
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Linux Crypto Mining Indicators
def rule(event):
    # Detection Logic:
    # ((CommandLine="* --cpu-priority=*" OR CommandLine="*--donate-level=0*" OR CommandLine="* -o pool.*" OR CommandLine="* --nicehash*" OR CommandLine="* --algo=rx/0 *" OR CommandLine="*stratum+tcp://*" OR CommandLine="*stratum+udp://*" OR CommandLine="*sh -c /sbin/modprobe msr allow_writes=on*" OR CommandLine="*LS1kb25hdGUtbGV2ZWw9*" OR CommandLine="*0tZG9uYXRlLWxldmVsP*" OR CommandLine="*tLWRvbmF0ZS1sZXZlbD*" OR CommandLine="*c3RyYXR1bSt0Y3A6Ly*" OR CommandLine="*N0cmF0dW0rdGNwOi8v*" OR CommandLine="*zdHJhdHVtK3RjcDovL*" OR CommandLine="*c3RyYXR1bSt1ZHA6Ly*" OR CommandLine="*N0cmF0dW0rdWRwOi8v*" OR CommandLine="*zdHJhdHVtK3VkcDovL*"))
    return True

def title(event):
    return "Linux Crypto Mining Indicators"

