# Title: Potential Dosfuscation Activity
# ID: a77c1610-fc73-4019-8e29-0f51efc04a51
# Status: test
# Level: medium
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-02-15
# Tags: attack.execution, attack.t1059
# Description: Detects possible payload obfuscation via the commandline
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Dosfuscation Activity
def rule(event):
    # Detection Logic:
    # ((CommandLine="*^^*" OR CommandLine="*^|^*" OR CommandLine="*,;,*" OR CommandLine="*;;;;*" OR CommandLine="*;; ;;*" OR CommandLine="*(,(,*" OR CommandLine="*%COMSPEC:~*" OR CommandLine="* c^m^d*" OR CommandLine="*^c^m^d*" OR CommandLine="* c^md*" OR CommandLine="* cm^d*" OR CommandLine="*^cm^d*" OR CommandLine="* s^et *" OR CommandLine="* s^e^t *" OR CommandLine="* se^t *"))
    return True

def title(event):
    return "Potential Dosfuscation Activity"

