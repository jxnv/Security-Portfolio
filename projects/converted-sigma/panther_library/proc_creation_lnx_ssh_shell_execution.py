# Title: Shell Invocation Via Ssh - Linux
# ID: 8737b7f6-8df3-4bb7-b1da-06019b99b687
# Status: test
# Level: high
# Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
# Date: 2024-08-29
# Tags: attack.execution, attack.t1059
# Description: Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Shell Invocation Via Ssh - Linux
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/bin/bash*" OR CommandLine="*/bin/dash*" OR CommandLine="*/bin/fish*" OR CommandLine="*/bin/sh*" OR CommandLine="*/bin/zsh*" OR CommandLine="*sh 0<&2 1>&2*" OR CommandLine="*sh 1>&2 0<&2*")) AND (Image="*/ssh" AND (CommandLine="*ProxyCommand=;*" OR CommandLine="*permitlocalcommand=yes*" OR CommandLine="*localhost*")))
    return True

def title(event):
    return "Shell Invocation Via Ssh - Linux"

