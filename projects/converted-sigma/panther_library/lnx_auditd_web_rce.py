# Title: Webshell Remote Command Execution
# ID: c0d3734d-330f-4a03-aae2-65dacc6a8222
# Status: test
# Level: critical
# Author: Ilyas Ochkov, Beyu Denis, oscd.community
# Date: 2019-10-12
# Tags: attack.persistence, attack.t1505.003
# Description: Detects possible command execution by web application/web shell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Webshell Remote Command Execution
def rule(event):
    # Detection Logic:
    # (type="SYSCALL" AND (SYSCALL="execve" OR SYSCALL="execveat") AND euid="33")
    return True

def title(event):
    return "Webshell Remote Command Execution"

