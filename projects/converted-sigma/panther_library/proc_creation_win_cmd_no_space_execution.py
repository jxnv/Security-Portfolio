# Title: Cmd.EXE Missing Space Characters Execution Anomaly
# ID: a16980c2-0c56-4de0-9a79-17971979efdd
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-08-23
# Tags: attack.execution, attack.t1059.001
# Description: Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe.
# This could be a sign of obfuscation of a fat finger problem (typo by the developer).
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cmd.EXE Missing Space Characters Execution Anomaly
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*cmd.exe/c*" OR CommandLine="*\\cmd/c*" OR CommandLine="*\"cmd/c*" OR CommandLine="*cmd.exe/k*" OR CommandLine="*\\cmd/k*" OR CommandLine="*\"cmd/k*" OR CommandLine="*cmd.exe/r*" OR CommandLine="*\\cmd/r*" OR CommandLine="*\"cmd/r*")) OR ((CommandLine="*/cwhoami*" OR CommandLine="*/cpowershell*" OR CommandLine="*/cschtasks*" OR CommandLine="*/cbitsadmin*" OR CommandLine="*/ccertutil*" OR CommandLine="*/kwhoami*" OR CommandLine="*/kpowershell*" OR CommandLine="*/kschtasks*" OR CommandLine="*/kbitsadmin*" OR CommandLine="*/kcertutil*")) OR ((CommandLine="*cmd.exe /c*" OR CommandLine="*cmd /c*" OR CommandLine="*cmd.exe /k*" OR CommandLine="*cmd /k*" OR CommandLine="*cmd.exe /r*" OR CommandLine="*cmd /r*"))) AND NOT ((((CommandLine="*AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules*") OR (CommandLine="*cmd.exe/c .") OR (CommandLine="cmd.exe /c") OR (CommandLine="cmd /c")) OR ((CommandLine="*cmd.exe /c *" OR CommandLine="*cmd /c *" OR CommandLine="*cmd.exe /k *" OR CommandLine="*cmd /k *" OR CommandLine="*cmd.exe /r *" OR CommandLine="*cmd /r *")))))
    return True

def title(event):
    return "Cmd.EXE Missing Space Characters Execution Anomaly"

