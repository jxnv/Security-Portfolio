# Title: AspNetCompiler Execution
# ID: a01b8329-5953-4f73-ae2d-aa01e1f35f00
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-11-24
# Tags: attack.execution, attack.stealth, attack.t1127
# Description: Detects execution of "aspnet_compiler.exe" which can be abused to compile and execute C# code.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AspNetCompiler Execution
def rule(event):
    # Detection Logic:
    # ((Image="*:\\Windows\\Microsoft.NET\\Framework\\*" OR Image="*:\\Windows\\Microsoft.NET\\Framework64\\*" OR Image="*:\\Windows\\Microsoft.NET\\FrameworkArm\\*" OR Image="*:\\Windows\\Microsoft.NET\\FrameworkArm64\\*") AND Image="*\\aspnet_compiler.exe")
    return True

def title(event):
    return "AspNetCompiler Execution"

