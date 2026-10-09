# Title: Potential Suspicious PowerShell Keywords
# ID: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems), Perez Diego (@darkquassar), Tuan Le (NCSGroup)
# Date: 2019-02-11
# Tags: attack.execution, attack.t1059.001
# Description: Detects potentially suspicious keywords that could indicate the use of a PowerShell exploitation framework
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Suspicious PowerShell Keywords
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*System.Reflection.Assembly.Load($*" OR ScriptBlockText="*[System.Reflection.Assembly]::Load($*" OR ScriptBlockText="*[Reflection.Assembly]::Load($*" OR ScriptBlockText="*System.Reflection.AssemblyName*" OR ScriptBlockText="*Reflection.Emit.AssemblyBuilderAccess*" OR ScriptBlockText="*Reflection.Emit.CustomAttributeBuilder*" OR ScriptBlockText="*Runtime.InteropServices.UnmanagedType*" OR ScriptBlockText="*Runtime.InteropServices.DllImportAttribute*" OR ScriptBlockText="*SuspendThread*" OR ScriptBlockText="*rundll32*"))
    return True

def title(event):
    return "Potential Suspicious PowerShell Keywords"

