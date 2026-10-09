# Title: Unusual Parent Process For Cmd.EXE
# ID: 4b991083-3d0e-44ce-8fc4-b254025d8d4b
# Status: test
# Level: medium
# Author: Tim Rauch, Elastic (idea)
# Date: 2022-09-21
# Tags: attack.execution, attack.t1059
# Description: Detects suspicious parent process for cmd.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Unusual Parent Process For Cmd.EXE
def rule(event):
    # Detection Logic:
    # (Image="*\\cmd.exe" AND (ParentImage="*\\csrss.exe" OR ParentImage="*\\ctfmon.exe" OR ParentImage="*\\dllhost.exe" OR ParentImage="*\\epad.exe" OR ParentImage="*\\FlashPlayerUpdateService.exe" OR ParentImage="*\\GoogleUpdate.exe" OR ParentImage="*\\jucheck.exe" OR ParentImage="*\\jusched.exe" OR ParentImage="*\\LogonUI.exe" OR ParentImage="*\\lsass.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\SearchIndexer.exe" OR ParentImage="*\\SearchProtocolHost.exe" OR ParentImage="*\\SIHClient.exe" OR ParentImage="*\\sihost.exe" OR ParentImage="*\\slui.exe" OR ParentImage="*\\spoolsv.exe" OR ParentImage="*\\sppsvc.exe" OR ParentImage="*\\taskhostw.exe" OR ParentImage="*\\unsecapp.exe" OR ParentImage="*\\WerFault.exe" OR ParentImage="*\\wermgr.exe" OR ParentImage="*\\wlanext.exe" OR ParentImage="*\\WUDFHost.exe"))
    return True

def title(event):
    return "Unusual Parent Process For Cmd.EXE"

