# Title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File
# ID: d353dac0-1b41-46c2-820c-d7d2561fc6ed
# Status: test
# Level: medium
# Author: Julia Fomina, oscd.community
# Date: 2020-10-06
# Tags: attack.stealth, attack.t1216
# Description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File
def rule(event):
    # Detection Logic:
    # (((TargetFilename="*WsmPty.xsl" OR TargetFilename="*WsmTxt.xsl")) AND NOT (((TargetFilename="C:\\Windows\\System32\\*" OR TargetFilename="C:\\Windows\\SysWOW64\\*"))))
    return True

def title(event):
    return "AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File"

