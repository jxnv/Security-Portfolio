# Title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
# ID: 074e0ded-6ced-4ebd-8b4d-53f55908119d
# Status: test
# Level: medium
# Author: Julia Fomina, oscd.community
# Date: 2020-10-06
# Tags: attack.stealth, attack.t1216
# Description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
def rule(event):
    # Detection Logic:
    # ((CommandLine="*winrm*") AND (((CommandLine="*format:pretty*" OR CommandLine="*format:\"pretty\"*" OR CommandLine="*format:\"text\"*" OR CommandLine="*format:text*")) AND NOT (((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*")))))
    return True

def title(event):
    return "AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl"

