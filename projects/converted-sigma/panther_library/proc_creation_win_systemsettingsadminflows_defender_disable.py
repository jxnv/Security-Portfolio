# Title: Windows Defender Disabled Via SystemSettingsAdminFlows.EXE
# ID: da92713f-ca2d-4fab-8320-098013d3f43a
# Status: experimental
# Level: high
# Author: Chirag Damani (KPMG India), Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2026-07-01
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects the usage of SystemSettingsAdminFlows.exe to disable Windows Defender.
# SystemSettingsAdminFlows.exe is a legitimate Windows component used for administrative configuration tasks.
# However, attackers may abuse it to disable Windows Defender as part of their attack chain, especially in the context of ransomware or other malware campaigns.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Defender Disabled Via SystemSettingsAdminFlows.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*defender*") AND ((Image="*\\SystemSettingsAdminFlows.exe") OR (OriginalFileName="SystemSettingsAdminFlows.EXE"))) AND ((((CommandLine="*RTP *" OR CommandLine="*RealTimeProtection *" OR CommandLine="*DisableEnhancedNotifications *")) AND (CommandLine="*1*")) OR (((CommandLine="*SubmitSamplesConsent *" OR CommandLine="*SpyNetReporting *" OR CommandLine="*DisableCDPUserAuthPolicy *")) AND (CommandLine="*0*"))))
    return True

def title(event):
    return "Windows Defender Disabled Via SystemSettingsAdminFlows.EXE"

