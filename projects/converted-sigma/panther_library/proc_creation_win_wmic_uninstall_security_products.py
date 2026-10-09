# Title: Potential Tampering With Security Products Via WMIC
# ID: 847d5ff3-8a31-4737-a970-aeae8fe21765
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
# Date: 2021-01-30
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects uninstallation or termination of security products using the WMIC utility
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Tampering With Security Products Via WMIC
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*wmic*" AND CommandLine="*product *" AND CommandLine="*uninstall*") AND (CommandLine="*/nointeractive*" OR CommandLine="*-nointeractive*")) OR ((CommandLine="*wmic*" AND CommandLine="*caption like *") AND (CommandLine="*call delete*" OR CommandLine="*call terminate*")) OR ((CommandLine="*process *" AND CommandLine="*where *" AND CommandLine="*delete*"))) AND ((CommandLine="*%carbon%*" OR CommandLine="*%cylance%*" OR CommandLine="*%endpoint%*" OR CommandLine="*%eset%*" OR CommandLine="*%malware%*" OR CommandLine="*%Sophos%*" OR CommandLine="*%symantec%*" OR CommandLine="*Antivirus*" OR CommandLine="*AVG *" OR CommandLine="*Carbon Black*" OR CommandLine="*CarbonBlack*" OR CommandLine="*Cb Defense Sensor 64-bit*" OR CommandLine="*Crowdstrike Sensor*" OR CommandLine="*Cylance *" OR CommandLine="*Dell Threat Defense*" OR CommandLine="*DLP Endpoint*" OR CommandLine="*Endpoint Detection*" OR CommandLine="*Endpoint Protection*" OR CommandLine="*Endpoint Security*" OR CommandLine="*Endpoint Sensor*" OR CommandLine="*ESET File Security*" OR CommandLine="*LogRhythm System Monitor Service*" OR CommandLine="*Malwarebytes*" OR CommandLine="*McAfee Agent*" OR CommandLine="*Microsoft Security Client*" OR CommandLine="*Sophos Anti-Virus*" OR CommandLine="*Sophos AutoUpdate*" OR CommandLine="*Sophos Credential Store*" OR CommandLine="*Sophos Management Console*" OR CommandLine="*Sophos Management Database*" OR CommandLine="*Sophos Management Server*" OR CommandLine="*Sophos Remote Management System*" OR CommandLine="*Sophos Update Manager*" OR CommandLine="*Threat Protection*" OR CommandLine="*VirusScan*" OR CommandLine="*Webroot SecureAnywhere*" OR CommandLine="*Windows Defender*")))
    return True

def title(event):
    return "Potential Tampering With Security Products Via WMIC"

