# Title: Suspicious Git Clone
# ID: aef9d1f1-7396-4e92-a927-4567c7a495c1
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-03
# Tags: attack.reconnaissance, attack.t1593.003
# Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Git Clone
def rule(event):
    # Detection Logic:
    # (((CommandLine="* clone *" OR CommandLine="*git-remote-https *")) AND (((Image="*\\git.exe" OR Image="*\\git-remote-https.exe")) OR (OriginalFileName="git.exe")) AND ((CommandLine="*exploit*" OR CommandLine="*Vulns*" OR CommandLine="*vulnerability*" OR CommandLine="*RemoteCodeExecution*" OR CommandLine="*Invoke-*" OR CommandLine="*CVE-*" OR CommandLine="*poc-*" OR CommandLine="*ProofOfConcept*" OR CommandLine="*proxyshell*" OR CommandLine="*log4shell*" OR CommandLine="*eternalblue*" OR CommandLine="*eternal-blue*" OR CommandLine="*MS17-*")))
    return True

def title(event):
    return "Suspicious Git Clone"

