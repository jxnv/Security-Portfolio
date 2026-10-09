# Title: AppX Located in Known Staging Directory Added to Deployment Pipeline
# ID: 5cdeaf3d-1489-477c-95ab-c318559fc051
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-11
# Tags: attack.stealth
# Description: Detects an appx package that was added to the pipeline of the "to be processed" packages that is located in a known folder often used as a staging directory.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AppX Located in Known Staging Directory Added to Deployment Pipeline
def rule(event):
    # Detection Logic:
    # ((EventID="854") AND (((Path="*:\\PerfLogs\\*" OR Path="*:\\Users\\Public\\*" OR Path="*:\\Windows\\Temp\\*" OR Path="*\\AppdData\\Local\\Temp\\*" OR Path="*\\Desktop\\*" OR Path="*\\Downloads\\*")) OR ((Path="*:/Perflogs/*" OR Path="*:/Users/Public/*" OR Path="*:/Windows/Temp/*" OR Path="*/AppdData/Local/Temp/*" OR Path="*/Desktop/*" OR Path="*/Downloads/*"))))
    return True

def title(event):
    return "AppX Located in Known Staging Directory Added to Deployment Pipeline"

