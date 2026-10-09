# Title: Scheduled Cron Task/Job - Linux
# ID: 6b14bac8-3e3a-4324-8109-42f0546a347f
# Status: test
# Level: medium
# Author: Alejandro Ortuno, oscd.community
# Date: 2020-10-06
# Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.003
# Description: Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Scheduled Cron Task/Job - Linux
def rule(event):
    # Detection Logic:
    # (Image="*crontab" AND CommandLine="*/tmp/*")
    return True

def title(event):
    return "Scheduled Cron Task/Job - Linux"

