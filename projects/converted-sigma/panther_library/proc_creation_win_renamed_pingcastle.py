# Title: Renamed PingCastle Binary Execution
# ID: 2433a154-bb3d-42e4-86c3-a26bdac91c45
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
# Date: 2024-01-11
# Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
# Description: Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Renamed PingCastle Binary Execution
def rule(event):
    # Detection Logic:
    # ((((OriginalFileName="PingCastleReporting.exe" OR OriginalFileName="PingCastleCloud.exe" OR OriginalFileName="PingCastle.exe")) OR ((CommandLine="*--scanner aclcheck*" OR CommandLine="*--scanner antivirus*" OR CommandLine="*--scanner computerversion*" OR CommandLine="*--scanner foreignusers*" OR CommandLine="*--scanner laps_bitlocker*" OR CommandLine="*--scanner localadmin*" OR CommandLine="*--scanner nullsession*" OR CommandLine="*--scanner nullsession-trust*" OR CommandLine="*--scanner oxidbindings*" OR CommandLine="*--scanner remote*" OR CommandLine="*--scanner share*" OR CommandLine="*--scanner smb*" OR CommandLine="*--scanner smb3querynetwork*" OR CommandLine="*--scanner spooler*" OR CommandLine="*--scanner startup*" OR CommandLine="*--scanner zerologon*")) OR (CommandLine="*--no-enum-limit*") OR ((CommandLine="*--healthcheck*" AND CommandLine="*--level Full*")) OR ((CommandLine="*--healthcheck*" AND CommandLine="*--server *"))) AND NOT (((Image="*\\PingCastleReporting.exe" OR Image="*\\PingCastleCloud.exe" OR Image="*\\PingCastle.exe"))))
    return True

def title(event):
    return "Renamed PingCastle Binary Execution"

