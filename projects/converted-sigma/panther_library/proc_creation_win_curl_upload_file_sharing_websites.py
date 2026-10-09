# Title: Curl File Upload To File Sharing Websites
# ID: e328cc73-f92a-42fb-b3fa-7c2cffda981a
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2026-03-29
# Tags: attack.exfiltration, attack.t1567.002
# Description: Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Curl File Upload To File Sharing Websites
def rule(event):
    # Detection Logic:
    # (((CommandLine="*0x0.st*" OR CommandLine="*bashupload.com*" OR CommandLine="*chunk.io*" OR CommandLine="*file.io*" OR CommandLine="*filebin.net*" OR CommandLine="*pastebin*" OR CommandLine="*send.firefox.com*" OR CommandLine="*temp.sh*" OR CommandLine="*transfer.sh*" OR CommandLine="*ufile.io*" OR CommandLine="*uploadfiles.io*" OR CommandLine="*wetransfer.com*" OR CommandLine="*x0.at*")) AND (((CommandLine="* --form*" OR CommandLine="* --upload-file*" OR CommandLine="* --data*" OR CommandLine="* -X POST*" OR CommandLine="* --request POST *")) OR ((CommandLine=regex("\\s-[FTd]\\s") OR CommandLine=regex("\\s-sT\\s")))) AND ((Image="*\\curl.exe") OR (OriginalFileName="curl.exe")))
    return True

def title(event):
    return "Curl File Upload To File Sharing Websites"

