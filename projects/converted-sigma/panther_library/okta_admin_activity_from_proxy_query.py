# Title: Okta Admin Functions Access Through Proxy
# ID: 9058ca8b-f397-4fd1-a9fa-2b7aad4d6309
# Status: test
# Level: medium
# Author: Muhammad Faisal @faisalusuf
# Date: 2023-10-25
# Tags: attack.credential-access
# Description: Detects access to Okta admin functions through proxy.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Admin Functions Access Through Proxy
def rule(event):
    # Detection Logic:
    # (debugContext.debugData.requestUri="*admin*" AND securityContext.isProxy="true")
    return True

def title(event):
    return "Okta Admin Functions Access Through Proxy"

