# Title: Github Push Protection Disabled
# ID: ccd55945-badd-4bae-936b-823a735d37dd
# Status: test
# Level: high
# Author: Muhammad Faisal (@faisalusuf)
# Date: 2024-03-07
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects if the push protection feature is disabled for an organization, enterprise, repositories or custom pattern rules.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Github Push Protection Disabled
def rule(event):
    # Detection Logic:
    # ((action="business_secret_scanning_custom_pattern_push_protection.disabled" OR action="business_secret_scanning_push_protection.disable" OR action="business_secret_scanning_push_protection.disabled_for_new_repos" OR action="org.secret_scanning_custom_pattern_push_protection_disabled" OR action="org.secret_scanning_push_protection_disable" OR action="org.secret_scanning_push_protection_new_repos_disable" OR action="repository_secret_scanning_custom_pattern_push_protection.disabled"))
    return True

def title(event):
    return "Github Push Protection Disabled"

