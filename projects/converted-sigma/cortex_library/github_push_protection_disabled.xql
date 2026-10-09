// Title: Github Push Protection Disabled
// ID: ccd55945-badd-4bae-936b-823a735d37dd
// Status: test
// Level: high
// Author: Muhammad Faisal (@faisalusuf)
// Date: 2024-03-07
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects if the push protection feature is disabled for an organization, enterprise, repositories or custom pattern rules.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action = "business_secret_scanning_custom_pattern_push_protection.disabled" or action = "business_secret_scanning_push_protection.disable" or action = "business_secret_scanning_push_protection.disabled_for_new_repos" or action = "org.secret_scanning_custom_pattern_push_protection_disabled" or action = "org.secret_scanning_push_protection_disable" or action = "org.secret_scanning_push_protection_new_repos_disable" or action = "repository_secret_scanning_custom_pattern_push_protection.disabled"))
