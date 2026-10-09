// Title: Bitbucket Global Secret Scanning Rule Deleted
// ID: e16cf0f0-ee88-4901-bd0b-4c8d13d9ee05
// Status: test
// Level: medium
// Author: Muhammad Faisal (@faisalusuf)
// Date: 2024-02-25
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects Bitbucket global secret scanning rule deletion activity.
// Converted by: Sigma Universal SIEM/EDR CLI

(auditType.category == "Global administration" AND auditType.action == "Global secret scanning rule deleted")
