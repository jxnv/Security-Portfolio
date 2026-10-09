// Title: Kubernetes Admission Controller Modification
// ID: eed82177-38f5-4299-8a76-098d50d225ab
// Status: test
// Level: medium
// Author: kelnage
// Date: 2024-07-11
// Tags: attack.privilege-escalation, attack.initial-access, attack.persistence, attack.stealth, attack.t1078, attack.credential-access, attack.t1552, attack.t1552.007
// Description: Detects when a modification (create, update or replace) action is taken that affects mutating or validating webhook configurations, as they can be used by an adversary to achieve persistence or exfiltrate access credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (objectRef.apiGroup = "admissionregistration.k8s.io" and (objectRef.resource = "mutatingwebhookconfigurations" or objectRef.resource = "validatingwebhookconfigurations") and (verb = "create" or verb = "delete" or verb = "patch" or verb = "replace" or verb = "update"))
