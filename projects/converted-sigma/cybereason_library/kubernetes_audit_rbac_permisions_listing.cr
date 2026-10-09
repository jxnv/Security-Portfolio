// Title: RBAC Permission Enumeration Attempt
// ID: 84b777bd-c946-4d17-aa2e-c39f5a454325
// Status: test
// Level: low
// Author: Leo Tsaousis (@laripping)
// Date: 2024-03-26
// Tags: attack.t1069.003, attack.t1087.004, attack.discovery
// Description: Detects identities attempting to enumerate their Kubernetes RBAC permissions.
// In the early stages of a breach, attackers will aim to list the permissions they have within the compromised environment.
// In a Kubernetes cluster, this can be achieved by interacting with the API server, and querying the SelfSubjectAccessReview API via e.g. a "kubectl auth can-i --list" command.
// This will enumerate the Role-Based Access Controls (RBAC) rules defining the compromised user's authorization.
// Converted by: Sigma Universal SIEM/EDR CLI

(verb == "create" AND apiGroup == "authorization.k8s.io" AND objectRef.resource == "selfsubjectrulesreviews")
