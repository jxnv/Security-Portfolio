-- Title: Kubernetes Rolebinding Modification
-- ID: 10b97915-ec8d-455f-a815-9a78926585f6
-- Status: test
-- Level: medium
-- Author: kelnage
-- Date: 2024-07-11
-- Tags: attack.privilege-escalation
-- Description: Detects when a Kubernetes Rolebinding is created or modified.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (objectRef.apiGroup = 'rbac.authorization.k8s.io' AND (objectRef.resource = 'clusterrolebindings' OR objectRef.resource = 'rolebindings') AND (verb = 'create' OR verb = 'delete' OR verb = 'patch' OR verb = 'replace' OR verb = 'update'))
