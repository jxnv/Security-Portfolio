-- Title: New Kubernetes Service Account Created
-- ID: e31bae15-83ed-473e-bf31-faf4f8a17d36
-- Status: test
-- Level: low
-- Author: Leo Tsaousis (@laripping)
-- Date: 2024-03-26
-- Tags: attack.persistence, attack.t1136
-- Description: Detects creation of new Kubernetes service account, which could indicate an attacker's attempt to persist within a cluster.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (verb = 'create' AND objectRef.resource = 'serviceaccounts')
