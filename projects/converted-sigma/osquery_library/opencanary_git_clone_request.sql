-- Title: OpenCanary - GIT Clone Request
-- ID: 4fe17521-aef3-4e6a-9d6b-4a7c8de155a8
-- Status: test
-- Level: high
-- Author: Security Onion Solutions
-- Date: 2024-03-08
-- Tags: attack.collection, attack.t1213
-- Description: Detects instances where a GIT service on an OpenCanary node has had Git Clone request.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (logtype = '16001')
