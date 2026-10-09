-- Title: Suspicious X509Enrollment - Process Creation
-- ID: 114de787-4eb2-48cc-abdb-c0b449f93ea4
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-12-23
-- Tags: attack.defense-impairment, attack.t1553.004
-- Description: Detect use of X509Enrollment
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%X509Enrollment.CBinaryConverter%' OR CommandLine LIKE '%884e2002-217d-11da-b2a4-000e7bbb2b09%'))
