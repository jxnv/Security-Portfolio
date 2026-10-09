-- Title: Default Cobalt Strike Certificate
-- ID: 7100f7e3-92ce-4584-b7b7-01b40d3d4118
-- Status: test
-- Level: high
-- Author: Bhabesh Raj
-- Date: 2021-06-23
-- Tags: attack.command-and-control, attack.s0154
-- Description: Detects the presence of default Cobalt Strike certificate in the HTTPS traffic
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (certificate.serial = '8BB00EE')
