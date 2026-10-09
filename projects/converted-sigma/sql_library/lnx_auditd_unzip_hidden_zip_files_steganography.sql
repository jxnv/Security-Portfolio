-- Title: Steganography Unzip Hidden Information From Picture File
-- ID: edd595d7-7895-4fa7-acb3-85a18a8772ca
-- Status: test
-- Level: low
-- Author: Pawel Mazur
-- Date: 2021-09-09
-- Tags: attack.stealth, attack.t1027.003
-- Description: Detects extracting of zip file from image file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((type = 'EXECVE' AND a0 = 'unzip') AND ((a1 ILIKE '%.jpg' OR a1 ILIKE '%.png')))
