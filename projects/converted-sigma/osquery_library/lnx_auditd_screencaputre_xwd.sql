-- Title: Screen Capture with Xwd
-- ID: e2f17c5d-b02a-442b-9052-6eb89c9fec9c
-- Status: test
-- Level: low
-- Author: Pawel Mazur
-- Date: 2021-09-13
-- Tags: attack.collection, attack.t1113
-- Description: Detects adversary creating screen capture of a full with xwd. Highly recommended using rule on servers, due high usage of screenshot utilities on user workstations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((type = 'EXECVE' AND a0 = 'xwd') AND ((a1 = '-out' AND a2="*.xwd") OR (a1 = '-root' AND a2 = '-out' AND a3="*.xwd")))
