-- Title: Powershell Base64 Encoded MpPreference Cmdlet
-- ID: c6fb44c6-71f5-49e6-9462-1425d328aee3
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-04
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects base64 encoded "MpPreference" PowerShell cmdlet code that tries to modifies or tamper with Windows Defender AV
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%QWRkLU1wUHJlZmVyZW5jZS%' OR CommandLine LIKE '%FkZC1NcFByZWZlcmVuY2Ug%' OR CommandLine LIKE '%BZGQtTXBQcmVmZXJlbmNlI%' OR CommandLine LIKE '%U2V0LU1wUHJlZmVyZW5jZS%' OR CommandLine LIKE '%NldC1NcFByZWZlcmVuY2Ug%' OR CommandLine LIKE '%TZXQtTXBQcmVmZXJlbmNlI%' OR CommandLine LIKE '%YWRkLW1wcHJlZmVyZW5jZS%' OR CommandLine LIKE '%FkZC1tcHByZWZlcmVuY2Ug%' OR CommandLine LIKE '%hZGQtbXBwcmVmZXJlbmNlI%' OR CommandLine LIKE '%c2V0LW1wcHJlZmVyZW5jZS%' OR CommandLine LIKE '%NldC1tcHByZWZlcmVuY2Ug%' OR CommandLine LIKE '%zZXQtbXBwcmVmZXJlbmNlI%')) OR ((CommandLine LIKE '%QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA%' OR CommandLine LIKE '%EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA%' OR CommandLine LIKE '%BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA%' OR CommandLine LIKE '%UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA%' OR CommandLine LIKE '%MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA%' OR CommandLine LIKE '%TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA%' OR CommandLine LIKE '%YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA%' OR CommandLine LIKE '%EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA%' OR CommandLine LIKE '%hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA%' OR CommandLine LIKE '%cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA%' OR CommandLine LIKE '%MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA%' OR CommandLine LIKE '%zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA%')))
