-- Title: Suspicious Environment Variable Has Been Registered
-- ID: 966315ef-c5e1-4767-ba25-fce9c8de3660
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-20
-- Tags: attack.persistence, attack.stealth
-- Description: Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((Details = 'powershell' OR Details = 'pwsh')) OR ((Details LIKE '%\\AppData\\Local\\Temp\\%' OR Details LIKE '%C:\\Users\\Public\\%' OR Details LIKE '%TVqQAAMAAAAEAAAA%' OR Details LIKE '%TVpQAAIAAAAEAA8A%' OR Details LIKE '%TVqAAAEAAAAEABAA%' OR Details LIKE '%TVoAAAAAAAAAAAAA%' OR Details LIKE '%TVpTAQEAAAAEAAAA%' OR Details LIKE '%SW52b2tlL%' OR Details LIKE '%ludm9rZS%' OR Details LIKE '%JbnZva2Ut%' OR Details LIKE '%SQBuAHYAbwBrAGUALQ%' OR Details LIKE '%kAbgB2AG8AawBlAC0A%' OR Details LIKE '%JAG4AdgBvAGsAZQAtA%')) OR ((Details="SUVY*" OR Details="SQBFAF*" OR Details="SQBuAH*" OR Details="cwBhA*" OR Details="aWV4*" OR Details="aQBlA*" OR Details="R2V0*" OR Details="dmFy*" OR Details="dgBhA*" OR Details="dXNpbm*" OR Details="H4sIA*" OR Details="Y21k*" OR Details="cABhAH*" OR Details="Qzpc*" OR Details="Yzpc*"))) AND (TargetObject LIKE '%\\Environment\\%'))
