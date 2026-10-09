-- Title: Mimikatz Use
-- ID: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), David ANDRE (additional keywords)
-- Date: 2017-01-10
-- Tags: attack.s0002, attack.lateral-movement, attack.credential-access, car.2013-07-001, car.2019-04-004, attack.t1003.002, attack.t1003.004, attack.t1003.001, attack.t1003.006
-- Description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (("dpapi::masterkey" OR "eo.oe.kiwi" OR "event::clear" OR "event::drop" OR "gentilkiwi.com" OR "kerberos::golden" OR "kerberos::ptc" OR "kerberos::ptt" OR "kerberos::tgt" OR "Kiwi Legit Printer" OR "lsadump::" OR "mimidrv.sys" OR "\\mimilib.dll" OR "misc::printnightmare" OR "misc::shadowcopies" OR "misc::skeleton" OR "privilege::backup" OR "privilege::debug" OR "privilege::driver" OR "sekurlsa::") AND NOT ((EventID = '15')))
