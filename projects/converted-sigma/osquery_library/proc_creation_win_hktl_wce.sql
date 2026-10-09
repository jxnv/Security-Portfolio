-- Title: HackTool - Windows Credential Editor (WCE) Execution
-- ID: 7aa7009a-28b9-4344-8c1f-159489a390df
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-12-31
-- Tags: attack.credential-access, attack.t1003.001, attack.s0005
-- Description: Detects the use of Windows Credential Editor (WCE), a popular post-exploitation tool used to extract plaintext passwords, hash, PIN code and Kerberos tickets from memory.
-- It is often used by threat actors for credential dumping and lateral movement within compromised networks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Hashes LIKE '%IMPHASH=136F0A8572C058A96436C82E541E4C41%' OR Hashes LIKE '%IMPHASH=589657C64DDE88533186C39F82FA1F50%' OR Hashes LIKE '%IMPHASH=6BFE09EFCB4FFDE061EBDBAFC4DB84CF%' OR Hashes LIKE '%IMPHASH=7D490037BF450877E6D0287BDCFF8D2E%' OR Hashes LIKE '%IMPHASH=8AB93B061287C79F3088C5BC7E7D97ED%' OR Hashes LIKE '%IMPHASH=A53A02B997935FD8EEDCB5F7ABAB9B9F%' OR Hashes LIKE '%IMPHASH=BA434A7A729EEC20E136CA4C32D6C740%' OR Hashes LIKE '%IMPHASH=BD1D1547DA13C0FCB6C15E86217D5EB8%' OR Hashes LIKE '%IMPHASH=E96A73C7BF33A464C510EDE582318BF2%')) OR ((Image="*\\WCE.exe" OR Image="*\\WCE64.exe")))
