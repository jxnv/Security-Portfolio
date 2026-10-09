-- Title: Potential Suspicious PowerShell Keywords
-- ID: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Perez Diego (@darkquassar), Tuan Le (NCSGroup)
-- Date: 2019-02-11
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects potentially suspicious keywords that could indicate the use of a PowerShell exploitation framework
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%System.Reflection.Assembly.Load($%' OR ScriptBlockText LIKE '%[System.Reflection.Assembly]::Load($%' OR ScriptBlockText LIKE '%[Reflection.Assembly]::Load($%' OR ScriptBlockText LIKE '%System.Reflection.AssemblyName%' OR ScriptBlockText LIKE '%Reflection.Emit.AssemblyBuilderAccess%' OR ScriptBlockText LIKE '%Reflection.Emit.CustomAttributeBuilder%' OR ScriptBlockText LIKE '%Runtime.InteropServices.UnmanagedType%' OR ScriptBlockText LIKE '%Runtime.InteropServices.DllImportAttribute%' OR ScriptBlockText LIKE '%SuspendThread%' OR ScriptBlockText LIKE '%rundll32%'))
