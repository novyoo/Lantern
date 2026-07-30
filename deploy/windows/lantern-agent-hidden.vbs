Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

strDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = strDir

shell.Run "cmd /c """ & strDir & "\lantern-agent.exe"" >> """ & strDir & "\agent.log"" 2>&1", 0, False
