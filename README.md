# CrowdStrike-Queries
CrowdStrike Falcon Queries For Advanced Attack Detection

## Detect the persistent activities in Registry Run Key (MITRE ATTACK ID: T1547.001)

```
event_simpleName IN (AsepValueUpdate, RegGenericValueUpdate) 
| search RegObjectName="*\\Software\\Microsoft\\Windows\\CurrentVersion*" AND AuthenticationId_decimal=999
| rename RegOperationType_decimal as RegOperationType
| lookup local=true RegOperation.csv RegOperationType OUTPUT RegOperationName 
| stats count by ComputerName RegObjectName RegValueName RegOperationName
```

Note:
- AuthenticationId_decimal=999 #system level privs
- AuthenticationId_decimal=996  #network service
- AuthenticationId_decimal=997 #local service

#Detect In-Memory .Net Assembly Modules Loaded from C2 Frameworks such as SilverC2, Metasploit. (MITRE ATTACK ID: T1055)

```
event_simpleName=ImageHash
| rename FileName as Dll_Loaded FilePath as Dll_Path
| join TargetProcessId_decimal
    [search event_simpleName=ProcessRollup* FileName!=powershell.exe]
| search Dll_Loaded IN ("mscoree.dll", "clr.dll", "clrjit.dll", "mscorlib.ni.dll", "mscoreei.dll")
| table ComputerName FileName CommandLine Dll_Loaded Dll_Path
```
