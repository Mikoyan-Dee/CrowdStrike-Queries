# CrowdStrike-Queries
<blockquote>CrowdStrike Logscale Queries For Advanced Threat Detection</blockquote>

## Detect the persistent activities in Registry Run Key (MITRE ATTACK ID: T1547.001)

```Logscale
// Filter registry changes in Windows  
#event_simpleName = /AsepValueUpdate|RegGenericValueUpdate/F platform = Win  
// Filter for specific registry paths and auth ID  
| RegObjectName=/\\Software\\Microsoft\\Windows\\CurrentVersion/iF AND AuthenticationId_decimal=999  
// Rename field for clarity  
| rename(field = RegOperationType_decimal, as = RegOperationType)  
// Match registry operations from CSV  
| match(file="RegOperation.csv", field=[RegOperationName])  
// Group by system, registry object, value, and operation, then count occurrences  
| groupBy([ComputerName, RegObjectName, RegValueName, RegOperationName], function=count())
```

Note:
- AuthenticationId_decimal=999 #system level privs
- AuthenticationId_decimal=996  #network service
- AuthenticationId_decimal=997 #local service

<br/>

## Detect In-Memory .Net Assembly Modules Loaded from C2 Frameworks such as SilverC2, Metasploit. (MITRE ATTACK ID: T1055)

```Logscale
//Filter for ImageHash Events
event_simpleName=ImageHash
//Rename Fields for Readability
| rename(field=[[FileName, Dll_Loaded], [FilePath, Dll_Path]])
//Filter for non-PowerShell ImageHash events related to the same host and process
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName=/processrollup/iF}, {FileName!=/powershell\.exe/i}, {#event_simpleName=ImageHash}])
//Filter for processes that invoke the .NET runtime, which can be a sign of suspicious activity like C#-based malware execution
| in(field="Dll_Loaded", values=["mscoree.dll", "clr.dll", "clrjit.dll", "mscorlib.ni.dll", "mscoreei.dll"], ignoreCase=true)
//Grouping by Host and Process
| groupBy([aid, ComputerName, TargetProcessId], function=([collect([FileName, CommandLine, Dll_Loaded, Dll_Path])]))
//Display Results in Table Format
| table([ComputerName, FileName, CommandLine, Dll_Loaded, Dll_Path])
```

Note:
- mscoree.dll – Core .NET runtime DLL.
- clr.dll – Common Language Runtime (CLR).
- clrjit.dll – Just-In-Time compiler for .NET.
- mscorlib.ni.dll – Precompiled .NET core library.
- mscoreei.dll – .NET execution engine.
<br/>

## Detect Renamed Executable - Masquerading (MITRE ATTACK ID: T1036.003)

```Logscale
//Detect renamed executables 
#event_simpleName="NewExecutableRenamed"
//Rename field for correlation in join query
| rename(field=TargetFileName, as=ImageFileName)
//Join with process execution data  
| join(query={#event_simpleName=/ProcessRollup2/F}, field=[ImageFileName])  
//Create a table with key fields 
| table([aid, ComputerName, SourceFileName, ImageFileName, CommandLine])  
```

<br/>

## LOLBAS -Living Off The Land Binaries Execution (MITRE ATTACK ID: T1218)

Reference to https://lolbas-project.github.io/

Method-1 "join"

```
// Filter DNS requests  
#event_simpleName=DnsRequest  
// Rename field for consistency  
| rename(field = ContextProcessId_decimal, as=TargetProcessId_decimal)  
// Join with process execution data for specific executables  
| join(query={#event_simpleName=/ProcessRollup2/F FileName = /powershell\.exe|certutil\.exe|regsvr32\.exe|rundll32\.exe/iF}, field = TargetProcessId_decimal)  
// Create a table with key fields  
| table([ComputerName, ImageFileName, DomainName, CommandLine]) 
```

Method-2 "mvappend"

```
// Filter for process execution and DNS request events  
#event_simpleName = /ProcessRollup2/F OR #event_simpleName = /DnsRequest/F  
// Assign process IDs for correlation  
| falconPID := ContextProcessId | falconPID := TargetProcessId  
// Self-join to link process and DNS events  
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=/ProcessRollup2/F}, {#event_simpleName=/DnsRequest/F}])  
// Enrich with product and version details from CSV  
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ProductType, Version])  
// Group and collect relevant event data  
| groupBy([aid, ComputerName, falconPID], function=([collect([#event_simpleName, FileName, DomainName, UserSid, UserName, ImageFileName, aip, LocalAddressIP4, LocalPort, Protocol, ProductType, Version])]))  
// Enrich data with Falcon helper functions  
| $falcon/helper:enrich(field=ProductType)  
| $falcon/helper:enrich(field=Protocol)  
// Filter for suspicious processes with DNS activity  
| FileName=/rundll32\.exe|powershell\.exe|mpcmdrun\.exe/iF DomainName!=NULL  

```
