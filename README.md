# CrowdStrike-Queries
<blockquote>CrowdStrike Logscale Queries For Advanced Threat Detection</blockquote>

## Detect the persistent activities in Registry Run Key (MITRE ATTACK ID: T1547.001)

```Logscale
#event_simpleName = /AsepValueUpdate|RegGenericValueUpdate/F platform = Win
| RegObjectName=/\\Software\\Microsoft\\Windows\\CurrentVersion/iF AND AuthenticationId_decimal=999
| rename( field = RegOperationType_decimal, as = RegOperationType)
| match(file="RegOperation.csv", field=[RegOperationName]) 
| groupBy([ComputerName, RegObjectName, RegValueName, RegOperationName], function=count())
```

Note:
- AuthenticationId_decimal=999 #system level privs
- AuthenticationId_decimal=996  #network service
- AuthenticationId_decimal=997 #local service

<br/>

## Detect In-Memory .Net Assembly Modules Loaded from C2 Frameworks such as SilverC2, Metasploit. (MITRE ATTACK ID: T1055)

```
event_simpleName=ImageHash
| rename FileName as Dll_Loaded FilePath as Dll_Path
| join TargetProcessId_decimal
    [search event_simpleName=ProcessRollup* FileName!=powershell.exe]
| search Dll_Loaded IN ("mscoree.dll", "clr.dll", "clrjit.dll", "mscorlib.ni.dll", "mscoreei.dll")
| table ComputerName FileName CommandLine Dll_Loaded Dll_Path
```

<br/>

## Detect Renamed Executable - Masquerading (MITRE ATTACK ID: T1036.003)

```
event_simpleName="NewExecutableRenamed"
| rename TargetFileName as ImageFileName
| join ImageFileName 
    [ search event_simpleName="ProcessRollup2" ]
| table ComputerName SourceFileName ImageFileName CommandLine
```

<br/>

## LOLBAS -Living Off The Land Binaries Execution (MITRE ATTACK ID: T1218)

Reference to https://lolbas-project.github.io/

Method-1 "join"

```
event_simpleName=DnsRequest
| rename ContextProcessId_decimal as TargetProcessId_decimal
| join TargetProcessId_decimal
    [search event_simpleName=ProcessRollup2 FileName IN ("powershell.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe")]
| table ComputerName ImageFileName DomainName CommandLine
```

Method-2 "mvappend"

```
event_simpleName IN ("*ProcessRollup2*") OR event_simpleName IN ("*DnsRequest*") 
| eval PID=mvappend(ContextProcessId_decimal, TargetProcessId_decimal)
| lookup userinfo.csv UserSid_readable OUTPUT UserName
| stats values(ComputerName) values(UserName) as UserName values(event_simpleName) as event_simpleName  values(FileName) as ProcessName values(DomainName) as DomainName by PID
| search ProcessName IN ("*rundll32.exe*", "*powershell.exe*", "*MpCmdRun.exe*")
| where isnotnull(DomainName)
```
