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
