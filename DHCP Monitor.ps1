$BlackListedMACs = @(
"70ca973533d8",
"3C528287DF5F"
)

function Write-MSPLog {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [ValidateSet('MSP DHCP Monitor')]
         [string] $LogSource,
         [Parameter(Mandatory=$true, Position=1)]
         [ValidateSet('Information','Warning','Error')]
         [string] $LogType,
         [Parameter(Mandatory=$true, Position=2)]
         [string] $LogMessage
    )

    New-EventLog -LogName MSP-IT -Source 'MSP' -ErrorAction SilentlyContinue
    if(!(Get-EventLog -LogName MSP-IT -Source 'MSP DHCP Monitor' -ErrorAction SilentlyContinue)){
        New-EventLog -LogName MSP-IT -Source 'MSP DHCP Monitor' -ErrorAction SilentlyContinue
    }
    Write-EventLog -Log MSP-IT -Source "MSP DHCP Monitor" -EventID 0 -EntryType $LogType -Message "$LogMessage"
}

function Send-Alert () {
    param(
        [cmdletbinding()]
        [parameter()]
        [string]$ToAddress,
        [parameter()]
        [string]$FromAddress,
        [parameter()]
        [string]$Subject,
        [parameter()]
        [string]$Body
    )
    $MailBodyType = 'text/plain'
    $MailBodyValue = $Body
    $SendGridBody = @{
        "personalizations" = @(
            @{
                "to"      = @(
                    @{
                        "email" = $ToAddress
                    }
                )
                "subject" = $Subject
            }
        )
        "content"          = @(
            @{
                "type"  = $MailBodyType
                "value" = $MailBodyValue
            }
        )
        "from"             = @{
            "email" = $FromAddress
        }
    }

    try{
        if(!(Test-Path -Path "C:\MSP\EmailAlertConnectionInfo.txt")){
            Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Error" -LogMessage "C:\MSP\EmailAlertConnectionInfo.txt does not exist...exiting..."
            EXIT
        }
        $SensitiveString = Get-Content -Path "C:\MSP\EmailAlertConnectionInfo.txt" | ConvertTo-SecureString
        $Marshal = [System.Runtime.InteropServices.Marshal]
        $Bstr = $Marshal::SecureStringToBSTR($SensitiveString)
        $DecryptedString = $Marshal::PtrToStringAuto($Bstr)
        $Marshal::ZeroFreeBSTR($Bstr)
        $Secret = $DecryptedString -split ";" | Select-Object -Index 3
    }
    catch{
        Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Error" -LogMessage "Failed to decrypt email alert info..."
    }

    $BodyJson = $SendGridBody | ConvertTo-Json -Depth 4
    $Token = $Secret
    $Header = @{
        "authorization" = "Bearer $Token"
    }
    $Parameters = @{
        Method      = "POST"
        Uri         = "https://api.sendgrid.com/v3/mail/send"
        Headers     = $Header
        ContentType = "application/json"
        Body        = $BodyJson
    }
    Invoke-RestMethod @Parameters  
}

function Get-DhcpServerLog {
    param(
        [parameter(Position=0,Mandatory=$false)]
        [Alias("count")]
        [int]$Lines = 50000,
        [parameter(Position=3,Mandatory=$false)]
        [ValidateSet("mon","tue", "wed", "thu", "fri", IgnoreCase=$true)]
        [string]$Day= (Get-Date).DayOfWeek.ToString().Substring(0,3)
    )
    Write-Verbose "Get-DHCPServerLog called with parameters - Lines:$Lines, Day:$Day"

    # CSV header fields, to be used later when converting each line of the tailed log from CSV
    $HeaderFields = @("ID","Date","Time","Description","IP Address","Host Name","MAC Address","User Name","TransactionID","QResult","Probationtime","CorrelationID","Dhcid","VendorClass(Hex)","VendorClass(ASCII)","UserClass(Hex)","UserClass(ASCII)","RelayAgentInformation","DnsRegError")

    # Translations of the ID field, as per the description inside the log file itself
    $idMeanings = @{ 
        00 = "The log was started.";
        01 = "The log was stopped.";
        02 = "The log was temporarily paused due to low disk space.";
        10 = "A new IP address was leased to a client.";
        11 = "A lease was renewed by a client.";
        12 = "A lease was released by a client.";
        13 = "An IP address was found to be in use on the network.";
        14 = "A lease request could not be satisfied because the scope's address pool was exhausted.";
        15 = "A lease was denied.";
        16 = "A lease was deleted.";
        17 = "A lease was expired and DNS records for an expired leases have not been deleted.";
        18 = "A lease was expired and DNS records were deleted.";
        20 = "A BOOTP address was leased to a client.";
        21 = "A dynamic BOOTP address was leased to a client.";
        22 = "A BOOTP request could not be satisfied because the scope's address pool for BOOTP was exhausted.";
        23 = "A BOOTP IP address was deleted after checking to see it was not in use.";
        24 = "IP address cleanup operation has begun.";
        25 = "IP address cleanup statistics.";
        30 = "DNS update request to the named DNS server.";
        31 = "DNS update failed.";
        32 = "DNS update successful.";
        33 = "Packet dropped due to NAP policy.";
        34 = "DNS update request failed as the DNS update request queue limit exceeded.";
        35 = "DNS update request failed.";
        36 = "Packet dropped because the server is in failover standby role or the hash of the client ID does not match.";
        # Event descriptions for 50-64 sourced from https://technet.microsoft.com/en-us/library/cc776384(v=ws.10).aspx
        50 = "The DHCP server could not locate the applicable domain for its configured Active Directory installation.";
        51 = "The DHCP server was authorized to start on the network.";
        52 = "The DHCP server was recently upgraded to a Windows Server 2003 operating system, and, therefore, the unauthorized DHCP server detection feature (used to determine whether the server has been authorized in Active Directory) was disabled."
        53 = "The DHCP server was authorized to start using previously cached information. Active Directory was not currently visible at the time the server was started on the network.";
        54 = "The DHCP server was not authorized to start on the network. When this event occurs, it is likely followed by the server being stopped.";
        55 = "The DHCP server was successfully authorized to start on the network.";
        56 = "The DHCP server was not authorized to start on the network and was shut down by the operating system. You must first authorize the server in the directory before starting it again.";
        57 = "Another DHCP server exists and is authorized for service in the same domain.";
        58 = "The DHCP server could not locate the specified domain.";
        59 = "A network-related failure prevented the server from determining if it is authorized.";
        60 = "No Windows Server 2003 domain controller (DC) was located. For detecting whether the server is authorized, a DC that is enabled for Active Directory is needed.";
        61 = "Another DHCP server was found on the network that belongs to the Active Directory domain.";
        62 = "Another DHCP server was found on the network.";
        63 = "The DHCP server is trying once more to determine whether it is authorized to start and provide service on the network.";
        64 = "The DHCP server has its service bindings or network connections configured so that it is not enabled to provide service."
    }

    $qResultMeanings = @{0 = "No Quarantine"; 1 = "Quarantine"; 2 = "Drop Packet"; 3 = "Probation"; 6 = "No Quarantine Information"}

    $filePath = "$env:SystemRoot\System32\dhcp\DhcpSrvLog-$Day.log"
    
    Write-Verbose "Attempting to search for DHCP log at location: $filePath"
    if ((Test-Path $filePath) -eq $false) { throw "Couldn't locate DHCP log at $filePath" }

    Write-Verbose "Reading last $Lines lines from DHCP log at location: $filePath"
    Get-Content $filePath -Tail $Lines | ConvertFrom-Csv -Header $HeaderFields | Select-Object *,@{n="ID Description";e={$idMeanings[[int]::parse($_.ID)]}},@{n="QResult Description";e={$qResultMeanings[[int]::parse($_.QResult)]}}

}

function PunchIt {
    try{
        if(!(Test-Path -Path "C:\MSP\EmailAlertConnectionInfo.txt")){
            Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Error" -LogMessage "C:\MSP\EmailAlertConnectionInfo.txt does not exist...exiting..."
            EXIT
        }
        $SensitiveString = Get-Content -Path "C:\MSP\EmailAlertConnectionInfo.txt" | ConvertTo-SecureString
        $Marshal = [System.Runtime.InteropServices.Marshal]
        $Bstr = $Marshal::SecureStringToBSTR($SensitiveString)
        $DecryptedString = $Marshal::PtrToStringAuto($Bstr)
        $Marshal::ZeroFreeBSTR($Bstr)
        $FirstRecpient = $DecryptedString -split ";" | Select-Object -Index 0
        $SecondRecipient = $DecryptedString -split ";" | Select-Object -Index 1
        $SenderAddress = $DecryptedString -split ";" | Select-Object -Index 2
    }
    catch{
        Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Error" -LogMessage "Failed to decrypt email alert info..."
    }
    
    do{
        $TodaysDHCPLogs = Get-DhcpServerLog | Select-Object ID,Date,Time,Description,"Host Name","IP Address","MAC Address"
        $MACsDiscoveredInLogs = $TodaysDHCPLogs | Select-Object "MAC Address"
        $BlackListedMACs | ForEach-Object {
            if($MACsDiscoveredInLogs | Select-String "$_"){
                [string]$BlacklistedMACFoundLogs = $TodaysDHCPLogs | Where-Object {$BlackListedMACs -contains $_."MAC Address"} | Format-Table -AutoSize | Out-String
                try{
                    $IPToRevoke = ($TodaysDHCPLogs | Where-Object {$BlackListedMACs -contains $_."MAC Address"})."IP Address" | Select-Object -First 1
                    Remove-DhcpServerv4Lease -ComputerName $Env:ComputerName -IPAddress $IPToRevoke
                }
                catch{
                    Write-Warning "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor failed to revoke the lease...address immediately!`r`n`r`n$BlacklistedMACFoundLogs`r`n`r`nRevoke lease error:`r`n$($global:intErr++)Error #:$global:intErr`r`n$Error$($Error.Clear())"
                    Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Warning" -LogMessage "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor failed to revoke the lease...address immediately!`r`n`r`n$BlacklistedMACFoundLogs`r`n`r`nRevoke lease error:`r`n$($global:intErr++)Error #:$global:intErr`r`n$Error$($Error.Clear())"
                    Send-Alert -ToAddress "$FirstRecpient,$SecondRecipient" -FromAddress $SenderAddress -Subject "($Env:ComputerName) leased an IP to a blacklised device!" -Body "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor failed to revoke the lease...address immediately!`r`n`r`n$BlacklistedMACFoundLogs`r`n`r`nRevoke lease error:`r`n$($global:intErr++)Error #:$global:intErr`r`n$Error$($Error.Clear())"
                }
                Write-Host "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor successfiully revoked the lease!`r`n`r`n$BlacklistedMACFoundLogs"
                Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Information" -LogMessage "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor successfiully revoked the lease!`r`n`r`n$BlacklistedMACFoundLogs"
                Send-Alert -ToAddress "$FirstRecpient,$SecondRecipient" -FromAddress $SenderAddress -Subject "($Env:ComputerName) leased an IP to a blacklised device and successfully revoked it!" -Body "The DHCP server ($Env:ComputerName) leased an IP to a blacklised device and the DHCP Monitor successfiully revoked the lease!`r`n`r`n$BlacklistedMACFoundLogs"
            }   
        }
        if($TodaysDHCPLogs | Where-Object {$_.ID -eq 14}){
            [string]$EmptyDHCPPoolLogs = $TodaysDHCPLogs | Where-Object {$_.ID -eq 14} | Format-Table -AutoSize | Out-String
            Write-Host "The DHCP server ($Env:ComputerName) has run out of DHCP leases...address immediately!`r`n`r`n$EmptyDHCPPoolLogs"
            Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Warning" -LogMessage "The DHCP server ($Env:ComputerName) has run out of DHCP leases...address immediately!`r`n`r`n$EmptyDHCPPoolLogs"
            Send-Alert -ToAddress "$FirstRecpient,$SecondRecipient" -FromAddress $SenderAddress -Subject "($Env:ComputerName) has run out of DHCP leases!" -Body "The DHCP server ($Env:ComputerName) has run out of DHCP leases...address immediately!`r`n`r`n$EmptyDHCPPoolLogs"
        }
        if($TodaysDHCPLogs | Where-Object {$_.ID -eq 61}){
            [string]$RogueADDHCPServerLogs = $TodaysDHCPLogs | Where-Object {$_.ID -eq 61} | Format-Table -AutoSize | Out-String
            Write-Host "The DHCP server ($Env:ComputerName) has found another DHCP server on the network that belongs to the AD domain...address immediately!`r`n`r`n$RogueADDHCPServerLogs"
            Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Warning" -LogMessage "The DHCP server ($Env:ComputerName) has found another DHCP server on the network that belongs to the AD domain...address immediately!`r`n`r`n$RogueADDHCPServerLogs"
            Send-Alert -ToAddress "$FirstRecpient,$SecondRecipient" -FromAddress $SenderAddress -Subject "($Env:ComputerName) has found another DHCP server!" -Body "The DHCP server ($Env:ComputerName) has found another DHCP server on the network that belongs to the AD domain...address immediately!`r`n`r`n$RogueADDHCPServerLogs"
        }
        if($TodaysDHCPLogs | Where-Object {$_.ID -eq 62}){
            [string]$RogueDHCPServerLogs = $TodaysDHCPLogs | Where-Object {$_.ID -eq 62} | Format-Table -AutoSize | Out-String
            Write-Host "The DHCP server ($Env:ComputerName) has found another DHCP server on the network...address immediately!`r`n`r`n$RogueDHCPServerLogs"
            Write-MSPLog -LogSource "MSP DHCP Monitor" -LogType "Warning" -LogMessage "The DHCP server ($Env:ComputerName) has found another DHCP server on the network...address immediately!`r`n`r`n$RogueDHCPServerLogs"
            Send-Alert -ToAddress "$FirstRecpient,$SecondRecipient" -FromAddress $SenderAddress -Subject "($Env:ComputerName) has found another DHCP server!" -Body "The DHCP server ($Env:ComputerName) has found another DHCP server on the network...address immediately!`r`n`r`n$RogueDHCPServerLogs"

        }

        Start-Sleep -Seconds 240

    }
    while($True)    
}
