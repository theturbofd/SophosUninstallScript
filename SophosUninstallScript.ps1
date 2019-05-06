#Sophos uninstall strings
$sophosAutoUpdate = @("7CD26A0C-9B59-4E84-B5EE-B386B2F7AA16","BCF53039-A7FC-4C79-A3E3-437AE28FD918","9D1B8594-5DD2-4CDC-A5BD-98E7E9D75520", `
"AFBCA1B9-496C-4AE6-98AE-3EA1CFF65C54","E82DD0A8-0E5C-4D72-8DDE-41BB0FC06B3E","AFBCA1B9-496C-4AE6-98AE-3EA1CFF65C54")

$SophosNetworkThreat = @("66967E5F-43E8-4402-87A4-04685EE5C2CB")

$SophosPatch = @("DB337276-74CC-485E-921C-4AA45857EB2A","5565E71F-091B-42B8-8514-7E8944860BFD")

$SophosSystemProtect = @("1093B57D-A613-47F3-90CF-0FD5C5DCFFE6","934BEF80-B9D1-4A86-8B42-D8A6716A8D27")

$SophosFirewall = @("A805FB2A-A844-4cba-8088-CA64087D59E1")

$SophosVirus = @("8123193C-9000-4EEB-B28A-E74E779759FA","36333618-1CE1-4EF2-8FFD-7F17394891CE","DFDA2077-95D0-4C5F-ACE7-41DA16639255", "6654537D-935E-41C0-A18A-C55C2BF77B7E", `
"CA3CE456-B2D9-4812-8C69-17D6980432EF","3B998572-90A5-4D61-9022-00B288DD755D","72E30858-FC95-4C87-A697-670081EBF065","09863DA9-7A9B-4430-9561-E04D178D7017","23E4E25E-E963-4C62-A18A-49C73AA3F963")

$SophosManagement = @("FED1005D-CBC8-45D5-A288-FFC7BB304121","A1DC5EF8-DD20-45E8-ABBD-F529A24D477B","1FFD3F20-5D24-4C9A-B9F6-A207A53CF179","D875F30C-B469-4998-9A08-FE145DD5DC1A", `
"2C14E1A2-C4EB-466E-8374-81286D723D3A")

#force kill services to prevent hanging
Get-WmiObject -Class win32_service | Where-Object {$_.name -like 'sophos*'} | foreach{Stop-Process $_.ProcessId -Force}

#Stop services
Get-Service | Where-Object {$_.DisplayName -like "Sophos*"} | Stop-Service -Force

#loops through each uninstall string
write-host "now doing sophos patch" 
foreach($item in $sophosPatch){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item}"
    if($check32 -eq $true){
        Write-Output $item
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosPatchlog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item}"
    if($check64 -eq $true){
        Write-Output $item
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosPatchlog.txt" -wait -PassThru).ExitCode
    }
}
write-output "Now doing network threat"
foreach($item2 in $sophosnetworkthreat){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item2}"
    if($check32 -eq $true){
        Write-Output $item2
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item2} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosNetworklog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item2}"
    if($check64 -eq $true){
        Write-Output $item2
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item2} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosNetworklog.txt" -wait -PassThru).ExitCode
    }
}
write-output "Finished network threat, now doing system protect"
foreach($item3 in $SophosSystemProtect){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item3}"
    if($check32 -eq $true){
        Write-Output $item3
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item3} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosprotectlog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item3}"
    if($check64 -eq $true){
        Write-Output $item3
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item3} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosprotectlog.txt" -wait -PassThru).ExitCode
    }
}
write-output "now doing firewall"
foreach($item4 in $SophosFirewall){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item4}"
    if($check32 -eq $true){
        Write-Output $item4
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item4} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosfirewalllog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item4}"
    if($check64 -eq $true){
        Write-Output $item4
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item4} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosfirewalllog.txt" -wait -PassThru).ExitCode
    }
}
write-output "now doing anti virus"
foreach($item5 in $SophosVirus){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item5}"
    if($check32 -eq $true){
        Write-Output $item5
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item5} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosantiViruslog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item5}"
    if($check64 -eq $true){
        Write-Output $item5
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item5} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosantiViruslog.txt" -wait -PassThru).ExitCode
    }
}
write-output "Finished anti virus, now doing sophos Management"
foreach($item6 in $SophosManagement){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item6}"
    if($check32 -eq $true){
        Write-Output $item6
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item6} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosManagementlog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item6}"
    if($check64 -eq $true){
        Write-Output $item6
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item6} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosManagementlog.txt" -wait -PassThru).ExitCode
    }
}
write-output "now doing auto update"
foreach($item7 in $sophosAutoUpdate){
    $check32 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$item7}"
    if($check32 -eq $true){
        Write-Output $item6
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item7} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosupdatelog.txt" -wait -PassThru).ExitCode
    }
    $check64 = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$item7}"
    if($check64 -eq $true){
        Write-Output $item7
        (Start-Process -FilePath "MsiExec.exe" -ArgumentList "/X {$item7} /qn REBOOT=REALLYSUPPRESS /L*V C:\sophosupdatelog.txt" -wait -PassThru).ExitCode
    }
}
write-output "Finished auto update, now doing Endpoint defense"

& "C:\Program Files\Sophos\Endpoint Defense\uninstall.exe" /quiet
write-output "About to restart"