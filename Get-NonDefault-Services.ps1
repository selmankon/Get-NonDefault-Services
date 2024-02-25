<#
.SYNOPSIS
  A script to get all non-default services on a Windows machine.

.NOTES
  Version:        1.1
  Author:         selmankon
  Creation Date:  2024-02-25
#>

$NonDefaultServices = @() 
$Services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client" -and $_.DisplayName -notmatch "NetSetupSvc" -and $_.Caption -notmatch "Windows" -and $_.Caption -notmatch "Microsoft" -and $_.PathName -notmatch "Windows"  -and $_.PathName -notmatch "Microsoft" }

Foreach ($Service in $Services) {
    $icaclsOutput = ""
    if ($Service.PathName -ne $null) {
        if ($Service.PathName.StartsWith('"') -and $Service.PathName.EndsWith('"')) {
            $exePathQuoted = $Service.PathName
        } else {
            $exePathQuoted = "`"" + $Service.PathName + "`""
        }

        $exePathForTest = $Service.PathName.Trim('"')
        if (Test-Path -LiteralPath $exePathForTest) {
            $icaclsCommand = "icacls $exePathQuoted"
            try {
                $icaclsOutputRaw = Invoke-Expression $icaclsCommand | Out-String
                
                $lines = $icaclsOutputRaw -split "\r?\n"
                $filteredLines = $lines | Where-Object {
                    $_ -notmatch "^\s*$" -and
                    $_ -notmatch "Successfully processed"
                } | ForEach-Object {
                    if ($_ -match "^\s*$([regex]::Escape($exePathForTest))\s") {
                        $_ -replace "$([regex]::Escape($exePathForTest))", ''
                    } else {
                        $_
                    }
                } | ForEach-Object {
                    $_ -replace '\s+', ' ' 
                }

                $icaclsOutput = $filteredLines -join "`n"
                
            } catch {
                $icaclsOutput = "Error processing ICACLS command for path: $exePathQuoted"
            }
        } else {
            Write-Output "Path does not exist or cannot be accessed: $exePathQuoted"
        }
    }
    
    $NonDefaultServices += [pscustomobject]@{
        DisplayName = $Service.DisplayName
        State = $Service.State
        StartMode = $Service.StartMode
        Status = $Service.Status
        ProcessID = $Service.ProcessId                
        ExePath = $Service.PathName
        Description = $Service.Description
        ICACLSPermissions = $icaclsOutput
    }
}

$NonDefaultServices | ForEach-Object { Write-Output $_ }
