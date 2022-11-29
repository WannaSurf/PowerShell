<#
  .SYNOPSIS
  Creates user accounts in your domain.

  .DESCRIPTION
  The Add-WSADUser.ps1 script creates user accounts.
  You may specify a CSV file for bulk operations or manually
  by naviagting in the script's menu. 

  .PARAMETER CSV
  Specifies the path to the CSV-based input file.
  CSV file should include mandatory "UserPrincipalName" and "DisplayName"
  fields.

  .PARAMETER Pass
  Specifies the password assigned to new accounts.

  .EXAMPLE
  PS> .\Add-WSADUser.ps1

  .EXAMPLE
  PS> .\Add-WSADUser.ps1 -CSV C:\Accounts.csv

  .EXAMPLE
  PS> .\Add-WSADUser.ps1 -CSV C:\Accounts.csv -Pass "password" -WhatIf
#>

[cmdletbinding(SupportsShouldProcess)]
param (
    [ValidateScript ({ $_ -is [securestring] -or $_ -is [string]})] $Pass,
    [ValidateScript ({(Test-Path $_) -and (Get-ItemProperty $_).Extension -eq '.csv' })]$CSV = $null,
    [ValidateScript ({Get-ADDomain $_})]$Domain = $(Get-ADDomain)
)

function Select-WSOrganizationalUnit([Microsoft.ActiveDirectory.Management.ADPartition]$Domain){
    Clear-Host
    $Filter = $Domain.DistinguishedName
    while ($true){
        $Units = [array](Get-ADOrganizationalUnit -SearchBase $Filter -SearchScope OneLevel -Filter '*')
        Write-Host "`nChoose destination`n------------------"
        Write-Host "Current location: $Filter" -ForegroundColor Yellow
        if ($Filter -ne $Domain.DistinguishedName){ 
            Write-Host "[0] .."
        }
        $Units.foreach({
            Write-Host "[$(($Units.IndexOf($_)+1).toString())] $($_.Name)"
        })
        Write-Host "------------------"
        Write-Host "[s] Select current location"
        Write-Host "------------------"
        switch (Read-Host "Enter the value") {
            0 {
                if ($Filter.Split(',').Count -gt $Domain.DistinguishedName.Split(',').Count){
                    $Filter = $Filter.Remove(0,$Filter.IndexOf(',')+1)
                }
                Clear-Host
            }
            {(1..$Units.Count+1) -contains $_} {
                $Filter = $Units[$_-1].DistinguishedName
                Clear-Host
            }
            s {
                Clear-Host
                return $Filter
            }
            Default {
                Clear-Host
                Write-Warning "Wrong input"
            }

        }
    }
}    #AD Structure Navigation.

function New-WSSamAccountName ([string]$DisplayName) {
    $SamAccountName = $DisplayName.split(" ") 
    $FirstName = $SamAccountName[0]
    $LastName = $SamAccountName[1]
    $SamAccountName = "$($FirstName[0])$LastName".ToLower()
    return $SamAccountName
}    #Generates SamAccountName

$Domain = Get-ADDomain $Domain

$Path = Select-WSOrganizationalUnit($Domain)

if ($null -ne $CSV){
    [System.Object]$CSV = Get-Content $CSV
    $Headers = $CSV[0].Split(',')
    $MissingHeaders = @(@('UserPrincipalName','DisplayName') | Where-Object {$Headers -notcontains "`"$_`"" -and $Headers -notcontains "$_"})
    if ($MissingHeaders.Count -gt 0){
        "CSV data: "
        "----------"
        $Headers.foreach({
            "[$($Headers.IndexOf($_)+1)] $_"
        })
        "----------"
    }
    $MissingHeaders.ForEach({
        while ($true){
            $MatchValue = Read-Host "Match the header for value `"$_`""
            if ( (1..$Headers.Count) -contains $MatchValue ){
                $CSV[0] = $CSV[0].Replace($Headers[$MatchValue-1], "`"$_`"")
                Clear-Host
                break
            }
        }
    })
    $CSV = ConvertFrom-Csv $CSV

    if ($Headers -contains 'Password' -or $Headers -contains '"Password"' -or $null -ne $Pass) {} else {    #Checking if the password is specified
        $Pass = Read-Host "Enter Password" -AsSecureString 
    }

    $CSV.ForEach({
        if($_.Password.Count -gt 0){
            $Pass =  ConvertTo-SecureString $_.Password -AsPlainText -Force   #Taking password from CSV 
        }else{
            if($null -ne $PSBoundParameters.Pass){ 
                $Pass = ConvertTo-SecureString $PSBoundParameters.Pass -AsPlainText -Force   #Taking defined $Pass
            }else{
                $Pass = Read-Host "Enter missing password for $($_.DisplayName)" -AsSecureString 
            } 
        }
        New-ADUser -Name $_.DisplayName -SamAccountName $(New-WSSamAccountName $_.DisplayName) -GivenName $_.DisplayName.split(' ')[0] `
        -SurName $_.DisplayName.split(' ')[1]`
        -UserPrincipalName $_.UserPrincipalName -Path $Path -Enabled:$true `
        -AccountPassword $Pass -ChangePasswordAtLogon $true 
    })
    return
}    #CSV procedure
 
while ($true) {
    Write-Host "`n------------------------"
    Write-Host "Press `'Ctrl+C`' to quit" -ForegroundColor Yellow
    Write-Host "------------------------"
    $UserName = read-host "New User Name (ex. Sean Evans)"
    $FirstName = $UserName.split(" ")[0]
    $LastName = $UserName.split(" ")[1]
    
    if (!$PSBoundParameters.ContainsKey('Pass')) {
        $Pass = read-host "Enter Password" -AsSecureString
    }else{
        ConvertTo-SecureString $PSBoundParameters.Pass -AsPlainText -Force    #Taking defined $Pass
    }

    New-ADUser -Name $UserName -SamAccountName (New-WSSamAccountName $UserName) -GivenName $FirstName -SurName $LastName `
    -UserPrincipalName "$(New-WSSamAccountName $UserName)@$($Domain.DNSRoot)" -Path $Path -Enabled:$true `
    -AccountPassword $Pass -ChangePasswordAtLogon $true
    Write-Host 'Task finished'
}    #Manual procedure
return