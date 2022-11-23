[cmdletbinding(SupportsShouldProcess)]
param (
    [ValidateScript ({ $_ -is [securestring] -or $_ -is [string]})] $Pass,
    [ValidateScript ({(Test-Path $_) -and (Get-ItemProperty $_).Extension -eq '.csv' })]$CSV = $null,
    [ValidateScript ({Get-ADDomain $_})]$Domain = $(Get-ADDomain)
)

$Domain = Get-ADDomain $Domain

function Get-WSADContainer([Microsoft.ActiveDirectory.Management.ADPartition]$Domain){  #AD Structure Navigation.
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
}

function New-WSSamAccountName ([string]$DisplayName) {
    $SamAccountName = $DisplayName.split(" ") 
    $FirstName = $SamAccountName[0]
    $LastName = $SamAccountName[1]
    $SamAccountName = "$($FirstName[0])$LastName".ToLower()
    return $SamAccountName
}

$Path = Get-WSADContainer($Domain)

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

    if ($Headers -contains 'Password' -or $Headers -contains '"Password"') {} else {
        $Pass = Read-Host "Enter Password" -AsSecureString 
    }

    $CSV.ForEach({
        if($_.Password.Count -gt 0){ $Pass = $_.Password }
        New-ADUser -Name $_.DisplayName -SamAccountName $(New-WSSamAccountName $_.DisplayName) -GivenName $_.DisplayName.split(' ')[0] `
        -SurName $_.DisplayName.split(' ')[1]`
        -UserPrincipalName $_.UserPrincipalName -Path $Path -Enabled:$true `
        -AccountPassword $Pass -ChangePasswordAtLogon $true  
    })
    return
}
 
while ($true) {
    Write-Host "`n------------------------"
    Write-Host "Press `'Ctrl+C`' to quit" -ForegroundColor Yellow
    Write-Host "------------------------"
    $UserName = read-host "New User Name (ex. Sean Evans)"
    $FirstName = $UserName.split(" ")[0]
    $LastName = $UserName.split(" ")[1]
    
    if (!$PSBoundParameters.ContainsKey('Pass')) {
        $Pass = read-host "Enter Password" -AsSecureString
    }

    New-ADUser -Name $UserName -SamAccountName (New-WSSamAccountName $UserName) -GivenName $FirstName -SurName $LastName `
    -UserPrincipalName "$(New-WSSamAccountName $UserName)@$($Domain.DNSRoot)" -Path $Path -Enabled:$true `
    -AccountPassword $Pass -ChangePasswordAtLogon $true
    'Task finished'
}