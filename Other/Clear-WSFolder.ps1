[cmdletbinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript ({Test-Path $_ -PathType Container})] $Folder,
    
    [ValidateSet("CreationTime","AccessTime")]
    [Parameter(Mandatory=$true)] [string]$Compare,

    [Parameter(Mandatory=$true)] [int] $Days

)

$Folder = Get-Item $Folder
$Files = @(Get-Item "$($Folder.FullName)\*")

foreach ($file in $Files) {
    
        switch ($Compare){
            CreationTime {
                if (((Get-Date) - $file.CreationTime).Days -gt $Days) {
                    Remove-Item $file -Recurse
                }
            }

            AccessTime {
                if (((Get-Date) - $file.LastAccessTime).Days -gt $Days) {
                    Remove-Item $file -Recurse
                }
            }

            Default {Write-Error "Wrong compare value"}
        }
}
return