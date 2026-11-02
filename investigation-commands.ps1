# Case 005 - Read-only Windows process triage reference
# Run in PowerShell on Windows. Security log queries may require Administrator privileges.
# These commands inspect current state; current PIDs may differ from the original case.

Write-Host "=== Top processes by accumulated CPU time ==="
Get-Process | Sort-Object CPU -Descending |
    Select-Object -First 10 ProcessName, Id, CPU, Path |
    Format-Table -AutoSize

Write-Host "=== Current iCloud-related processes and parent PIDs ==="
$icloud = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'iCloud|secd' })
$icloud | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath | Format-List

Write-Host "=== Current parent process metadata (not historical proof) ==="
$parentIds = @($icloud | Select-Object -ExpandProperty ParentProcessId -Unique)
Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -in $parentIds } |
    Select-Object Name, ProcessId, ParentProcessId, ExecutablePath | Format-List

Write-Host "=== Signatures of currently accessible iCloud executables ==="
$paths = @($icloud | ForEach-Object { $_.ExecutablePath } | Where-Object { $_ } | Select-Object -Unique)
$signatureResults = foreach ($path in $paths) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        [pscustomobject]@{ File=$path; Status=$sig.Status; Signer=$sig.SignerCertificate.Subject }
    } catch {
        [pscustomobject]@{ File=$path; Status='Error'; Signer=$_.Exception.Message }
    }
}
$signatureResults | Format-List

Write-Host "=== Apple/iCloud Windows services ==="
Get-CimInstance Win32_Service | Where-Object {
    $_.Name -match 'Apple|iCloud' -or $_.DisplayName -match 'Apple|iCloud' -or $_.PathName -match 'Apple|iCloud'
} | Select-Object Name, State, StartMode, PathName | Format-List

Write-Host "=== Conventional Apple/iCloud startup entries ==="
Get-CimInstance Win32_StartupCommand | Where-Object {
    $_.Name -match 'Apple|iCloud' -or $_.Command -match 'Apple|iCloud'
} | Select-Object Name, Command, Location, User | Format-List

Write-Host "=== Apple/iCloud scheduled tasks ==="
Get-ScheduledTask | Where-Object {
    $_.TaskName -match 'Apple|iCloud' -or $_.TaskPath -match 'Apple|iCloud' -or
    ($_.Actions.Execute -match 'Apple|iCloud') -or ($_.Actions.Arguments -match 'Apple|iCloud')
} | Select-Object TaskName, TaskPath, State, Actions | Format-List

Write-Host "=== Registered Start menu applications ==="
Get-StartApps | Where-Object { $_.Name -match 'Apple|iCloud' } | Format-Table -AutoSize

Write-Host "=== Installed iCloud package ==="
Get-AppxPackage -Name AppleInc.iCloud |
    Select-Object Name, Version, Status, InstallLocation | Format-List

Write-Host "=== Current iCloud process start times ==="
Get-Process | Where-Object { $_.ProcessName -match 'iCloud|secd' } |
    Select-Object ProcessName, Id, StartTime | Sort-Object StartTime | Format-Table -AutoSize

Write-Host "=== Successful interactive/cached logons near case timeline ==="
# Historical investigation window: October 31, 2026, 6:00-6:30 PM local.
# Event property index 8 is LogonType in standard Event ID 4624 versions; verify if needed.
try {
    Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4624
        StartTime=[datetime]'2026-10-31 18:00:00'
        EndTime=[datetime]'2026-10-31 18:30:00'
    } -ErrorAction Stop | Where-Object { $_.Properties.Count -gt 8 -and $_.Properties[8].Value -in @(2,11) } |
        Select-Object TimeCreated, @{Name='LogonType';Expression={$_.Properties[8].Value}} |
        Sort-Object TimeCreated | Format-Table -AutoSize
} catch {
    Write-Warning "Security log query failed or found no matching records: $($_.Exception.Message)"
}

Write-Host "=== Current services associated with iCloud PIDs ==="
$icloudIds = @($icloud | Select-Object -ExpandProperty ProcessId)
Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -in $icloudIds } |
    Select-Object Name, DisplayName, ProcessId, State, StartMode | Format-List
