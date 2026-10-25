<#
.SYNOPSIS
Runs Maven with Java 25, preferring an existing JAVA_HOME or an installed/local JDK.
.EXAMPLE
.\scripts\maven.ps1 clean verify
.EXAMPLE
.\scripts\maven.ps1 -pl rasp-samples spring-boot:run
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $MavenArguments = @('clean', 'verify')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$jdkCandidates = @()
if ($env:JAVA_HOME) { $jdkCandidates += $env:JAVA_HOME }
if (Test-Path -LiteralPath (Join-Path $projectRoot '.tools\jdk25')) {
    $jdkCandidates += Get-ChildItem -LiteralPath (Join-Path $projectRoot '.tools\jdk25') -Directory |
        Select-Object -ExpandProperty FullName
}
if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Java')) {
    $jdkCandidates += Get-ChildItem -LiteralPath (Join-Path $env:ProgramFiles 'Java') -Directory |
        Select-Object -ExpandProperty FullName
}
$javaCommand = Get-Command java.exe -ErrorAction SilentlyContinue
if ($javaCommand) { $jdkCandidates += Split-Path -Parent (Split-Path -Parent $javaCommand.Source) }
$selectedJdk = $null
foreach ($candidate in $jdkCandidates) {
    $releaseFile = Join-Path $candidate 'release'
    if ((Test-Path -LiteralPath $releaseFile) -and
        (Select-String -LiteralPath $releaseFile -Pattern '^JAVA_VERSION="25[.\"]' -Quiet)) {
        $selectedJdk = $candidate
        break
    }
}
if (-not $selectedJdk) {
    throw 'Java 25 JDK is required. Set JAVA_HOME to its installation directory, then run this script again.'
}
$mavenCommand = Get-Command mvn.cmd -ErrorAction SilentlyContinue
if (-not $mavenCommand) { throw 'Maven 3.8.6 or newer is required on PATH.' }
$env:JAVA_HOME = $selectedJdk
$env:PATH = (Join-Path $selectedJdk 'bin') + [IO.Path]::PathSeparator + $env:PATH
# Windows desktop runners can virtualize the normal TEMP socket path. Keep Java's
# temporary NIO sockets in this workspace for Maven and its child JVMs only.
$previousJavaOptions = $env:JDK_JAVA_OPTIONS
$socketDirectory = Join-Path $projectRoot '.tools\socket-tmp'
New-Item -ItemType Directory -Path $socketDirectory -Force | Out-Null
$socketOption = '"-Djdk.net.unixdomain.tmpdir=' + $socketDirectory + '"'
$env:JDK_JAVA_OPTIONS = (($previousJavaOptions + ' ' + $socketOption).Trim())
Push-Location -LiteralPath $projectRoot
try {
    & $mavenCommand.Source @MavenArguments
    $mavenExitCode = $LASTEXITCODE
} finally {
    Pop-Location
    $env:JDK_JAVA_OPTIONS = $previousJavaOptions
}
exit $mavenExitCode
