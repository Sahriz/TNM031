# Run from PowerShell. Requires keytool from a JDK on PATH.
# Follows the course handout: generate -> export -> import the peer certificate.
$ErrorActionPreference = 'Stop'
$labRoot = $PSScriptRoot
$keytool = (Get-Command keytool -ErrorAction Stop).Source

$outputs = @(
    'server/server-keystore.ks', 'server/server-truststore.ks', 'server/server.cer',
    'client/client-keystore.ks', 'client/client-truststore.ks', 'client/client.cer'
)
foreach ($relative in $outputs) {
    if (Test-Path -LiteralPath (Join-Path $labRoot $relative)) {
        throw "Already exists: $relative. This script does not replace existing identities."
    }
}

function Invoke-LabKeytool {
    param([string[]]$Arguments)
    & $keytool @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'keytool failed; inspect its message before continuing.' }
}

# These demo passwords match the constants in the Java files; not personal passwords.
Invoke-LabKeytool -Arguments @(
    '-genkeypair', '-alias', 'server', '-keyalg', 'RSA', '-keysize', '3072',
    '-sigalg', 'SHA256withRSA', '-validity', '365', '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'server/server-keystore.ks'),
    '-storepass', 'serverkey-demo', '-keypass', 'serverkey-demo',
    '-dname', 'CN=localhost, OU=Lab3, O=TNM031, C=SE',
    '-ext', 'SAN=dns:localhost,ip:127.0.0.1', '-ext', 'EKU=serverAuth'
)
Invoke-LabKeytool -Arguments @(
    '-genkeypair', '-alias', 'client', '-keyalg', 'RSA', '-keysize', '3072',
    '-sigalg', 'SHA256withRSA', '-validity', '365', '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'client/client-keystore.ks'),
    '-storepass', 'clientkey-demo', '-keypass', 'clientkey-demo',
    '-dname', 'CN=Lab3 Client, OU=Lab3, O=TNM031, C=SE', '-ext', 'EKU=clientAuth'
)
Invoke-LabKeytool -Arguments @(
    '-exportcert', '-alias', 'server', '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'server/server-keystore.ks'),
    '-storepass', 'serverkey-demo', '-rfc', '-file', (Join-Path $labRoot 'server/server.cer')
)
Invoke-LabKeytool -Arguments @(
    '-exportcert', '-alias', 'client', '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'client/client-keystore.ks'),
    '-storepass', 'clientkey-demo', '-rfc', '-file', (Join-Path $labRoot 'client/client.cer')
)
# -noprompt accepts only the certificates this script just generated locally.
Invoke-LabKeytool -Arguments @(
    '-importcert', '-noprompt', '-alias', 'trusted-server',
    '-file', (Join-Path $labRoot 'server/server.cer'), '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'client/client-truststore.ks'),
    '-storepass', 'clienttrust-demo'
)
Invoke-LabKeytool -Arguments @(
    '-importcert', '-noprompt', '-alias', 'trusted-client',
    '-file', (Join-Path $labRoot 'client/client.cer'), '-storetype', 'JCEKS',
    '-keystore', (Join-Path $labRoot 'server/server-truststore.ks'),
    '-storepass', 'servertrust-demo'
)
Write-Host 'Created two independent identities and two peer truststores.'
Write-Host 'The certificates work for localhost and 127.0.0.1. See README.md for other hosts.'
