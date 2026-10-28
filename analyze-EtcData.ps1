#Requires -Version 5.1
<#
.SYNOPSIS
    collect-EtcData.ps1 で収集した /etc データを解析し、CSV レポートを出力します。

.DESCRIPTION
    収集フォルダー(EtcCollected_<日時>)配下のホストディレクトリごとに /etc の内容を解析し、
    次の 2 つの CSV を出力します。

      1. EtcAnalysis_<日時>.csv   … ホストごとの設定一覧(1 ホスト 1 行の横断マトリクス)
      2. EtcFindings_<日時>.csv   … 要確認項目(1 項目 1 行。重大度 高/中/低/情報 付き)

    解析項目(主なもの):
      - OS / ホスト名 / タイムゾーン / SELinux / ファイアウォール
      - DNS(/etc/resolv.conf)/ hosts / fstab(NFS)
      - アカウント(/etc/passwd, shadow, group):UID 0 アカウント・空パスワード・
        ロック状態・パスワード無期限・wheel/sudo グループ
      - sudo(/etc/sudoers, sudoers.d):NOPASSWD エントリ
      - SSH(/etc/ssh/sshd_config, sshd_config.d):Port / PermitRootLogin /
        PasswordAuthentication / PermitEmptyPasswords(Include 展開・先頭優先)
      - cron(/etc/cron.*)

    使用例:
        .\analyze-EtcData.ps1 -CollectDir .\EtcCollected_20260916_120000
        .\analyze-EtcData.ps1 -CollectDir .\EtcCollected_20260916_120000 -AnalysisCsvPath .\Report.csv -FindingsCsvPath .\Findings.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectDir,
    [string]$AnalysisCsvPath = (Join-Path $PSScriptRoot ('EtcAnalysis_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$FindingsCsvPath = (Join-Path $PSScriptRoot ('EtcFindings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$LogPath = (Join-Path $PSScriptRoot 'EtcAnalyze.log')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# 共通関数
# ----------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 300)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -gt $Max) { return ($Text.Substring(0, $Max) + '...') }
    return $Text
}

function Read-Lines {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
}

function Get-OsInfo {
    param([string]$EtcDir)
    $osName = ''
    $osVersion = ''
    $osReleasePath = Join-Path $EtcDir 'os-release'
    if (Test-Path -LiteralPath $osReleasePath) {
        $map = @{}
        foreach ($line in @(Get-Content -LiteralPath $osReleasePath -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
                $val = $Matches[2].Trim()
                if ($val.Length -ge 2 -and (
                    ($val.StartsWith('"') -and $val.EndsWith('"')) -or
                    ($val.StartsWith("'") -and $val.EndsWith("'")))) {
                    $val = $val.Substring(1, $val.Length - 2)
                }
                $map[$Matches[1]] = $val
            }
        }
        if ($map.ContainsKey('PRETTY_NAME')) { $osName = $map['PRETTY_NAME'] }
        elseif ($map.ContainsKey('NAME')) { $osName = $map['NAME'] }
        if ($map.ContainsKey('VERSION_ID')) { $osVersion = $map['VERSION_ID'] }
        elseif ($map.ContainsKey('VERSION')) { $osVersion = $map['VERSION'] }
    }
    if (-not $osName) {
        foreach ($rel in @('redhat-release', 'centos-release', 'rocky-release', 'alma-release', 'oracle-release', 'fedora-release')) {
            $p = Join-Path $EtcDir $rel
            if (Test-Path -LiteralPath $p) { $osName = (Get-Content -LiteralPath $p -TotalCount 1); break }
        }
        $deb = Join-Path $EtcDir 'debian_version'
        if ((Test-Path -LiteralPath $deb) -and -not $osName) {
            $osName = 'Debian GNU/Linux'
            $osVersion = (Get-Content -LiteralPath $deb -TotalCount 1)
        }
    }
    if (-not $osName) { $osName = '不明' }
    return @{ Name = $osName; Version = $osVersion }
}

function Get-SshdColumn {
    param([hashtable]$Settings, [string]$Key, [string]$DefaultLabel)
    if ($Settings.ContainsKey($Key)) { return $Settings[$Key] }
    return ('未設定(既定={0})' -f $DefaultLabel)
}

# sshd_config の Include を展開し、OpenSSH と同じ「先頭で設定された値が優先」で値を確定する
function ConvertTo-LocalGlob {
    param([string]$IncludeArg, [string]$EtcDir)
    if ($IncludeArg -eq '/etc') { return $EtcDir }
    if ($IncludeArg.StartsWith('/etc/')) { return ($EtcDir + $IncludeArg.Substring(4)) }
    # 相対パスは sshd_config の配置ディレクトリ(/etc/ssh)基準とみなす
    return (Join-Path (Join-Path $EtcDir 'ssh') $IncludeArg)
}

function Get-SshdSettings {
    param([string]$EtcDir, [string[]]$WatchKeys)
    $effective = @{}
    $processedFiles = New-Object 'System.Collections.Generic.HashSet[string]'

    function Process-SshdFile {
        param([string]$FilePath, [int]$Depth)
        if ($Depth -gt 16) { return }
        if (-not (Test-Path -LiteralPath $FilePath)) { return }
        if (-not $processedFiles.Add((Resolve-Path -LiteralPath $FilePath).Path)) { return }
        foreach ($line in @(Get-Content -LiteralPath $FilePath -ErrorAction SilentlyContinue)) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            if ($t -match '^Include\s+(\S+)') {
                $glob = ConvertTo-LocalGlob -IncludeArg $Matches[1].Trim() -EtcDir $EtcDir
                $included = @(Get-ChildItem -Path $glob -File -ErrorAction SilentlyContinue | Sort-Object Name)
                foreach ($inc in $included) { Process-SshdFile -FilePath $inc.FullName -Depth ($Depth + 1) }
                continue
            }
            if ($t -match '^([A-Za-z][A-Za-z0-9_]*)\s+(.+)$') {
                $key = $Matches[1].ToLowerInvariant()
                if (($WatchKeys -contains $key) -and -not $effective.ContainsKey($key)) {
                    $effective[$key] = $Matches[2].Trim()
                }
            }
        }
    }

    Process-SshdFile -FilePath (Join-Path $EtcDir 'ssh/sshd_config') -Depth 0
    return $effective
}

# ----------------------------------------------------------------------------
# メイン処理
# ----------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $CollectDir)) {
    throw "収集フォルダーが見つかりません: $CollectDir"
}

# ホストディレクトリの検出(直下に etc/ を持つディレクトリ。収集フォルダー自体が 1 ホスト分の場合にも対応)
if (Test-Path -LiteralPath (Join-Path $CollectDir 'etc')) {
    $hostDirs = @(Get-Item -LiteralPath $CollectDir)
}
else {
    $hostDirs = @(Get-ChildItem -LiteralPath $CollectDir -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'etc') })
}
if ($hostDirs.Count -eq 0) {
    throw "解析対象が見つかりません。$CollectDir 配下に <ホスト名>/etc が存在しません(collect-EtcData.ps1 の出力を指定してください)。"
}

Write-Log ('/etc データ解析処理を開始します。(対象: {0} / ホスト数: {1})' -f $CollectDir, $hostDirs.Count)

$sshdWatchKeys = @('port', 'permitrootlogin', 'passwordauthentication', 'pubkeyauthentication', 'permitemptypasswords')
$sshdDefaults = @{
    port                  = '22'
    permitrootlogin       = 'prohibit-password'
    passwordauthentication = 'yes'
    pubkeyauthentication  = 'yes'
    permitemptypasswords  = 'no'
}
$nonLoginShells = @('/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/usr/bin/nologin', '/sbin/shutdown', '/sbin/halt', '/bin/sync')
$severityOrder = @('高', '中', '低', '情報')

$analysisRows = New-Object System.Collections.Generic.List[object]
$findingRows = New-Object System.Collections.Generic.List[object]

foreach ($hostDir in $hostDirs) {
    $computer = $hostDir.Name
    $etcDir = Join-Path $hostDir.FullName 'etc'
    $findings = New-Object System.Collections.Generic.List[object]
    $addFinding = {
        param([string]$Severity, [string]$Category, [string]$Item, [string]$Detail)
        $findings.Add([pscustomobject][ordered]@{
            ComputerName = $computer; Severity = $Severity; Category = $Category; Item = $Item; Detail = $Detail
        })
    }

    Write-Log ("解析開始: {0}" -f $computer)

    # --- 基本情報 --------------------------------------------------------
    $osInfo = Get-OsInfo -EtcDir $etcDir
    $hostNameFile = Join-Path $etcDir 'hostname'
    $hostname = ''
    if (Test-Path -LiteralPath $hostNameFile) { $hostname = (Read-Lines -Path $hostNameFile | Select-Object -First 1) }
    if (-not $hostname) { $hostname = '不明' }

    # タイムゾーン(/etc/timezone → メタデータの LOCALTIME 行)
    $tz = ''
    $tzFile = Join-Path $etcDir 'timezone'
    if (Test-Path -LiteralPath $tzFile) { $tz = (Read-Lines -Path $tzFile | Select-Object -First 1) }
    if (-not $tz) {
        foreach ($meta in @(Get-ChildItem -Path $hostDir.FullName -Filter 'etc_meta*.txt' -File -ErrorAction SilentlyContinue)) {
            $m = ((Read-Lines -Path $meta.FullName) | Where-Object { $_ -match '^LOCALTIME:' } | Select-Object -First 1)
            if ($m) {
                $target = $m.Substring('LOCALTIME:'.Length).Trim()
                $tz = ($target -replace '^(\.\.)?/usr/share/zoneinfo/', '')
                break
            }
        }
    }
    if (-not $tz) { $tz = '不明' }

    # SELinux
    $selinuxMode = '不明'
    $selinuxConf = Join-Path $etcDir 'selinux/config'
    if (Test-Path -LiteralPath $selinuxConf) {
        $m = ((Read-Lines -Path $selinuxConf) | Where-Object { $_ -match '^\s*SELINUX=' } | Select-Object -First 1)
        if ($m -match '^\s*SELINUX=(\S+)') { $selinuxMode = $Matches[1] }
        if ($selinuxMode -eq 'disabled') {
            & $addFinding '中' 'SELinux' 'SELinux 無効' 'SELINUX=disabled です。'
        }
        elseif ($selinuxMode -eq 'permissive') {
            & $addFinding '低' 'SELinux' 'SELinux permissive' 'SELINUX=permissive です(監視のみ)。'
        }
    }
    else {
        $selinuxMode = '不明(設定ファイルなし)'
    }

    # ファイアウォール(ufw / firewalld / nftables の設定ファイルから判定)
    $fwParts = @()
    $ufwConf = Join-Path $etcDir 'ufw/ufw.conf'
    if (Test-Path -LiteralPath $ufwConf) {
        $m = ((Read-Lines -Path $ufwConf) | Where-Object { $_ -match '^\s*ENABLED=' } | Select-Object -First 1)
        if ($m -match '^\s*ENABLED=(\S+)') { $fwParts += ('ufw({0})' -f $Matches[1]) }
        else { $fwParts += 'ufw(設定あり)' }
    }
    $fwdConf = Join-Path $etcDir 'firewalld/firewalld.conf'
    if (Test-Path -LiteralPath $fwdConf) {
        $m = ((Read-Lines -Path $fwdConf) | Where-Object { $_ -match '^\s*DefaultZone=' } | Select-Object -First 1)
        if ($m -match '^\s*DefaultZone=(\S+)') { $fwParts += ('firewalld(zone={0})' -f $Matches[1]) }
        else { $fwParts += 'firewalld' }
    }
    if (Test-Path -LiteralPath (Join-Path $etcDir 'nftables.conf')) { $fwParts += 'nftables(設定あり)' }
    $firewall = if ($fwParts.Count -gt 0) { $fwParts -join ' / ' } else { '検出なし' }

    # --- ネットワーク ----------------------------------------------------
    $dnsServers = @()
    $resolvSearch = @()
    foreach ($line in (Read-Lines -Path (Join-Path $etcDir 'resolv.conf'))) {
        if ($line -match '^\s*nameserver\s+(\S+)') { $dnsServers += $Matches[1] }
        elseif ($line -match '^\s*search\s+(.+)$') { $resolvSearch = @($Matches[1].Trim() -split '\s+') }
    }
    if ($dnsServers -contains '127.0.0.53') {
        & $addFinding '情報' 'DNS' 'systemd-resolved スタブ' 'resolv.conf が 127.0.0.53 を参照しています(実効 DNS は resolvectl で確認してください)。'
    }

    $hostsEntries = 0
    $hostsCustom = @()
    foreach ($line in (Read-Lines -Path (Join-Path $etcDir 'hosts'))) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $hostsEntries++
        if ($t -notmatch 'localhost') { $hostsCustom += $t }
    }

    $mountCount = 0
    $nfsMounts = @()
    foreach ($line in (Read-Lines -Path (Join-Path $etcDir 'fstab'))) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $mountCount++
        $f = @($t -split '\s+')
        if ($f.Count -ge 3 -and $f[2] -match '^(nfs|nfs4)$') {
            $nfsMounts += ('{0} -> {1}' -f $f[0], $f[1])
        }
    }

    # --- アカウント ------------------------------------------------------
    $userCount = 0
    $loginUserCount = 0
    $uid0Accounts = @()
    foreach ($line in (Read-Lines -Path (Join-Path $etcDir 'passwd'))) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $f = @($t -split ':')
        if ($f.Count -lt 7) { continue }
        $userCount++
        if ($nonLoginShells -notcontains $f[6]) { $loginUserCount++ }
        if ($f[2] -eq '0' -and $f[0] -ne 'root') { $uid0Accounts += $f[0] }
    }
    foreach ($u in $uid0Accounts) {
        & $addFinding '高' 'アカウント' 'UID 0 アカウント' ("root 以外の UID 0 アカウントが存在します: {0}" -f $u)
    }

    # /etc/shadow(現行の collect はハッシュを除去した etc_shadow_redacted_*.txt を格納。
    # 旧データは etc/shadow をそのまま参照。sudo なしで収集した場合はどちらも存在しない)
    $shadowCollected = 'いいえ'
    $emptyPasswordAccounts = @()
    $lockedAccountCount = 0
    $noAgingAccounts = @()
    $shadowPath = Join-Path $etcDir 'shadow'
    $shadowLabel = 'はい'
    if (-not (Test-Path -LiteralPath $shadowPath)) {
        $redacted = Get-ChildItem -Path $hostDir.FullName -Filter 'etc_shadow_redacted_*.txt' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($redacted) { $shadowPath = $redacted.FullName; $shadowLabel = 'はい(ハッシュ除去)' }
    }
    if (Test-Path -LiteralPath $shadowPath) {
        $shadowCollected = $shadowLabel
        foreach ($line in (Read-Lines -Path $shadowPath)) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $f = @($t -split ':')
            if ($f.Count -lt 5) { continue }
            $name = $f[0]; $pw = $f[1]; $maxAge = $f[4]
            if ($pw -eq '') {
                $emptyPasswordAccounts += $name
            }
            elseif ($pw -match '^(\!|\*|\*LK\*)') {
                $lockedAccountCount++
            }
            elseif (($maxAge -eq '') -or ($maxAge -eq '99999')) {
                $noAgingAccounts += $name
            }
        }
        foreach ($a in $emptyPasswordAccounts) {
            & $addFinding '高' 'アカウント' '空パスワード' ("{0} はパスワードなしでログイン可能な状態です。" -f $a)
        }
        if ($noAgingAccounts.Count -gt 0) {
            & $addFinding '低' 'アカウント' 'パスワード無期限' ("パスワード有効期限が無期限のアカウント: {0}" -f (($noAgingAccounts | Select-Object -First 20) -join ', '))
        }
    }
    else {
        & $addFinding '低' 'アカウント' 'shadow 未収集' '/etc/shadow が収集されていません(sudo なし収集の可能性)。パスワードポリシー解析には sudo 付きで再収集してください。'
    }

    # wheel / sudo グループのメンバー
    $sudoGroupMembers = @()
    foreach ($line in (Read-Lines -Path (Join-Path $etcDir 'group'))) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $f = @($t -split ':')
        if ($f.Count -ge 4 -and $f[0] -in @('wheel', 'sudo') -and $f[3] -ne '') {
            $sudoGroupMembers += @($f[3] -split ',')
        }
    }

    # --- sudo ------------------------------------------------------------
    $sudoFiles = @()
    $sudoersPath = Join-Path $etcDir 'sudoers'
    if (Test-Path -LiteralPath $sudoersPath) { $sudoFiles += $sudoersPath }
    $sudoersD = Join-Path $etcDir 'sudoers.d'
    if (Test-Path -LiteralPath $sudoersD) {
        $sudoFiles += @(Get-ChildItem -LiteralPath $sudoersD -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike '.*' -and $_.Name -notlike '*~' } |
            ForEach-Object { $_.FullName })
    }
    $sudoSpecCount = 0
    $sudoNopasswdCount = 0
    foreach ($file in $sudoFiles) {
        foreach ($line in (Read-Lines -Path $file)) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            if ($t -match '^(Defaults|Host_Alias|User_Alias|Runas_Alias|Cmnd_Alias|@includedir|#includedir)') { continue }
            $sudoSpecCount++
            if ($t -match 'NOPASSWD') {
                $sudoNopasswdCount++
                & $addFinding '中' 'sudo' 'NOPASSWD エントリ' ("{0}: {1}" -f (Split-Path -Leaf $file), $t)
            }
        }
    }

    # --- SSH -------------------------------------------------------------
    $sshd = Get-SshdSettings -EtcDir $etcDir -WatchKeys $sshdWatchKeys
    $sshdEffective = @{}
    foreach ($key in $sshdWatchKeys) {
        if ($sshd.ContainsKey($key)) { $sshdEffective[$key] = $sshd[$key] }
        else { $sshdEffective[$key] = $sshdDefaults[$key] }
    }
    if ($sshdEffective['permitrootlogin'] -eq 'yes') {
        & $addFinding '高' 'SSH' 'root 直接ログイン許可' 'sshd_config の PermitRootLogin が yes です。'
    }
    if ($sshdEffective['permitemptypasswords'] -eq 'yes') {
        & $addFinding '高' 'SSH' '空パスワード許可' 'sshd_config の PermitEmptyPasswords が yes です。'
    }
    if ($sshdEffective['passwordauthentication'] -eq 'yes') {
        & $addFinding '中' 'SSH' 'パスワード認証有効' 'sshd_config の PasswordAuthentication が yes です(既定値の場合を含みます)。'
    }

    # --- コマンドレポート(collect のコマンド収集。旧データには存在しない) ----
    $kernel = ''
    $virtualization = ''
    $effectiveDns = ''
    $cmdDir = Join-Path $hostDir.FullName 'commands'
    if (Test-Path -LiteralPath $cmdDir) {
        $unameLine = (Read-Lines -Path (Join-Path $cmdDir '02_uname.txt')) | Select-Object -First 1
        if ($unameLine) {
            $u = @($unameLine -split '\s+')
            if ($u.Count -ge 3) { $kernel = $u[2] }
        }
        $vLine = (Read-Lines -Path (Join-Path $cmdDir '01_hostnamectl.txt')) | Where-Object { $_ -match '^\s*Virtualization:\s*(\S+)' } | Select-Object -First 1
        if ($vLine -match '^\s*Virtualization:\s*(\S+)') { $virtualization = $Matches[1] }
        $dnsFromCmd = @()
        foreach ($line in (Read-Lines -Path (Join-Path $cmdDir '05_resolvectl.txt'))) {
            if ($line -match '^\s*DNS Servers:\s*(.+)$') { $dnsFromCmd += @($Matches[1] -split '\s+') }
        }
        $effectiveDns = (($dnsFromCmd | Sort-Object -Unique) -join ',')
        if ($effectiveDns -and (($dnsServers -join ',') -notlike "*$effectiveDns*")) {
            & $addFinding '情報' 'DNS' '実効 DNS と resolv.conf の差異' ("resolvectl が参照する実効 DNS: {0}" -f $effectiveDns)
        }
    }

    # --- cron ------------------------------------------------------------
    $cronFiles = 0
    if (Test-Path -LiteralPath (Join-Path $etcDir 'crontab')) { $cronFiles++ }
    foreach ($d in @('cron.d', 'cron.hourly', 'cron.daily', 'cron.weekly', 'cron.monthly')) {
        $p = Join-Path $etcDir $d
        if (Test-Path -LiteralPath $p) { $cronFiles += @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue).Count }
    }

    # --- 行まとめ --------------------------------------------------------
    & $addFinding '情報' '基本情報' 'OS' (Limit-Text (("{0} {1}" -f $osInfo.Name, $osInfo.Version).Trim()))
    foreach ($f in $findings) { $findingRows.Add($f) }

    $high = @($findings | Where-Object { $_.Severity -eq '高' }).Count
    $medium = @($findings | Where-Object { $_.Severity -eq '中' }).Count
    $low = @($findings | Where-Object { $_.Severity -eq '低' }).Count
    $info = @($findings | Where-Object { $_.Severity -eq '情報' }).Count

    & $addFinding '情報' '基本情報' 'OS' ("{0} {1}" -f $osInfo.Name, $osInfo.Version).Trim()

    $analysisRows.Add([pscustomobject][ordered]@{
        ComputerName            = $computer
        HostName                = $hostname
        OsName                  = $osInfo.Name
        OsVersion               = $osInfo.Version
        Kernel                  = $kernel
        Virtualization          = $virtualization
        TimeZone                = $tz
        SelinuxMode             = $selinuxMode
        Firewall                = $firewall
        DnsServers              = ($dnsServers -join ',')
        EffectiveDns            = $effectiveDns
        ResolvSearch            = ($resolvSearch -join ',')
        MountCount              = $mountCount
        NfsMounts               = Limit-Text ($nfsMounts -join ' | ')
        HostsEntries            = $hostsEntries
        HostsCustomEntries      = Limit-Text (($hostsCustom | Select-Object -First 10) -join ' | ') 200
        UserCount               = $userCount
        LoginUserCount          = $loginUserCount
        Uid0Accounts            = ($uid0Accounts -join ',')
        ShadowCollected         = $shadowCollected
        EmptyPasswordAccounts   = ($emptyPasswordAccounts -join ',')
        LockedAccountCount      = $lockedAccountCount
        NoAgingAccounts         = Limit-Text (($noAgingAccounts | Select-Object -First 20) -join ',')
        SudoGroupMembers        = ($sudoGroupMembers -join ',')
        SudoSpecCount           = $sudoSpecCount
        SudoNopasswdCount       = $sudoNopasswdCount
        SshPort                 = Get-SshdColumn -Settings $sshd -Key 'port' -DefaultLabel '22'
        SshPermitRootLogin      = Get-SshdColumn -Settings $sshd -Key 'permitrootlogin' -DefaultLabel 'prohibit-password'
        SshPasswordAuthentication = Get-SshdColumn -Settings $sshd -Key 'passwordauthentication' -DefaultLabel 'yes'
        SshPubkeyAuthentication = Get-SshdColumn -Settings $sshd -Key 'pubkeyauthentication' -DefaultLabel 'yes'
        SshPermitEmptyPasswords = Get-SshdColumn -Settings $sshd -Key 'permitemptypasswords' -DefaultLabel 'no'
        CronFiles               = $cronFiles
        FindingsHigh            = $high
        FindingsMedium          = $medium
        FindingsLow             = $low
        FindingsInfo            = $info
    })

    Write-Log ("解析終了: {0} (高={1} / 中={2} / 低={3} / 情報={4})" -f $computer, $high, $medium, $low, $info)
}

# ----------------------------------------------------------------------------
# 結果出力
# ----------------------------------------------------------------------------
$analysisRows | Export-Csv -LiteralPath $AnalysisCsvPath -NoTypeInformation -Encoding UTF8
$findingRows | Export-Csv -LiteralPath $FindingsCsvPath -NoTypeInformation -Encoding UTF8

$totalHigh = @($findingRows | Where-Object { $_.Severity -eq '高' }).Count
$totalMedium = @($findingRows | Where-Object { $_.Severity -eq '中' }).Count
$totalLow = @($findingRows | Where-Object { $_.Severity -eq '低' }).Count
$totalInfo = @($findingRows | Where-Object { $_.Severity -eq '情報' }).Count

$summary = ('処理サマリー: ホスト数={0} / 要確認項目 高={1} 中={2} 低={3} 情報={4}' -f $hostDirs.Count, $totalHigh, $totalMedium, $totalLow, $totalInfo)
Write-Log $summary
Write-Log ("分析CSV: {0}" -f $AnalysisCsvPath)
Write-Log ("要確認CSV: {0}" -f $FindingsCsvPath)
Write-Log '/etc データ解析処理を終了します。'

if ($totalHigh -gt 0) { Write-Host "`n[注意] 重大度「高」の項目が $totalHigh 件あります。EtcFindings CSV を確認してください。" -ForegroundColor Red }
