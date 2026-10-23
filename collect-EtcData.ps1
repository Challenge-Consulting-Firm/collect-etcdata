#Requires -Version 5.1
<#
.SYNOPSIS
    Linux サーバーの /etc 配下を一括取得するスクリプト(Windows から SSH 経由)。

.DESCRIPTION
    対象サーバー一覧(CSV)を読み込み、各サーバーへ SSH(Posh-SSH モジュール)で接続して
    /etc 配下を tar.gz アーカイブ化 → SFTP でダウンロード → ローカルへ展開します。
    あわせて /etc のメタデータ(パス・パーミッション・所有者)を etc_meta_*.txt として収集します。

    リモート側は /tmp 直下に一時ファイルを作成するだけで、既存のファイルは一切変更しません
    (終了後に一時ファイルを削除します)。
    /etc 以外の設定情報(カーネル/ネットワーク/サービス/パッケージ/ファイアウォール等)は
    コマンド出力として commands/ フォルダーに収集します(-NoCommandReport でスキップ可)。

    出力先フォルダー構成:
        EtcCollected_<日時>/
          ├─ <ComputerName>/etc/...                  # 展開済み /etc の中身
          ├─ <ComputerName>/commands/...             # コマンド収集レポート(hostnamectl / ip / systemctl / resolvectl 等)
          ├─ <ComputerName>/etc_meta_<日時>.txt      # パーミッション等のメタデータ
          ├─ <ComputerName>/etc_collect_<日時>.tar.gz # ダウンロードしたアーカイブ(既定は展開後に削除。-KeepArchive で保持)
          └─ EtcCollectResult.csv                    # 取得結果(CSV)

    既定では sudo を使って /etc/shadow や SSH ホスト鍵などの機密ファイルも収集します。
    アーカイブには機密情報が含まれるため、保管・取り扱いには十分注意してください。
    機密ファイルが不要な場合は -NoSudo を指定してください(読み取り可能なファイルのみ収集)。

    CSV の UserName 列に複数のユーザーが混在する場合、ユーザーごとに 1 回ずつ
    パスワードを入力します(同一ユーザーは最初の 1 回のみ)。sudo パスワードは既定で
    そのユーザーのログインパスワードを使用します。

    -KeyFile(または CSV の KeyFile 列)を指定すると、秘密鍵による公開鍵認証で接続します。
    鍵のパスフレーズは鍵ファイルごとに 1 回だけ入力します(パスフレーズなしの鍵は Enter のみ)。
    鍵認証ではログインパスワードが無いため、sudo パスワードは -SudoPassword で指定するか、
    ユーザーごとに 1 回入力します(空 Enter の場合は NOPASSWD 前提で sudo -n を使用)。

    使用例:
        .\collect-EtcData.ps1 -UserName admin
        .\collect-EtcData.ps1 -Credential (Get-Credential) -InputCsvPath .\Targets.csv
        .\collect-EtcData.ps1 -UserName root -NoSudo
        .\collect-EtcData.ps1 -UserName admin -KeyFile ~\.ssh\id_ed25519

    事前に Posh-SSH を導入してください(初回のみ):
        Install-Module Posh-SSH -Scope CurrentUser
#>
[CmdletBinding()]
param(
    [string]$InputCsvPath = (Join-Path $PSScriptRoot 'TargetServers.csv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot ('EtcCollected_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$LogPath = (Join-Path $PSScriptRoot 'EtcCollect_Check.log'),
    [pscredential]$Credential,
    [string]$UserName,
    [string]$KeyFile,
    [securestring]$KeyPassphrase,
    [int]$Port = 22,
    [int]$ConnectionTimeoutSeconds = 15,
    [int]$CommandTimeoutSeconds = 300,
    [string]$EtcPath = '/etc',
    [switch]$NoCommandReport,
    [securestring]$SudoPassword,
    [switch]$NoSudo,
    [switch]$KeepArchive
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

function ConvertTo-PlainText {
    param([securestring]$SecureString)
    if (-not $SecureString) { return $null }
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    catch {
        # PowerShell 7 (Windows 以外) では Marshal API が使えないためフォールバック
        return (ConvertFrom-SecureString -SecureString $SecureString -AsPlainText)
    }
}

function Test-TcpPort {
    param([string]$HostName, [int]$TcpPort, [int]$TimeoutSeconds)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $TcpPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Get-MarkerValue {
    param([string]$Text, [string]$Name)
    $m = [regex]::Match($Text, ('(?m)^' + [regex]::Escape($Name) + ':(.*)$'))
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [regex]::Escape((-join [System.IO.Path]::GetInvalidFileNameChars()))
    return ($Name -replace "[$invalid]", '_')
}

# ----------------------------------------------------------------------------
# 前提確認
# ----------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "対象サーバー一覧 CSV が見つかりません: $InputCsvPath"
}
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    throw 'Posh-SSH モジュールが未導入です。Install-Module Posh-SSH -Scope CurrentUser を実行してください。'
}
Import-Module Posh-SSH -ErrorAction Stop
if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
    throw 'tar コマンドが見つかりません。Windows 10 (1803+) / macOS / Linux には標準で含まれます。'
}

# 資格情報の解決
# CSV の UserName 列に複数ユーザーが混在する場合、ユーザーごとに 1 回だけパスワードを入力し、
# 以降のホストで再利用します(ユーザー名でキャッシュ)。
# -Credential / -UserName は「UserName 列が空の行」に対する既定ユーザーとして扱われます。
$defaultUserName = $UserName
$credentialCache = @{}
if ($Credential) {
    $defaultUserName = $Credential.UserName
    $credentialCache[$defaultUserName.ToLowerInvariant()] = $Credential
}

function Get-HostCredential {
    param([string]$HostName, [string]$RowUserName)
    if ($RowUserName) {
        $key = $RowUserName.ToLowerInvariant()
        if ($credentialCache.ContainsKey($key)) { return $credentialCache[$key] }
        $cred = Get-Credential -UserName $RowUserName -Message ("SSH ログイン資格情報を入力してください (user={0}, host={1})" -f $RowUserName, $HostName)
        if ($cred -and $cred.UserName) { $credentialCache[$cred.UserName.ToLowerInvariant()] = $cred }
    }
    else {
        $cred = Get-Credential -Message ("SSH ログイン資格情報を入力してください (host={0})" -f $HostName)
        if ($cred -and $cred.UserName) { $credentialCache[$cred.UserName.ToLowerInvariant()] = $cred }
    }
    if (-not $cred -or -not $cred.UserName) {
        throw ("資格情報が入力されませんでした (host={0})。" -f $HostName)
    }
    return $cred
}

# 鍵認証の資格情報
# Posh-SSH では -KeyFile 指定時、Credential のパスワード欄が鍵のパスフレーズとして扱われます。
# パスフレーズは鍵ファイルごとに 1 回だけ入力し(-KeyPassphrase 指定時は入力なし)、以降は再利用します。
# -Credential のパスワードはログインパスワードとして扱うため、鍵認証ではユーザー名のみ使用します。
$passphraseCache = @{}
$sudoPasswordCache = @{}

function Resolve-KeyFilePath {
    param([string]$Path)
    # ~ や相対パスをカレントディレクトリ基準のフルパスへ変換
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-KeyCredential {
    param([string]$HostName, [string]$RowUserName, [string]$KeyPath)
    if (-not $RowUserName) {
        throw ("鍵認証ではユーザー名が必要です。-UserName / -Credential または CSV の UserName 列を指定してください (host={0})。" -f $HostName)
    }
    $passphrase = $KeyPassphrase
    if (-not $passphrase) {
        $key = $KeyPath.ToLowerInvariant()
        if (-not $passphraseCache.ContainsKey($key)) {
            $passphraseCache[$key] = Read-Host -AsSecureString -Prompt ("秘密鍵のパスフレーズを入力してください(パスフレーズなしの場合は Enter) (key={0})" -f $KeyPath)
        }
        $passphrase = $passphraseCache[$key]
    }
    return (New-Object System.Management.Automation.PSCredential($RowUserName, $passphrase))
}

function Get-KeyAuthSudoPassword {
    param([string]$HostName, [string]$RowUserName)
    $key = $RowUserName.ToLowerInvariant()
    if (-not $sudoPasswordCache.ContainsKey($key)) {
        $sudoPasswordCache[$key] = Read-Host -AsSecureString -Prompt ("sudo パスワードを入力してください(NOPASSWD の場合は Enter) (user={0}, host={1})" -f $RowUserName, $HostName)
    }
    return $sudoPasswordCache[$key]
}

# tar 対象パスの分解(/etc → base='/', name='etc')
$lastSlash = $EtcPath.LastIndexOf('/')
if ($lastSlash -lt 0 -or $lastSlash -eq ($EtcPath.Length - 1)) {
    throw "EtcPath が不正です: $EtcPath (例: /etc)"
}
$tarBase = $EtcPath.Substring(0, $lastSlash)
if (-not $tarBase) { $tarBase = '/' }
$tarName = $EtcPath.Substring($lastSlash + 1)

# リモートで実行するシェルスクリプトのテンプレート
#   - メタデータ(stat)は一般ユーザーで取得(メタ情報の参照に root は不要)
#   - tar は __SUDOPREFIX__ 付きで実行(既定 sudo。/etc/shadow 等も収集)
#   - パスワードは printf '%s\n' 経由のため ps に出ず、シェルのエスケープ解釈(echo の \ 問題)も受けない
$payloadTemplate = @'
set -u
TS=$(date +%Y%m%d_%H%M%S)
CMDIR="/tmp/etc_cmds_${TS}"
META="/tmp/etc_meta_${TS}.txt"
ARCHIVE="/tmp/etc_collect_${TS}.tar.gz"
ERRLOG="/tmp/etc_collect_err_${TS}.log"
echo "CMDIR:$CMDIR"
echo "METAPATH:$META"
echo "ERRLOGPATH:$ERRLOG"
find __ETCPATH__ -exec stat -c '%n|%A|%U|%G|%s|%Y' {} + >"$META" 2>/dev/null
echo "METAEXIT:$?"
echo "LOCALTIME:$(readlink __ETCPATH__/localtime 2>/dev/null)" >>"$META"
__COMMANDBLOCK__
__SUDOPREFIX__tar czf "$ARCHIVE" -C "__TARBASE__" "__TARNAME__" __CMDIRTARARG__ -C /tmp "$(basename "$META")" 2>"$ERRLOG"
echo "TAREXIT:$?"
echo "ERRSUMMARY:$(head -c 300 "$ERRLOG" 2>/dev/null | tr '\n' ' ')"
if [ -f "$ARCHIVE" ]; then
  echo "SIZE:$(stat -c %s "$ARCHIVE")"
  echo "SHA256:$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
  echo "FILES:$(tar tzf "$ARCHIVE" 2>/dev/null | wc -l)"
  echo "ARCHIVEPATH:$ARCHIVE"
fi
'@

# コマンドレポート(/etc に存在しない設定情報をコマンド出力として収集)
# 存在しないコマンドは「not found」がファイルに記録されるだけで処理は継続する。
# 各行は LF で結合すること(Windows で実行した場合に CR が混入しないよう、送出前に CR を除去)。
$commandBlock = ':'
$cmdirTarArg = ''
if (-not $NoCommandReport) {
    $reportCommands = @(
        @('01_hostnamectl.txt', 'hostnamectl'),
        @('02_uname.txt', 'uname -a'),
        @('03_ip_addr.txt', 'ip -o addr show'),
        @('04_ip_route.txt', 'ip route show'),
        @('05_resolvectl.txt', 'resolvectl status'),
        @('06_timedatectl.txt', 'timedatectl'),
        @('07_df.txt', 'df -hT'),
        @('08_lsblk.txt', 'lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT'),
        @('09_services_running.txt', 'systemctl list-units --type=service --state=running --no-pager'),
        @('10_services_enabled.txt', 'systemctl list-unit-files --type=service --no-pager'),
        @('11_packages_rpm.txt', 'rpm -qa | sort'),
        @('11_packages_dpkg.txt', 'dpkg-query -W | sort'),
        @('12_root_crontab.txt', 'crontab -l'),
        @('13_nmcli.txt', 'nmcli device show'),
        @('14_nftables.txt', 'nft list ruleset'),
        @('15_iptables.txt', 'iptables -S'),
        @('16_getenforce.txt', 'getenforce')
    )
    $block = New-Object System.Text.StringBuilder
    [void]$block.Append('mkdir -p "$CMDIR/commands"' + "`n")
    foreach ($pair in $reportCommands) {
        [void]$block.Append(('__SUDOPREFIX__{0} >"$CMDIR/commands/{1}" 2>&1' -f $pair[1], $pair[0]) + "`n")
    }
    $commandBlock = $block.ToString()
    $cmdirTarArg = '-C "$CMDIR" commands'
}

# ----------------------------------------------------------------------------
# メイン処理
# ----------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Log ('/etc データ一括取得処理を開始します。(出力先: {0})' -f $OutputPath)

$targets = @(Import-Csv -LiteralPath $InputCsvPath | Where-Object { $_.PSObject.Properties['ComputerName'] -and $_.ComputerName -and $_.ComputerName.Trim() -ne '' })
if ($targets.Count -eq 0) {
    throw "対象サーバー一覧 CSV に有効な行がありません(ComputerName 列が必要です): $InputCsvPath"
}
Write-Log ("対象サーバー数: {0}" -f $targets.Count)

$resultRows = New-Object System.Collections.Generic.List[object]
$usedDirNames = @{}
$successCount = 0
$failCount = 0
$hostIndex = 0

foreach ($target in $targets) {
    $hostIndex++
    $computer = $target.ComputerName.Trim()

    # CSV の UserName / Port 列による行単位の上書き(空欄は既定値へフォールバック)
    $rowUserName = $defaultUserName
    if ($target.PSObject.Properties['UserName'] -and $target.UserName -and $target.UserName.Trim() -ne '') {
        $rowUserName = $target.UserName.Trim()
    }
    $rowPort = $Port
    if ($target.PSObject.Properties['Port'] -and $target.Port -and $target.Port.Trim() -match '^\d+$') {
        $rowPort = [int]$target.Port.Trim()
    }
    # CSV の KeyFile 列による行単位の上書き(指定があれば秘密鍵による公開鍵認証)
    $rowKeyFile = $KeyFile
    if ($target.PSObject.Properties['KeyFile'] -and $target.KeyFile -and $target.KeyFile.Trim() -ne '') {
        $rowKeyFile = $target.KeyFile.Trim()
    }
    $authMethod = 'password'
    $keyFileMissing = $false
    if ($rowKeyFile) {
        $authMethod = 'key'
        $rowKeyFile = Resolve-KeyFilePath -Path $rowKeyFile
        $keyFileMissing = -not (Test-Path -LiteralPath $rowKeyFile -PathType Leaf)
    }

    # ユーザーごとの資格情報(同一ユーザーは最初の 1 回だけ入力)
    # 鍵ファイルが見つからない場合は入力を求めず、下の try 内で失敗として記録する
    $hostCredential = $null
    $sudoPrefix = ''
    if (-not $keyFileMissing) {
        if ($authMethod -eq 'key') {
            $hostCredential = Get-KeyCredential -HostName $computer -RowUserName $rowUserName -KeyPath $rowKeyFile
        }
        else {
            $hostCredential = Get-HostCredential -HostName $computer -RowUserName $rowUserName
        }

        # sudo プレフィックス(既定はそのユーザーのログインパスワード。シングルクォートはリモートシェル向けにエスケープ)
        # ※ echo は dash 系 /bin/sh でバックスラッシュ解釈されるため、解釈されない printf '%s\n' を使用
        # 鍵認証ではログインパスワードが無いため、-SudoPassword かユーザーごとの入力値を使用。
        # 空の場合は NOPASSWD 前提で sudo -n(パスワードを要求されたら待たずに失敗)
        if (-not $NoSudo) {
            if ($SudoPassword) { $sudoSecure = $SudoPassword }
            elseif ($authMethod -eq 'key') { $sudoSecure = Get-KeyAuthSudoPassword -HostName $computer -RowUserName $hostCredential.UserName }
            else { $sudoSecure = $hostCredential.Password }
            if ($sudoSecure.Length -eq 0) {
                $sudoPrefix = 'sudo -n '
            }
            else {
                $plainSudoPw = ConvertTo-PlainText -SecureString $sudoSecure
                $sudoPrefix = "printf '%s\n' '" + $plainSudoPw.Replace("'", "'\\''") + "' | sudo -S -p '' "
            }
        }
    }

    $row = [pscustomobject]@{
        ComputerName    = $computer
        AuthMethod      = $authMethod
        Status          = ''
        ArchiveSizeBytes = ''
        FileCount       = ''
        Sha256          = ''
        LocalEtcPath    = ''
        LocalArchivePath = ''
        LocalMetadataPath = ''
        LocalCommandsPath = ''
        CommandFileCount = ''
        RemoteTempCleaned = ''
        ErrorMessage    = ''
    }

    $authLabel = $authMethod
    if ($authMethod -eq 'key') { $authLabel = 'key:{0}' -f $rowKeyFile }
    Write-Log ("処理開始 ({0}/{1}): {2} (user={3}, port={4}, auth={5})" -f $hostIndex, $targets.Count, $computer, $rowUserName, $rowPort, $authLabel)

    # ローカル保存先ディレクトリ(同名ホストは _2, _3 ... で回避)
    $safeName = Get-SafeFileName -Name $computer
    if ($usedDirNames.ContainsKey($safeName)) {
        $usedDirNames[$safeName]++
        $safeName = '{0}_{1}' -f $safeName, $usedDirNames[$safeName]
    }
    else { $usedDirNames[$safeName] = 1 }
    $hostDir = Join-Path $OutputPath $safeName
    New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
    $row.LocalEtcPath = Join-Path $hostDir $tarName

    $sshSession = $null
    $sftpSession = $null
    $remoteArchive = $null
    $remoteMeta = $null
    $remoteErrLog = $null
    $remoteCmdDir = $null

    try {
        if ($keyFileMissing) {
            throw ("SSH接続失敗: 秘密鍵ファイルが見つかりません: {0}" -f $rowKeyFile)
        }

        # SSH / SFTP セッション共通の接続パラメーター(鍵認証時は -KeyFile を追加)
        $sessionParams = @{
            ComputerName = $computer
            Port         = $rowPort
            Credential   = $hostCredential
            ErrorAction  = 'Stop'
        }
        if ($authMethod -eq 'key') { $sessionParams['KeyFile'] = $rowKeyFile }

        # 1) TCP 到達確認(実際に使う SSH ポートを確認)
        if (-not (Test-TcpPort -HostName $computer -TcpPort $rowPort -TimeoutSeconds $ConnectionTimeoutSeconds)) {
            throw ("SSH接続失敗: TCP {0}:{1} へ接続できませんでした(タイムアウト/拒否)。ホスト名・ポート・ファイアウォールを確認してください。" -f $computer, $rowPort)
        }
        Write-Log ("SSH通信確認 成功: {0}:{1}" -f $computer, $rowPort)

        # 2) SSH ログイン
        try { $sshSession = New-SSHSession @sessionParams }
        catch { throw ('SSH接続失敗: {0}' -f $_.Exception.Message) }
        Write-Log ("SSHログイン 成功: {0}" -f $computer)

        # 3) リモートでアーカイブ作成(+メタデータ取得)
        $payload = $payloadTemplate.Replace('__COMMANDBLOCK__', $commandBlock).Replace('__CMDIRTARARG__', $cmdirTarArg).Replace('__SUDOPREFIX__', $sudoPrefix).Replace('__ETCPATH__', $EtcPath).Replace('__TARBASE__', $tarBase).Replace('__TARNAME__', $tarName)
        $payload = $payload -replace "`r", ''   # Windows で実行した場合の CR 混入対策

        $result = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command $payload -TimeOut $CommandTimeoutSeconds
        $stdout = @($result.Output) -join "`n"
        $stderr = @($result.Error) -join "`n"

        $remoteArchive = Get-MarkerValue -Text $stdout -Name 'ARCHIVEPATH'
        $remoteMeta    = Get-MarkerValue -Text $stdout -Name 'METAPATH'
        $remoteErrLog  = Get-MarkerValue -Text $stdout -Name 'ERRLOGPATH'
        $remoteCmdDir  = Get-MarkerValue -Text $stdout -Name 'CMDIR'
        $remoteSha256  = Get-MarkerValue -Text $stdout -Name 'SHA256'
        $remoteSize    = Get-MarkerValue -Text $stdout -Name 'SIZE'
        $remoteFiles   = Get-MarkerValue -Text $stdout -Name 'FILES'
        $tarExit       = Get-MarkerValue -Text $stdout -Name 'TAREXIT'
        $metaExit      = Get-MarkerValue -Text $stdout -Name 'METAEXIT'
        $errSummary    = Get-MarkerValue -Text $stdout -Name 'ERRSUMMARY'

        if (-not $remoteArchive) {
            $detail = $errSummary
            if (-not $detail) { $detail = $stderr }
            throw ('アーカイブ作成失敗: リモート側で tar.gz が作成されませんでした。TAREXIT={0} / 詳細: {1}' -f $tarExit, $detail)
        }
        if ($metaExit -and $metaExit -ne '0') {
            Write-Log ("WARN: メタデータ取得に失敗(BusyBox 等の stat 非対応の可能性): {0}" -f $computer) 'WARN'
            $row.ErrorMessage = 'メタデータ取得失敗(stat 非対応の可能性)。'
        }
        if ($tarExit -and $tarExit -ne '0') {
            Write-Log ("WARN: tar が終了コード {0} で完了(一部ファイル読み取り不可の可能性): {1} / {2}" -f $tarExit, $computer, $errSummary) 'WARN'
            $row.ErrorMessage += ("tar終了コード={0}(一部未収集の可能性)。" -f $tarExit)
        }
        Write-Log ("アーカイブ作成 成功: {0} ({1} bytes, {2} files)" -f $remoteArchive, $remoteSize, ($remoteFiles -replace '\s', ''))

        # 4) SFTP ダウンロード(Posh-SSH 3.2 は SSH セッションの流用に未対応のため別セッションで按続)
        $sftpSession = New-SFTPSession @sessionParams

        $archiveName = Split-Path -Leaf $remoteArchive
        try {
            Get-SFTPItem -SessionId $sftpSession.SessionId -Path $remoteArchive -Destination $hostDir -Force -ErrorAction Stop | Out-Null
        }
        catch { throw ('SFTPダウンロード失敗: {0}' -f $_.Exception.Message) }
        $localArchive = Join-Path $hostDir $archiveName
        if (-not (Test-Path -LiteralPath $localArchive)) { throw 'SFTPダウンロード失敗: ローカルファイルが作成されませんでした。' }
        Write-Log ("ダウンロード 成功: {0}" -f $localArchive)

        # 5) 整合性確認(SHA256)
        $localHash = (Get-FileHash -LiteralPath $localArchive -Algorithm SHA256).Hash
        if ($remoteSha256 -and ($localHash -ne $remoteSha256)) {
            throw ("整合性不一致: リモートSHA256={0} / ローカルSHA256={1}" -f $remoteSha256, $localHash)
        }
        $row.Sha256 = $localHash
        $row.ArchiveSizeBytes = $remoteSize
        $row.FileCount = ($remoteFiles -replace '\s', '')
        $row.LocalArchivePath = $localArchive
        $metaName = Split-Path -Leaf $remoteMeta
        $localMeta = Join-Path $hostDir $metaName
        if (Test-Path -LiteralPath $localMeta) { $row.LocalMetadataPath = $localMeta }
        Write-Log ('整合性確認 成功 (SHA256 一致)')

        # 6) ローカル展開(Windows 標準の bsdtar を使用)
        $tarOutput = & tar -xzf $localArchive -C $hostDir 2>&1
        $tarExitCode = $LASTEXITCODE
        if (-not (Test-Path -LiteralPath $row.LocalEtcPath)) {
            throw ("展開失敗: {0} が作成されませんでした。tar exit={1} / 出力: {2}" -f $row.LocalEtcPath, $tarExitCode, ((@($tarOutput) -join ' ')))
        }
        if ($tarExitCode -ne 0) {
            Write-Log ("WARN: 展開中に警告がありました(シンボリックリンク等)。tar exit={0}: {1}" -f $tarExitCode, ((@($tarOutput) | Select-Object -First 2) -join ' ')) 'WARN'
            $row.ErrorMessage += '展開時に警告(シンボリックリンク等)。'
        }
        Write-Log ('ローカル展開 成功')

        # コマンドレポートの確認
        $commandsPath = Join-Path $hostDir 'commands'
        if (Test-Path -LiteralPath $commandsPath) {
            $row.LocalCommandsPath = $commandsPath
            $row.CommandFileCount = @(Get-ChildItem -LiteralPath $commandsPath -File -ErrorAction SilentlyContinue).Count
            Write-Log ('コマンドレポート: {0} ファイル' -f $row.CommandFileCount)
        }

        # アーカイブ削除(既定。-KeepArchive 指定時は保持。
        # 展開に警告があった場合は再展開できるよう保持)
        if (-not $KeepArchive) {
            if ($tarExitCode -ne 0) {
                Write-Log 'WARN: 展開に警告があったため、アーカイブを保持します(必要に応じて他環境で再展開してください)。' 'WARN'
                $row.ErrorMessage += '展開警告のためアーカイブを保持。'
            }
            else {
                Remove-Item -LiteralPath $localArchive -Force
                $row.LocalArchivePath = '(展開後に削除)'
                Write-Log ('アーカイブを削除しました(保持する場合は -KeepArchive を指定): {0}' -f (Split-Path -Leaf $localArchive))
            }
        }

        $row.Status = '成功'
        $successCount++
        Write-Log ("処理終了 ({0}/{1}): {2} → 成功" -f $hostIndex, $targets.Count, $computer)
    }
    catch {
        $row.Status = '失敗'
        $row.ErrorMessage = ($row.ErrorMessage + $_.Exception.Message).Trim()
        $failCount++
        Write-Log ("処理失敗 ({0}/{1}): {2} / {3}" -f $hostIndex, $targets.Count, $computer, $_.Exception.Message) 'ERROR'
    }
    finally {
        # 7) リモート一時ファイルの削除(ダウンロード成否に関わらず実行)
        # 1 件だけの場合もスカラーにならないよう @() で配列化(StrictMode 下で .Count が失敗するため)
        $cleanupTargets = @(@($remoteArchive, $remoteMeta, $remoteErrLog, $remoteCmdDir) | Where-Object { $_ })
        if ($sshSession -and $cleanupTargets.Count -gt 0) {
            try {
                $cleanupList = ($cleanupTargets | ForEach-Object { "'$_'" }) -join ' '
                # sudo が失敗した場合(パスワード誤り / sudo -n でパスワード要求等)は sudo なしで再試行
                # (アーカイブ作成前に失敗した場合、残るのは接続ユーザー所有のファイルのみ)
                $cleanup = $sudoPrefix + 'rm -rf ' + $cleanupList + ' 2>/dev/null || rm -rf ' + $cleanupList + '; echo "CLEANUPEXIT:$?"'
                $cleanupResult = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command $cleanup -TimeOut 60
                $cleanupExit = Get-MarkerValue -Text (@($cleanupResult.Output) -join "`n") -Name 'CLEANUPEXIT'
                if ($cleanupExit -ne '0') {
                    throw ('rm 終了コード={0} / {1}' -f $cleanupExit, ((@($cleanupResult.Error) -join ' ').Trim()))
                }
                $row.RemoteTempCleaned = 'はい'
                Write-Log ('リモート一時ファイル削除 完了')
            }
            catch {
                $row.RemoteTempCleaned = 'いいえ'
                Write-Log ("リモート一時ファイル削除 失敗: {0}" -f $_.Exception.Message) 'WARN'
            }
        }
        if ($sftpSession) { try { Remove-SFTPSession -SessionId $sftpSession.SessionId | Out-Null } catch {} }
        if ($sshSession) { try { Remove-SSHSession -SessionId $sshSession.SessionId | Out-Null } catch {} }
    }

    $resultRows.Add($row)
}

# ----------------------------------------------------------------------------
# 結果出力
# ----------------------------------------------------------------------------
$resultCsv = Join-Path $OutputPath 'EtcCollectResult.csv'
$resultRows | Export-Csv -LiteralPath $resultCsv -NoTypeInformation -Encoding UTF8

$summary = ('処理サマリー: 対象={0} / 成功={1} / 失敗={2} / 結果CSV={3}' -f $targets.Count, $successCount, $failCount, $resultCsv)
Write-Log $summary
Write-Log '/etc データ一括取得処理を終了します。'
