# etc-collector-analyzer

[Challenge-Consulting-Firm/replace-dnsaddress](https://github.com/Challenge-Consulting-Firm/replace-dnsaddress) を参考にした運用スクリプト群です。
対象サーバー一覧(CSV)を読み込み、Linux サーバーの **/etc 配下を一括で取得(Windows から SSH 経由)** し、
収集データを **解析して CSV レポート化** します。

```
research-linux/
├── collect-EtcData.ps1    # /etc 一括取得(SSH + Posh-SSH / tar.gz アーカイブ → SFTP ダウンロード → ローカル展開)
├── analyze-EtcData.ps1   # 収集データの解析(設定一覧 CSV + 要確認項目 CSV を出力)
├── TargetServers.csv      # 入力: 対象サーバー一覧(サンプル)
├── README.md
└── .gitignore
```

いずれも PowerShell スクリプトで、参考リポジトリと同じく **入力 CSV・出力 CSV・レベル付きログ** の運用スタイルです。
`collect` はリモート側の既存ファイルを一切変更しない(読み取り専用)安全設計です。

## コマンド例(チートシート)

Linux 版は `Install-Module Posh-SSH -Scope CurrentUser` を初回に実行してください。

```powershell
# ── 準備 ──
Install-Module Posh-SSH -Scope CurrentUser          # 初回のみ

# 対象 CSV をその場で作る(ComputerName だけ)
"ComputerName`n192.0.2.10`n192.0.2.11" | Set-Content .\Targets.csv -Encoding UTF8

# UserName / Port も指定した CSV(ユーザーが混在する場合、ユーザーごとに 1 回ずつパスワードを入力)
@"
ComputerName,UserName,Port
192.0.2.10,admin,22
192.0.2.11,operator,2222
"@ | Set-Content .\Targets.csv -Encoding UTF8

$cred = Get-Credential admin                        # 資格情報を一度だけ入力して使い回す

# ── 1) /etc 一括取得 ──
.\collect-EtcData.ps1 -UserName admin                                     # パスワードは実行時入力
.\collect-EtcData.ps1 -Credential $cred -InputCsvPath .\Targets.csv        # 資格情報を使い回す
.\collect-EtcData.ps1 -UserName root -NoSudo                               # root 直接ログイン(sudo 不要)
.\collect-EtcData.ps1 -UserName admin -KeepArchive                         # tar.gz を残す(既定は展開後に削除)

# ── 2) 解析 ──
$dir = Get-ChildItem -Directory -Path .\EtcCollected_* | Sort-Object Name -Descending | Select-Object -First 1
.\analyze-EtcData.ps1 -CollectDir $dir.FullName

# ── 3) 確認 ──
Import-Csv .\EtcAnalysis_<日時>.csv   | Format-Table ComputerName,OsName,DnsServers,SshPermitRootLogin -AutoSize
Import-Csv .\EtcFindings_<日時>.csv   | Format-Table ComputerName,Severity,Category,Item -AutoSize
Import-Csv .\EtcCollectResult.csv     | Format-Table ComputerName,Status,FileCount,ErrorMessage -AutoSize
```

実行ポリシーでブロックされる場合は、そのセッションだけ一時的に許可します:

```powershell
powershell -ExecutionPolicy Bypass -File .\collect-EtcData.ps1 -UserName admin
```

## collect-EtcData.ps1(/etc 一括取得)

### 概要

入力 CSV に列挙したサーバーに対して、次の処理を順に実行します。

1. **SSH 通信確認** — 対象ポートへの TCP 到達確認(実際に使う通信を確認)
2. **リモートでアーカイブ作成** — `/etc` 配下を `tar.gz` 化。あわせてパーミッション・所有者のメタデータ(`etc_meta_*.txt`)と **コマンドレポート**(`commands/`)も取得
3. **SFTP ダウンロード** — 作成した `tar.gz` をローカルへ取得(SHA256 で整合性確認)
4. **ローカル展開** — Windows 標準の `tar`(bsdtar)で展開
5. **リモート一時ファイル削除** — `/tmp` に作成した一時ファイルをクリーンアップ
6. **結果出力** — 取得結果を CSV に、処理経過をログに出力

通信不可・取得失敗のサーバーもスキップせず、失敗理由付きで結果行に記録します。

### コマンドレポート(/etc 以外の設定情報)

`/etc` に存在しない設定情報を、リモートでコマンドを実行して `commands/` フォルダーに収集します
(アーカイブに同梱されるため、`/etc` と同じようにダウンロード・展開されます)。
存在しないコマンドは「not found」がファイルに記録されるだけで処理は継続します。

| ファイル | 取得コマンド | 内容 / 補足 |
| --- | --- | --- |
| `01_hostnamectl.txt` | `hostnamectl` | ホスト名 / OS / カーネル / 仮想化 hypervisor |
| `02_uname.txt` | `uname -a` | カーネルバージョン(非 systemd 環境向け) |
| `03_ip_addr.txt` / `04_ip_route.txt` | `ip -o addr show` / `ip route show` | IP アドレス / ルーティング |
| `05_resolvectl.txt` | `resolvectl status` | **実効 DNS**(resolv.conf がスタブ 127.0.0.53 の場合の実参照先) |
| `06_timedatectl.txt` | `timedatectl` | 時刻同期(NTP)状態 |
| `07_df.txt` / `08_lsblk.txt` | `df -hT` / `lsblk -o ...` | ファイルシステム / ブロックデバイス |
| `09_services_running.txt` | `systemctl list-units --state=running` | 稼働中サービス |
| `10_services_enabled.txt` | `systemctl list-unit-files` | 有効化サービス(自動起動) |
| `11_packages_rpm.txt` / `11_packages_dpkg.txt` | `rpm -qa` / `dpkg-query -W` | インストール済みパッケージ(存在する方のみ出力) |
| `12_root_crontab.txt` | `crontab -l` | **root の crontab**(/etc/cron* には存在しない) |
| `13_nmcli.txt` | `nmcli device show` | NetworkManager の設定(RHEL 系) |
| `14_nftables.txt` / `15_iptables.txt` | `nft list ruleset` / `iptables -S` | ファイアウォールルール(root) |
| `16_getenforce.txt` | `getenforce` | SELinux の実効状態 |

- スキップする場合は `-NoCommandReport` を指定
- 実行はすべて `sudo` 経由(既定時)。読み取り専用コマンドのみ使用

### 動作要件

| 項目 | 内容 |
| --- | --- |
| 実行元 | PowerShell 5.1 以降 + **Posh-SSH 3.x**(Windows / macOS / Linux で動作) |
| ローカル | `tar` コマンド(Windows 10 1803+ には標準搭載) |
| 対象サーバー | sshd が稼働していること(対象側に PowerShell は不要) |
| ネットワーク | SSH: TCP **22**(CSV / パラメーターで変更可) |
| 認証 | パスワード認証(`-Credential` / 実行時プロンプト) |

### 入力ファイル(TargetServers.csv)

`ComputerName` 列が必須。任意で `UserName` / `Port` 列を追加すると、 **行ごとに接続先を上書き** できます
(空欄の行はパラメーター既定値にフォールバック)。空行は自動的に無視されます。

`UserName` 列に複数のユーザーが混在する場合、 **ユーザーごとに 1 回ずつ** パスワードを入力します
(同一ユーザーは最初の 1 回のみ)。`-Credential` / `-UserName` で指定した資格情報は
「UserName 列が空の行」に対する既定として使われます。sudo パスワードは既定で
各ユーザーのログインパスワードを使用します。

```
ComputerName,UserName,Port
web01.example.local,admin,22
db01.example.local,,2222
```

### パラメーター

| パラメーター | 既定値 | 説明 |
| --- | --- | --- |
| `-InputCsvPath` | スクリプトと同じフォルダーの `TargetServers.csv` | 対象サーバー一覧 CSV。 |
| `-OutputPath` | `EtcCollected_<日時>` | 取得先フォルダー。 |
| `-LogPath` | `EtcCollect_Check.log` | 処理ログ。 |
| `-Credential` / `-UserName` / `-Port` | (実行時入力) / 22 | SSH 接続情報(UserName 列が空の行の既定)。CSV の `UserName` 列を行単位で優先し、ユーザーごとに 1 回ずつパスワードを入力。 |
| `-ConnectionTimeoutSeconds` | `15` | TCP 接続確認のタイムアウト秒。 |
| `-CommandTimeoutSeconds` | `300` | リモートコマンド(tar 等)のタイムアウト秒。 |
| `-EtcPath` | `/etc` | 取得対象ディレクトリ。 |
| `-NoCommandReport` | (off) | コマンドレポート(commands/)の収集をスキップ。 |
| `-NoSudo` | (off) | sudo を使わない(root 直接ログイン時、または機密ファイルを意図的に除外する場合)。 |
| `-SudoPassword` | (ログインと同じ) | sudo パスワードが別の場合に指定。 |
| `-KeepArchive` | (off) | tar.gz を展開後も保持(既定は展開後に削除。展開警告時は自動的に保持)。 |

### sudo 方式(参考リポジトリと同じ)

| 環境 | 指定 | 説明 |
| --- | --- | --- |
| 通常(sudo にパスワードあり) | (既定) | `sudo -S`。既定で **そのユーザーのログインパスワード** を使用。パスワードは `printf '%s\n'` 経由のため `ps` に出ず、`echo` のバックスラッシュ解釈(dash 系 /bin/sh)の影響も受けません。 |
| sudo パスワードが別 | `-SudoPassword <SecureString>` | 全ホスト共通の sudo パスワードを指定。 |
| root で直接ログイン / 機密ファイル除外 | `-NoSudo` | sudo を使わない。`/etc/shadow` 等の読み取り不可ファイルは一部欠けた状態で収集されます。 |

### 出力

```
EtcCollected_<日時>/
  ├─ <ComputerName>/
  │   ├─ etc/...                        # 展開済み /etc の中身
  │   ├─ commands/*.txt                 # コマンド収集レポート(hostnamectl / ip / systemctl 等)
  │   ├─ etc_meta_<日時>.txt            # パス|パーミッション|所有者|サイズ|mtime(+LOCALTIME 行)
  │   └─ etc_collect_<日時>.tar.gz      # ダウンロードしたアーカイブ(既定は展開後に削除。保持は -KeepArchive)
  └─ EtcCollectResult.csv               # 取得結果
```

`EtcCollectResult.csv`(サーバーごとに 1 行、UTF-8):

| 列 | 説明 |
| --- | --- |
| `ComputerName` | サーバー名 |
| `Status` | `成功` / `失敗`(失敗理由は `ErrorMessage`) |
| `ArchiveSizeBytes` / `FileCount` / `Sha256` | アーカイブサイズ / ファイル数 / ハッシュ |
| `LocalEtcPath` / `LocalArchivePath` / `LocalMetadataPath` | ローカルの保存先 |
| `LocalCommandsPath` / `CommandFileCount` | コマンドレポートの保存先 / ファイル数 |
| `RemoteTempCleaned` | リモート一時ファイルを削除したか(`はい` / `いいえ`) |
| `ErrorMessage` | 失敗理由・警告(tar 一部読み取り不可、展開時の警告など) |

ログは `[日時] [レベル] メッセージ` 形式(`INFO` / `WARN` / `ERROR`)。

> **セキュリティ上の注意:** 既定(sudo)では `/etc/shadow` や SSH ホスト鍵などの機密ファイルも収集されます。
> `tar.gz`・展開フォルダーには機密情報が含まれるため、保管場所のアクセス制御と解析後の削除を必ず行ってください。
> アーカイブは既定で展開後に削除されます(保持する場合は `-KeepArchive`。SHA256 は `EtcCollectResult.csv` に記録されます)。
> 機密ファイルが不要な場合は `-NoSudo` を指定してください。

## analyze-EtcData.ps1(解析)

### 概要

`EtcCollected_<日時>` フォルダー配下のホストディレクトリごとに `/etc` の内容を解析し、
次の 2 つの CSV を出力します。

1. **EtcAnalysis_<日時>.csv** — ホストごとの設定一覧(1 ホスト 1 行の横断マトリクス)
2. **EtcFindings_<日時>.csv** — 要確認項目(1 項目 1 行、重大度付き)

### 解析項目と重大度

| カテゴリ | 解析内容 | 重大度 |
| --- | --- | --- |
| 基本情報 | OS(os-release / *-release / debian_version)、hostname、タイムゾーン、SELinux、ファイアウォール(ufw / firewalld / nftables) | 情報 |
| コマンド情報 | カーネル(uname)、仮想化(hostnamectl)、実効 DNS(resolvectl)※ コマンドレポート収集時 | -(列のみ) |
| DNS | resolv.conf の nameserver / search。`127.0.0.53`(systemd-resolved スタブ)を検出 | 情報 |
| hosts / fstab | hosts エントリ(localhost 以外)、マウント数、NFS マウント | -(列のみ) |
| アカウント | root 以外の UID 0 アカウント | **高** |
| アカウント | 空パスワード(shadow のパスワードフィールドが空) | **高** |
| アカウント | パスワード有効期限が無期限(max=99999 / 空) | 低 |
| アカウント | ロックアカウント数、wheel/sudo グループのメンバー、ログイン可能シェル数 | -(列のみ) |
| アカウント | shadow 未収集(sudo なし収集) | 低 |
| sudo | sudoers / sudoers.d の NOPASSWD エントリ | 中 |
| SSH | PermitRootLogin yes / PermitEmptyPasswords yes | **高** |
| SSH | PasswordAuthentication yes(未設定の既定値を含む) | 中 |
| SSH | Port / PubkeyAuthentication 等(`sshd_config.d` の Include を展開し、OpenSSH と同じ「先頭で設定された値が優先」で確定) | -(列のみ) |
| SELinux | disabled / permissive | 中 / 低 |
| cron | /etc/crontab + cron.{d,hourly,daily,weekly,monthly} のファイル数 | -(列のみ) |

※ `EtcAnalysis` CSV には上記の設定値そのもの(OS 名、DNS、SSH 設定、ユーザー数など)が列として出力されます。
※ コマンドレポート(`commands/`)は収集データとしてそのまま残ります。`systemctl` のサービス一覧や
　パッケージ一覧などは `EtcFindings` では集約しないため、必要に応じて直接参照してください。

### パラメーター

| パラメーター | 既定値 | 説明 |
| --- | --- | --- |
| `-CollectDir` | (必須) | `collect-EtcData.ps1` の出力フォルダー(`EtcCollected_<日時>`)。ホスト 1 台分のフォルダー直指定も可。 |
| `-AnalysisCsvPath` | `EtcAnalysis_<日時>.csv` | 設定一覧 CSV の出力先。 |
| `-FindingsCsvPath` | `EtcFindings_<日時>.csv` | 要確認項目 CSV の出力先。 |
| `-LogPath` | `EtcAnalyze.log` | 処理ログ。 |

### 制限事項

- Windows 上に展開した場合、ファイルのパーミッション / 所有者情報は失われるため、
  それらは collect 時に取得した `etc_meta_*.txt` を参照してください。
- `/etc/localtime` 等のシンボリックリンクは、Windows 展開時に警告が出ることがあります(展開自体は継続)。
- SSH の `Include` に相対パス・特殊トークン(`%h` 等)が使われている場合は近似解釈になります。

## トラブルシューティング

| 症状 | 主な原因と対処 |
| --- | --- |
| `SSH接続失敗 / TCP ... へ接続できませんでした` | ホスト名・`Port`・ファイアウォール(TCP 22)を確認。 |
| `SSH接続失敗 / Permission denied` | `-UserName` を確認。公開鍵運用の場合は Posh-SSH の鍵認証に変更が必要。 |
| `sudo: a password is required` / sudo 失敗 | `-SudoPassword` で別パスワードを指定、または `-NoSudo`。 |
| `tar コマンドが見つかりません` | Windows 10 1803+ / Windows Server 1809+ を使用、または tar を PATH へ。 |
| `アーカイブ作成失敗` | 対象が BusyBox 系で `stat`/`sha256sum` が無い可能性(メタデータ取得失敗は継続可)。TAREXIT と ERRSUMMARY をログで確認。 |
| 分析CSV に shadow 由来の列が埋まらない | `-NoSudo` で収集した可能性。sudo 付きで再収集してください。 |
| 実行ポリシーで起動不可 | `powershell -ExecutionPolicy Bypass -File ...` |
