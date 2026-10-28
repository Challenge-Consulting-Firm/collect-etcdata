# etc-collector-analyzer

[Challenge-Consulting-Firm/replace-dnsaddress](https://github.com/Challenge-Consulting-Firm/replace-dnsaddress) を参考にした運用スクリプト群です。
対象サーバー一覧(CSV)を読み込み、Linux サーバーの **/etc 配下を一括で取得(Windows から SSH 経由)** し、
収集データを **解析して CSV レポート化** します。

```
research-linux/
├── collect-EtcData.ps1    # /etc 一括取得(SSH + Posh-SSH / tar.gz アーカイブ → SFTP ダウンロード → ローカル展開)
├── analyze-EtcData.ps1   # 収集データの解析(設定一覧 CSV + 要確認項目 CSV を出力)
├── TargetServers.csv      # 入力: 対象サーバー一覧(サンプル)
├── test/sshlab/           # 鍵認証の検証用 SSH サーバー(Dockerfile / 検証用 CSV)
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
.\collect-EtcData.ps1 -UserName admin -KeyFile ~\.ssh\id_ed25519           # 秘密鍵で接続(公開鍵認証)

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
2. **リモートでアーカイブ作成** — `/etc` 配下を `tar.gz` 化。あわせてパーミッション・所有者のメタデータ(`etc_meta_*.txt`)と **コマンドレポート**(`commands/`)も取得。
   機密ファイルとサイズ上限超過ファイルは除外し、テキストファイルを指すシンボリックリンクはリンク先の中身で格納(後述「収集対象の調整」)
3. **SFTP ダウンロード** — 作成した `tar.gz` をローカルへ取得(SHA256 で整合性確認)
4. **ローカル展開** — Windows 標準の `tar`(bsdtar)で展開
5. **リモート一時ファイル削除** — `/tmp/etc_collect_<日時>/`(パーミッション 700)に作成した一時ファイルをディレクトリごと削除
6. **結果出力** — 取得結果を CSV に、処理経過をログに出力

通信不可・取得失敗のサーバーもスキップせず、失敗理由付きで結果行に記録します。

### 収集対象の調整(機密ファイル除外・サイズ上限・シンボリックリンク)

リモート側で `/etc` 配下のファイルを分類し、次のとおり扱います。除外したファイルは
`etc_excluded_<日時>.txt`(`理由|パス`)に記録され、パーミッション等は `etc_meta_*.txt` に残ります。

| 対象 | 扱い | 記録される理由 |
| --- | --- | --- |
| `shadow` / `shadow-` / `gshadow` / `gshadow-` / `opasswd` / `*.keytab` / `*.p12` / `*.pfx` / `*.jks` / `*.keystore` / `key3.db` / `key4.db`(ファイル名で判定) | 収集しない | `secret-name` |
| PEM 形式の秘密鍵(`-----BEGIN ... PRIVATE KEY-----` を含むファイル。SSH ホスト鍵、`*.key`、`*-key.pem`、`private.key.2025` のような退避ファイル等。中身で判定) | 収集しない | `secret-private-key` |
| `-MaxFileSizeMB`(既定 1MB)を超えるファイル(`udev/hwdb.bin`、SELinux ポリシー、`/etc` 配下に置かれたバックアップ等) | 収集しない | `size-over(<bytes> bytes)` |
| テキストファイルを指すシンボリックリンク(`os-release`、`*.wants/*.service` 等) | リンク先の中身を通常ファイルとして格納 | (記録なし。件数は `DerefSymlinkCount`) |
| ディレクトリ・バイナリ・リンク切れ・`/proc` 等を指すリンク、上記で除外対象になったリンク | リンクのまま格納 | 除外対象のリンクは `(symlink-kept)` 付き |

- `/etc/shadow` はパスワードハッシュを `REDACTED` に置き換えた `etc_shadow_redacted_<日時>.txt` だけを格納します
  (空パスワード・ロック状態 `!` `*`・有効期限などのフィールドはそのまま残るため、解析は従来どおり可能です)。
- DER 形式(バイナリ)の秘密鍵は中身で判定できません。拡張子で判定できないものが置かれている環境では、`etc_meta_*.txt` で確認してください。
- 実体化したリンクのパーミッション・所有者はリンク先のものになります。リンク自体の情報(リンク先パス)は `etc_meta_*.txt` の最終列で確認できます。

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
| 認証 | パスワード認証(`-Credential` / 実行時プロンプト)、または秘密鍵による公開鍵認証(`-KeyFile` / CSV の `KeyFile` 列) |

### 入力ファイル(TargetServers.csv)

`ComputerName` 列が必須。任意で `UserName` / `Port` / `KeyFile` 列を追加すると、 **行ごとに接続先を上書き** できます
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

`KeyFile` 列(または `-KeyFile`)に秘密鍵のパスを指定した行は **公開鍵認証** で接続します
(`~` や相対パスはカレントディレクトリ基準で解決)。パスワード認証の行と混在できます。

```
ComputerName,UserName,Port,KeyFile
web01.example.local,admin,22,
app01.example.local,deploy,22,C:\keys\deploy_ed25519
```

### 秘密鍵による接続(公開鍵認証)

| 項目 | 動作 |
| --- | --- |
| 鍵の指定 | `-KeyFile`(全行の既定)、または CSV の `KeyFile` 列(行単位で優先)。OpenSSH 形式 / PEM 形式の鍵に対応(Posh-SSH 3.x の対応形式に準拠)。 |
| ユーザー名 | 必須。`-UserName` / `-Credential` のユーザー名、または CSV の `UserName` 列。 |
| パスフレーズ | 鍵ファイルごとに 1 回だけ入力(パスフレーズなしの鍵は Enter のみ)。`-KeyPassphrase <SecureString>` で事前指定すると入力を省略。 |
| sudo パスワード | ログインパスワードが無いため、`-SudoPassword` を指定するか、ユーザーごとに 1 回入力。**空 Enter の場合は NOPASSWD 前提で `sudo -n`** を使用(パスワードを要求されたら待たずに失敗)。 |
| `-Credential` との併用 | `-Credential` のユーザー名のみを使用します(パスワード欄はパスフレーズとして扱いません)。 |
| 鍵ファイルが無い | そのホストは `失敗`(`秘密鍵ファイルが見つかりません`)として記録し、次のホストへ進みます。 |

```powershell
# パスフレーズを事前に入力して使い回す(sudo は NOPASSWD の場合)
$pp = Read-Host -AsSecureString '鍵のパスフレーズ'
.\collect-EtcData.ps1 -UserName admin -KeyFile ~\.ssh\id_ed25519 -KeyPassphrase $pp
```

### パラメーター

| パラメーター | 既定値 | 説明 |
| --- | --- | --- |
| `-InputCsvPath` | スクリプトと同じフォルダーの `TargetServers.csv` | 対象サーバー一覧 CSV。 |
| `-OutputPath` | `EtcCollected_<日時>` | 取得先フォルダー。 |
| `-LogPath` | `EtcCollect_Check.log` | 処理ログ。 |
| `-Credential` / `-UserName` / `-Port` | (実行時入力) / 22 | SSH 接続情報(UserName 列が空の行の既定)。CSV の `UserName` 列を行単位で優先し、ユーザーごとに 1 回ずつパスワードを入力。 |
| `-KeyFile` | (なし) | 秘密鍵ファイルのパス。指定すると公開鍵認証で接続(CSV の `KeyFile` 列を行単位で優先)。 |
| `-KeyPassphrase` | (実行時入力) | 秘密鍵のパスフレーズ(SecureString)。未指定時は鍵ファイルごとに 1 回入力。 |
| `-ConnectionTimeoutSeconds` | `15` | TCP 接続確認のタイムアウト秒。 |
| `-CommandTimeoutSeconds` | `300` | リモートコマンド(tar 等)のタイムアウト秒。 |
| `-EtcPath` | `/etc` | 取得対象ディレクトリ。 |
| `-MaxFileSizeMB` | `1` | これを超えるファイルは収集しない(`0` で無制限)。除外したファイルは `etc_excluded_*.txt` に記録。 |
| `-NoCommandReport` | (off) | コマンドレポート(commands/)の収集をスキップ。 |
| `-NoSudo` | (off) | sudo を使わない(root 直接ログイン時など)。読み取り権限のないファイルは収集されません。 |
| `-SudoPassword` | (ログインと同じ) | sudo パスワードが別の場合に指定。鍵認証時は未指定ならユーザーごとに入力(空なら `sudo -n`)。 |
| `-KeepArchive` | (off) | tar.gz を展開後も保持(既定は展開後に削除。展開警告時は自動的に保持)。 |

### sudo 方式(参考リポジトリと同じ)

| 環境 | 指定 | 説明 |
| --- | --- | --- |
| 通常(sudo にパスワードあり) | (既定) | `sudo -S`。既定で **そのユーザーのログインパスワード** を使用。パスワードは `printf '%s\n'` 経由のため `ps` に出ず、`echo` のバックスラッシュ解釈(dash 系 /bin/sh)の影響も受けません。 |
| sudo パスワードが別 | `-SudoPassword <SecureString>` | 全ホスト共通の sudo パスワードを指定。 |
| 鍵認証 + NOPASSWD sudo | (sudo パスワード入力で空 Enter) | `sudo -n`。パスワードを要求された場合は待たずに失敗します。 |
| root で直接ログイン | `-NoSudo` | sudo を使わない。読み取り不可のファイル・ディレクトリは一部欠けた状態で収集されます(メタデータも同様)。 |

### 出力

```
EtcCollected_<日時>/
  ├─ <ComputerName>/
  │   ├─ etc/...                        # 展開済み /etc の中身
  │   ├─ commands/*.txt                 # コマンド収集レポート(hostnamectl / ip / systemctl 等)
  │   ├─ etc_meta_<日時>.txt            # パス|パーミッション|所有者|グループ|サイズ|mtime(エポック秒)|リンク先(+LOCALTIME 行)
  │   ├─ etc_excluded_<日時>.txt        # 収集から除外したファイル(理由|パス)
  │   ├─ etc_shadow_redacted_<日時>.txt # パスワードハッシュを除去した /etc/shadow(sudo 収集時のみ)
  │   └─ etc_collect_<日時>.tar.gz      # ダウンロードしたアーカイブ(既定は展開後に削除。保持は -KeepArchive)
  └─ EtcCollectResult.csv               # 取得結果
```

`EtcCollectResult.csv`(サーバーごとに 1 行、UTF-8):

| 列 | 説明 |
| --- | --- |
| `ComputerName` | サーバー名 |
| `AuthMethod` | 認証方式(`password` / `key`) |
| `Status` | `成功` / `失敗`(失敗理由は `ErrorMessage`) |
| `ArchiveSizeBytes` / `FileCount` / `Sha256` | アーカイブサイズ / ファイル数 / ハッシュ |
| `LocalEtcPath` / `LocalArchivePath` / `LocalMetadataPath` | ローカルの保存先 |
| `LocalCommandsPath` / `CommandFileCount` | コマンドレポートの保存先 / ファイル数 |
| `DerefSymlinkCount` | リンク先の中身で格納したシンボリックリンクの数 |
| `ExcludedSecretCount` / `ExcludedLargeCount` | 機密ファイル / サイズ上限超過として除外した数(内訳は `etc_excluded_*.txt`) |
| `RemoteTempCleaned` | リモート一時ファイルを削除したか(`はい` / `いいえ`) |
| `ErrorMessage` | 失敗理由・警告(tar 一部読み取り不可、展開時の警告など) |

ログは `[日時] [レベル] メッセージ` 形式(`INFO` / `WARN` / `ERROR`)。

> **セキュリティ上の注意:** `/etc/shadow`(ハッシュ)・SSH ホスト鍵・TLS 秘密鍵などは収集から除外されますが、
> 設定ファイル内に直接書かれたパスワード・トークン等は除外されません。保管場所のアクセス制御と解析後の削除を必ず行ってください。
> アーカイブは既定で展開後に削除されます(保持する場合は `-KeepArchive`。SHA256 は `EtcCollectResult.csv` に記録されます)。

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
| アカウント | 空パスワード(shadow のパスワードフィールドが空。`etc_shadow_redacted_*.txt`、旧データは `etc/shadow` を参照) | **高** |
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
- テキストファイルを指すシンボリックリンクは収集時に実体化されます。`/etc/localtime` などリンクのまま格納されたものは、
  Windows 展開時に警告が出ることがあります(展開自体は継続。リンク先は `etc_meta_*.txt` で確認できます)。
- SSH の `Include` に相対パス・特殊トークン(`%h` 等)が使われている場合は近似解釈になります。

## 検証環境(鍵認証の接続試験用 SSH コンテナ)

`test/sshlab/Dockerfile` で、鍵認証のみ許可した SSH サーバーをローカルに立てて接続試験ができます
(Docker Desktop 等が必要)。対象側に `/etc` があれば良いため、Debian コンテナを Linux サーバー代わりに使います。

| ユーザー | 秘密鍵 | パスフレーズ | sudo |
| --- | --- | --- | --- |
| `keyuser` | `keyuser_ed25519` / `keyuser_rsa` | なし | NOPASSWD(sudo パスワード入力は空 Enter) |
| `keypp` | `keypp_ed25519` | `KeyPass#1` | パスワード必須(`SudoPass#1`) |

パスワード認証は無効(鍵のみ)です。鍵はイメージのビルド時に生成されるので、`docker cp` で取り出して使います。

> **注意:** 検証専用です。鍵・パスワードが固定値のため、ポートは `127.0.0.1` にのみ公開し、本番環境では使わないでください。
> 取り出した鍵(`test/sshlab/keys/`)は `.gitignore` 済みです。

### 1) 起動と鍵の取り出し

リポジトリのルートで実行します。

```powershell
docker build -t etc-sshlab .\test\sshlab
docker run -d --name etc-sshlab -p 127.0.0.1:2222:22 etc-sshlab
docker cp etc-sshlab:/lab/keys .\test\sshlab\keys
```

### 2) 接続試験

`test/sshlab/TargetServers.lab.csv` には 3 行(`keyuser` の ed25519 / RSA、`keypp` の ed25519)が入っています。

```powershell
.\collect-EtcData.ps1 -InputCsvPath .\test\sshlab\TargetServers.lab.csv
```

実行中に次の入力を求められます(鍵ファイル・ユーザーごとに 1 回ずつ)。

| プロンプト | 入力値 |
| --- | --- |
| 秘密鍵のパスフレーズ (key=...keyuser_ed25519) | 空 Enter |
| sudo パスワード (user=keyuser) | 空 Enter(NOPASSWD → `sudo -n`) |
| 秘密鍵のパスフレーズ (key=...keyuser_rsa) | 空 Enter |
| 秘密鍵のパスフレーズ (key=...keypp_ed25519) | `KeyPass#1` |
| sudo パスワード (user=keypp) | `SudoPass#1` |

```powershell
# 結果確認(3 行とも Status=成功 / AuthMethod=key。sudo が効いていれば etc_shadow_redacted_*.txt も取得される)
Import-Csv .\EtcCollected_<日時>\EtcCollectResult.csv | Format-Table ComputerName,AuthMethod,Status,FileCount,RemoteTempCleaned,ErrorMessage -AutoSize
```

初回接続時は Posh-SSH がホスト鍵を信頼するか確認してくるので `y` で登録します
(非対話で実行する場合は事前登録が必要。登録先は `~/.poshssh/hosts.json`)。

異常系は次の操作で確認できます。いずれも該当ホストが `失敗` として記録され、処理は次のホストへ進みます。

| 試験内容 | 操作 | 期待される ErrorMessage |
| --- | --- | --- |
| パスフレーズ誤り | `keypp` でパスフレーズを誤入力 | `SSH接続失敗: The random check bytes of the OpenSSH key do not match ...` |
| パスフレーズ未入力 | `keypp` でパスフレーズを空 Enter | `SSH接続失敗: Private key is encrypted but passphrase is empty.` |
| 未登録の鍵 | `keypp` に `keyuser_ed25519` を指定 | `SSH接続失敗: Permission denied (publickey).` |
| 鍵ファイルなし | 存在しないパスを `-KeyFile` に指定 | `SSH接続失敗: 秘密鍵ファイルが見つかりません: ...` |
| sudo パスワード誤り / 空 | `keypp` で sudo パスワードを誤入力 / 空 Enter | `アーカイブ作成失敗: ... sudo: a password is required` 等 |

### 3) 停止・削除

```powershell
docker stop etc-sshlab                 # 停止(再開は docker start etc-sshlab)
docker rm -f etc-sshlab; docker rmi etc-sshlab   # 削除
Remove-SSHTrustedHost -HostName 127.0.0.1        # Posh-SSH に登録したホスト鍵の削除
Remove-Item -Recurse .\test\sshlab\keys          # 取り出した鍵の削除
```

イメージを作り直すとホスト鍵と秘密鍵が変わります。`docker cp` で鍵を取り出し直し、
`Remove-SSHTrustedHost -HostName 127.0.0.1` で古いホスト鍵の登録を削除してから接続してください。

## トラブルシューティング

| 症状 | 主な原因と対処 |
| --- | --- |
| `SSH接続失敗 / TCP ... へ接続できませんでした` | ホスト名・`Port`・ファイアウォール(TCP 22)を確認。 |
| `SSH接続失敗 / Permission denied` | `-UserName` を確認。公開鍵運用の場合は `-KeyFile`(または CSV の `KeyFile` 列)を指定。 |
| `SSH接続失敗 / 秘密鍵ファイルが見つかりません` | `-KeyFile` / `KeyFile` 列のパスを確認(相対パスはカレントディレクトリ基準)。 |
| 鍵認証で `Invalid private key file` 等 | パスフレーズ誤り、または未対応の鍵形式。`ssh-keygen -p -m PEM -f <鍵>` で PEM 形式に変換すると解消する場合があります。 |
| `sudo: a password is required` / sudo 失敗 | `-SudoPassword` で別パスワードを指定、または `-NoSudo`。鍵認証で sudo パスワードを空にした場合は NOPASSWD 設定を確認。 |
| `tar コマンドが見つかりません` | Windows 10 1803+ / Windows Server 1809+ を使用、または tar を PATH へ。 |
| `アーカイブ作成失敗` | `TAREXIT=sudo` の場合は sudo の失敗(パスワード誤り等)。それ以外は対象が BusyBox 系で `find -printf`/`sha256sum` が無い可能性(メタデータ取得失敗は継続可)。TAREXIT と ERRSUMMARY をログで確認。 |
| `メタデータ取得で一部エラー` | `-NoSudo` で読み取れないディレクトリがあった、または `find -printf` 非対応。 |
| 必要なファイルが収集されていない | `etc_excluded_*.txt` を確認。サイズ上限超過なら `-MaxFileSizeMB` を引き上げて再収集(`0` で無制限)。 |
| 分析CSV に shadow 由来の列が埋まらない | `-NoSudo` で収集した可能性。sudo 付きで再収集してください。 |
| 実行ポリシーで起動不可 | `powershell -ExecutionPolicy Bypass -File ...` |
