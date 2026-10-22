# php2shell F5 WAF Tools

PHP 漏洞 php2shell（CVE-2026-109618／CVE-2026-109619）的 F5 BIG-IP Advanced WAF 設定檢查與防禦驗證工具。

這些工具搭配《php2shell F5 WAF 特徵碼設定與驗證指南》使用。所有工具都在 lab 實測過（BIG-IP 17.5.1.8、ASU 20261021_191526、PHP 8.3.36 mod_php），測試日期 2026-10-22。

> **重要**：唯一完整的修補方式是把 PHP 升級到 8.5.12、8.4.27、8.3.36 或 8.2.35。WAF 設定只能在升級完成前降低風險。

## 檔案

| 路徑 | 在哪裡執行 | 用途 |
|---|---|---|
| [`client/php2shell_waf_test_page.html`](client/php2shell_waf_test_page.html) | 工程師的瀏覽器 | 瀏覽器測試頁。送出帶有 `PHP_SESSION_UPLOAD_PROGRESS` 欄位的上傳表單 |
| [`client/php2shell_waf_test.py`](client/php2shell_waf_test.py) | 任何有 Python 3.6+ 的電腦 | 完整測試：3 個正常 request＋6 個攻擊特徵 request，並判讀結果 |
| [`bigip/php2shell_bigip_check.sh`](bigip/php2shell_bigip_check.sh) | BIG-IP（root、bash） | 唯讀檢查：3 個 signature 是否存在、每個 policy 是否已加入並 enforce |
| [`bigip/irule_php2shell_require_content_length.tcl`](bigip/irule_php2shell_require_content_length.tcl) | BIG-IP virtual server | 選用 iRule：拒絕沒有 Content-Length 的 POST（回 411） |
| [`lab-backend/index.php`](lab-backend/index.php) | 自建測試站 | 回傳 PHP 實際收到哪些參數，用來證明 request 有沒有送到 PHP |

下載全部：[main.zip](https://github.com/ryantseng24/php2shell-f5-waf-tools/archive/refs/heads/main.zip)

## F5 指定的 signature（K000163821）

| Signature ID | 名稱 | CVE | Accuracy |
|---|---|---|---|
| 200204113 | PHP Remote Code Execution | CVE-2026-109619 | Medium |
| 200103697 | PHP Remote Code Execution (2) | CVE-2026-109618 | Low |
| 200204115 | PHP Remote Code Execution (3) | CVE-2026-109618 | Low |

需要 ASU `ASM-AttackSignatures_20261021_191526.im` 或更新版本。

## 使用方式

### 1. 瀏覽器測試頁

1. 用文字編輯器開啟 `php2shell_waf_test_page.html`。
2. 把 `<form action="...">` 改成受 WAF 保護的 PHP 網址。
3. 用瀏覽器直接開啟這個本機檔案，按「送出測試」。
4. 出現 `The requested URL was rejected` 與 Support ID，表示已阻擋。

### 2. curl

```bash
# 正常 multipart 表單：應該通過
curl -s -X POST -F "note=test" https://www.example.com/index.php

# php2shell 特徵（CVE-2026-109619）：應該被擋
curl -s -X POST -F "PHP_SESSION_UPLOAD_PROGRESS=waftest" -F "note=test" https://www.example.com/index.php
```

### 3. Python 完整測試

```bash
python3 client/php2shell_waf_test.py https://www.example.com/index.php
# lab 自簽憑證
python3 client/php2shell_waf_test.py https://10.1.1.10/index.php --insecure
# 只跑部分項目
python3 client/php2shell_waf_test.py https://www.example.com/index.php --only N1,A1,A2
```

| ID | 測試內容 | 預期 |
|---|---|---|
| N1 | 正常 GET | 通過 |
| N2 | 正常表單 POST（urlencoded） | 通過 |
| N3 | 正常 multipart 上傳 | 通過 |
| A1 | 109619：multipart 帶 `PHP_SESSION_UPLOAD_PROGRESS`（有值） | 阻擋 |
| A2 | 109619：同上，值為空 | 阻擋 |
| A3 | 109618：300 個空的檔案欄位 | 阻擋（需要 max parameters 檢查） |
| A4 | 109618：單一 part 帶 300 個額外 header | 阻擋 |
| A5 | 109618：參數名稱巢狀深度 70 | 阻擋（需要禁止參數名稱 `[ ]`，一般 PHP 網站不建議） |
| A6 | 109618：chunked 傳送、沒有 Content-Length | 阻擋（需要 iRule） |

只設定 3 個 signature 時，lab 實測會擋下 A1、A2、A4。結束代碼：全部符合預期回 0，否則回 1。

### 4. BIG-IP 唯讀檢查

```bash
scp bigip/php2shell_bigip_check.sh root@<BIG-IP>:/var/tmp/
ssh root@<BIG-IP> bash /var/tmp/php2shell_bigip_check.sh
```

lab 實測輸出（第二個 policy 沒有加入這 3 個 signature）：

```text
== 1. Signatures on this system (needs ASU 20261021_191526 or later)
   200103697  OK       PHP Remote Code Execution (2) (accuracy low)
   200204115  OK       PHP Remote Code Execution (3) (accuracy low)
   200204113  OK       PHP Remote Code Execution (accuracy medium)

== 2. Per security policy
-- /Common/php2shell_lab_policy  mode=blocking  vs=/Common/vs_php2shell_lab
   200103697  OK (enforced, block)
   200204115  OK (enforced, block)
   200204113  OK (enforced, block)
-- /Common/awf-lab-policy  mode=blocking  vs=/Common/vs-awf-http,/Common/vs-awf-https
   200103697  NOT IN POLICY
   200204115  NOT IN POLICY
   200204113  NOT IN POLICY
```

其他可能的判定：`DISABLED`、`STAGING (alarm only, not blocking)`、`ENFORCED but no assigned set has Block on`。這些分支在 lab 沒有實際出現過。執行時間約 40 秒（lab 有 2 個 policy）。

### 5. 自建測試站（選用）

在有 Docker 的 Linux 主機上：

```bash
mkdir -p ~/php2shell-lab/www && cp lab-backend/index.php ~/php2shell-lab/www/
docker run -d --name php2shell_lab -p 8081:80 -v ~/php2shell-lab/www:/var/www/html:ro php:8.3-apache
```

再把這台主機加到 BIG-IP 的 pool，從 virtual server 測試。

## 安全說明

- 測試 request 只帶有攻擊的結構特徵，不含攻擊程式碼，也不會耗盡記憶體（每個 request 只有數 KB）。
- 只對你有權限測試的系統執行。正式環境請在維護時段進行，並先通知監控單位。
- 不要用網路上公開的 PoC 測試正式環境。

## 參考資料

- [F5 K000163821](https://my.f5.com/manage/s/article/K000163821)
- [GHSA-w8hw-w9fx-j79w（CVE-2026-109618）](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp（CVE-2026-109619）](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CISA Alert 2026-10-21](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
