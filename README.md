# php2shell F5 WAF Tools

PHP 漏洞 php2shell（CVE-2026-109618／CVE-2026-109619）的 F5 BIG-IP Advanced WAF 設定檢查與防禦驗證工具。

**說明網頁：<https://ryantseng24.github.io/php2shell-f5-waf-tools/>**（公告、設定步驟、驗證方法、BIG-IP 升級與緩解、升級步驟）

> **重要**：完整的修補方式是把 PHP 升級到 8.5.12、8.4.27、8.3.36 或 8.2.35。WAF 防護只能在升級完成前降低風險。
>
> **BIG-IP 設備本身**也受影響。F5 修正版：17.1.3.7、17.5.1.11、21.1.0.4（[K000163848](https://my.f5.com/manage/s/article/K000163848)）。說明見[BIG-IP 升級與緩解](https://ryantseng24.github.io/php2shell-f5-waf-tools/bigip.html)與[升級步驟](https://ryantseng24.github.io/php2shell-f5-waf-tools/upgrade.html)。

## 下載

- 全部工具：[main.zip](https://github.com/ryantseng24/php2shell-f5-waf-tools/archive/refs/heads/main.zip)

| 檔案 | 在哪裡執行 | 用途 |
|---|---|---|
| [`client/php2shell_waf_test_page.html`](client/php2shell_waf_test_page.html) | 瀏覽器 | 瀏覽器測試頁，確認 WAF 是否阻擋 |
| [`client/php2shell_waf_test.py`](client/php2shell_waf_test.py) | 有 Python 3.6+ 的電腦 | 完整測試，同時確認正常流量與漏洞特徵的處理結果 |
| [`bigip/php2shell_bigip_check.sh`](bigip/php2shell_bigip_check.sh) | BIG-IP（root、bash） | 唯讀檢查：每個 policy 是否已加入並 enforce 3 個 signature |
| [`bigip/irule_php2shell_require_content_length.tcl`](bigip/irule_php2shell_require_content_length.tcl) | BIG-IP virtual server | 選用 iRule：拒絕沒有 Content-Length 的 POST |
| [`lab-backend/index.php`](lab-backend/index.php) | 自建測試站 | 回傳 PHP 收到的參數，用來確認請求是否送到 PHP |

## F5 指定的 signature（K000163821）

| Signature ID | 名稱 | CVE |
|---|---|---|
| 200204113 | PHP Remote Code Execution | CVE-2026-109619 |
| 200103697 | PHP Remote Code Execution (2) | CVE-2026-109618 |
| 200204115 | PHP Remote Code Execution (3) | CVE-2026-109618 |

需要 ASU `ASM-AttackSignatures_20261022_154742.im` 或更新版本。設定方式見[說明網頁的設定步驟](https://ryantseng24.github.io/php2shell-f5-waf-tools/setup.html)。

## 使用方式

### 1. 瀏覽器測試頁

1. 用文字編輯器開啟 `php2shell_waf_test_page.html`。
2. 把 `<form action="...">` 改成受 WAF 保護的 PHP 網址。
3. 用瀏覽器直接開啟這個本機檔案，按「送出測試」。
4. 出現 `The requested URL was rejected` 與 Support ID，表示已阻擋。

### 2. curl

```bash
# 一般表單：應該正常回應
curl -s -X POST -F "note=test" https://www.example.com/index.php

# php2shell 特徵：應該被擋
curl -s -X POST -F "PHP_SESSION_UPLOAD_PROGRESS=waftest" -F "note=test" https://www.example.com/index.php
```

### 3. Python 完整測試

```bash
python3 client/php2shell_waf_test.py https://www.example.com/index.php
# 自簽憑證的測試環境
python3 client/php2shell_waf_test.py https://10.1.1.10/index.php --insecure
```

script 會送出 3 個正常請求（N1–N3）與 6 個漏洞特徵請求（A1–A6），逐項顯示是否送到 PHP 或被 WAF 擋下。

- N1–N3 應該全部通過。如果被擋，表示有誤擋，請依 Event Log 調整。
- 只完成 3 個 signature 的設定時，A1–A6 中有部分項目不會被擋。這是預期結果，那些項目對應 F5 K000163821 中的選用設定。
- ASU 20261022 的 3 個 signature 都 Enforce 後，lab 實測：A1、A2 由 200204113 擋下，A4 由 200103697 擋下，A5 由 200204115 擋下；A3、A6 要靠選用設定。
- 瀏覽器測試頁與 curl 只會觸發 200204113。要確認另外 2 個，請用這個 script 或第 4 節的檢查 script。
- 結束代碼：全部符合預期回 0，否則回 1。

### 4. BIG-IP 唯讀檢查

```bash
scp bigip/php2shell_bigip_check.sh root@<BIG-IP>:/var/tmp/
ssh root@<BIG-IP> bash /var/tmp/php2shell_bigip_check.sh
```

script 不修改任何設定。它先確認設備上是否已有 3 個 signature，再逐一列出每個 policy 的狀態：

| 結果 | 意思 | 處理方式 |
|---|---|---|
| `OK (enforced, block)` | 已生效 | — |
| `NOT IN POLICY` | policy 沒有這個 signature | 依設定步驟 2、3 加入 |
| `STAGING (alarm only)` | 在 staging，只記錄不阻擋 | 依設定步驟 4 Enforce |
| `DISABLED` | signature 被停用 | 在 policy 中啟用 |
| `ENFORCED but no assigned set has Block on` | 所屬 signature set 沒有勾選 Block | 在 Learning and Blocking Settings 勾選 Block |
| `MISSING`（第 1 段） | 設備上沒有這個 signature | 先安裝 ASU |

安裝更新版 ASU 後，F5 有更新的 signature 會回到 `STAGING`。這時舊版規則仍會阻擋，新版規則只記錄。請再 Enforce 一次並 Apply Policy。

### 5. 自建測試站（選用）

在有 Docker 的 Linux 主機上：

```bash
mkdir -p ~/php2shell-lab/www && cp lab-backend/index.php ~/php2shell-lab/www/
docker run -d --name php2shell_lab -p 8081:80 -v ~/php2shell-lab/www:/var/www/html:ro php:8.3-apache
```

再把這台主機加到 BIG-IP 的 pool，從 virtual server 測試。

## 安全說明

- 測試請求只帶有漏洞的特徵欄位，不含攻擊程式碼，不會影響網站運作。
- 只對你有權限測試的系統執行。正式環境請在維護時段進行，並先通知監控單位。

## 參考資料

- [F5 K000163821](https://my.f5.com/manage/s/article/K000163821)
- [F5 K000163848](https://my.f5.com/manage/s/article/K000163848)（BIG-IP 修正版清單）
- [CISA Alert 2026-10-21](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
