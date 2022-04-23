
## 1.Tuning rule 941310

![](https://i.imgur.com/ZqBguIh.png)
### 1.1. Kiểm tra request.

![](https://i.imgur.com/dyJzrDG.jpeg)

### 1.2. Decode URL thành text để kiểm tra dấu hiệu tấn công XSS
![](https://i.imgur.com/BZsTLmc.png)

```
transid=635b2ef7a68bd&custData=<custData><mobile>0963695966</mobile><status>N</status><fullname>BÙI THẾ ĐĂNG</fullname><dob>19951228</dob><gender>M</gender><idnum>022095002345-20210813-VN</idnum><passport></passport><email>boyhanoi.air@gmail.com</email><addr1></addr1><addr2></addr2><province>22</province><district>195</district><ward>Phường Quang Hanh</ward><post>10000</post><region>22</region><bank>MB</bank><bankacct>6040103866007</bankacct><bankname>BUI THE DANG</bankname></custData>
```
 Sau khi kiểm tra kết luận Query an toàn không chưa ký tự dấu hiệu tấn công XSS => **False positive**
 
 ## 2. Fixing 
 ### 2.1. Nguyên nhân
 - Regex: `\xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe`

	Với rule này sẽ match regex với request URL có chứa những ký tự nguy cơ: `¼script¾alert(¢XSS¢)¼/script¾`

- False positve xảy ra với khi data theo URL là dạng **XML** và có chứa ký tự **"Ế"** khi decode sang UTF-8 sẽ trở thành **"áº¾"** đồng thời trước nó sẽ có ký tự đặc biệt **"<"** do dạng dữ liệu là XML  dẫn đến match với: `<[^\xbe]*\xbe` gây cảnh báo sai.

![](https://i.imgur.com/FHKuWUO.png)
 
### 2.2. Cấu hình chỉnh sửa rule
Chỉnh sửa tại file : 	

> /etc/nginx/modsec/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Rule id: **941310**

Chỉnh sửa lại rule regex:
```c
"@rx \xbc[^\xbe>]*[\xbe>]"
```
Lưu lại sau khi chỉnh sửa.
```c
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx \xbc[^\xbe>]*[\xbe>]" \
  "id:941310,\
  phase:2,\
  block,\
  capture,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
  msg:'US-ASCII Malformed Encoding XSS Filter - Attack Detected',\
  logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"
```
Kiểm tra sau khi thay đổi rule.

![](https://i.imgur.com/RfuPRlQ.png)


#### Preferences
- [**github**](https://github.com/coreruleset/coreruleset/issues/1942) 
- [**Modsec-NginX**](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1645) 

