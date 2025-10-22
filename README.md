# JeecgBoot Go版本综合漏洞检测工具
JeecgGo 综合漏洞检测工具, 基于Go语言开发, 该工具结合作者在工作中测试时遇到的问题进行改进。使用时, 需下载主程序以及Config.yaml文件放在同一目录下运行（重要）, 运行结束后会生成result.json文件, 里边包含检测到存在漏洞的URL、payload以及响应内容。
# 漏洞如下
## SQL注入
  queryTableData SQL注入漏洞

  qurestSql SQL注入漏洞

  getTotalData SQL注入漏洞

  show SQL注入漏洞

  getDictItemsByTable SQL注入漏洞

  check SQL注入漏洞

  getDictItemsByTable 后台未授权SQL注入漏洞

  column 参数SQL注入漏洞

  parseSql SQL注入漏洞

## 命令执行
  testConnection 远程命令执行漏洞

  loadTableData SSTI模板注入漏洞

  queryFieldBySql 模板注入漏洞

  sendMsg freemaker模板注入

  AviatorScript 表达式注入漏洞
## 文件上传
  jmreport/upload 接口未授权任意文件上传漏洞

  commonController.do  任意文件上传漏洞
## 信息泄露
  querySysUser 信息泄露漏洞

  checkOnlyUser 信息泄露漏洞

  httptrace 信息泄露漏洞

  dataSource_list 接口数据库账号密码泄露
## fileTree 目录遍历漏洞
## passwordChange 任意用户密码重置漏洞
# 使用说明
简单用法
```
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/
```
携带token进行测试
```
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -x token
```
命令执行
```
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n sendMsg -c id -x token
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n queryFieldBySql -c whoami
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n loadTableData -c "echo 111"
```
check、column SQL注入基于延时技术检测漏洞是否存在，主要靠比较响应时间的差异。网络波动可能会直接影响响应时间，所以这种容易产生误报，不可避免。为确保准确性，强烈建议对检测出的漏洞进行手动验证。
# 更新
- 2025/10/18: 对代码结构进行重构, 便于后续新增POC及内容调整
- 2025/10/15: 增加了parseSql SQL注入漏洞

# 免责声明

本工具仅用于安全研究、教育、漏洞验证和经明确授权的渗透测试（例如：目标所有者书面授权、合同约定或靶场环境）。禁止在未获授权的生产环境或第三方系统上使用本工具。

在使用本工具之前，使用者必须确保已取得目标系统所有者的明确授权（书面或可验证的合同/邮件）。使用者应遵守其所在司法辖区的所有适用法律与规定。

任何因使用、修改或分发本工具而直接或间接造成的损害、数据丢失、业务中断或法律后果，均由使用者自行承担。作者不对因滥用本工具导致的任何损失承担责任。

# 参考链接

https://github.com/MInggongK/jeecg-

https://www.cnblogs.com/CVE-Lemon/p/18392679

https://blog.csdn.net/YJ_12340/article/details/146536305
