# JeecgBoot Go版本综合漏洞利用工具
JeecgGo 综合漏洞利用工具, 基于Go语言开发, 使用时, 需下载主程序以及 config.yaml（POC）文件放在同一目录下运行
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
## 命令执行
  testConnection 远程命令执行漏洞
  loadTableData SSTI模板注入漏洞
  queryFieldBySql 模板注入漏洞
  sendMsg freemaker模板注入
  AviatorScript 表达式注入漏洞
## 文件上传
  /jmreport/upload 接口未授权任意文件上传漏洞
  commonController.do  任意文件上传漏洞
## 信息泄露
  querySysUser 信息泄露漏洞
  checkOnlyUser 信息泄露漏洞
  httptrace 信息泄露漏洞
  dataSource_list 接口数据库账号密码泄露
## passwordChange任意用户密码重置漏洞
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
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n queryFieldBySql -c whoami
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n queryFieldBySql -c "echo 111"
JeecgGo.exe -u http://127.0.0.1/jeecg-boot/ -n queryFieldBySql -c id -x token
```
# 免责声明
本工具仅用于学习，严禁用于任何非法活动。使用本文所述技术前，请确保已获得目标系统所有者的明确授权。任何滥用信息造成的法律责任及后果均由使用者自行承担，作者不承担任何责任。
