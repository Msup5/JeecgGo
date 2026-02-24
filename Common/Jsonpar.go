package common

import (
	"encoding/json"
	"strings"
)

// 统一接口
type UnifiedInterface interface {
	IsEmpty() bool
	Print()
}

// queryTableData SQL注入
type QueryTableData struct {
	QueryTableDataResult []struct {
		Value string `json:"value"`
		Text  string `json:"text"`
		Title string `json:"title"`
	} `json:"result"`
}

func (q *QueryTableData) IsEmpty() bool {
	return q.QueryTableDataResult == nil
}

func (q *QueryTableData) Print() {
	v := q.QueryTableDataResult[1]

	Colors(ColorYellow).Printf("[+++]value: %s Text: %s label: %s\n", v.Value, v.Text, v.Title)
}

// qurestSql SQL注入漏洞
type QurestSql struct {
	QurestSqlResult []struct {
		GData string `json:"gdata"`
		TData string `json:"tdata"`
	} `json:"result"`
}

func (q *QurestSql) IsEmpty() bool {
	return q.QurestSqlResult == nil
}

func (q *QurestSql) Print() {
	for _, v := range q.QurestSqlResult {
		Colors(ColorYellow).Printf("[+++]dbname: %s, version: %s\n", v.GData, v.TData)
	}
}

// getTotalData SQL注入漏洞

type GetTotalData struct {
	GetTotalDataResult struct {
		ChartData []struct {
			Name string `json:"name"`
		} `json:"chartData"`
		RawData []struct {
			Name string `json:"name"`
		} `json:"rawData"`
	} `json:"result"`
}

func (g *GetTotalData) IsEmpty() bool {
	return len(g.GetTotalDataResult.ChartData) == 0 ||
		len(g.GetTotalDataResult.RawData) == 0
}

func (g *GetTotalData) Print() {
	Colors(ColorYellow).Printf("[+++]version: %s\n", g.GetTotalDataResult.ChartData)
	Colors(ColorYellow).Printf("[+++]version: %s\n", g.GetTotalDataResult.RawData)
}

// show SQL注入漏洞
type Show struct {
	Message string `json:"message"`
}

func (s *Show) IsEmpty() bool {
	return !strings.Contains(s.Message, "PreparedStatementCallback")
}

func (s *Show) Print() {
	Colors(ColorYellow).Printf("[+++]message: %s\n", s.Message)
}

// getDictItemsByTable SQL注入漏洞
type GetDictItemsByTable []struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
}

func (g *GetDictItemsByTable) IsEmpty() bool {
	return g == nil || len(*g) == 0
}

func (g *GetDictItemsByTable) Print() {
	Colors(ColorYellow).Printf("[+++]username: %s, password: %s, salt: %s\n",
		(*g)[0].Username, (*g)[0].Password, (*g)[0].Salt)
}

// getDictItemsByTable 后台未授权SQL注入漏洞
type GetDictItemsByTableBackSql []struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Error string `json:"error"`
}

func (gb *GetDictItemsByTableBackSql) IsEmpty() bool {
	return gb == nil || len(*gb) == 0
}

func (gb *GetDictItemsByTableBackSql) Print() {
	Colors(ColorYellow).Printf("[+++]label: %s, value: %s\n",
		(*gb)[0].Label, (*gb)[0].Value)
}

// parseSql SQL注入漏洞
type ParseSql struct {
	ParseSqlResult struct {
		ParseSqlFields []struct {
			FieldName string `json:"fieldName"`
			FieldTxt  string `json:"fieldTxt"`
		} `json:"fields"`
	} `json:"result"`
}

func (p *ParseSql) IsEmpty() bool {
	return len(p.ParseSqlResult.ParseSqlFields) == 0
}

func (p *ParseSql) Print() {
	fieldName := p.ParseSqlResult.ParseSqlFields[0].FieldName
	fieldTxt := p.ParseSqlResult.ParseSqlFields[0].FieldTxt

	Colors(ColorYellow).Printf("[+++]fieldName: %s, fieldTxt: %s\n", fieldName, fieldTxt)
}

// testConnection 远程命令执行漏洞
type TestConnection struct {
	Message string `json:"message"`
}

func (t *TestConnection) IsEmpty() bool {
	return !strings.Contains(t.Message, "数据库连接成功")
}

func (t *TestConnection) Print() {
	Colors(ColorYellow).Printf("[+++]message: %s\n", t.Message)
}

// loadTableData SSTI模板注入漏洞
type LoadTableData struct {
	LoadTableDataResult struct {
		LoadTableDataRecords []map[string]interface{} `json:"records"`
	} `json:"result"`
}

func (l *LoadTableData) IsEmpty() bool {
	return l.LoadTableDataResult.LoadTableDataRecords == nil
}

func (l *LoadTableData) Print() {
	output := map[string]interface{}{
		"records": l.LoadTableDataResult.LoadTableDataRecords,
	}
	outputJson, _ := json.Marshal(output)
	Colors(ColorYellow).Printf("[+++]%s\n", string(outputJson))
}

/*
type LoadTableData_poc_2 struct {
	LoadTableDataResult struct {
		LoadTableDataRecords []map[string]interface{} `json:"records"`
	} `json:"result"`
}

func (l *LoadTableData_poc_2) IsEmpty() bool {
	return l.LoadTableDataResult.LoadTableDataRecords == nil
}

func (l *LoadTableData_poc_2) Print() {
	output := map[string]interface{}{
		"records": l.LoadTableDataResult.LoadTableDataRecords,
	}
	outputJson, _ := json.Marshal(output)
	Colors(ColorYellow).Printf("[+++]%s\n", string(outputJson))
}*/

// queryFieldBySql 模板注入漏洞
type QueryFieldBySql struct {
	QueryFieldBySqlResult struct {
		QueryFieldBySqlFieldList []map[string]interface{} `json:"fieldList"`
	} `json:"result"`
}

func (q *QueryFieldBySql) IsEmpty() bool {
	return q.QueryFieldBySqlResult.QueryFieldBySqlFieldList == nil
}

func (q *QueryFieldBySql) Print() {
	output := map[string]interface{}{
		"fieldList": q.QueryFieldBySqlResult.QueryFieldBySqlFieldList,
	}
	outputJson, _ := json.Marshal(output)
	Colors(ColorYellow).Printf("[+++]%s\n", string(outputJson))
}

// sendMsg freemaker模板注入
type SendMsg struct {
	SendMsgResults struct {
		SendMsgRecords []struct {
			EsContent string `json:"esContent"`
		} `json:"records"`
	} `json:"result"`
}

func (s *SendMsg) IsEmpty() bool {
	return s.SendMsgResults.SendMsgRecords == nil
}

func (s *SendMsg) Print() {
	records := s.SendMsgResults.SendMsgRecords[0].EsContent
	Colors(ColorYellow).Printf("[+++]%s\n", records)
}

// AviatorScript 表达式注入漏洞
type AviatorScript struct {
	AviatorScriptResult struct {
		ID      string `json:"id"`
		Code    string `json:"code"`
		JsonStr string `json:"jsonStr"`
	} `json:"result"`
}

func (a *AviatorScript) IsEmpty() bool {
	return !(a.AviatorScriptResult.ID == "980882669965455363") &&
		a.AviatorScriptResult.Code == "" &&
		a.AviatorScriptResult.JsonStr == ""
}

func (a *AviatorScript) Print() {
	Colors(ColorYellow).Printf("[+++]id: %s, code: %s\n", a.AviatorScriptResult.ID, a.AviatorScriptResult.Code)
}

// /jmreport/upload 接口未授权任意文件上传漏洞
type JmreportUpload struct {
	Message string `json:"message"`
}

func (j *JmreportUpload) IsEmpty() bool {
	return !(strings.Contains(j.Message, "jimureport/YWv873Lw"))
}

func (j *JmreportUpload) Print() {
	Colors(ColorYellow).Printf("[+++]uploadPath: %s\n", j.Message)
}

type Httptrace struct {
	HttptraceResult []struct {
		Requests string `json:"timestamp"`
	} `json:"traces"`
}

func (h *Httptrace) IsEmpty() bool {
	return h.HttptraceResult == nil
}

func (h *Httptrace) Print() {
	// Colors(ColorYellow).Printf("[+++]%s\n", h.HttptraceResult[0].Requests)
}

// dataSource_list 接口数据库账号密码泄露
type DataSource_list struct {
	DataSourceResult struct {
		DataSourceRecords []struct {
			DbName     string `json:"dbName"`
			DbUsername string `json:"dbUsername"`
			DbPassword string `json:"dbPassword"`
		} `json:"records"`
	} `json:"result"`
}

// 数据库账号密码泄露
func (d *DataSource_list) IsEmpty() bool {
	return d.DataSourceResult.DataSourceRecords == nil
}

func (d *DataSource_list) Print() {
	records := d.DataSourceResult.DataSourceRecords[0]
	Colors(ColorYellow).Printf("[+++]dbName: %s, dbUsername: %s, dbPassword: %s\n",
		records.DbName, records.DbUsername, records.DbPassword)
}

// fileTree 目录遍历漏洞
type FileTree struct {
	FileTreeResult []struct {
		Key string `json:"key"`
	} `json:"result"`
}

func (f *FileTree) IsEmpty() bool {
	return f.FileTreeResult == nil
}

func (f *FileTree) Print() {
	key1 := f.FileTreeResult[1].Key
	key2 := f.FileTreeResult[2].Key
	key3 := f.FileTreeResult[3].Key
	key4 := f.FileTreeResult[4].Key
	key5 := f.FileTreeResult[5].Key

	Colors(ColorYellow).Printf("[+++]%s,%s,%s,%s,%s\n", key1, key2, key3, key4, key5)
}

// passwordChange 任意用户密码重置漏洞
type PasswordChange struct {
	Message string `json:"message"`
}

func (p *PasswordChange) IsEmpty() bool {
	return !strings.Contains(p.Message, "修改完成")
}

func (p *PasswordChange) Print() {
	Colors(ColorYellow).Println("[+++]重置账号密码为 [jeecg/YioVke@1743]")
}

// uploadImgByHttp SSRF 漏洞
type UploadImgByHttp struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Result  string `json:"result"`
}

func (u *UploadImgByHttp) IsEmpty() bool {
	return !(u.Code == 200 && u.Success)
}

func (u *UploadImgByHttp) Print() {
	Colors(ColorYellow).Printf("[+++]uploadPath: %s\n", u.Result)
}
