package common

type QurestSql struct {
	Message         string `json:"message"`
	QurestSqlResult []struct {
		GData string `json:"gdata"`
		TData string `json:"tdata"`
	} `json:"result"`
}

type QueryTableData struct {
	QueryTableDataResult []struct {
		Value string `json:"value"`
		Text  string `json:"text"`
		Label string `json:"label"`
	} `json:"result"`
}

type Httptrace struct {
	HttptraceResult []struct {
		Requests string `json:"timestamp"`
	} `json:"traces"`
}

var LoadTableData_poc_1 struct {
	LoadTableDataResult struct {
		LoadTableDataRecords []map[string]interface{} `json:"records"`
	} `json:"result"`
}

var LoadTableData_poc_2 struct {
	LoadTableDataResult struct {
		LoadTableDataRecords []map[string]interface{} `json:"records"`
	} `json:"result"`
}

var QueryFieldBySql struct {
	QueryFieldBySqlResult struct {
		QueryFieldBySqlFieldList []map[string]interface{} `json:"fieldList"`
	} `json:"result"`
}

type FileTree struct {
	FileTreeResult []struct {
		Key string `json:"key"`
	} `json:"result"`
}

type DataSource_list struct {
	DataSourceResult struct {
		DataSourceRecords []struct {
			DbName     string `json:"dbName"`
			DbUsername string `json:"dbUsername"`
			DbPassword string `json:"dbPassword"`
		} `json:"records"`
	} `json:"result"`
}

type SendMsg struct {
	SendMsgResults struct {
		SendMsgRecords []struct {
			EsContent string `json:"esContent"`
		} `json:"records"`
	} `json:"result"`
}

type GetDictItemsByTableBackSql []struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type GetDictItemsByTable []struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
}

type JmreportUpload struct {
	Message string `json:"message"`
}

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

type AviatorScript struct {
	AviatorScriptResult struct {
		ID      string `json:"id"`
		Code    string `json:"code"`
		JsonStr string `json:"jsonStr"`
	} `json:"result"`
}

type Show struct {
	Message string `json:"message"`
}
