package common

import (
	"encoding/json"
	"os"
)

type OutputJson struct {
	URL          string      `json:"url"`
	RequestBody  interface{} `json:"payload"`
	ResponseBody interface{} `json:"response"`
}

func OutputFile(url, requestBody, responseBody string) {
	newResult := OutputJson{
		URL:          url,
		RequestBody:  requestBody,
		ResponseBody: responseBody,
	}

	fileName := "results.json"

	var results []OutputJson

	if _, err := os.Stat(fileName); err == nil {
		data, err := os.ReadFile(fileName)
		if err == nil && len(data) > 0 {
			_ = json.Unmarshal(data, &results)
		}
	}

	results = append(results, newResult)

	file, err := os.Create(fileName)
	if err != nil {
		Colors(ColorRed).Printf("[*]创建 %s 文件失败, %v\n", fileName, err)
		return
	}

	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(results); err != nil {
		Colors(ColorRed).Printf("[*]写入 %s 文件失败, %v\n", fileName, err)
		return
	}
}
