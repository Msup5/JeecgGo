package common

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Request struct {
	URL         string `yaml:"URL"`
	Method      string `yaml:"Method"`
	UserAgent   string `yaml:"User-Agent"`
	ContentType string `yaml:"Content-Type"`
	Body        string `yaml:"Body"`
}

type Config struct {
	Requests map[string]Request `yaml:"requests"`
}

func ReadFile() Config {
	yamlData, err := os.ReadFile("Config.yaml")
	if err != nil {
		Colors(ColorRed).Printf("[-]读取 Config.yaml 配置文件失败, %v\n", err)
		os.Exit(1)
	}

	var ConfigData Config

	if err := yaml.Unmarshal(yamlData, &ConfigData); err != nil {
		Colors(ColorRed).Printf("[-]解析 Config.yaml 配置文件失败， %v\n", err)
		os.Exit(1)
	}

	return ConfigData
}
