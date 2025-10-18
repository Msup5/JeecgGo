package Core

import (
	common "JeecgExploitssGo/Common"
	"flag"
	"fmt"
	"os"
)

var (
	Urls    string
	Token   string
	VulName string
	Command string
	SetTime int
	// Output  string
	// ResponseContnet int
)

func init() {
	flag.StringVar(&Urls, "u", "", "url")
	flag.StringVar(&Token, "x", "", "x-access-token")
	flag.StringVar(&VulName, "n", "", "vulnerability name (loadTableData/queryFieldBySql/sendMsg)")
	flag.StringVar(&Command, "c", "", "execute command")
	// flag.StringVar(&Output, "o", "", "output file")
	flag.IntVar(&SetTime, "s", 0, "sleep time")
}

func Flags() {
	flag.Parse()

	if Urls == "" {
		common.Logo()
		fmt.Println("options: ")
		flag.PrintDefaults()
		fmt.Println("example usage: ")
		fmt.Println("  JeecgGo.exe -u http://127.0.0.1:8080/jeecg-boot/")
		fmt.Println("  JeecgGo.exe -u http://127.0.0.1:8080/jeecg-boot/ -t 1 -x token")
		fmt.Println("  JeecgGo.exe -u http://127.0.0.1:8080/jeecg-boot/ -n loadTableData -x token -c whoami")
		os.Exit(0)
	}

	if VulName != "" {
		if Command == "" {
			common.Colors(common.ColorRed).Println("[-]-c 参数不能为空, --help 查看帮助")
			os.Exit(1)
		}

		Cmd(Command)
	}
}
