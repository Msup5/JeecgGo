package common

import "strings"

func JoinURL(url, path string) string {
	newURL := strings.TrimRight(url, "/")

	urls := newURL + "/" + path

	return urls
}
