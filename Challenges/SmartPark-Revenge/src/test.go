package main

import (
	"fmt"
	"regexp"
)

func test() {
	str := "123abc'沙比"

	// 定义正则表达式，匹配数字、字母、汉字
	pattern := "^[0-9a-zA-Z\\p{Han}]+$"
	reg := regexp.MustCompile(pattern)

	// 使用正则表达式判断字符串是否匹配
	if reg.MatchString(str) {
		fmt.Println("yes")
	} else {
		fmt.Println("字符串包含其他字符")
	}
}
