package main

import (
	"fmt"
	"os"
)

var model *RexService

func main() {
	baseURL := os.Getenv("REX_BASE_URL")
	user := os.Getenv("REX_USER")
	pass := os.Getenv("REX_PASS")
	model = NewRexService(
		baseURL,
		user,
		pass,
	)
	fmt.Println(model)
}
