//go:generate go run tools/genobf.go

package main

import (
	"Ebyte-StrObf/include"
	"fmt"
	"syscall"
)
// we use this to obfuscate the function
//obfuscate:function
func calculate(a, b int) int {
	return a + b
}

func main() {
	fmt.Println(include.OBF("Hello, world!"))
	fmt.Println(include.OBF("Short WinAPI demo"))
	fmt.Println("Obfuscated number:", 1337)
	result := calculate(5, 7)
	fmt.Printf("%s %d\n", include.OBF("Sum is:"), result)
	kernel32 := syscall.NewLazyDLL(include.OBF("kernel32.dll"))
	getprocaddr := kernel32.NewProc(include.OBF("GetProcAddress"))
	fmt.Printf("kernel32.GetProcAddress address: %v\n", getprocaddr.Addr())
}
