//go:generate go run tools/genobf.go

package main

import (
	"Ebyte-StrObf/include"
	"fmt"
	"syscall"
)
//we obfuscated the function
//obfuscate:function
func OBF_C7DF5C1C8BDB561C(OBF_29213DBE437D6C0D, OBF_29213ABE437D66F4 int) int {
	return OBF_29213DBE437D6C0D + OBF_29213ABE437D66F4
}

func main() {
	fmt.Println(include.OBF_13A91E13D1BF3834())
	fmt.Println(include.OBF_91628FA6A512EF9C())
	fmt.Println("Obfuscated number:", 1337)
	OBF_C34AFE0ADF6E13B7 := OBF_C7DF5C1C8BDB561C(5, 7)
	fmt.Printf("%s %d\n", include.OBF_E36AB4D93CD2C0BE(), OBF_C34AFE0ADF6E13B7)
	OBF_C3DD23FF43B8F51A := syscall.NewLazyDLL(include.OBF_79AEC94396C55A83())
	OBF_3D0351B49C46A165 := OBF_C3DD23FF43B8F51A.NewProc(include.OBF_7C8D88AF83F9FFE5())
	fmt.Printf("kernel32.GetProcAddress address: %v\n", OBF_3D0351B49C46A165.Addr())
}
