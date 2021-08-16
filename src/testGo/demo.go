package main
import "fmt"

// 加法运算
func add(x, y int) int {
	return x + y
}

func init() {	
	fmt.Println("main  init....")
}

func main() {
	var value1 int = 2
	var value2 = 3
	sum := add(value1,value2)
	fmt.Printf("%d + %d = %d",value1,value2,sum)

	a := `"dev_info"`
	b := []byte{`"dev_info"`}
	fmt.Printf("%s",a)
	fmt.Printf("%s",b[0])
}