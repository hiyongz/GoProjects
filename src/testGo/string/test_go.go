
import (
	// "bufio"
	"fmt"
	// "strconv"
	// "io/ioutil"
	"net"
	// "os"
	// "strings"
)

func main() {

	datas := []string{
		"D8380DDBCE90",
		"V2.0.0.7(7924)",
		"W36AP"}
		
	var messages []byte
	for _, b := range datas {
		body := []byte(b)	
		oneMessage := append(body, byte(len(body)))
		oneMessage = append(oneMessage, body...)
		messages = append(messages, oneMessage...)
	}
	
	fmt.Printf("%x", messages)
	
	byte_str := byte(01)
	fmt.Println(byte_str)
	fmt.Println("222")
	// aa := fmt.Sprintf("%8b", 6)
	// fmt.Printf(aa)
	// hex := strconv.FormatInt(0xff, 2)
	// fmt.Printf(hex)
	fmt.Println("\n222")
}