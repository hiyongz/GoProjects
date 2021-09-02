package main

import (
	"bytes"
	"fmt"
	"strings"
)

func DemoBytes() {
	var buffer bytes.Buffer	
	buffer.WriteString("hello ")		
	buffer.WriteString("world !")
	fmt.Printf("The length of buffer: %d\n", buffer.Len())
	fmt.Printf("The capacity of buffer: %d\n", buffer.Cap())
	fmt.Println(buffer.String())

	p1 := make([]byte, 2)
	// p1 := []byte{1,2,3,4,5}
	n, _ := buffer.Read(p1)
	fmt.Println(buffer.String())
	fmt.Println(string(p1))
	fmt.Printf("%d bytes were read. (call Read)\n", n)
	fmt.Printf("The length of buffer: %d\n", buffer.Len())
	fmt.Printf("The capacity of buffer: %d\n", buffer.Cap())


}

func DemoStrings() {
	var builder1 strings.Builder
	builder1.WriteString("hello")
	// fmt.Printf("The length 0f builder1: %d\n", builder1.Len())
	builder1.WriteByte(' ')
	builder1.WriteString("world")
	builder1.Write([]byte{' ', '!'})
	fmt.Println(builder1.String())	

	reader1 := strings.NewReader("hello world!")
	buf1 := make([]byte, 5)
	n, _ := reader1.Read(buf1)
	fmt.Printf("%d bytes were read. (call Read)\n", n)
	fmt.Println(string(buf1))
	f1 := func(b strings.Builder) {
		// b.WriteString("world !")  //会报错
	}
	f1(builder1)

	builder1.Reset()
	fmt.Printf("The length of builder1: %d\n", builder1.Len())

}


func main() {
	// DemoBytes()
	DemoStrings()
}