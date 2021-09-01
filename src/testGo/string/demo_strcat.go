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
	strs := buffer.String()
	fmt.Println(strs)
	fmt.Printf("%T",strs)

}

func DemoStrings() {
	var builder1 strings.Builder
	builder1.WriteString("hello")
	// fmt.Printf("The length 0f builder1: %d\n", builder1.Len())
	builder1.WriteByte(' ')
	builder1.WriteString("world")
	builder1.Write([]byte{' ', '!'})

	fmt.Println(builder1.String())	

	f1 := func(b strings.Builder) {
		// b.WriteString("world !")  //会报错
	}
	f1(builder1)

	builder1.Reset()
	fmt.Printf("The length 0f builder1: %d\n", builder1.Len())

}


func main() {
	// DemoBytes()
	DemoStrings()
}