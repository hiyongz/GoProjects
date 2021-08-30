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
	builder1.WriteByte(' ')
	builder1.WriteString("world !")
	builder1.Write([]byte{'\n'})
	fmt.Println(builder1.String())
	fmt.Printf("%T",builder1.String())
	// builder1.Reset()
	// fmt.Println(builder1.String())

	f1 := func(b strings.Builder) {
		// b.WriteString("world !")
		fmt.Println(b.String())
	}
	f1(builder1)

}


func main() {
	DemoBytes()
	DemoStrings()
}