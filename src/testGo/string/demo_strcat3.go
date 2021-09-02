package string

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func DemoBytes(n int) {
	var buffer bytes.Buffer

	for i := 0; i < n; i++ {
		buffer.WriteString("hello ")
		buffer.WriteString("world !")
	}
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

func BenchmarkDemoBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DemoBytes(10000)
	}
}
