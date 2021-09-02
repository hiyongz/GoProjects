package benchmark

import (
	"bytes"
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

func DemoStrings(n int) {
	var builder1 strings.Builder
	for i := 0; i < n; i++ {
		builder1.WriteString("hello ")
		builder1.WriteString("world !")
	}
}

func DemoPlus(n int) {

	str1 := "hello "
	str2 := "world !"
	str3 := ""
	for i := 0; i < n; i++ {
		str3 += str1
		str3 += str2
	}
}

func BenchmarkDemoBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DemoBytes(10000)
	}
}

func BenchmarkDemoStrings(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DemoStrings(10000)
	}
}

func BenchmarkDemoPlus(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DemoPlus(10000)
	}
}