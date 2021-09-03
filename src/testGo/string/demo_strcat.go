package main

import (
	"bytes"
	"fmt"
	"io"
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

	f1 := func(b strings.Builder) {
		// b.WriteString("world !")  //会报错
	}
	f1(builder1)

	builder1.Reset()
	fmt.Printf("The length of builder1: %d\n", builder1.Len())

	reader1 := strings.NewReader("hello world!")
	buf1 := make([]byte, 5)
	n, _ := reader1.Read(buf1)
	fmt.Println(string(buf1))
	fmt.Printf("%d bytes were read. (call Read)\n", n)

	// 示例2。
	buf2 := make([]byte, 6)
	offset1 := int64(6)
	n, _ = reader1.ReadAt(buf2, offset1)
	fmt.Printf("%d bytes were read. (call ReadAt, offset: %d)\n", n, offset1)
	fmt.Printf("The reading index in reader: %d\n",
		reader1.Size()-int64(reader1.Len()))
	fmt.Println(string(buf2))
	fmt.Println()

	// 示例3。
	offset2 := int64(6)
	expectedIndex := reader1.Size() - int64(reader1.Len()) + offset2
	fmt.Printf("Seek with offset %d and whence %d ...\n", offset2, io.SeekCurrent)
	readingIndex, _ := reader1.Seek(offset2, io.SeekCurrent)
	fmt.Printf("The reading index in reader: %d (returned by Seek)\n", readingIndex)
	fmt.Printf("The reading index in reader: %d (computed by me)\n", expectedIndex)

	n, _ = reader1.Read(buf2)
	fmt.Printf("%d bytes were read. (call Read)\n", n)
	fmt.Printf("The reading index in reader: %d\n",
		reader1.Size()-int64(reader1.Len()))
	fmt.Println(string(buf2))
}

func main() {
	// DemoBytes()
	DemoStrings()
}
