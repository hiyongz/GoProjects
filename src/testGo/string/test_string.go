package main

import (
	"bytes"
	"fmt"
	"time"
)

func main() {
	str := "chinese"
	city := "beijing"

	// 1. +=
	s := time.Now()
	for i := 0; i < 100000; i++ {
		str += city
	}
	e := time.Since(s)
	fmt.Println("time cost 1:", e)

	// 2. fmt.Sprintf
	str = "chinese"
	city = "beijing"
	s = time.Now()
	for i := 0; i < 100000; i++ {
		str = fmt.Sprintf("%s%s", str, city)
	}
	e = time.Since(s)
	fmt.Println("time cost 2:", e)

	//3.  buffer.WriteString
	str = "chinese"
	city = "beijing"
	s = time.Now()
	var buf = bytes.Buffer{}
	buf.WriteString(str)
	for i := 0; i < 100000; i++ {
		buf.WriteString(city)
	}
	e = time.Since(s)
	fmt.Println("time cost 3:", e)

	//4. append
	str = "chinese"
	city = "beijing"
	s = time.Now()
	bstr := []byte(str)
	bcity := []byte(city)
	for i := 0; i < 100000; i++ {
		bstr = append(bstr, bcity...)
	}
	e = time.Since(s)
	// fmt.Printf("randstrs : %s", bstr)
	fmt.Println("time cost 4:", e)

	// 5. copy
	str = "chinese"
	city = "beijing"
	s = time.Now()
	zstr := []byte(str)
	for i := 0; i < 100000; i++ {
		copy(zstr, city)
	}
	e = time.Since(s)
	// fmt.Printf("randstrs : %s", zstr)
	// fmt.Printf("randstrs : %s", city)
	fmt.Println("time cost 5:", e)

	hello := "hello"
    world := "world"

	var buffer bytes.Buffer
    for i := 0; i < 10; i++ {
        
        buffer.WriteString(hello)
        buffer.WriteString(",")
        buffer.WriteString(world)
        _= buffer.String()

    }
	// fmt.Printf("buffer : %s", buffer.String())
}
