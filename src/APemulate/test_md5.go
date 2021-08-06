package main

import (
	"crypto/md5"
	"fmt"
	"log"
)

func main() {
	version_a := "V16.01.0.7(1075)"
	version_salt := version_a + "tenda"
	version_salt_uint8 := []byte(version_salt)
	msg2 := md5.Sum(version_salt_uint8)
	log.Println("66666666666666666")
	fmt.Println("msg2: ", msg2)
	fmt.Printf("msg2: %x\n", msg2)
	log.Println("66666666666666666")
	mac := 0xD8380DDBCE90
	fmt.Println("mac: ", mac)
}