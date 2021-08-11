package main

import (
	"fmt"
	"log"
	"os/exec"
)

func main() {

	randstr1 := "6033ff352c5a8395f75cba2162be574f0f712da5f4e4595cf50281ce567416c1"
	log.Printf("type of randstr %T", randstr1)
	// randstr := "123"
	log.Println(fmt.Sprintf("randstr : %s", randstr1))
	// randstr := fmt.Sprintf("%x", randstr1)
	mac2 := "d8380ddbce90"

	cmd := exec.Command("./test_openssl", mac2, randstr1)
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	// err := cmd.Run()
	// if err != nil {
	// 	log.Fatalf("failed to call cmd.Run(): %v", err)
	// }

	data, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to call Output(): %v", err)
	}
	log.Printf("666666666666666\n")
	log.Printf("output: %s", data)
	log.Printf("output: %T", data)
	log.Printf("output: %x", data)
	log.Printf("666666666666666\n")

}
