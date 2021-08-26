package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

func UpdateRandstr(tlvdata []byte) {
	// 替换随机字符串
	// randstr := tlvdata[16:]
	var buffer bytes.Buffer
	for index := range tlvdata {
		hex_data := fmt.Sprintf("%02x", tlvdata[index])
		if index == 0 {
			buffer.WriteString("char buff[] = {")
		}
		buffer.WriteString("0x")
		buffer.WriteString(hex_data)

		if index != len(tlvdata)-1 {
			buffer.WriteString(",")
		} else {
			buffer.WriteString("};")
		}

	}
	randstrs := buffer.String()

	randstr_sed := fmt.Sprintf("s/char\\ buff\\[\\].*$/%s/", randstrs)
	cmd_sed_randstr := fmt.Sprintf("sed -i '%s' dev_encrypt.c", randstr_sed)
	log.Printf("cmd_sed: %s", cmd_sed_randstr)
	_, err := exec.Command("bash", "-c", cmd_sed_randstr).Output()
	if err != nil {
		log.Fatalf("failed to update randstr: %v", err)
	}
}