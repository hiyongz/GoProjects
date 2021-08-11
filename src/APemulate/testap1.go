package main

import (
	// "bufio"
	// "crypto/aes"
	"fmt"
	"os/exec"

	// "strconv"
	// "io/ioutil"

	"io"
	"log"
	"net"
	// "os"
	// "strings"
)

func chkError(err error) {
	if err != nil {
		fmt.Println("err :", err)
	}
}

func main() {
	// tcpAddr, _ := net.ResolveTCPAddr("tcp","ims.ip-com.com.cn:11822") // 获取一个TCPAddr
	// tcpAddr, _ := net.ResolveTCPAddr("tcp","47.98.176.85:11822") // 获取一个TCPAddr
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "118.31.2.168:1821") // 获取一个TCPAddr
	fmt.Println("tcpAddr: ", tcpAddr)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("err :", err)
		return
	} else {
		fmt.Println("connect successful")
		fmt.Println(conn.LocalAddr().String() + " : Client connected!")
	}

	var outBuf = make([]byte, 18)
	outBuf[0] = 0x24
	outBuf[1] = 0x0
	outBuf[2] = 0x6
	outBuf[3] = 0x0
	outBuf[4] = 0x0
	outBuf[5] = 0x1b
	outBuf[6] = 0x0
	outBuf[7] = 0x0
	outBuf[8] = 0x04
	outBuf[9] = 0x2e
	outBuf[10] = 0x0
	outBuf[11] = 0x0
	outBuf[12] = 0x0
	outBuf[13] = 0x0
	outBuf[14] = 0x0
	outBuf[15] = 0x2b
	outBuf[16] = 0x0
	outBuf[17] = 0x02

	mac := "D8380DDBCE90"
	version := "V2.0.0.7(7924)"
	pruduct := "W36AP"

	oneMessage := append(outBuf, byte(0))
	oneMessage = append(oneMessage, byte(12))
	mac_uint8 := []byte(mac)
	// mac_uint8 := mac
	oneMessage = append(oneMessage, mac_uint8...)
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(3))
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(len(version)))
	version_uint8 := []byte(version)
	oneMessage = append(oneMessage, version_uint8...)
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(19))
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(len(pruduct)))
	pruduct_uint8 := []byte(pruduct)
	oneMessage = append(oneMessage, pruduct_uint8...)

	fmt.Printf("data: %x\n", oneMessage)

	// // defer conn.Close() // 关闭连接
	_, err = conn.Write([]byte(oneMessage)) // 发送数据
	chkError(err)

	header := make([]byte, 52)

Loop:

	for {
		// deHead := make([]byte, 52)
		// log.Println(fmt.Sprintf("recv header : %x", header))
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			log.Println("recv failed. ", err)
		} else {
			log.Println(fmt.Sprintf("recv header : %x", header))
			log.Println(header)
			break Loop
		}
	}

	// version2 := "admin"
	// version2_uint8 := []byte(version2)

	randstr1 := header[20:]
	log.Println(fmt.Sprintf("randstr : %s", randstr1))

	randstr := fmt.Sprintf("%x", randstr1)
	log.Printf("type of randstr %T", randstr)
	fmt.Printf("randstr : %s", randstr)
	// randstr := fmt.Sprintf("%x", randstr1)
	mac2 := "d8380ddbce90"
	// mac2 := "000c29bb0c0c"

	cmd := exec.Command("./test_openssl", mac2, header)
	msg, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to call Output(): %v", err)
	}
	log.Printf("666666666666666\n")
	log.Printf("output: %s", msg)
	log.Printf("output: %T", msg)
	log.Printf("output: %x", msg)
	log.Printf("666666666666666\n")

	// dev_auth_k
	var tmpmsg = make([]byte, 15)
	tmpmsg[0] = 0x24
	tmpmsg[1] = 0x0
	tmpmsg[2] = 0x6
	tmpmsg[3] = 0x0
	tmpmsg[4] = 0x0
	tmpmsg[5] = 0x1d
	tmpmsg[6] = 0x0
	tmpmsg[7] = 0x0
	tmpmsg[8] = 0x04
	tmpmsg[9] = 0x30
	tmpmsg[10] = 0x0
	tmpmsg[11] = 0x0
	tmpmsg[12] = 0x0
	tmpmsg[13] = 0x0
	tmpmsg[14] = 0x0
	tmpmsg = append(tmpmsg, byte(len(msg)+4))
	tmpmsg = append(tmpmsg, byte(0))
	tmpmsg = append(tmpmsg, byte(6))
	tmpmsg = append(tmpmsg, byte(0))
	tmpmsg = append(tmpmsg, byte(len(msg)))
	for index, _ := range msg {
		tmpmsg = append(tmpmsg, msg[index])
	}
	//tmpmsg = append(tmpmsg)

	fmt.Printf("tmpmsg: %x\n", tmpmsg)
	// fmt.Println("tmpmsg : ", tmpmsg)

	// // defer conn.Close() // 关闭连接
	_, err = conn.Write([]byte(tmpmsg)) // 发送数据
	chkError(err)

	header2 := make([]byte, 45)
Loop2:
	for {
		// deHead := make([]byte, 52)
		_, err2 := io.ReadFull(conn, header2[:])
		if err != nil {
			log.Println("recv failed. ", err2)
		} else {
			log.Println(fmt.Sprintf("recv header : %x", header2))
			break Loop2
		}
	}
	// log.Println(fmt.Sprintf("recv header : %x", header2))

}
