package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

func chkError(err error) {
    if err != nil {
		fmt.Println("err :", err);
    }
}

func main() {	
	// tcpAddr, _ := net.ResolveTCPAddr("tcp","ims.ip-com.com.cn:11822") // 获取一个TCPAddr
	tcpAddr, _ := net.ResolveTCPAddr("tcp","47.98.176.85:11822") // 获取一个TCPAddr
	fmt.Println("tcpAddr: ", tcpAddr)	
	conn, err := net.DialTCP("tcp", nil, tcpAddr)	
	if err != nil {
		fmt.Println("err :", err)
		return
	} else {
		fmt.Println("connect successful")
	}

	var outBuf = make([]byte, 30)
	outBuf[0] = 0x24
	outBuf[1] = 0x0
	outBuf[2] = 0x6
	outBuf[3] = 0x0
	outBuf[4] = uint8(213 / 256)
	outBuf[5] = uint8(213 % 256)
	outBuf[6] = 0x0
	outBuf[7] = 0x0

	fmt.Println(conn.LocalAddr().String() + " : Client connected!")
	
	// defer conn.Close() // 关闭连接

	_, err = conn.Write([]byte(outBuf)) // 发送数据
	chkError(err)

	result,err := ioutil.ReadAll(conn)
	chkError(err)
	fmt.Println(result)
	
	inputReader := bufio.NewReader(os.Stdin)
	for {
		input, _ := inputReader.ReadString('\n') // 读取用户输入
		inputInfo := strings.Trim(input, "\r\n")
		if strings.ToUpper(inputInfo) == "Q" { // 如果输入q就退出
			return
		}
		_, err = conn.Write([]byte(inputInfo)) // 发送数据
		if err != nil {
			return
		}
		buf := [512]byte{}
		n, err := conn.Read(buf[:])
		if err != nil {
			fmt.Println("recv failed, err:", err)
			return
		}
		fmt.Println(string(buf[:n]))
	}
}