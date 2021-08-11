package main

import (
	// "bufio"
	// "crypto/aes"
	"fmt"
	// "strconv"
	// "io/ioutil"
	"crypto/md5"
	"io"
	"log"
	"net"

	// "os"
	// "strings"
	"crypto/sha1"
)

func chkError(err error) {
	if err != nil {
		fmt.Println("err :", err)
	}
}

func int2byte(number int, l int) {
	// str：填充字符串
	// l：占位长度
	aa := fmt.Sprintf("%8b", number)

	byte_str := []byte(aa)
	fmt.Print(byte_str)
	// byte_str := []byte(10)
	fmt.Println("222")
	fmt.Printf("%s: %b", "10", 6)

	// s1 := "字符串"
	// s2 := "拼接"
	// var build strings.Builder
	// build.WriteString(s1)
	// build.WriteString(s2)
	// s3 := build.String()
	// return
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

	// mac := "D8380DDBCE90"
	// version := "V2.0.0.7(7924)"
	// pruduct := "W36AP"
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

	// deHead = AesDecryptECB(header, []byte(""))
	// // log.Println(fmt.Sprintf("%s recv header : %x", dev.Ip, deHead))
	// log.Println(fmt.Sprintf("recv header : %x", deHead))

	version2 := "admin"
	version2_uint8 := []byte(version2)

	randstr := header[20:]
	log.Printf("type of randstr %T", randstr)
	// randstr := "123"
	log.Println(fmt.Sprintf("randstr : %x", randstr))

	mid := append(mac_uint8, version2_uint8...)
	mid = append(mid, randstr...)
	log.Println(fmt.Sprintf("version2_uint8 : %x", version2_uint8))
	log.Println("version2_uint8: ", version2_uint8)
	log.Println("randstr: ", randstr)

	mid22 := fmt.Sprintf("%x", mid)
	log.Println("mid2: ", mid22)
	log.Println("mid: ", mid)
	salt := "tenda" + "\x00\x00\x00"
	log.Println("salt: ", salt)

	salt_uint8 := []byte(salt)
	// salt_hex := fmt.Sprintf("%x",salt_uint8)
	log.Println("salt_uint8: ", salt_uint8)
	// key, iv := BytesToKey(salt_uint8, mid, sha256.New(), 16, aes.BlockSize)
	key, iv := EVPBytesToKey(16, 16, sha1.New(), salt_uint8, mid, 5)
	log.Println(fmt.Sprintf("key : %x", key))
	log.Println(fmt.Sprintf("iv : %x", iv))

	mid2 := append(key, iv...)
	mid2 = append(mid2, salt...)
	msg := md5.Sum(mid2)
	
	// msg := ClacMd5(mid2)
	// msg = byte(msg)
	//msg = string(msg)

	fmt.Printf("msg : %x", msg)
	fmt.Println("msg : ", msg)

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
	// Loop2:
	for {
		// deHead := make([]byte, 52)
		_, err2 := io.ReadFull(conn, header2[:])
		if err != nil {
			log.Println("recv failed. ", err2)
		}
		// } else {
		// 	log.Println(fmt.Sprintf("recv header : %x", header2))
		// 	break Loop2
		// }
		log.Println(fmt.Sprintf("recv header : %x", header2))

	}

	// result,err := ioutil.ReadAll(conn)
	// var buf [1024]byte
	// readSize, err := conn.Read(buf[0:])
	// chkError(err)
	// remoteAddr := conn.RemoteAddr()
	// fmt.Println("来自远程ip:", remoteAddr, " 的消息:", string(buf[0:readSize]))

	// fmt.Println(result)
	// inputReader := bufio.NewReader(os.Stdin)
	// for {
	// 	input, _ := inputReader.ReadString('\n') // 读取用户输入
	// 	inputInfo := strings.Trim(input, "\r\n")
	// 	if strings.ToUpper(inputInfo) == "Q" { // 如果输入q就退出
	// 		return
	// 	}
	// 	_, err = conn.Write([]byte(inputInfo)) // 发送数据
	// 	if err != nil {
	// 		return
	// 	}
	// 	buf := [512]byte{}
	// 	n, err := conn.Read(buf[:])
	// 	if err != nil {
	// 		fmt.Println("recv failed, err:", err)
	// 		return
	// 	}
	// 	fmt.Println(string(buf[:n]))
	// }
}
