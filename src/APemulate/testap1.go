package main

import (
	// "bufio"
	// "crypto/aes"
	"bytes"
	"fmt"
	"os/exec"

	// "os/exec"

	// "strconv"

	// "os/exec"

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

func ExtractSN(data []byte) (sn []byte) {
	// 从TLV中提取SN
	sn = data[20 : len(data)-1]
	return sn
}

func UpdateMac(mac string) {
	// 替换MAC地址
	// mac = "char devmac[] = {\"D8380DDBCE90\"};"
	mac = fmt.Sprintf("char devmac[] = {\"%s\"};", mac)
	mac_sed := fmt.Sprintf("s/char\\ devmac\\[\\].*$/%s/", mac)
	cmd_sed_mac := fmt.Sprintf("sed -i '%s' test_devencrypt.c", mac_sed)
	log.Printf("cmd_sed: %s", cmd_sed_mac)
	cmd := exec.Command("bash", "-c", cmd_sed_mac)
	_, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to update mac address: %v", err)
	}
}

func UpdateRandstr(tlvdata []byte) {
	// 替换随机字符串
	randstr := tlvdata[16:]
	var buffer bytes.Buffer
	for index := range randstr {
		hex_data := fmt.Sprintf("%02x", randstr[index])
		if index == 0 {
			buffer.WriteString("char buff[] = {")
		}
		buffer.WriteString("0x")
		buffer.WriteString(hex_data)

		if index != len(randstr)-1 {
			buffer.WriteString(",")
		} else {
			buffer.WriteString("};")
		}

	}
	randstrs := buffer.String()

	randstr_sed := fmt.Sprintf("s/char\\ buff\\[\\].*$/%s/", randstrs)
	cmd_sed_randstr := fmt.Sprintf("sed -i '%s' test_devencrypt.c", randstr_sed)
	log.Printf("cmd_sed: %s", cmd_sed_randstr)
	_, err := exec.Command("bash", "-c", cmd_sed_randstr).Output()
	if err != nil {
		log.Fatalf("failed to update randstr: %v", err)
	}
}

func UpdateSN(sn []byte) {
	// 替换SN
	sn_asci := fmt.Sprintf("%s", sn)
	UpdateSNflag(1) // 设置SN标记为1，表示需要计算SN的aes值
	sn_str := fmt.Sprintf("char sn[] = {\"%s\"};", sn_asci)
	sn_sed := fmt.Sprintf("s/char\\ sn\\[\\].*$/%s/", sn_str)
	cmd_sed_sn := fmt.Sprintf("sed -i '%s' test_devencrypt.c", sn_sed)
	log.Printf("cmd_sed: %s", cmd_sed_sn)
	cmd := exec.Command("bash", "-c", cmd_sed_sn)
	_, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to update SN: %v", err)
	}
}

func UpdateSNflag(flag int) {
	// 设置SN标记

	sn_flag := fmt.Sprintf("int sn_flag = %d;", flag)
	sn_flag_sed := fmt.Sprintf("s/int\\ sn_flag.*$/%s/", sn_flag)
	cmd_sn_flag := fmt.Sprintf("sed -i '%s' test_devencrypt.c", sn_flag_sed)
	log.Printf("cmd_sed: %s", cmd_sn_flag)
	cmd := exec.Command("bash", "-c", cmd_sn_flag)
	_, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to update SN flag: %v", err)
	}
}

func CalcAesMd5() (md5 []byte) {
	// 重新编译
	cmd_build := "gcc test_devencrypt.c -o encrypt"
	_, err := exec.Command("bash", "-c", cmd_build).Output()
	if err != nil {
		log.Fatalf("failed to build: %v", err)
	}

	// 计算AES的MD5值：./encrypt
	md5, err = exec.Command("./encrypt").Output()
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}

	log.Printf("666666666666666\n")
	log.Printf("md5: %s\n", md5)
	log.Printf("md5: %T\n", md5)
	log.Printf("md5: %x\n", md5)
	log.Printf("size of md5: %d\n", len(md5))
	log.Printf("666666666666666\n")
	return md5
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

	// var outBuf = make([]byte, 18)
	outBuf := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x04, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x02}
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

	// 处理随机字符串和MAC地址
	randstr := header[16:]
	log.Printf("type of randstr: %T", randstr)
	mac = "char devmac[] = {\"D8380DDBCE90\"};"

	var buffer bytes.Buffer
	for index := range randstr {
		hex_data := fmt.Sprintf("%02x", randstr[index])
		if index == 0 {
			buffer.WriteString("char buff[] = {")
		}
		buffer.WriteString("0x")
		buffer.WriteString(hex_data)

		if index != len(randstr)-1 {
			buffer.WriteString(",")
		} else {
			buffer.WriteString("};")
		}

	}
	randstrs := buffer.String()

	mac_sed := fmt.Sprintf("s/char\\ devmac\\[\\].*$/%s/", mac)
	cmd_sed_mac := fmt.Sprintf("sed -i '%s' test_devencrypt.c", mac_sed)
	log.Printf("cmd_sed: %s", cmd_sed_mac)
	cmd := exec.Command("bash", "-c", cmd_sed_mac)
	_, err = cmd.Output()
	if err != nil {
		log.Fatalf("failed to update mac address: %v", err)
	}

	randstr_sed := fmt.Sprintf("s/char\\ buff\\[\\].*$/%s/", randstrs)
	cmd_sed_randstr := fmt.Sprintf("sed -i '%s' test_devencrypt.c", randstr_sed)
	log.Printf("cmd_sed: %s", cmd_sed_randstr)
	_, err = exec.Command("bash", "-c", cmd_sed_randstr).Output()
	if err != nil {
		log.Fatalf("failed to update randstr: %v", err)
	}

	// 重新编译
	cmd_build := "gcc test_devencrypt.c -o encrypt"
	_, err = exec.Command("bash", "-c", cmd_build).Output()
	if err != nil {
		log.Fatalf("failed to build: %v", err)
	}

	// 计算AES的MD5值：./encrypt
	md5, err := exec.Command("./encrypt").Output()
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}

	log.Printf("666666666666666\n")
	log.Printf("md5: %s\n", md5)
	log.Printf("md5: %T\n", md5)
	log.Printf("md5: %x\n", md5)
	log.Printf("size of md5: %d\n", len(md5))
	log.Printf("666666666666666\n")

	// dev_auth_k
	// var tmpmsg = make([]byte, 15)
	tmpmsg := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0x1d, 0x0, 0x0, 0x04, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0}
	tmpmsg = append(tmpmsg, byte(len(md5)+4))
	tmpmsg = append(tmpmsg, byte(0))
	tmpmsg = append(tmpmsg, byte(6))
	tmpmsg = append(tmpmsg, byte(0))
	tmpmsg = append(tmpmsg, byte(len(md5)))
	for index, _ := range md5 {
		tmpmsg = append(tmpmsg, md5[index])
	}

	fmt.Printf("tmpmsg: %x\n", tmpmsg)
	_, err = conn.Write([]byte(tmpmsg)) // 发送数据
	chkError(err)

	header2 := make([]byte, 45)
Loop2:
	for {
		// deHead := make([]byte, 52)
		_, err2 := io.ReadFull(conn, header2[:])
		if err != nil {
			log.Println("recv failed. ", err2)
		}

		if header2[0] != 0 {
			log.Println(fmt.Sprintf("recv header : %x", header2))
			break Loop2
		}
	}

	// 设备端向服务器请求分配sn : CMD_DEV_ALLOCATE_SN_Q

	allocate_sn_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0xf4, 0x0, 0x0, 0x04, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13}
	company := "IP-COM"
	pruduct = "W36AP"
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(18))
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(len(company)))
	company_uint8 := []byte(company)
	allocate_sn_msg = append(allocate_sn_msg, company_uint8...)
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(19))
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(len(pruduct)))
	pruduct_uint8 = []byte(pruduct)
	// mac_uint8 := mac
	allocate_sn_msg = append(allocate_sn_msg, pruduct_uint8...)
	log.Printf("allocate_sn_msg: %02x\n", allocate_sn_msg)

	_, err = conn.Write([]byte(allocate_sn_msg)) // 发送数据
	chkError(err)

	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	header3 := make([]byte, 42)
Loop3:
	for {
		// deHead := make([]byte, 52)
		_, err2 := io.ReadFull(conn, header3[:])
		if err != nil {
			log.Println("recv failed. ", err2)
		}

		if header3[0] != 0 {
			log.Println(fmt.Sprintf("recv SN : %x", header3))
			break Loop3
		}
	}

	conn.Close()                                                // 关闭连接
	tcpAddr, _ = net.ResolveTCPAddr("tcp", "118.31.2.168:1821") // 获取一个TCPAddr
	fmt.Println("tcpAddr: ", tcpAddr)
	conn, err = net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("err :", err)
		return
	} else {
		fmt.Println("connect successful")
		fmt.Println(conn.LocalAddr().String() + " : Client connected!")
	}

	// 开始SN认证
	// CMD_DEV_SN_AUTH_Q：设备端向服务器发起设备sn认证请求。
	version = "V2.0.0.7(7924)"
	pruduct = "W36AP"
	sn := ExtractSN(header3) // 提取SN
	log.Printf("type of sn: %T\n", sn)
	log.Printf("sn: %s\n", sn)
	sn_auth_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0x17, 0x0, 0x0, 0x04, 0x2a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x34}
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(1))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(len(sn)))
	sn_auth_msg = append(sn_auth_msg, sn...)
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(3))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(len(version)))
	version_uint8 = []byte(version)
	sn_auth_msg = append(sn_auth_msg, version_uint8...)
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(19))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(len(pruduct)))
	pruduct_uint8 = []byte(pruduct)
	sn_auth_msg = append(sn_auth_msg, pruduct_uint8...)

	log.Printf("sn_auth_msg: %02x\n", sn_auth_msg)

	_, err = conn.Write([]byte(sn_auth_msg)) // 发送数据
	chkError(err)

	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	header4 := make([]byte, 52)
Loop4:
	for {
		_, err2 := io.ReadFull(conn, header4[:])
		if err != nil {
			log.Println("recv failed. ", err2)
		}

		if header4[0] != 0 {
			log.Println(fmt.Sprintf("recv sn auth randstr: %02x", header4))
			break Loop4
		}
	}

}
