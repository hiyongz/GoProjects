package main

import (
	"bytes"
	"fmt"
	"time"
	"os/exec"
	"io"
	"log"
	"net"
)

var allocate_server = "118.31.2.168:1821"
var dev_server = "47.98.176.85:11822"
var mac = "D8380DDBCE90"
var version = "V2.0.0.7(7924)"
var pruduct = "W36AP"
var company = "IP-COM"
var model = "ap"
var cloud_id = "7d39daac23b51e13d0bf293b6b724a1c"
var mac_uint8 = []byte(mac)
var version_uint8 = []byte(version)
var pruduct_uint8 = []byte(pruduct)
var company_uint8 = []byte(company)

func chkError(err error) {
	if err != nil {
		fmt.Println("err :", err)
	}
}

func connect_server(server string) (conn *net.TCPConn) {
	// TCP 连接服务器
	// tcpAddr, _ := net.ResolveTCPAddr("tcp","ims.ip-com.com.cn:11822") // 获取一个TCPAddr
	// tcpAddr, _ := net.ResolveTCPAddr("tcp","47.98.176.85:11822") // 获取一个TCPAddr
	tcpAddr, _ := net.ResolveTCPAddr("tcp", server) // 获取一个TCPAddr
	fmt.Println("tcpAddr: ", tcpAddr)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("err :", err)
		return
	} else {
		fmt.Println("connect successful")
		fmt.Println(conn.LocalAddr().String() + " : Client connected!")
	}
	return conn
}

func ExtractSN(data []byte) (sn []byte) {
	// 从TLV中提取SN
	sn = data[20 : len(data)-1]
	return sn
}

func UpdateMac(mac string) {
	// 替换MAC地址
	// mac = "char devmac[] = {\"D8380DDBCE90\"};"
	mac_str := fmt.Sprintf("char devmac[] = {\"%s\"};", mac)
	mac_sed := fmt.Sprintf("s/char\\ devmac\\[\\].*$/%s/", mac_str)
	cmd_sed_mac := fmt.Sprintf("sed -i '%s' dev_encrypt.c", mac_sed)
	log.Printf("cmd_sed: %s", cmd_sed_mac)
	cmd := exec.Command("bash", "-c", cmd_sed_mac)
	_, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to update mac address: %v", err)
	}
}

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

func UpdateSN(sn []byte) {
	// 替换SN
	sn_asci := fmt.Sprintf("%s", sn)
	UpdateSNflag(1) // 设置SN标记为1，表示需要计算SN的aes值
	sn_str := fmt.Sprintf("char sn[] = {\"%s\"};", sn_asci)
	sn_sed := fmt.Sprintf("s/char\\ sn\\[\\].*$/%s/", sn_str)
	cmd_sed_sn := fmt.Sprintf("sed -i '%s' dev_encrypt.c", sn_sed)
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
	cmd_sn_flag := fmt.Sprintf("sed -i '%s' dev_encrypt.c", sn_flag_sed)
	log.Printf("cmd_sed: %s", cmd_sn_flag)
	cmd := exec.Command("bash", "-c", cmd_sn_flag)
	_, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to update SN flag: %v", err)
	}
}

func CalcAesMd5() (md5 []byte) {
	// 重新编译
	cmd_build := "gcc dev_encrypt.c -o encrypt"
	_, err := exec.Command("bash", "-c", cmd_build).Output()
	if err != nil {
		log.Fatalf("failed to build: %v", err)
	}

	// 计算AES的MD5值：./encrypt
	md5, err = exec.Command("./encrypt").Output()
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}

	log.Printf("md5 value: % 02x\n", md5)
	return md5
}

func cmd_dev_encrypt_q(conn *net.TCPConn) {
	// var outBuf = make([]byte, 18)
	outBuf := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x04, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x02}

	oneMessage := append(outBuf, byte(0))
	oneMessage = append(oneMessage, byte(12))
	oneMessage = append(oneMessage, mac_uint8...)
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(3))
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(len(version)))
	oneMessage = append(oneMessage, version_uint8...)
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(19))
	oneMessage = append(oneMessage, byte(0))
	oneMessage = append(oneMessage, byte(len(pruduct)))
	oneMessage = append(oneMessage, pruduct_uint8...)

	fmt.Printf("data: %x\n", oneMessage)

	// // defer conn.Close() // 关闭连接
	_, err := conn.Write([]byte(oneMessage)) // 发送数据
	chkError(err)
}

func cmd_dev_encrypt_a(conn *net.TCPConn) (header []byte) {
	// 接收服务器对设备端发起的认证响应数据
	header = make([]byte, 52)
Loop:
	for {
		// deHead := make([]byte, 52)
		// log.Println(fmt.Sprintf("recv header : %x", header))
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			log.Println("recv failed. ", err)
		} else {
			log.Println(fmt.Sprintf("cmd_dev_encrypt_a : %x", header))
			log.Println(header)
			break Loop

		}
	}
	return header
}


func cmd_dev_encrypt_k(conn *net.TCPConn, md5 []byte) {
	// 设备端发AES密钥的md5给服务器
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
	_, err := conn.Write([]byte(tmpmsg)) // 发送数据
	chkError(err)

}

func cmd_dev_encrypt_l(conn *net.TCPConn) {
	// 服务器发给设备端，告诉设备端授权认证成功。
	header2 := make([]byte, 45)
	Loop2:
		for {
			// deHead := make([]byte, 52)
			_, err2 := io.ReadFull(conn, header2[:])
			if err2 != nil {
				log.Println("recv failed. ", err2)
			}
	
			if header2[0] != 0 {
				log.Println(fmt.Sprintf("recv header : %x", header2))
				break Loop2
			}
		}
}

func cmd_dev_allocate_sn_q(conn *net.TCPConn) {
	// 设备端向服务器请求分配sn : CMD_DEV_ALLOCATE_SN_Q
	allocate_sn_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0xf4, 0x0, 0x0, 0x04, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13}
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(18))
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(len(company)))
	allocate_sn_msg = append(allocate_sn_msg, company_uint8...)
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(19))
	allocate_sn_msg = append(allocate_sn_msg, byte(0))
	allocate_sn_msg = append(allocate_sn_msg, byte(len(pruduct)))
	pruduct_uint8 = []byte(pruduct)
	allocate_sn_msg = append(allocate_sn_msg, pruduct_uint8...)
	log.Printf("allocate_sn_msg: %02x\n", allocate_sn_msg)

	_, err := conn.Write([]byte(allocate_sn_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_allocate_sn_a(conn *net.TCPConn) (allocate_sn_data []byte){
	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	allocate_sn_data = make([]byte, 42)
Loop3:
	for {
		// deHead := make([]byte, 52)
		_, err := io.ReadFull(conn, allocate_sn_data[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if allocate_sn_data[0] != 0 {
			log.Println(fmt.Sprintf("recv SN : %x", allocate_sn_data))
			break Loop3
		}

	}
	return allocate_sn_data
}

func cmd_dev_sn_auth_q(conn *net.TCPConn, sn []byte) {
	// CMD_DEV_SN_AUTH_Q：设备端向服务器发起设备sn认证请求。
	// sn := ExtractSN(sn_data) // 提取SN
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
	sn_auth_msg = append(sn_auth_msg, version_uint8...)
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(19))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(len(pruduct)))
	sn_auth_msg = append(sn_auth_msg, pruduct_uint8...)

	log.Printf("sn_auth_q_msg: % 02x\n", sn_auth_msg)

	_, err := conn.Write([]byte(sn_auth_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_sn_auth_a(conn *net.TCPConn) (sn_auth_randstr []byte) {
	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	sn_auth_randstr = make([]byte, 52)
Loop4:
	for {
		_, err := io.ReadFull(conn, sn_auth_randstr[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if sn_auth_randstr[0] != 0 {
			// log.Println(fmt.Sprintf("recv sn auth randstr: % 02x", sn_auth_randstr))
			break Loop4
		}
	}
	return sn_auth_randstr
}


func cmd_dev_sn_auth_k(conn *net.TCPConn, md5 []byte) {
	// 设备端携带AES密钥的md5给服务器校验。
	// var tmpmsg = make([]byte, 15)
	sn_auth_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x0, 0x19, 0x0, 0x0, 0x04, 0x2c, 0x0, 0x0, 0x0, 0x0, 0x0}
	sn_auth_msg = append(sn_auth_msg, byte(len(md5)+4))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(6))
	sn_auth_msg = append(sn_auth_msg, byte(0))
	sn_auth_msg = append(sn_auth_msg, byte(len(md5)))
	for index, _ := range md5 {
		sn_auth_msg = append(sn_auth_msg, md5[index])
	}

	fmt.Printf("sn_auth_msg: %x\n", sn_auth_msg)
	_, err := conn.Write([]byte(sn_auth_msg)) // 发送数据
	chkError(err)

}


func cmd_dev_sn_auth_l(conn *net.TCPConn) {
	// 服务器发给设备端，告诉设备端授权认证成功。
	sn_auth_data := make([]byte, 45)
	Loop:
		for {
			// deHead := make([]byte, 52)
			_, err := io.ReadFull(conn, sn_auth_data[:])
			if err != nil {
				log.Println("recv failed. ", err)
			}
	
			if sn_auth_data[0] != 0 {
				log.Println(fmt.Sprintf("recv sn auth data : %x", sn_auth_data))
				break Loop
			}
		}
}

func cmd_where_server_q(conn *net.TCPConn) {
	// 设备端询问设备服务器位置
	where_server_msg := []byte{0x24, 0x0, 0x06, 0x0, 0x0, 0xd1, 0x0, 0x0, 0x04, 0x0d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	_, err := conn.Write([]byte(where_server_msg)) // 发送数据
	chkError(err)
}

func cmd_where_server_a(conn *net.TCPConn) {
// 服务器把设备服务器的位置回复给设备端
	where_server_data := make([]byte, 30)
	Loop:
		for {
			// deHead := make([]byte, 52)
			_, err := io.ReadFull(conn, where_server_data[:])
			if err != nil {
				log.Println("recv failed. ", err)
			}

			if where_server_data[0] != 0 {
				log.Println(fmt.Sprintf("recv where server data : %x", where_server_data))
				break Loop
			}
		}
}

func cmd_account_info_q(conn *net.TCPConn) {
	// 路由器向服务器请求当前管理路由器的云账号信息。
	
}

func cmd_dev_cloud_id_a(conn *net.TCPConn) {
	// AP向设备服务器发送cloud_id
	cloud_id_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x61, 0x0, 0x0, 0x04, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0, 0x51, 0x7b,0x0a,0x09}
	dev_cloud_id := "\"cloud_id\":"
	dev_project_id := "\"project_id\":"
	dev_url := "\"url\":"

	cloud_id_msg = append(cloud_id_msg, []byte(dev_cloud_id)...)
	cloud_id_msg = append(cloud_id_msg, []byte{0x09,0x22}...)
	cloud_id_msg = append(cloud_id_msg, []byte(cloud_id)...)
	cloud_id_msg = append(cloud_id_msg, []byte{0x22,0x2c,0x0a,0x09}...)
    
	cloud_id_msg = append(cloud_id_msg, []byte(dev_project_id)...)
	cloud_id_msg = append(cloud_id_msg, []byte{0x09,0x30,0x2c,0x0a,0x09}...)
	
	cloud_id_msg = append(cloud_id_msg, []byte(dev_url)...)
	cloud_id_msg = append(cloud_id_msg, []byte{0x09,0x22,0x22,0x0a,0x7d}...)

	fmt.Printf("cloud_id_msg: % 02x\n", cloud_id_msg)
	_, err := conn.Write([]byte(cloud_id_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_cloud_id_q(conn *net.TCPConn) {
	cloud_id_data := make([]byte, 48)
	Loop:
		for {
			// deHead := make([]byte, 52)
			_, err := io.ReadFull(conn, cloud_id_data[:])
			if err != nil {
				log.Println("recv failed. ", err)

			}

			if cloud_id_data[0] != 0 {
				log.Println(fmt.Sprintf("recv cloud bind data: %x", cloud_id_data))
				break Loop
			}
		}
}


func cmd_dev_cloud_bind_a(conn *net.TCPConn, sn []byte) {
	// AP向设备服务器发送cloud_id
	cloud_bind_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x67, 0x0, 0x0, 0x03, 0x0c, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa3, 0x7b}
	dev_type := "\"devType\":"
	dev_sn := "\"devSn\":"
	devmessage3 := "\"devMesh\":"
	dev_cloud_id := "\"cloud_id\":"
	dev_mac := "\"mac\":"
	dev_model := "\"model\":"

	cloud_bind_msg = append(cloud_bind_msg, []byte{0x0a,0x09}...)	

	cloud_bind_msg = append(cloud_bind_msg, []byte(dev_type)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, pruduct_uint8...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)	

	cloud_bind_msg = append(cloud_bind_msg, []byte(dev_sn)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, sn...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)

	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage3)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22,0x22,0x2c,0x0a,0x09}...)

	cloud_bind_msg = append(cloud_bind_msg, []byte(dev_cloud_id)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(cloud_id)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)

	cloud_bind_msg = append(cloud_bind_msg, []byte(dev_mac)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, mac_uint8...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)

	cloud_bind_msg = append(cloud_bind_msg, []byte(dev_model)...)	
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(model)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x0a,0x7d}...)
	
	
	fmt.Printf("cloud_bind_msg: % 02x\n", cloud_bind_msg)
	_, err := conn.Write([]byte(cloud_bind_msg)) // 发送数据
	chkError(err)	
}


// func cmd_dev_cloud_bind_q(conn *net.TCPConn) {
// 	repeat_time_data := make([]byte, 47)
// 	Loop:
// 		for {
// 			// deHead := make([]byte, 52)
// 			_, err := io.ReadFull(conn, repeat_time_data[:])
// 			if err != nil {
// 				log.Println("recv failed. ", err)
// 			}

// 			if repeat_time_data[0] != 0 {
// 				log.Println(fmt.Sprintf("recv repeat time data: %x", repeat_time_data))
// 				break Loop
// 			}
// 		}
// }


func main() {

	conn := connect_server(allocate_server)

	log.Printf("conn: %T\n", conn)

	cmd_dev_encrypt_q(conn)                // 设备端向服务器发起认证请求
	tlv_randstr := cmd_dev_encrypt_a(conn) // 服务器发起的认证进行响应: 下发一个32位的随机字符串

	// 更新随机字符串和MAC地址，计算MD5值
	tlvdata := tlv_randstr[16:]
	log.Printf("type of tlvdata: %T", tlvdata)
	UpdateRandstr(tlvdata)
	UpdateMac(mac)

	UpdateSNflag(0)
	md5 := CalcAesMd5()

	cmd_dev_encrypt_k(conn, md5)
	cmd_dev_encrypt_l(conn)
	

	// 设备端向服务器请求分配sn : CMD_DEV_ALLOCATE_SN_Q
	cmd_dev_allocate_sn_q(conn)

	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	sn_data := cmd_dev_allocate_sn_a(conn)	
	sn := ExtractSN(sn_data)

	conn.Close()  // 关闭连接

	// 再次建立连接
	conn = connect_server(allocate_server)

	/* **************************开始SN认证******************************** */
	// CMD_DEV_SN_AUTH_Q：设备端向服务器发起设备sn认证请求。
	cmd_dev_sn_auth_q(conn,sn)

	//  CMD_DEV_SN_AUTH_A ：服务器对设备端发起的认证进行响应。
	sn_auth_randstr := cmd_dev_sn_auth_a(conn)
	log.Println(fmt.Sprintf("recv sn auth randstr: % 02x", sn_auth_randstr))

	// 更新随机字符串、MAC地址和SN，计算MD5值
	sn_tlvdata := sn_auth_randstr[16:]
	log.Printf("type of sn_tlvdata: %T", sn_tlvdata)
	UpdateRandstr(sn_tlvdata)
	UpdateMac(mac)
	UpdateSN(sn)
	sn_md5 := CalcAesMd5()

	// 设备端携带AES密钥的md5给服务器校验: 用sn、mac、version和randstr生成aes后的md5值
	cmd_dev_sn_auth_k(conn, sn_md5)
	// 设备端sn认证成功
	cmd_dev_sn_auth_l(conn)

	// 设备端询问设备服务器位置
	cmd_where_server_q(conn)

	// 服务器把设备服务器的位置回复给设备端
	cmd_where_server_a(conn)
	conn.Close()  // 关闭连接

    /* **************************向设备服务器发起SN认证******************************** */

	conn = connect_server(dev_server)  // 连接设备服务器

	// CMD_DEV_SN_AUTH_Q：设备端向设备服务器发起设备sn认证请求。
	cmd_dev_sn_auth_q(conn,sn)

	//  CMD_DEV_SN_AUTH_A ：设备服务器对设备端发起的认证进行响应。
	sn_auth_randstr = cmd_dev_sn_auth_a(conn)
	log.Println(fmt.Sprintf("recv sn auth randstr: % 02x", sn_auth_randstr))

	// 更新随机字符串、MAC地址和SN，计算MD5值
	sn_tlvdata = sn_auth_randstr[16:]
	log.Printf("type of sn_tlvdata: %T", sn_tlvdata)
	UpdateRandstr(sn_tlvdata)
	UpdateMac(mac)
	UpdateSN(sn)
	sn_md5 = CalcAesMd5()

	// 设备端携带AES密钥的md5给设备服务器校验: 用sn、mac、version和randstr生成aes后的md5值
	cmd_dev_sn_auth_k(conn, sn_md5)
	// 设备端sn认证成功
	cmd_dev_sn_auth_l(conn)

	cmd_dev_cloud_id_a(conn) // 发送cloud id、project_id

	cmd_dev_cloud_id_q(conn) // 设备服务器回应

	cmd_dev_cloud_bind_a(conn, sn) // 发送devType、devSn、devMesh、cloud id、mac、model

	// cmd_dev_cloud_bind_q(conn) // 设备服务器回应

	time.Sleep(30 * time.Second)

}
