package main

import (
	"bytes"
	"fmt"
	"time"
	"os/exec"
	"io"
	"log"
	"net"
	"strings"
)

var allocate_server = "118.31.2.168:1821"
var dev_server = "47.98.176.85:11822"
var mac = "D8380DDBCE80"
var mac2 = "d8:38:0d:d8:ce:80"
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

	// log.Printf("data: %x\n", oneMessage)
	log.Println("CMD_DEV_ENCRYPT_Q")

	// // defer conn.Close() // 关闭连接
	_, err := conn.Write([]byte(oneMessage)) // 发送数据
	chkError(err)
}

func cmd_dev_encrypt_a(conn *net.TCPConn) (header []byte) {
	// 接收服务器对设备端发起的认证响应数据
	header = make([]byte, 52)
	for {
		// deHead := make([]byte, 52)
		// log.Println(fmt.Sprintf("recv header : %x", header))
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			log.Println("recv failed. ", err)
		} else {
			// log.Println(fmt.Sprintf("cmd_dev_encrypt_a : %x", header))
			log.Println("CMD_DEV_ENCRYPT_A")
			break

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

	// fmt.Printf("tmpmsg: %x\n", tmpmsg)
	log.Println("CMD_DEV_ENCRYPT_K")
	_, err := conn.Write([]byte(tmpmsg)) // 发送数据
	chkError(err)

}

func cmd_dev_encrypt_l(conn *net.TCPConn) {
	// 服务器发给设备端，告诉设备端授权认证成功。
	header2 := make([]byte, 45)
	for {
		// deHead := make([]byte, 52)
		_, err2 := io.ReadFull(conn, header2[:])
		if err2 != nil {
			log.Println("recv failed. ", err2)
		}

		if header2[0] != 0 {
			// log.Println(fmt.Sprintf("recv header : %x", header2))
			log.Println("CMD_DEV_ENCRYPT_L")
			break
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
	// log.Printf("allocate_sn_msg: %02x\n", allocate_sn_msg)
	log.Println("CMD_DEV_ALLOCATE_SN_Q")

	_, err := conn.Write([]byte(allocate_sn_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_allocate_sn_a(conn *net.TCPConn) (allocate_sn_data []byte){
	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	allocate_sn_data = make([]byte, 42)
	for {
		// deHead := make([]byte, 52)
		_, err := io.ReadFull(conn, allocate_sn_data[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if allocate_sn_data[0] != 0 {
			sn := fmt.Sprintf("%s", allocate_sn_data)
			if strings.Contains(sn, "IPCOM") {
				// log.Println(fmt.Sprintf("recv SN : %s", sn))
				log.Println("CMD_DEV_ALLOCATE_SN_A")
				break
			}
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

	// log.Printf("sn_auth_q_msg: % 02x\n", sn_auth_msg)
	log.Println("CMD_DEV_SN_AUTH_Q")
	_, err := conn.Write([]byte(sn_auth_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_sn_auth_a(conn *net.TCPConn) (sn_auth_randstr []byte) {
	//  CMD_DEV_ALLOCATE_SN_A ：服务器发送分配的sn给设备。
	sn_auth_randstr = make([]byte, 52)
	for {
		_, err := io.ReadFull(conn, sn_auth_randstr[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if sn_auth_randstr[0] != 0 {
			// log.Println(fmt.Sprintf("recv sn auth randstr: % 02x", sn_auth_randstr))
			log.Println("CMD_DEV_SN_AUTH_A")
			break
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

	// fmt.Printf("sn_auth_msg: %x\n", sn_auth_msg)
	log.Println("CMD_DEV_SN_AUTH_K")
	_, err := conn.Write([]byte(sn_auth_msg)) // 发送数据
	chkError(err)

}


func cmd_dev_sn_auth_l(conn *net.TCPConn) {
	// 服务器发给设备端，告诉设备端授权认证成功。
	sn_auth_data := make([]byte, 45)
	for {
		// deHead := make([]byte, 52)
		_, err := io.ReadFull(conn, sn_auth_data[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if sn_auth_data[0] != 0 {
			// log.Println(fmt.Sprintf("recv sn auth data : %x", sn_auth_data))
			log.Println("CMD_DEV_SN_AUTH_L")
			break
		}
	}
}

func cmd_where_server_q(conn *net.TCPConn) {
	// 设备端询问设备服务器位置
	where_server_msg := []byte{0x24, 0x0, 0x06, 0x0, 0x0, 0xd1, 0x0, 0x0, 0x04, 0x0d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	_, err := conn.Write([]byte(where_server_msg)) // 发送数据
	chkError(err)
	log.Println("CMD_WHERE_SERVER_Q")
}

func cmd_where_server_a(conn *net.TCPConn) {
// 服务器把设备服务器的位置回复给设备端
	where_server_data := make([]byte, 30)
	for {
		// deHead := make([]byte, 52)
		_, err := io.ReadFull(conn, where_server_data[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if where_server_data[0] != 0 {
			// log.Println(fmt.Sprintf("recv where server data : %x", where_server_data))
			log.Printf("CMD_WHERE_SERVER_A: %s", where_server_data)
			break
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

	// fmt.Printf("cloud_id_msg: % 02x\n", cloud_id_msg)
	log.Printf("CMD_DEV_CLOUD_ID_A: %s", cloud_id_msg)
	_, err := conn.Write([]byte(cloud_id_msg)) // 发送数据
	chkError(err)
}

func cmd_dev_cloud_id_q(conn *net.TCPConn) {
	cloud_id_data := make([]byte, 48)
	for {
		// deHead := make([]byte, 52)
		_, err := io.ReadFull(conn, cloud_id_data[:])
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if cloud_id_data[0] != 0 {
			// log.Println(fmt.Sprintf("recv cloud bind data: %x", cloud_id_data))
			log.Printf("CMD_DEV_CLOUD_ID_Q: %s", cloud_id_data)
			break
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
	
	
	// fmt.Printf("cloud_bind_msg: % 02x\n", cloud_bind_msg)
	log.Printf("CMD_DEV_CLOUD_BIND_A: %s", cloud_bind_msg)
	_, err := conn.Write([]byte(cloud_bind_msg)) // 发送数据
	chkError(err)	
}


func cmd_dev_cloud_bind_q(conn *net.TCPConn, sn []byte) {
	cloud_bind_data := make([]byte, 219)
	for {
		_, err := io.ReadFull(conn, cloud_bind_data)
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if cloud_bind_data[0] != 0 {
			bind_data := fmt.Sprintf("%s", cloud_bind_data)
			sn_asci := fmt.Sprintf("%s", sn)
			if strings.Contains(bind_data, sn_asci) {
				// log.Println(fmt.Sprintf("recv cloud bind data: %s", bind_data))
				log.Printf("CMD_DEV_CLOUD_BIND_Q: %s", bind_data)
				break
			}
		}
	}
}

func cmd_dev_time_q(conn *net.TCPConn) {
	// 服务器下发上报时间间隔及次数
	dev_time_data := make([]byte, 47)
	for {
		_, err := io.ReadFull(conn, dev_time_data)
		if err != nil {
			log.Println("recv failed. ", err)
		}

		if dev_time_data[0] != 0 {
			time_data := fmt.Sprintf("%s", dev_time_data)
			if strings.Contains(time_data, "repeat_time") {
				// log.Println(fmt.Sprintf("recv time value data: %s", time_data))
				log.Printf("CMD_DEV_TIME_Q: %s", time_data)
				break
			}
		}
	}
}

func cmd_node_status_upload_devinfo(conn *net.TCPConn) {
	// 维链
	node_status_data := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x5b, 0x0, 0x0, 0x03, 0x02, 0x0, 0x0, 0x0, 0x0, 0x02, 0x36}
	
	node_status_data = append(node_status_data, []byte(`{"dev_info":{"mode":"W36AP","soft_ver":"V2.0.0.7(7924)","mac":"d8:38:0d:db:ce:80","manage_ip":"192.168.4.101","hard_ver":"V2.0","manage_mode":2,"dev_type":"ap"},"run_status":{"cpu_info":5,"mem_info":82,"run_time":"184307","front_dev":{"ip":"","mac":"","self_port":"lan","sn":"","port":"lan"},"down_rate":"40.00","up_rate":"32.00","user_num":0},"ap_status":{"rf_rule":[{"channel":9,"bindwidth":20,"radioflag":9,"power":18,"rssi":-100,"radioenable":1}, {"channel":149,"bindwidth":80,"radioflag":0,"power":17,"rssi":-100,"radioenable":1}]},"user_list":[],"resp_code":0}`)...)

	
	// fmt.Printf("node status data: %s\n", node_status_data)
	log.Println("CMD_NODE_STATUS_UPLOAD_DEVINFO")
	
	_, err := conn.Write([]byte(node_status_data)) // 发送数据
	chkError(err)
}

func cmd_node_status_upload_wireless(conn *net.TCPConn) {
	// 维链
	node_status_data := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x5d, 0x0, 0x0, 0x03, 0x06, 0x0, 0x0, 0x0, 0x0, 0x01, 0x14}
	
	node_status_data = append(node_status_data, []byte(`{"wireless":{"timestamp":0,"radio_optimiza_config":{"rf_rule":[{"channel":9,"power":18,"rssi":-90,"radioenable":1}, {"channel":149,"power":17,"rssi":-90,"radioenable":1}]}},"maint":{"close_reboot":0,"timestamp":0,"mainetmode":2,"cycle_restart":{"timeval":1440}},"resp_code":0}`)...)

	
	// fmt.Printf("node status data: %s\n", node_status_data)
	log.Println("CMD_NODE_STATUS_UPLOAD_Wireless")
	_, err := conn.Write([]byte(node_status_data)) // 发送数据
	chkError(err)
}



func cmd_node_status_upload_syslog(conn *net.TCPConn) {
	// 上报系统日志
	node_status_data := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x5e, 0x0, 0x0, 0x09, 0x24, 0x0, 0x0, 0x0, 0x0, 0x0c, 0xbd}
	
	node_status_data = append(node_status_data, []byte(`{"sys_log":[{"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-12 22:01:09","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.236) ","time":"2021-08-12 22:01:09","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_DISCOVER ","time":"2021-08-13 08:42:18","event_type":"LAN DHCP"}, {"event":"DHCP_OFFER received from  (192.168.5.1)","time":"2021-08-13 08:42:22","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_REQUEST for (192.168.5.233)","time":"2021-08-13 08:42:22","event_type":"LAN DHCP"}, {"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-13 08:42:22","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.233) ","time":"2021-08-13 08:42:22","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_DISCOVER ","time":"2021-08-13 09:01:24","event_type":"LAN DHCP"}, {"event":"DHCP_OFFER received from  (192.168.5.1)","time":"2021-08-13 09:01:27","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_REQUEST for (192.168.5.234)","time":"2021-08-13 09:01:27","event_type":"LAN DHCP"}, {"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-13 09:01:28","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.234) ","time":"2021-08-13 09:01:30","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_DISCOVER ","time":"2021-08-13 09:54:27","event_type":"LAN DHCP"}, {"event":"DHCP_OFFER received from  (192.168.5.1)","time":"2021-08-13 09:54:31","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_REQUEST for (192.168.5.235)","time":"2021-08-13 09:54:31","event_type":"LAN DHCP"}, {"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-13 09:54:31","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.235) ","time":"2021-08-13 09:54:31","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_DISCOVER ","time":"2021-08-13 16:39:38","event_type":"LAN DHCP"}, {"event":"DHCP_OFFER received from  (192.168.5.1)","time":"2021-08-13 16:39:41","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_REQUEST for (192.168.5.236)","time":"2021-08-13 16:39:41","event_type":"LAN DHCP"}, {"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-13 16:39:41","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.236) ","time":"2021-08-13 16:39:43","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_DISCOVER ","time":"2021-08-13 17:23:13","event_type":"LAN DHCP"}, {"event":"DHCP_OFFER received from  (192.168.5.1)","time":"2021-08-13 17:23:17","event_type":"LAN DHCP"}, {"event":"Broadcasting DHCP_REQUEST for (192.168.5.237)","time":"2021-08-13 17:23:17","event_type":"LAN DHCP"}, {"event":"DHCP_ACK received from  (192.168.5.1)","time":"2021-08-13 17:23:17","event_type":"LAN DHCP"}, {"event":"Get Client IP Address (192.168.5.237) ","time":"2021-08-13 17:23:17","event_type":"LAN DHCP"}, {"event":"web 192.168.5.245 login","time":"2021-08-13 17:30:12","event_type":"System"}, {"event":" check network  success","time":"2021-08-13 17:32:32","event_type":"System"}, {"event":"Sync time success!","time":"2021-08-13 17:32:34","event_type":"System"}, {"event":"AP enter in discovery state.","time":"2021-08-13 17:32:34","event_type":"System"}, {"event":"Sync time success!","time":"2021-08-13 17:32:56","event_type":"System"}]}`)...)

	// 拆分为3个包发送
	block_size := 1404	
	data_len := len(node_status_data)
	block_num := data_len/block_size
	// block_rem := data_len%block_size

	log.Println("CMD_NODE_STATUS_UPLOAD_System")

	for i := 0; i <= block_num; i++ {
		var block_data []byte
		if i < block_num {
			block_data = node_status_data[block_size*i:block_size*(i+1)]
		} else {
			block_data = node_status_data[block_size*block_num:data_len]
		}	

		log.Printf("length of data %d: %d\n", i, len(block_data))
		// fmt.Printf("block_data %d: %s\n", i, block_data)
		
		_, err := conn.Write([]byte(block_data)) // 发送数据
		chkError(err)
	}
	// fmt.Printf("node status data: %s\n", node_status_data)
	// fmt.Printf("node status data: %d\n", len(node_status_data))
	

}

func MessageReceive(conn *net.TCPConn, info string) {
	header := make([]byte, 10)
	for {
		_, err2 := io.ReadFull(conn, header[:])
		if err2 != nil {
			log.Println("recv failed. ", err2)
		} else {
			log.Println(info)
			break
		}
	}
}


func keep_connection(conn *net.TCPConn) {
	// 上传设备信息
	for {
		time.Sleep(15 * time.Second)

		cmd_node_status_upload_devinfo(conn)

		MessageReceive(conn, "dev info")

		cmd_node_status_upload_wireless(conn)
		MessageReceive(conn, "wireless info")

	}

}


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

	/* ************************** 设备接入请求 ******************************** */

	cmd_dev_cloud_id_a(conn) // 发送cloud id、project_id 和 url

	cmd_dev_cloud_id_q(conn) // 设备服务器回应

	cmd_dev_cloud_bind_a(conn, sn) // 设备接入请求：发送devType、devSn、devMesh、cloud id、mac、model

	// 登录IMS平台统一加入设备
	// ............

	cmd_dev_cloud_bind_q(conn, sn) // 等待设备服务器回应，同意加入后，服务器下发project_id

	// cmd_dev_time_q(conn) // 服务器下发设备上报时间参数

	
	// 上传设备信息
	cmd_node_status_upload_devinfo(conn) // 上传设备信息dev_info、设备运行状态run_status、ap状态ap_status和用户列表信息user_list



	MessageReceive(conn, "########## 1. upload dev info success! ##########")

	cmd_node_status_upload_wireless(conn) // 上传设备无线信息


	MessageReceive(conn, "########## 2. upload wireless info success! ##########")

	
	cmd_node_status_upload_syslog(conn) // 上传系统日志

	MessageReceive(conn, "########## 3. upload syslog success! ##########")

	/* ************************** 维链 ******************************** */

	keep_connection(conn)

	// for {

	// 	_, err := conn.Write([]byte(node_status_data)) // 发送数据
	// 	chkError(err)
	// 	time.Sleep(15 * time.Second)
	// 	defer conn.Close()  // 关闭连接
	// 	conn = connect_server(dev_server)
	// }	

	for {
		time.Sleep(1 * time.Second)
	}
	
}
