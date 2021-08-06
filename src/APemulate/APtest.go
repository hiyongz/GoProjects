package main

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"runtime/pprof"
	"time"

	//"bufio"
	"encoding/json"
	"fmt"
	"io"

	//"io"
	"net"
	"os"
	"strconv"
	"os/exec"
	"golang.org/x/net/ipv4"
	"log"
	"github.com/gin-gonic/gin"
)

var apNum *int
var netInterface *string
//var ipArray []string
type ApDevData struct {
	Index int
	Ip	string
	Mac string
	InterfaceName string
	Manager string
	Key string
	//body []byte
	Conn *net.TCPConn
}

type ScanStr struct {
	Cmd int `json:"cmd"`
	Src int `json:"src"`
	UdpPort int `json:"udp_port"`
}

type BindOrReConnStr struct {
	Cmd 	int 	`json:"cmd"`
	Access	string	`json:"access"`
	Ip		string	`json:"ip"`
	Port	int		`json:"port"`
	Mac 	string	`json:"mac"`
	AcSn  	string	`json:"ac_sn"`
}

var devArray map[int]*ApDevData

var macAddrPre = [8]string{"10:00:00:00:00:","11:00:00:00:00:","12:00:00:00:00:","13:00:00:00:00:","14:00:00:00:00:","15:00:00:00:00:","16:00:00:00:00:","17:00:00:00:00:"}
var ipAddrPre = [8]string{"172.16.10.","172.16.11.","172.16.12.","172.16.13.","172.16.14.","172.16.15.","172.16.16.","172.16.17."}


/*
 * **********************************加密模块*****************************************
 */

func AesEncryptECB(origData []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	//length := (len(origData) - 1 + aes.BlockSize) / aes.BlockSize
	length := (len(origData) - 1 + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	//pad := byte(len(plain) - len(origData))
	//log.Println("解密结果：", string(decrypted))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = 0
	}
	encrypted = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs < len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return encrypted
}
func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))

	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	//log.Println(decrypted)
	//bEnd := searchByteSliceIndex(decrypted, 0)

	return decrypted
	//return decrypted
}
func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// []byte 字节切片 循环查找
func searchByteSliceIndex(bSrc []byte, b byte) int {
	for i := 0; i < len(bSrc); i++ {
		if bSrc[i] == b {
			return i
		}
	}

	return len(bSrc)
}


func ClacMd5(orig_string []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(orig_string)
	cipherStr := md5Ctx.Sum(nil)

	return hex.EncodeToString(cipherStr)
}

/*
 * **********************************加密模块*****************************************
 */

func exeSysCommand(cmdStr string) string {
	cmd := exec.Command("sh", "-c", cmdStr)
	opBytes, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(opBytes)
}

func AddVirtualNetworkCard(apNum int)  {
	ids := apNum / 200
	remain := apNum % 200
	for i := 0; i <= ids; i ++ {
		var times int
		if i != ids {
			times = 201
		}else {
			times = remain
			if remain == 0 {
				return
			}
		}

		for j := 2; j <= times + 1; j++ {
			tempIp := ipAddrPre[i] + strconv.Itoa(j)
			interfaceName := fmt.Sprintf("%s:%d", *netInterface,i * 200 + j - 1)
			//log.Println(tempAddr)
			msg := fmt.Sprintf("ifconfig %s %s netmask 255.255.0.0 up", interfaceName, tempIp)
			log.Println(msg)
			exeSysCommand(msg)
			ap := &ApDevData{
				Ip: tempIp,
				Mac: "",
				InterfaceName: interfaceName,
				Index: i * 200 + j - 1,
				Manager: "",
				Key: "",
				//body: []byte(""),
			}

			devArray[i * 200 + j - 1] = ap
			//ipArray = append(ipArray, tempAddr)
		}
	}
}

func AddVirtualNetworkCard2(apNum int)  {
	ids := apNum / 200
	remain := apNum % 200
	for i := 0; i <= ids; i ++ {
		var times int
		if i != ids {
			times = 201
		}else {
			times = remain
			if remain == 0 {
				return
			}
		}

		for j := 2; j <= times + 1; j++ {
			tempIp := ipAddrPre[i] + strconv.Itoa(j)
			interfaceName := fmt.Sprintf("%s:%d", *netInterface,i * 200 + j - 1)
			//log.Println(tempAddr)
			msg := fmt.Sprintf("ifconfig %s %s netmask 255.255.0.0 up", interfaceName, tempIp)
			log.Println(msg)
			exeSysCommand(msg)
			ap := &ApDevData{
				Ip: tempIp,
				Mac: "",
				InterfaceName: interfaceName,
				Index: i * 200 + j - 1,
				Manager: "",
				Key: "",
				//body: []byte(""),
			}

			devArray[i * 200 + j - 1] = ap
			//ipArray = append(ipArray, tempAddr)
		}
	}
}

func FindDevByMac(mac string) *ApDevData {
	for _, info := range devArray {
		if info.Mac == mac {
			return info
		}
	}

	return nil
}

type ByteBufferChan struct {
	Buffer64   chan []byte
	Buffer128  chan []byte
	Buffer256  chan []byte
	Buffer512  chan []byte
	Buffer1024 chan []byte
	Buffer2048 chan []byte
}

var ByteBuffer ByteBufferChan

func ByteBufferMalloc(length int) []byte {
	var ret []byte
	var buf chan []byte
	var buflen int
	if length <= 64 {
		buf = ByteBuffer.Buffer64
		buflen = 64
	} else if length <= 128 {
		buf = ByteBuffer.Buffer128
		buflen = 128
	} else if length <= 256 {
		buf = ByteBuffer.Buffer256
		buflen = 256
	} else if length <= 512 {
		buf = ByteBuffer.Buffer512
		buflen = 512
	} else if length <= 1024 {
		buf = ByteBuffer.Buffer1024
		buflen = 1024
	} else if length <= 2048 {
		buf = ByteBuffer.Buffer2048
		buflen = 2048
	} else {
		return make([]byte, length)
	}
	select {
	case ret = <-buf:
		return ret[:length]
	default:
		ret = make([]byte, buflen)
		return ret[:length]
	}
}

func MakeTcpPackage(module uint8, cmd uint8, respCode uint16,  length uint32, buf []byte, key []byte) []byte {
	var encLen uint32
	if length % 16 != 0 {
		encLen = uint32(length - (length % 16) + 16)
	}else {
		encLen = uint32(length)
	}
	log.Println(fmt.Sprintf("orginal len :%d, new len : %d", length, encLen))
	
	var outBuf = make([]byte, 16 + encLen)
	outBuf[0] = 0x24
	outBuf[1] = 0x0
	outBuf[2] = 0x6
	outBuf[3] = 0x0
	outBuf[4] = uint8(213 / 256)
	outBuf[5] = uint8(213 % 256)
	outBuf[6] = 0x0
	outBuf[7] = 0x0
	//msg len
	outBuf[8] = module
	outBuf[9] = cmd


	outBuf[10] = uint8(respCode / 256)
	outBuf[11] = uint8(respCode / 256)

	outBuf[12] = uint8((length & 0xff000000) >> 24)
	outBuf[13] = uint8((length & 0x00ff0000) >> 16)
	outBuf[14] = uint8((length & 0x0000ff00) >> 8)
	outBuf[15] = uint8(length & 0x000000ff)

	if encLen > 0 {
		copy(outBuf[16:], buf)
	}
	//加密
	outBuf = AesEncryptECB(outBuf, key)
	return outBuf
}

func execTcp(module uint8 , cmd uint8, conn *net.TCPConn, dev *ApDevData) error {
	log.Println(fmt.Sprintf("[exec tcp] moudle: %d, cmd: %d \n", module, cmd))
	if int(module) == 3 && int(cmd) == 5 {
		respMsg := []byte("{\"resp_code\":0}")
		err := SendTcpCmd(module  , cmd , conn , dev , respMsg)
		if err != nil {
			return err
		}
	}else if int(module) == 30 && int(cmd) == 0 {
		respMsg := []byte("{\"resp_code\":0}")
		err := SendTcpCmd(module  , cmd , conn , dev , respMsg)
		if err != nil {
			return err
		}
	}
	return nil
}

func AddCronTask(dev *ApDevData)  {
	ticker := time.NewTicker(time.Second * 40)

	go func(d *ApDevData) {
		for { //循环
			<-ticker.C
			log.Println("############################# ip: ", dev.Ip)
			SendTcpCmd(0x4, 0x32, d.Conn, d, []byte(""))
			log.Println("AddCronTask here1 " + dev.Mac)
			upMsg := fmt.Sprintf("{\"dev_info\":{\"dev_name\":\"iUAP-AC-MV1.0\",\"mode\":\"iUAP-AC-M\"," +
				"\"soft_ver\":\"V1.0.0.1(6448)\",\"mac\":\"%s\",\"manage_ip\":\"192.168.1.157\"," +
				"\"hard_ver\":\"V1.0\",\"manage_mode\":1,\"dev_type\":\"ap\"}," +
				"\"run_status\":{\"cpu_info\":39,\"mem_info\":63,\"run_time\":\"202\"," +
				"\"front_dev\":{\"ip\":\"\",\"name\":\"\",\"mac\":\"\",\"self_port\":\"lan\",\"sn\":\"\"," +
				"\"port\":\"lan\",\"speed\":10,\"duplex\":1,\"up_bytes\":\"537599\",\"down_bytes\":\"474200\"}," +
				"\"down_rate\":\"16.00\",\"up_rate\":\"24.00\",\"user_num\":1,\"latency\":12.193334,\"up_time\":202,\"led_status\":1}," +
				"\"ap_status\":{\"rf_rule\":[{\"channel\":8,\"bindwidth\":20,\"radioflag\":0,\"power\":26,\"rssi\":-100," +
				"\"radioenable\":1,\"utilization\":96,\"tx_bytes\":\"0\",\"rx_bytes\":\"0\",\"channel_busy\":45,\"channel_rx\":0," +
				"\"channel_tx\":0,\"tx_pkg\":0,\"rx_pkg\":0,\"noise\":-95,\"snr\":15}, " +
				"{\"channel\":161,\"bindwidth\":40,\"radioflag\":0,\"power\":26,\"rssi\":-100,\"radioenable\":1,\"utilization\":96," +
				"\"tx_bytes\":\"502839\",\"rx_bytes\":\"514371\",\"channel_busy\":17,\"channel_rx\":0,\"channel_tx\":0," +
				"\"tx_pkg\":7155,\"rx_pkg\":6732,\"noise\":-104,\"snr\":56}]," +
				"\"ssid_info\":[{\"ssid_mac\":\"00:90:4C:88:88:91\",\"ssid_channel\":8,\"ssididx\":0," +
				"\"ssid\":\"PSST-SMB-softwaveconrtroller1111\",\"encrypt\":0,\"passwd\":\"\",\"ssidenable\":1,\"radio_Id\":\"ath0\"," +
				"\"hide\":0,\"type\":0}, {\"ssid_mac\":\"00:90:4C:88:88:92\",\"ssid_channel\":8,\"ssididx\":1," +
				"\"ssid\":\"PSST-SMB-softwaveconrtroller2222\",\"encrypt\":2,\"passwd\":\"12345678\",\"ssidenable\":1,\"radio_Id\":\"ath1\"," +
				"\"hide\":0,\"type\":0}, {\"ssid_mac\":\"00:90:4C:88:88:99\",\"ssid_channel\":161,\"ssididx\":0," +
				"\"ssid\":\"PSST-SMB-softwaveconrtroller1111\",\"encrypt\":0,\"passwd\":\"\",\"ssidenable\":1,\"radio_Id\":\"ath10\",\"hide\":0," +
				"\"type\":1}, {\"ssid_mac\":\"00:90:4C:88:88:9A\",\"ssid_channel\":161,\"ssididx\":1,\"ssid\":\"PSST-SMB-softwaveconrtroller2222\"," +
				"\"encrypt\":2,\"passwd\":\"12345678\",\"ssidenable\":1,\"radio_Id\":\"ath11\",\"hide\":0,\"type\":1}]}," +
				"\"user_stats\":{\"all_users\":1,\"online_users\":0,\"offline_users\":0,\"timestamp\":1604486772}," +
				"\"user_list\":[{\"assoc_ssid\":\"PSST-SMB-softwaveconrtroller1111\",\"user_mac\":\"EC:D0:9F:9D:4B:84\",\"name\":\"MI6-xiaomishouji\"," +
				"\"ip\":\"192.168.1.113\",\"ap_mac\":\"00:90:4C:88:88:90\",\"up_flow\":\"514371.00\",\"down_flow\":\"420409.00\"," +
				"\"up_rate\":\"25541.20\",\"down_rate\":\"19877.67\",\"access_type\":1,\"os_type\":4,\"online_time\":\"140\",\"signal_intensity\":-48," +
				"\"ccq\":100,\"channel\":161,\"vlan\":0,\"is_guests\":0,\"tx_speed\":\"360\",\"rx_speed\":\"144\",\"link_speed\":\"270\"}]," +
				"\"locate_open\":0,\"throughput_stats\":{\"up\":\"23.01\",\"down\":\"24.92\"}}", dev.Mac)
			log.Println("AddCronTask here2 " + dev.Mac)
			SendTcpCmd(0x3, 0x2, d.Conn, d, []byte(upMsg))
		}
	}(dev)
}

func onMessageReceived(conn *net.TCPConn, dev *ApDevData) bool {
	defer conn.Close()

	for {
		header := make([]byte, 16)
		deHead := make([]byte, 16)
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			log.Println("recv failed. ", err)
			return false
		}

		deHead = AesDecryptECB(header, []byte(dev.Key))
		log.Println(fmt.Sprintf("%s recv header : %x", dev.Ip, deHead))
		if int(deHead[2]) != 0x3 {
			log.Println("recv info source error .")
			return false
		}

		module := deHead[8]
		cmd := deHead[9]
		msgLen := uint32(deHead[12])*256*256*256 + uint32(deHead[13])*256*256 + uint32(deHead[14])*256 + uint32(deHead[15])

		if msgLen > 0 {
			if msgLen % 16 != 0 {
				msgLen = msgLen - (msgLen % 16)
				msgLen += 16
			}
			var body []byte
			body = ByteBufferMalloc(int(msgLen))
			n, err := io.ReadFull(conn, body)
			if err != nil || n == 0 {
				log.Println("recv msg body failed. ", err)
				return false
			}
		}

		err = execTcp(module, cmd, conn, dev)
		if err != nil {
			return false
		}
	}
}

func SendTcpCmd(module uint8 , cmd uint8, conn *net.TCPConn, dev *ApDevData, respMsg []byte) error {
	encodeMsg := MakeTcpPackage(module, cmd, 0, uint32(len(respMsg)), respMsg, []byte(dev.Key))
	n ,err := conn.Write(encodeMsg)
	log.Println(fmt.Sprintf(" %s write %d", dev.Ip, n))
	if err != nil {
		log.Println(fmt.Sprintf("%s write failed. %v", dev.Ip, err))
		return err
	}

	return nil
}

func StartTcpProcess(dstIp string, dstPort int, dev* ApDevData) error {
	rAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", dstIp, dstPort))
	lAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:", dev.Ip))

	conn,err := net.DialTCP("tcp",lAddr, rAddr)
	if err !=nil {
		fmt.Println("Client connect error ! " + err.Error())
		return err
	}

	fmt.Println(conn.LocalAddr().String() + " : Client connected!")
	devArray[dev.Index].Conn = conn
	SendTcpCmd(0x4, 0x32, conn, dev, []byte(""))
	go AddCronTask(dev)
	go onMessageReceived(conn, dev)
	return nil
}

func execUdp(data []byte) {
	//log.Println(len(data))
	if len(data) > 35 {
		var bindOrReConnStr BindOrReConnStr
		_err := json.Unmarshal(data, &bindOrReConnStr)
		if _err != nil {
			log.Println("unmarshal json failed. ", _err)
			return
		}

		log.Println(bindOrReConnStr.Mac)
		dev := FindDevByMac(bindOrReConnStr.Mac)
		if dev != nil {
			devArray[dev.Index].Key = bindOrReConnStr.Access
			devArray[dev.Index].Manager = bindOrReConnStr.AcSn

			if dev.Conn != nil {
				dev.Conn.Close()
				dev.Conn = nil
			}
			err := StartTcpProcess(bindOrReConnStr.Ip, bindOrReConnStr.Port, dev)
			var respMsg string
			if err != nil {
				respMsg = fmt.Sprintf("{\"resp_code\":1,\"cmd\":%d}", bindOrReConnStr.Cmd)
			}else {
				respMsg = fmt.Sprintf("{\"resp_code\":0,\"cmd\":%d}", bindOrReConnStr.Cmd)
			}
			RespUdpBindOrReConn(dev, []byte(respMsg))
		}
	}else {
		var scanStr ScanStr
		_err := json.Unmarshal(data, &scanStr)
		if _err != nil {
			log.Println("unmarshal json failed. ", _err)
			return
		}

		go Traverse(*apNum)
	}
}

func RespUdpBindOrReConn(dev* ApDevData, msg []byte) {
	lAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:", dev.Ip))
	rAddr, _ := net.ResolveUDPAddr("udp4", "224.0.0.1:30000")
	conn, err := net.DialUDP("udp4", lAddr, rAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(msg)
	if err != nil {
		fmt.Println(err)
	}
}

func RespUdpScan(dev* ApDevData) {
	lAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", dev.Ip, dev.Index + 10000))
	rAddr, _ := net.ResolveUDPAddr("udp4", "224.0.0.1:30000")
	conn, err := net.DialUDP("udp4", lAddr, rAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	apInfo := fmt.Sprintf("{\"bind_site_id\":0,\"type\":\"ap\",\"ver\":\"V1.0.0.10(6448)\"," +
		"\"product\":\"iUAP-AC-M\",\"mac\":\"%s\",\"port\":3376," +
		"\"sn\":\"000000420002\",\"up_time\":140,\"cmd\":0,\"manage\":\"%s\"}", dev.Mac, dev.Manager)
	packet := []byte(apInfo)
	_, err = conn.Write(packet)
	if err != nil {
		fmt.Println(err)
	}
}

//func StartUdpProcess() {
//	log.Println("=================================")
//	ipv4Addr := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 9998}
//	conn, err := net.ListenUDP("udp4", ipv4Addr)
//	if err != nil {
//		log.Println("ListenUDP error ", err)
//		os.Exit(-1)
//	}
//
//	pc := ipv4.NewPacketConn(conn)
//	iface, err := net.InterfaceByName(*netInterface)
//	if err != nil {
//		log.Println("bind interface error. ", err)
//		os.Exit(-1)
//	}
//
//	if err := pc.JoinGroup(iface, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 1)}); err != nil {
//		log.Println("add group error. ", err)
//		os.Exit(-1)
//	}
//
//	if loop, err := pc.MulticastLoopback(); err == nil {
//		log.Println("MulticastLoopback status: ", loop)
//		if !loop {
//			if err := pc.SetMulticastLoopback(true); err != nil {
//				log.Println("SetMulticastLoopback error: ", err)
//			}
//		}
//	}
//
//	for {
//		buf := make([]byte, 1024)
//		log.Println("StartUdpProcess here1")
//		log.Println( "---------------------------- ", time.Now().String())
//		log.Println("StartUdpProcess here2")
//		if n, addr, err := conn.ReadFrom(buf); err != nil {
//			log.Println("StartUdpProcess here31")
//			if err != nil {
//				log.Println(err)
//			}
//		} else {
//			log.Println("StartUdpProcess here32")
//			log.Println("start exec udp. ", time.Now().String(), " : ", n)
//			log.Println("start exec udp. ", time.Now().String(), " : ", addr)
//			log.Printf("%s received: %s from <%s>", time.Now().String(), buf[:n], addr)
//			go execUdp(buf[:n])
//		}
//	}
//}

//func StartUdpProcess()  {
//	log.Println("=================================")
//	netInterfaceName, err := net.InterfaceByName(*netInterface)
//	if err != nil {
//		log.Println("bind interface error. ", err)
//		os.Exit(-1)
//	}
//	ipv4Addr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 1), Port: 9998}
//	conn, err := net.ListenMulticastUDP("udp4", netInterfaceName, ipv4Addr)
//	if err != nil {
//		log.Println("ListenUDP error ", err)
//		os.Exit(-1)
//	}
//
//	for {
//		buf := make([]byte, 1024)
//		log.Println("StartUdpProcess here1")
//		log.Println( "---------------------------- ", time.Now().String())
//		log.Println("StartUdpProcess here2")
//		if n, addr, err := conn.ReadFrom(buf); err != nil {
//			log.Println("StartUdpProcess here31")
//			if err != nil {
//				log.Println(err)
//			}
//		} else {
//			log.Println("StartUdpProcess here32")
//			log.Println("start exec udp. ", time.Now().String(), " : ", n)
//			log.Println("start exec udp. ", time.Now().String(), " : ", addr)
//			log.Printf("%s received: %s from <%s>", time.Now().String(), buf[:n], addr)
//			go execUdp(buf[:n])
//		}
//	}
//}


func StartUdpProcess()  {
	log.Println("=================================")
	udpEn, err := net.InterfaceByName(*netInterface)
	if err != nil {
		log.Println("bind interface error. ", err)
		os.Exit(-1)
	}

	group := net.IPv4(224, 0, 0, 1)
	addr := fmt.Sprintf("0.0.0.0:9998")
	log.Println(addr)
	//2. bind一个本地地址
	udpConn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	
	//3.
	p := ipv4.NewPacketConn(udpConn)
	if err := p.JoinGroup(udpEn, &net.UDPAddr{IP: group}); err != nil {
		log.Println("join group error. ", err)
		os.Exit(-1)
	}
	//4.更多的控制
	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	
	defer udpConn.Close()

	//5.接收消息

	b := make([]byte, 1024)
	for {
		log.Println("StartUdpProcess here1")
		log.Println( "---------------------------- ", time.Now().String())
		log.Println("StartUdpProcess here2")
		n, cm, src, err := p.ReadFrom(b)
		if err != nil {
			log.Println("StartUdpProcess here31")
			log.Println(err)
			continue
		}
		log.Println("start exec udp31.")
		if cm.Dst.IsMulticast() {
			if cm.Dst.Equal(group) {
				log.Println("StartUdpProcess here32.")
				log.Println("start exec udp. ", time.Now().String(), " : ", n, ", : ", src)
				log.Printf("received: %s from\n", b[:n])
				log.Println("StartUdpProcess here32.")
				go execUdp(b[:n])
			} else {
				log.Println("Unknown group")
				continue
			}
		}
	}
}

func Traverse(apNum int) {
	ids := apNum / 200
	remain := apNum % 200
	for i := 0; i <= ids; i ++ {
		var times int
		if i != ids {
			times = 201
		}else {
			times = remain
			if remain == 0 {
				return
			}
		}

		for j := 2; j <= times + 1; j++ {
			log.Println(j)
			tempMacAddr := macAddrPre[i] + fmt.Sprintf("%02x", j)
			devArray[i * 200 + j - 1].Mac = tempMacAddr
			log.Println(tempMacAddr)
			go RespUdpScan(devArray[i * 200 + j - 1])
		}
	}
}

func DumpNetInterfaces()  {
	lists, err := net.Interfaces()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	for _, address := range lists {
		log.Println(address.Name)
		// 检查ip地址判断是否回环地址
	}
}

func InitWebListen() {
	go func() {
		r := gin.Default()
		r.GET("/", func(c *gin.Context) {
			c.String(200, "Hello, i am is aptest gmtool.")
		})
		r.Run("0.0.0.0:80")
	}()
}

func main()  {

	netInterface = flag.String("i", "etn0", "net interface name")
	apNum = flag.Int("n", 1000, "ap numbers")
	flag.Parse()

	AddVirtualNetworkCard(*apNum)
	InitWebListen()
	DumpNetInterfaces()
	go StartUdpProcess()
	//Traverse(*apNum)
	for {
		time.Sleep(1 * time.Second)
	}
}

func init()  {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile )
	devArray = make(map[int]*ApDevData, 0)
}

