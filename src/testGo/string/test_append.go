
package main

import (
	"crypto/md5"
	"fmt"
	"log"
)

func main() {
	cloud_bind_msg := []byte{0x24, 0x0, 0x6, 0x0, 0x01, 0x67, 0x0, 0x0, 0x03, 0x0c, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa3, 0x7b}
	devmessage1 := "\"devType\":"
	devmessage2 := "\"devSn\":"
	devmessage3 := "\"devMesh\":"
	devmessage4 := "\"cloud_id\":"
	cloud_id := "7d39daac23b51e13d0bf293b6b724a1c"
	devmessage5 := "\"mac\":"
	devmessage6 := "\"model\":"
	model := "ap"

	cloud_bind_msg = append(cloud_bind_msg, []byte{0x0a,0x09}...)	
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage1)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, pruduct_uint8...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)	
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage2)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, sn)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage3)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22,0x22,0x2c,0x0a,0x09}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage4)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(cloud_id)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage5)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, mac_uint8...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x2c,0x0a,0x09}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(devmessage6)...)	
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x09,0x22}...)
	cloud_bind_msg = append(cloud_bind_msg, []byte(model)...)
	cloud_bind_msg = append(cloud_bind_msg, []byte{0x22,0x0a,0x7d}...)


	fmt.Printf("cloud_bind_msg: % 02x\n", cloud_bind_msg)
}