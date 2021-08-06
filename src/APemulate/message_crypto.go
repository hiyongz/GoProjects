package main

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
)

const (
	pkcs5SaltLen = 8
	aes265KeyLen = 32
)

func GenerateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(GenerateKey(key))
	decrypted = make([]byte, len(encrypted))

	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	//log.Println(decrypted)
	//bEnd := searchByteSliceIndex(decrypted, 0)

	return decrypted
	//return decrypted
}

// BytesToKey implements the Openssl EVP_BytesToKey logic.
// It takes the salt, data, a hash type and the key/block length used by that type.
// As such it differs considerably from the openssl method in C.
func BytesToKey(salt, data []byte, h hash.Hash, keyLen, blockLen int) (key, iv []byte) {
	saltLen := len(salt)
	if saltLen > 0 && saltLen != pkcs5SaltLen {
		panic(fmt.Sprintf("Salt length is %d, expected %d", saltLen, pkcs5SaltLen))
	}
	var (
		concat   []byte
		lastHash []byte
		totalLen = keyLen + blockLen
	)
	for ; len(concat) < totalLen; h.Reset() {
		// concatenate lastHash, data and salt and write them to the hash
		h.Write(append(lastHash, append(data, salt...)...))
		// passing nil to Sum() will return the current hash value
		lastHash = h.Sum(nil)
		// append lastHash to the running total bytes
		concat = append(concat, lastHash...)
	}
	return concat[:keyLen], concat[keyLen:totalLen]
}

func ClacMd5(orig_string []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(orig_string)
	cipherStr := md5Ctx.Sum(nil)

	return hex.EncodeToString(cipherStr)
}

func EVPBytesToKey(keyLen int, ivLen int, md hash.Hash, salt []byte, data []byte, count int) ([]byte, []byte) {

	result := make([][]byte, 2)
	key := make([]byte, keyLen)
	keyIx := 0
	iv := make([]byte, ivLen)
	ivIx := 0
	result[0] = key
	result[1] = iv
	var mdBuf []byte
	nkey := keyLen
	niv := ivLen
	i := 0
	if data == nil {
		return result[0], result[1]
	}

	addmd := 0
	for {
		md.Reset()
		if addmd > 0 {
			md.Write(mdBuf)
		}
		addmd++
		md.Write(data)
		if salt != nil {
			md.Write(salt[:8])
		}
		mdBuf = md.Sum(nil)
		for i = 1; i < count; i++ {
			md.Reset()
			md.Write(mdBuf)
			mdBuf = md.Sum(nil)
		}
		i = 0
		if nkey > 0 {
			for {
				if nkey == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				key[keyIx] = mdBuf[i]
				keyIx++
				nkey--
				i++
			}
		}
		if niv > 0 && i != len(mdBuf) {
			for {
				if niv == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				iv[ivIx] = mdBuf[i]
				ivIx++
				niv--
				i++
			}
		}
		if nkey == 0 && niv == 0 {
			break
		}
	}
	for i = 0; i < len(mdBuf); i++ {
		mdBuf[i] = 0
	}

	return result[0], result[1]
}
