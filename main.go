package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func encrypt(code []byte, text string) (string, error) {
	key := make([]byte,16)
	for i, b := range md5.Sum(code) {
		key[i] = b
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	msg := Pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(ciphertext))
	return finalMsg, nil
}

func decrypt(code []byte, text string) (string, error) {
	key := make([]byte,16)
	for i, b := range md5.Sum(code) {
		key[i] = b
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := Unpad(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}

func main() {
	de := flag.Bool("d",false,"Decrypt file")
	read := flag.Bool("r",false,"Only read for decrypt")
	flag.Parse()
	if len(flag.Args())<1{
		fmt.Println("File not found")
		return
	}
	file := flag.Args()[0]
	if *de{
		fmt.Println("Mode: decrypt")
	}else {
		fmt.Println("Mode: encrypt")
	}

	fmt.Print("Key: ")
	var key string
	_,err := fmt.Scanln(&key)
	if err != nil {
		fmt.Println(err)
		return
	}

	if *de{
		data,err  := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println(err)
			return
		}
		DataString, err := decrypt([]byte(key),string(data))
		if err != nil {
			fmt.Println(err)
			return
		}
		if *read{
			fmt.Println(DataString)
		}else {
			err = ioutil.WriteFile(file,[]byte(DataString),700)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

	}else {
		data,err  := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println(err)
			return
		}
		DataString, err := encrypt([]byte(key),string(data))
		if err != nil {
			fmt.Println(err)
			return
		}
		err = ioutil.WriteFile(file,[]byte(DataString),700)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	fmt.Println("Success")
}
