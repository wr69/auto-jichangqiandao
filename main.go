package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

//到Settings→Secrets and variables→Actions 新建以下参数
//使用方法：创建变量 名字：JICHANG 内容的写法：
//机场的名字(方便自己看)|机场的网址(https:www.xxxx...)|第一个邮箱(用户名),密码;第二个邮箱,密码;...
//每两个机场用回车键隔开
//例如: 某某云|https://www.yun.com|jjjj@qq.com,password

// "net/http/cookiejar"
var cookies map[string][]*http.Cookie
var filePath string
var noticeUrl string
var noticeKey string
var rsaPub *rsa.PublicKey
var rsaPri *rsa.PrivateKey

func main() {

	// 使用 make 函数进行初始化
	cookies = make(map[string][]*http.Cookie)
	filePath = "config/cookie.json"

	publicKey := os.Getenv("RSAPUBLIC")
	privateKey := os.Getenv("RSAPRIVATE")

	jichang := os.Getenv("JICHANG")
	noticeUrl = os.Getenv("TZURL")
	noticeKey = os.Getenv("TZKEY")

	rsa_pub, err := readPublicKeyFromText(publicKey)
	if err != nil {
		log.Println("Failed to read public key Text:", err)
		return
	}
	rsaPub = rsa_pub

	rsa_pri, err := readPrivateKeyFromText(privateKey)
	if err != nil {
		log.Println("Failed to read private key Text:", err)
		return
	}
	rsaPri = rsa_pri

	initCookie(filePath)
	results := make(chan string)
	groups := strings.Split(jichang, "\n")
	// 创建 WaitGroup，用于同步协程
	var wg sync.WaitGroup

	// 启动多个协程进行处理
	for _, group := range groups {
		wg.Add(1)

		go func(group string) {
			defer wg.Done()

			// 执行具体的任务，并将结果发送到通道中
			result := processNumber(group)
			results <- result
		}(group)
	}

	// 等待所有协程完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 从通道中读取结果
	postData := ""
	for result := range results {
		postData = postData + result
		//log.Println("result : ", result)
	}
	noticePost(postData, "jichang_qiandao")
	saveCookie(filePath)
}

func processNumber(group string) string {
	reStr := ""
	if group != "" {

		prop := strings.Split(group, "|")
		site_name := prop[0]
		urlStr := prop[1]
		prof := prop[2]
		profiles := strings.Split(prof, ";")
		reStr = site_name + " - " + urlStr
		for _, profile := range profiles {

			if profile != "" {
				profilel := strings.Split(profile, ",")
				email := profilel[0]
				passwd := profilel[1]
				reStr = reStr + " # " + sign(urlStr, email, passwd)
			}
		}
	}
	return reStr
}

func reqApi(method string, headers http.Header, apiurl string, cookieNum int, randomString string, data string) (int, string) {
	/*proxyURL, err2 := url.Parse("http://127.0.0.1:8888") // 代理设置
	if err2 != nil {
		log.Println(err2)
	}

	transport := &http.Transport{ // 创建自定义的 Transport
		Proxy: http.ProxyURL(proxyURL),
	} */

	// 创建客户端，并使用自定义的 Transport
	client := &http.Client{
		Timeout: 10 * time.Second, // 设置超时时间为10秒
		//Transport: transport,
	}
	var req *http.Request
	var err error

	headers.Set("User-Agent", "Mozilla / 5.0 (Windows NT 10.0; Win64; x64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 114.0.0.0 Safari / 537.36 Edg / 114.0.1823.37")
	headers.Set("Content-Type", "application/x-www-form-urlencoded")

	if method == "post" {
		if strings.HasPrefix(data, "{") {
			req, err = http.NewRequest("POST", apiurl, bytes.NewBuffer([]byte(data)))
		} else {
			req, err = http.NewRequest("POST", apiurl, strings.NewReader(data))
		}

	} else if method == "put" {
		if strings.HasPrefix(data, "{") {
			req, err = http.NewRequest("PUT", apiurl, bytes.NewBuffer([]byte(data)))
		} else {
			req, err = http.NewRequest("PUT", apiurl, strings.NewReader(data))
		}
	} else if method == "delete" {
		req, err = http.NewRequest("DELETE", apiurl, nil)
	} else {
		req, err = http.NewRequest("GET", apiurl, nil)
	}
	if err != nil {
		log.Println(apiurl, " NewRequest 失败 :", err)
		return 9999, ""
	}
	req.Header = headers

	if cookieNum == 1 {
		if len(cookies[randomString]) > 0 {
			for _, cookie := range cookies[randomString] {
				req.AddCookie(cookie)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(apiurl, " client 失败 :", err)
		return 9999, ""
	}
	defer resp.Body.Close()
	if cookieNum == 0 {
		cookies[randomString] = resp.Cookies()
	}
	resBody, _ := ioutil.ReadAll(resp.Body)
	return resp.StatusCode, string(resBody)

}

func sign(urlStr string, email string, passwd string) string {

	// 登录URL和签到URL
	loginURL := fmt.Sprintf("%s/auth/login", urlStr)
	checkURL := fmt.Sprintf("%s/user/checkin", urlStr)

	randomString := hex.EncodeToString([]byte(urlStr + email + passwd))

	postStr := email + " | "

	// 准备登录数据
	data := url.Values{}
	data.Set("email", email)
	data.Set("passwd", passwd)

	if len(cookies[randomString]) > 0 {
		checkinStr := checkin(checkURL, randomString)
		if strings.HasPrefix(checkinStr, "checkin err ：") == false {
			postStr = postStr + checkinStr
			return postStr + " ; "
		}
	}
	loginStr := login(loginURL, data, randomString)

	postStr = postStr + loginStr
	if loginStr != "连接失败" || strings.HasPrefix(loginStr, "login err ：") == false {
		checkinStr2 := checkin(checkURL, randomString)
		postStr = postStr + " | " + checkinStr2
	}
	return postStr + " ; "
}

func login(apiurl string, postData url.Values, randomString string) string {
	// 发送登录请求 statusCode
	_, resBody := reqApi("post", http.Header{}, apiurl, 0, randomString, postData.Encode())
	msg := gjson.Get(resBody, "msg").String()
	if msg == "" {
		if strings.HasPrefix(resBody, "<!DOCTYPE html>") {
			return "login err ：302 跳转"
		}
		return "login err ：" + resBody
	}
	/*
		{"ret":1,"msg":"登录成功"}
		{"ret":0,"msg":"邮箱或者密码失败"}
	*/
	return msg
}

func checkin(apiurl string, randomString string) string {
	// 发送签到请求 statusCode
	_, resBody := reqApi("post", http.Header{}, apiurl, 1, randomString, "")
	msg := gjson.Get(resBody, "msg").String()
	if msg == "" {
		if strings.HasPrefix(resBody, "<!DOCTYPE html>") {
			return "checkin err ：302 跳转"
		}
		return "checkin err ：" + resBody
	}
	/*
		{"msg":"你获得了 1642 MB流量","ret":1}
		{"ret":0,"msg":"您似乎已经签到过了..."}
	*/
	return msg
}

// 生成指定长度的随机字符串
func randString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" // 字符集
	charsetLength := len(charset)
	result := make([]byte, length)

	// 从加密随机源中读取随机字节
	_, err := rand.Read(result)
	if err != nil {
		return "", err
	}

	// 使用字符集将随机字节转换为字符串
	for i := 0; i < length; i++ {
		result[i] = charset[int(result[i])%charsetLength]
	}

	return string(result), nil
}

func readPrivateKeyFromText(keyString string) (*rsa.PrivateKey, error) {
	privateKeyFile := []byte(keyString)
	block, _ := pem.Decode(privateKeyFile)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func readPublicKeyFromText(keyString string) (*rsa.PublicKey, error) {
	publicKeyFile := []byte(keyString)
	block, _ := pem.Decode(publicKeyFile)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse RSA public key")
	}
	return publicKey, nil
}

/*
RSA加密时，对于原文数据的要求：
OAEP填充模式： 原文长度 <= 密钥模长 - (2 * 原文的摘要值长度) - 2字节
        各摘要值长度：
                SHA-1:    20字节
                SHA-256:  32字节
                SHA-384:  48字节
                SHA-512:  64字节
PKCA1-V1_5填充模式：原文长度 <= 密钥模长 - 11字节
*/

func RSApublicEncrypt(ciphertextString string) (string, error) {
	plaintext := []byte(ciphertextString)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
	if err != nil {
		log.Println("RSA encryption failed:", err)
		return "", err
	}
	return hex.EncodeToString(ciphertext), nil
}

func RSAprivateDecrypt(ciphertextString string) (string, error) {
	plaintext, err := hex.DecodeString(ciphertextString)
	if err != nil {
		return "", err
	}
	decryptedText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPri, plaintext, nil)
	if err != nil {
		log.Println("RSA decryption failed:", err)
		return "", err
	}
	return string(decryptedText), nil
}
func RSApublicEncryptBlock(ciphertextString string) (string, error) {
	plaintext := []byte(ciphertextString)

	keySize, srcSize := rsaPub.Size(), len(plaintext)
	//单次加密的长度需要减掉padding的长度
	padding := 2*32 + 2
	offSet, once := 0, keySize-padding
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 加密一部分
		bytesOnce, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext[offSet:endIndex], nil)
		if err != nil {
			log.Println("RSA encryption block failed:", err)
			return "", err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesEncrypt := buffer.Bytes()
	return hex.EncodeToString(bytesEncrypt), nil
}

func RSAprivateDecryptBlock(ciphertextString string) (string, error) {
	encryptedData, err := hex.DecodeString(ciphertextString)
	if err != nil {
		return "", err
	}
	keySize, srcSize := rsaPri.Size(), len(encryptedData)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPri, encryptedData[offSet:endIndex], nil)
		if err != nil {
			log.Println("RSA decrypt block failed:", err)
			return "", err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesDecrypt := buffer.Bytes()
	plaintext := string(bytesDecrypt)
	return plaintext, nil
}

func noticePost(postData string, name string) {
	//base64.StdEncoding.EncodeToString
	//base64.URLEncoding.EncodeToString
	encoder := base64.URLEncoding
	formData := url.Values{}
	formData.Set("pwd", noticeKey)
	formData.Set("name", name)
	formData.Set("json", encoder.EncodeToString([]byte(postData)))

	client := http.Client{
		Timeout: time.Duration(10 * time.Second),
	}

	req, err := http.NewRequest("POST", noticeUrl, strings.NewReader(formData.Encode())) //http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(name, "Failed to post HTTP URL :", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "github action")

	resp, err := client.Do(req)
	if err != nil {
		log.Println(name, "Failed to post resp :", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(name, "Failed to post body :", err)
		return
	}

	log.Println(name, string(body))
}

func saveFile(filePath string, data string) {
	// 获取文件所在目录路径
	dirPath := filepath.Dir(filePath)

	// 创建目录
	err3 := os.MkdirAll(dirPath, os.ModePerm)
	if err3 != nil {
		log.Println("创建目录出错：", err3)
		return
	}

	// 判断文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 文件不存在，创建文件并写入内容
		err := ioutil.WriteFile(filePath, []byte(data), 0644)
		if err != nil {
			log.Println("创建文件出错:", err)
			return
		}
	} else if err == nil {
		// 文件存在，更新文件内容
		err := ioutil.WriteFile(filePath, []byte(data), 0644)
		if err != nil {
			log.Println("更新文件出错:", err)
			return
		}
	} else {
		log.Println("其他错误:", err)
	}
}

func cookieReduction(jsonData string) {
	// 定义一个类型用于解析JSON数据
	type CookieData map[string][]*http.Cookie
	var ckdata CookieData
	jsonByte := []byte(jsonData)
	// 解析JSON字符串

	//index := bytes.IndexByte(jsonByte, 0)
	//err := json.Unmarshal(jsonByte[:index], &ckdata)

	err := json.Unmarshal(jsonByte, &ckdata)
	if err != nil {
		log.Println("解析cookie JSON时出错:", err)
	} else {
		cookies = ckdata
	}
	/* 	// 打印转换后的数据
	   	for keys, cookiesd := range data {
	   		fmt.Println("Key:", keys)
	   		fmt.Println("Cookies:")
	   		for _, cookiev := range cookiesd {
	   			fmt.Println("Name:", cookiev.Name)
	   			fmt.Println("Value:", cookiev.Value)
	   		}
	   		fmt.Println("---------")
	   	} */
}

func initCookie(filePath string) {
	// 判断文件是否存在
	if _, err := os.Stat(filePath); err == nil {
		// 文件存在，读取文件内容
		cipherdata, err := ioutil.ReadFile(filePath)
		if err != nil {
			log.Println("读取文件出错:", err)
			return
		} else {
			ciphertext := string(cipherdata)
			if ciphertext != "" {
				// 加密
				decryptedText, err := RSAprivateDecryptBlock(ciphertext)
				if err != nil {
					log.Println("RSA Decrypt 失败", err)
					return
				}
				cookieReduction(decryptedText)
			}
		}
	} else if os.IsNotExist(err) {
		log.Println("文件不存在")
	} else {
		log.Println("其他错误:", err)
	}
}
func saveCookie(filePath string) {
	// 将Map转换为JSON格式
	jsonData, err := json.Marshal(cookies)
	if err != nil {
		fmt.Println("转换为JSON时出错:", err)
	}
	// Example usage
	plaintext := string(jsonData) //"Hello, World! 废了惨"
	// Encrypt the plaintext
	ciphertext, err := RSApublicEncryptBlock(plaintext)
	if err != nil {
		log.Println("RSA Decrypt 失败", err)
		return
	}
	saveFile(filePath, ciphertext)
}
