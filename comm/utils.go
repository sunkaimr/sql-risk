package comm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
)

func HttpDo(method, url string, headers, query map[string]string, b string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	if len(query) > 0 {
		url += "?"
		for k, v := range query {
			url += fmt.Sprintf("%s=%s&", k, v)
		}
	}

	req, err := http.NewRequest(method, url, strings.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("new http client failed, err:%s", err)
	}

	req.Header.Set("Host", req.URL.Host)
	req.Close = true

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	//req.Header.Set("Content-LogType", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do http request failed, %s", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read http response failed, err:%s", err)
	}

	return body, nil
}

// Intersect 2个切片的交集
func Intersect(o, n []string) []string {
	m := make(map[string]int)
	var arr []string
	for _, v := range o {
		m[v]++
	}
	for _, v := range n {
		m[v]++
		if m[v] > 1 {
			arr = append(arr, v)
		}
	}
	return arr
}

func SlicesEqual(slice1, slice2 interface{}) bool {
	s1 := reflect.ValueOf(slice1)
	s2 := reflect.ValueOf(slice2)

	if s1.Kind() != reflect.Slice || s2.Kind() != reflect.Slice {
		return false
	}

	if s1.Len() != s2.Len() {
		return false
	}

	m1 := make(map[interface{}]int)
	m2 := make(map[interface{}]int)

	for i := 0; i < s1.Len(); i++ {
		m1[s1.Index(i).Interface()]++
		m2[s2.Index(i).Interface()]++
	}

	if len(m1) != len(m2) {
		return false
	}

	for k, v := range m1 {
		if m2[k] != v {
			return false
		}
	}

	return true
}

func mapsEqual(map1, map2 interface{}) bool {
	// 检查类型是否为 map
	if reflect.TypeOf(map1).Kind() != reflect.Map || reflect.TypeOf(map2).Kind() != reflect.Map {
		return false
	}

	// 比较 map 的长度
	value1 := reflect.ValueOf(map1)
	value2 := reflect.ValueOf(map2)
	if value1.Len() != value2.Len() {
		return false
	}

	// 遍历第一个 map，检查键值对是否存在于第二个 map 中
	for _, key := range value1.MapKeys() {
		value1Elem := value1.MapIndex(key)
		value2Elem := value2.MapIndex(key)

		// 比较键值对的值和对应类型
		if !value2Elem.IsValid() || !reflect.DeepEqual(value1Elem.Interface(), value2Elem.Interface()) {
			return false
		}
	}

	return true
}

func Decrypt(cryted string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte("abcdefghijklmnop")

	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	if (len(orig) % blockMode.BlockSize()) != 0 {
		return ""
	}
	blockMode.CryptBlocks(orig, crytedByte)
	//// 去补全码
	orig = PKCS7UnPadding(orig)
	if orig == nil {
		return ""
	}
	return string(orig)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	if origData == nil {
		return nil
	}
	if len(origData) > 0 {
		length := len(origData)
		unpadding := int(origData[length-1])
		if (length - unpadding) < 0 {
			return nil
		}
		return origData[:(length - unpadding)]
	}
	return nil
}

func hmacSha256(stringToSign string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func EleExist(element any, slice any) bool {
	sliceValue := reflect.ValueOf(slice)

	if sliceValue.Kind() != reflect.Slice {
		return false
	}

	for i := 0; i < sliceValue.Len(); i++ {
		value := sliceValue.Index(i).Interface()
		if reflect.DeepEqual(value, element) {
			return true
		}
	}

	return false
}

func Slice2String(s []string) string {
	o, _ := json.Marshal(s)
	return strings.Trim(string(o), "[]")
}

func IsSubsetSlice(subSet, set []string) bool {
	setB := make(map[string]struct{})
	for _, item := range set {
		setB[item] = struct{}{}
	}
	for _, item := range subSet {
		if _, ok := setB[item]; !ok {
			return false
		}
	}

	return true
}

func PathExist(path string) bool {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return true
		}
		return false
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func FileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil {
		return false
	}
	return true
}

func Hash(str string) string {
	id := md5.New()
	io.WriteString(id, str)
	return fmt.Sprintf("%x", id.Sum(nil))
}

// GetNextWord 用正则表达式找到下一个完整的单词
func GetNextWord(sentence string, startIndex int) string {
	if startIndex >= len(sentence) || startIndex < 0 {
		return ""
	}
	// 用正则表达式找到下一个完整的单词
	regex := regexp.MustCompile(`\b\w+\b`)
	matches := regex.FindAllString(sentence[startIndex:], 1)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}
