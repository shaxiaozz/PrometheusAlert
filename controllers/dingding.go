package controllers

import (
	"PrometheusAlert/models"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

type DDMessage struct {
	Msgtype  string `json:"msgtype"`
	Markdown struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown"`
	At struct {
		AtMobiles []string `json:"atMobiles"`
		IsAtAll   bool     `json:"isAtAll"`
	} `json:"at"`
}

type DDActionCardMessage struct {
	Msgtype    string `json:"msgtype"`
	ActionCard struct {
		Title          string `json:"title"`
		Text           string `json:"text"`
		BtnOrientation string `json:"btnOrientation"`
		Btns           []struct {
			Title     string `json:"title"`
			ActionURL string `json:"actionURL"`
		} `json:"btns"`
	} `json:"actionCard"`
}

func PostToDingDing(title, text, Ddurl, AtSomeOne, logsign string) string {
	open := beego.AppConfig.String("open-dingding")
	if open != "1" {
		logs.Info(logsign, "[dingding]", "钉钉接口未配置未开启状态,请先配置open-dingding为1")
		return "钉钉接口未配置未开启状态,请先配置open-dingding为1"
	}
	// dingding sign
	if openSecret := beego.AppConfig.String("open-dingding-secret"); openSecret == "1" {
		Ddurl = dingdingSign(Ddurl)
	}

	Isatall, _ := beego.AppConfig.Int("dd_isatall")
	Atall := true
	if Isatall == 0 {
		Atall = false
	}
	atMobile := []string{"15888888888"}
	SendText := text
	if AtSomeOne != "" {
		atMobile = strings.Split(AtSomeOne, ",")
		AtText := ""
		for _, phoneN := range atMobile {
			AtText += " @" + phoneN
		}
		SendText += AtText
		Atall = false
	}

	// 如果SendText包含恢复信息,则无需添加按钮
	var u interface{}
	if strings.Contains(SendText, "恢复信息") {
		u = DDMessage{
			Msgtype: "markdown",
			Markdown: struct {
				Title string `json:"title"`
				Text  string `json:"text"`
			}{Title: title, Text: SendText},
			At: struct {
				AtMobiles []string `json:"atMobiles"`
				IsAtAll   bool     `json:"isAtAll"`
			}{AtMobiles: atMobile, IsAtAll: Atall},
		}
	} else {
		// 生成uuid
		uuid := uuid.New().String()
		parts := strings.Split(uuid, "-")
		shortUUID := strings.Join(parts[:3], "-")

		// 封装后端接口
		aiopsApiUrl := beego.AppConfig.String("aiops_api_url")
		aiopsApiSign := beego.AppConfig.String("aiops_api_sign")
		actionURL := aiopsApiUrl + `?sign=` + aiopsApiSign + `&id=` + shortUUID
		encodedURL := url.QueryEscape(actionURL)
		actionURL = `dingtalk://dingtalkclient/page/link?url=` + encodedURL + `&pc_slide=false`

		// 告警内容追加告警ID
		SendText = SendText + `##### <font color="#e3133f">告警ID</font>：` + shortUUID

		// 写入告警ID和相关的告警内容至数据库
		if err := postAlertAnalysis(actionURL, SendText); err != nil {
			logs.Error(logsign, "[dingding]", err.Error())
		}

		u = DDActionCardMessage{
			Msgtype: "actionCard",
			ActionCard: struct {
				Title          string `json:"title"`
				Text           string `json:"text"`
				BtnOrientation string `json:"btnOrientation"`
				Btns           []struct {
					Title     string `json:"title"`
					ActionURL string `json:"actionURL"`
				} `json:"btns"`
			}{
				Title:          title,
				Text:           SendText,
				BtnOrientation: "0",
				Btns: []struct {
					Title     string `json:"title"`
					ActionURL string `json:"actionURL"`
				}{
					{Title: "AI分析", ActionURL: actionURL},
				},
			},
		}
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(u)
	logs.Info(logsign, "[dingding]", b)
	var tr *http.Transport
	if proxyUrl := beego.AppConfig.String("proxy"); proxyUrl != "" {
		proxy := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyUrl)
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           proxy,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{Transport: tr}
	res, err := client.Post(Ddurl, "application/json", b)
	if err != nil {
		logs.Error(logsign, "[dingding]", err.Error())
	}
	defer res.Body.Close()
	result, err := io.ReadAll(res.Body)
	if err != nil {
		logs.Error(logsign, "[dingding]", err.Error())
	}
	models.AlertToCounter.WithLabelValues("dingding").Add(1)
	ChartsJson.Dingding += 1
	logs.Info(logsign, "[dingding]", string(result))
	return string(result)
}

// dingdingSign adds sign and timestamp parms to dingding webhook url
// docs: https://open.dingtalk.com/document/orgapp/custom-bot-creation-and-installation
func dingdingSign(ddurl string) string {
	timestamp := time.Now()
	timestampMs := timestamp.UnixNano() / int64(time.Millisecond)
	tsMsStr := strconv.FormatInt(timestampMs, 10)
	// parse ddurl parms
	u, err := url.Parse(ddurl)
	if err != nil {
		logs.Info("[dingdingSign]", "配置文件已开启钉钉加签，钉钉机器人地址解析加签参数 secret 失败，将使用不加签的地址！")
		return ddurl
	}
	// get parm secret
	queryParams := u.Query()
	secret := queryParams.Get("secret")
	if len(secret) == 0 {
		logs.Info("[dingdingSign]", "配置文件已开启钉钉加签，钉钉机器人地址解析加签参数 secret 为空，将使用不加签的地址！")
		return ddurl
	}
	// sign string
	signStr := tsMsStr + "\n" + secret
	// HmacSHA256
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(signStr))
	signature := h.Sum(nil)
	// Base64
	sign := base64.StdEncoding.EncodeToString(signature)
	// splice url
	delete(queryParams, "secret")
	queryParams.Add("timestamp", tsMsStr)
	queryParams.Add("sign", sign)
	u.RawQuery = queryParams.Encode()
	signURL := u.String()

	return signURL
}

// 写入uuid和相关的告警内容至数据库
func postAlertAnalysis(url, alertContent string) error {
	// 封装请求体
	postParams := new(struct {
		AlertContent string `json:"alert_content"` // 告警内容
	})
	postParams.AlertContent = alertContent
	jsonData, _ := json.Marshal(postParams)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 判断是否增加成功
	if resp.StatusCode != 200 {
		return err
	}
	return nil
}
