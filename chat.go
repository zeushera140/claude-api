package claude

import (
	"fmt"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bincooo/emit.io"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
	"io"
	"mime/multipart"
	//"path/filepath"
)

var (
	ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)

const (
	baseURL   = "https://claude.ai/api"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.79"
)

// 新的消息响应结构
type MessageResponse struct {
	Type    string       `json:"type"`
	Message *MessageData `json:"message,omitempty"`
	Index   int          `json:"index,omitempty"`
	Delta   *DeltaData   `json:"delta,omitempty"`
	ContentBlock *ContentBlock `json:"content_block,omitempty"`
}

type MessageData struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Role       string `json:"role"`
	Model      string `json:"model"`
	ParentUUID string `json:"parent_uuid"`
	UUID       string `json:"uuid"`
	Content    []interface{} `json:"content"`
	StopReason interface{} `json:"stop_reason"`
	StopSequence interface{} `json:"stop_sequence"`
}

type ContentBlock struct {
	Type      string `json:"type"`
	Thinking  string `json:"thinking"`
	Text      string `json:"text"`
	Summaries []interface{} `json:"summaries"`
	CutOff    bool   `json:"cut_off"`
}

type DeltaData struct {
	Type     string            `json:"type"`
	Thinking string            `json:"thinking,omitempty"`
	Text     string            `json:"text,omitempty"`
	Summary  map[string]string `json:"summary,omitempty"`
}

type webClaude2Response struct {
	Id           string `json:"id"`
	Completion   string `json:"completion"`
	StopReason   string `json:"stop_reason"`
	Model        string `json:"model"`
	Type         string `json:"type"`
	Truncated    bool   `json:"truncated"`
	Stop         string `json:"stop"`
	LogId        string `json:"log_id"`
	Exception    any    `json:"exception"`
	MessageLimit struct {
		Type string `json:"type"`
	} `json:"messageLimit"`
}

func Ja3(j string) {
	ja3 = j
}

// UploadFile 上传文件到Claude
func (c *Chat) UploadFile(filename string, fileContent []byte) (*UploadResponse, error) {
	// 获取组织ID
	organizationId, err := c.getO()
	if err != nil {
		return nil, fmt.Errorf("fetch organization failed: %v", err)
	}

	// 创建multipart请求体
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	// 创建文件字段
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	
	// 写入文件内容
	_, err = io.Copy(part, bytes.NewReader(fileContent))
	if err != nil {
		return nil, err
	}
	
	// 关闭writer以设置boundary
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	// 发送上传请求
	response, err := emit.ClientBuilder(c.session).
		Ja3().
		CookieJar(c.opts.jar).
		POST(baseURL+"/"+organizationId+"/upload").
		Header("content-type", writer.FormDataContentType()).
		Header("referer", "https://claude.ai/new").
		Header("origin", "https://claude.ai").
		Header("user-agent", userAgent).
		Bytes(body.Bytes()).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	
	if err != nil {
		return nil, fmt.Errorf("upload failed: %v", err)
	}
	
	defer response.Body.Close()
	
	// 解析响应
	var uploadResp UploadResponse
	if err := json.NewDecoder(response.Body).Decode(&uploadResp); err != nil {
		return nil, fmt.Errorf("parse upload response failed: %v", err)
	}
	
	// 发送上传完成信号到 a-api.anthropic.com
	err = c.sendUploadSignal()
	if err != nil {
		logrus.Warnf("send upload signal failed: %v", err)
		// 不要因为这个失败而中断流程
	}
	
	return &uploadResp, nil
}

// sendUploadSignal 发送上传完成信号
func (c *Chat) sendUploadSignal() error {
	payload := map[string]bool{
		"success": true,
	}
	
	response, err := emit.ClientBuilder(c.session).
		Ja3().
		CookieJar(c.opts.jar).
		POST("https://a-api.anthropic.com/v1/t").
		Header("referer", "https://claude.ai/").
		Header("origin", "https://claude.ai").
		Header("user-agent", userAgent).
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK))
	
	if err != nil {
		return err
	}
	
	response.Body.Close()
	return nil
}

func NewDefaultOptions(cookies string, model string, mode string) (*Options, error) {
    options := Options{
        Retry: 2,
        Model: model,
        Mode:  mode, // Add mode parameter
    }

    if cookies != "" {
        if !strings.Contains(cookies, "sessionKey=") {
            cookies = "sessionKey=" + cookies
        }

        jar, err := emit.NewCookieJar("https://claude.ai", cookies)
        if err != nil {
            return nil, err
        }
        options.jar = jar
    }

    return &options, nil
}

func New(opts *Options) (*Chat, error) {
	if opts.Model != "" && !strings.HasPrefix(opts.Model, "claude-") {
		return nil, errors.New("claude-model cannot has `claude-` prefix")
	}
	return &Chat{
		opts: opts,
	}, nil
}

func (c *Chat) Client(session *emit.Session) {
	c.session = session
}

// 修改 Reply 函数签名，返回上传的文件信息
func (c *Chat) Reply(ctx context.Context, message string, attrs []Attachment, fileUUIDs []string) (chan PartialResponse, error) {
	if c.opts.Model == "" {
		// 动态加载 model
		model, err := c.loadModel()
		if err != nil {
			return nil, err
		}
		c.opts.Model = model
	}

	c.mu.Lock()
	logrus.Info("curr model: ", c.opts.Model)
	var response *http.Response
	for index := 1; index <= c.opts.Retry; index++ {
		r, err := c.PostMessage(message, attrs, fileUUIDs)
		if err != nil {
			if index >= c.opts.Retry {
				c.mu.Unlock()
				return nil, err
			}

			var wap *ErrorWrapper
			ok := errors.As(err, &wap)

			if ok && wap.ErrorType.Message == "Invalid model" {
				c.mu.Unlock()
				return nil, errors.New(wap.ErrorType.Message)
			} else {
				logrus.Error("[retry] ", err)
			}
		} else {
			response = r
			break
		}
	}

	ch := make(chan PartialResponse)
	go c.resolve(ctx, response, ch)
	return ch, nil
}

func (c *Chat) PostMessage(message string, attrs []Attachment, fileUUIDs []string) (*http.Response, error) {
	var (
		organizationId string
		conversationId string
	)

	// 获取组织ID
	{
		oid, err := c.getO()
		if err != nil {
			return nil, fmt.Errorf("fetch organization failed: %v", err)
		}
		organizationId = oid
	}

	// 获取会话ID
	{
		cid, err := c.getC(organizationId)
		if err != nil {
			return nil, fmt.Errorf("fetch conversation failed: %v", err)
		}
		conversationId = cid
	}

	// 构建payload - 完全匹配实际请求格式
	payload := map[string]interface{}{
		"prompt":               message,
		"parent_message_uuid":  "00000000-0000-4000-8000-000000000000",
		"timezone":             "Asia/Shanghai",
		"locale":               "en-US",
		"rendering_mode":       "messages",
		"attachments":          []interface{}{}, // 保持空数组
		"files":                fileUUIDs,      // 直接使用UUID字符串数组
		"sync_sources":         []interface{}{},
		"personalized_styles": []map[string]interface{}{
			{
				"type":        "default",
				"key":         "Default",
				"name":        "Normal",
				"nameKey":     "normal_style_name",
				"prompt":      "Normal",
				"summary":     "Default responses from Claude",
				"summaryKey":  "normal_style_summary",
				"isDefault":   true,
			},
		},
		"tools": []map[string]interface{}{
			{"type": "web_search_v0", "name": "web_search"},
			{"type": "artifacts_v0", "name": "artifacts"},
			{"type": "repl_v0", "name": "repl"},
		},
	}

	// 添加model字段 - 这是关键！
	if c.opts.Model != "" {
		payload["model"] = c.opts.Model
	}

	logrus.Infof("发送请求 - 模型: %s, files: %v", c.opts.Model, fileUUIDs)

	response, err := emit.ClientBuilder(c.session).
		Ja3().
		CookieJar(c.opts.jar).
		POST(baseURL+"/organizations/"+organizationId+"/chat_conversations/"+conversationId+"/completion").
		Header("referer", "https://claude.ai/chat/"+conversationId).
		Header("accept", "text/event-stream, text/event-stream").
		Header("anthropic-client-platform", "web_claude_ai").
		Header("user-agent", userAgent).
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsSTREAM)

	if err != nil {
		logrus.Errorf("请求失败 - 模型: %s, 错误类型: %T, 错误内容: %v", c.opts.Model, err, err)
	}

	return response, err
}

func (c *Chat) Delete() {
	if c.oid == "" {
		return
	}

	if c.cid == "" {
		return
	}

	_, err := emit.ClientBuilder(c.session).
		Ja3().
		CookieJar(c.opts.jar).
		DELETE(baseURL+"/organizations/"+c.oid+"/chat_conversations/"+c.cid).
		Header("Origin", "https://claude.ai").
		Header("Referer", "https://claude.ai/chat/"+c.cid).
		Header("Accept-Language", "en-US,en;q=0.9").
		Header("user-agent", userAgent).
		Bytes([]byte(`"`+c.cid+`"`)).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		c.cid = ""
	}
}

	// 添加新的响应结构体
type ContentBlockDelta struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Thinking string `json:"thinking,omitempty"`
}

type NewClaudeResponse struct {
	Type        string             `json:"type"`
	Index       int               `json:"index,omitempty"`
	Delta       *ContentBlockDelta `json:"delta,omitempty"`
	Message     interface{}       `json:"message,omitempty"`
	ContentBlock interface{}      `json:"content_block,omitempty"`
}

func (c *Chat) resolve(ctx context.Context, r *http.Response, message chan PartialResponse) {
	defer c.mu.Unlock()
	defer close(message)
	defer r.Body.Close()

	if c.session != nil {
		defer func() {
			c.session.IdleClose()
		}()
	}

	var (
		prefix1 = "event: "
		prefix2 = []byte("data: ")
	)

	scanner := bufio.NewScanner(r.Body)
	logrus.Infof("Response Status: %s", r.Status)
	logrus.Infof("Response Headers: %+v", r.Header)
	
	eventCount := 0
	var currentText strings.Builder // 累积文本内容
	
	scanner.Split(func(data []byte, eof bool) (advance int, token []byte, err error) {
		if eof && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if eof {
			return len(data), data, nil
		}
		return 0, nil, nil
	})

	// 处理事件的函数
	handler := func() bool {
		if !scanner.Scan() {
			logrus.Warnf("Scanner stopped. Events processed: %d", eventCount)
			return true
		}

		var event string
		data := scanner.Text()
		logrus.Trace("--------- ORIGINAL MESSAGE ---------")
		logrus.Trace(data)

		if len(data) < 7 || data[:7] != prefix1 {
			logrus.Debugf("Skipping non-event line: %s", data)
			return false
		}
		event = data[7:]
		logrus.Infof("Event type: %s", event)

		if !scanner.Scan() {
			logrus.Warn("Failed to read data line after event")
			return true
		}

		dataBytes := scanner.Bytes()
		logrus.Trace("--------- DATA ---------")
		logrus.Trace(string(dataBytes))
		
		if len(dataBytes) < 6 || !bytes.HasPrefix(dataBytes, prefix2) {
			logrus.Debugf("Invalid data format: %s", string(dataBytes))
			return false
		}

		eventCount++

		// 处理不同的事件类型
		switch event {
		case "message_start":
			logrus.Debug("Message started")
			return false
			
		case "content_block_start":
			logrus.Debug("Content block started")
			return false
			
		case "content_block_delta":
			var response MessageResponse
			if err := json.Unmarshal(dataBytes[6:], &response); err != nil {
				logrus.Errorf("JSON parse error: %v, Raw: %s", err, string(dataBytes[6:]))
				return false
			}

			var textContent string
			if response.Delta != nil {
				if response.Delta.Type == "text_delta" && response.Delta.Text != "" {
					textContent = response.Delta.Text
					currentText.WriteString(textContent)
				} else if response.Delta.Type == "thinking_delta" && response.Delta.Thinking != "" {
					// 对于thinking内容，我们可以选择是否包含
					textContent = response.Delta.Thinking
					currentText.WriteString(textContent)
				}
			}

			if textContent != "" {
				message <- PartialResponse{
					Text:    textContent,
					RawData: dataBytes[6:],
				}
			}
			return false
			
		case "content_block_stop":
			logrus.Debug("Content block stopped")
			return false
			
		case "message_delta":
			var response MessageResponse
			if err := json.Unmarshal(dataBytes[6:], &response); err != nil {
				logrus.Errorf("JSON parse error: %v, Raw: %s", err, string(dataBytes[6:]))
				return false
			}
			logrus.Debug("Message delta received")
			return false
			
		case "message_stop":
			logrus.Info("Message completed")
			return true
			
		case "error":
			logrus.Errorf("Received error event: %s", string(dataBytes[6:]))
			message <- PartialResponse{
				Error: fmt.Errorf("server error: %s", string(dataBytes[6:])),
			}
			return true
			
		case "completion":
			// 兼容旧格式
			var response webClaude2Response
			if err := json.Unmarshal(dataBytes[6:], &response); err != nil {
				logrus.Errorf("JSON parse error: %v, Raw: %s", err, string(dataBytes[6:]))
				return false
			}

			message <- PartialResponse{
				Text:    response.Completion,
				RawData: dataBytes[6:],
			}

			return response.StopReason == "stop_sequence"
			
		default:
			logrus.Warnf("Unknown event type: %s, data: %s", event, string(dataBytes[6:]))
			return false
		}
	}

	for {
		select {
		case <-ctx.Done():
			logrus.Warnf("Context timeout. Events processed: %d", eventCount)
			message <- PartialResponse{
				Error: errors.New("resolve timeout"),
			}
			return
		default:
			if handler() {
				logrus.Infof("Handler returned true, ending stream. Total events: %d", eventCount)
				return
			}
		}
	}
}
    
    // 解析响应并发送消息的辅助函数
    func (c *Chat) parseAndSendResponse(dataContent string, message chan PartialResponse) error {
    	if strings.TrimSpace(dataContent) == "" || dataContent == "[DONE]" {
    		return nil
    	}
    
    	// 尝试解析为原始webClaude2Response格式
    	var response webClaude2Response
    	if err := json.Unmarshal([]byte(dataContent), &response); err == nil && response.Completion != "" {
    		logrus.Infof("Parsed webClaude2Response: completion='%s', stop_reason='%s'", response.Completion, response.StopReason)
    		message <- PartialResponse{
    			Text:    response.Completion,
    			RawData: []byte(dataContent),
    		}
    		return nil
    	}
    
    	// 尝试解析为新的流式格式（类似OpenAI）
    	var streamResponse struct {
    		Type   string `json:"type"`
    		Index  int    `json:"index"`
    		Delta  struct {
    			Type string `json:"type"`
    			Text string `json:"text"`
    		} `json:"delta"`
    		ContentBlock struct {
    			Type string `json:"type"`
    			Text string `json:"text"`
    		} `json:"content_block"`
    	}
    	
    	if err := json.Unmarshal([]byte(dataContent), &streamResponse); err == nil {
    		text := ""
    		if streamResponse.Delta.Text != "" {
    			text = streamResponse.Delta.Text
    		} else if streamResponse.ContentBlock.Text != "" {
    			text = streamResponse.ContentBlock.Text
    		}
    		
    		if text != "" {
    			logrus.Infof("Parsed stream response: text='%s'", text)
    			message <- PartialResponse{
    				Text:    text,
    				RawData: []byte(dataContent),
    			}
    			return nil
    		}
    	}
    
    	// 尝试解析其他可能的格式
    	var genericResponse map[string]interface{}
    	if err := json.Unmarshal([]byte(dataContent), &genericResponse); err == nil {
    		logrus.Infof("Generic response keys: %v", getKeys(genericResponse))
    		
    		// 寻找可能包含文本内容的字段
    		possibleTextFields := []string{"completion", "text", "content", "message"}
    		for _, field := range possibleTextFields {
    			if value, exists := genericResponse[field]; exists {
    				if textValue, ok := value.(string); ok && textValue != "" {
    					logrus.Infof("Found text in field '%s': %s", field, textValue)
    					message <- PartialResponse{
    						Text:    textValue,
    						RawData: []byte(dataContent),
    					}
    					return nil
    				}
    			}
    		}
    		
    		// 检查嵌套的delta或content字段
    		if delta, exists := genericResponse["delta"]; exists {
    			if deltaMap, ok := delta.(map[string]interface{}); ok {
    				if text, exists := deltaMap["text"]; exists {
    					if textValue, ok := text.(string); ok && textValue != "" {
    						logrus.Infof("Found text in delta.text: %s", textValue)
    						message <- PartialResponse{
    							Text:    textValue,
    							RawData: []byte(dataContent),
    						}
    						return nil
    					}
    				}
    			}
    		}
    	}
    
    	return fmt.Errorf("unable to parse response: %s", dataContent)
    }
    
    // 获取map的所有key
    func getKeys(m map[string]interface{}) []string {
    	keys := make([]string, 0, len(m))
    	for k := range m {
    		keys = append(keys, k)
    	}
    	return keys
    }

// 加载默认模型
func (c *Chat) IsPro() (bool, error) {
	o, err := c.getO()
	if err != nil {
		return false, err
	}

	response, err := emit.ClientBuilder(c.session).
		GET(baseURL+"/bootstrap/"+o+"/statsig").
		Ja3().
		CookieJar(c.opts.jar).
		Header("Origin", "https://claude.ai").
		Header("Referer", "https://claude.ai/").
		Header("Accept-Language", "en-US,en;q=0.9").
		Header("user-agent", userAgent).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return false, err
	}

	defer response.Body.Close()
	value := emit.TextResponse(response)
	compileRegex := regexp.MustCompile(`"custom":{"isPro":true,`)
	matchArr := compileRegex.FindStringSubmatch(value)
	return len(matchArr) > 0, nil
}

// 加载默认模型
func (c *Chat) loadModel() (string, error) {
    o, err := c.getO()
    if err != nil {
        return "", err
    }

    response, err := emit.ClientBuilder(c.session).
        GET(baseURL+"/bootstrap/"+o+"/statsig").
        Ja3().
        CookieJar(c.opts.jar).
        Header("Origin", "https://claude.ai").
        Header("Referer", "https://claude.ai/").
        Header("Accept-Language", "en-US,en;q=0.9").
        Header("user-agent", userAgent).
        DoC(emit.Status(http.StatusOK), emit.IsJSON)
    if err != nil {
        return "", err
    }

    defer response.Body.Close()
    responseBody := emit.TextResponse(response)
    
    // First try to find models array using regex
    modelsRegex := regexp.MustCompile(`"models":\[\{"model":"(claude-[^"]+)"`)
    matchArr := modelsRegex.FindStringSubmatch(responseBody)
    if len(matchArr) > 0 {
        return matchArr[1], nil
    }
    
    // If that fails, try parsing the JSON
    var responseData map[string]interface{}
    if err := json.Unmarshal([]byte(responseBody), &responseData); err == nil {
        if statsig, ok := responseData["statsig"].(map[string]interface{}); ok {
            if values, ok := statsig["values"].(map[string]interface{}); ok {
                // Search for any value containing a models array
                for _, v := range values {
                    if valueObj, ok := v.(map[string]interface{}); ok {
                        if valueValue, ok := valueObj["value"].(map[string]interface{}); ok {
                            if models, ok := valueValue["models"].([]interface{}); ok && len(models) > 0 {
                                if modelObj, ok := models[0].(map[string]interface{}); ok {
                                    if modelName, ok := modelObj["model"].(string); ok {
                                        return modelName, nil
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Fall back to old regex as last resort
    oldRegex := regexp.MustCompile(`"value":{"model":"(claude-[^"]+)"}`)
    matchArr = oldRegex.FindStringSubmatch(responseBody)
    if len(matchArr) > 0 {
        return matchArr[1], nil
    }
    
    // Try one more pattern as last resort
    simpleRegex := regexp.MustCompile(`"model":"(claude-[^"]+)"`)
    matchArr = simpleRegex.FindStringSubmatch(responseBody)
    if len(matchArr) > 0 {
        return matchArr[1], nil
    }
    
    return "", errors.New("failed to fetch the model from the conversation")
}

func (c *Chat) getO() (string, error) {
	if c.oid != "" {
		return c.oid, nil
	}

	response, err := emit.ClientBuilder(c.session).
		GET(baseURL+"/organizations").
		Ja3().
		CookieJar(c.opts.jar).
		Header("Origin", "https://claude.ai").
		Header("Referer", "https://claude.ai/").
		Header("Accept-Language", "en-US,en;q=0.9").
		Header("user-agent", userAgent).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()
	results, err := emit.ToSlice(response)
	if err != nil {
		return "", err
	}

	if uid, _ := results[0]["uuid"]; uid != nil && uid != "" {
		c.oid = uid.(string)
		return c.oid, nil
	}

	return "", errors.New("failed to fetch the organization")
}

// 在chat.go文件中修改getC函数
func (c *Chat) getC(o string) (string, error) {
    if c.cid != "" {
        return c.cid, nil
    }

    payload := map[string]interface{}{
        "name": "",
        "uuid": uuid.New().String(),
        // 直接指定模型，无需检查用户是否为pro
        "model": c.opts.Model,
    }

    // 移除以下代码块
    /*
    pro, err := c.IsPro()
    if err != nil {
        return "", err
    }

    if pro {
        payload["model"] = c.opts.Model
    } else {
        if strings.Contains(c.opts.Model, "opus") || strings.Contains(c.opts.Model, "claude-sonnet-4") || strings.Contains(c.opts.Model, "claude-opus-4") {
            return "", errors.New("failed to used pro model: " + c.opts.Model)
        }
        payload["model"] = c.opts.Model
    }
    */

    response, err := emit.ClientBuilder(c.session).
        POST(baseURL+"/organizations/"+o+"/chat_conversations").
        Ja3().
        CookieJar(c.opts.jar).
        JHeader().
        Header("Origin", "https://claude.ai").
        Header("Referer", "https://claude.ai/").
        Header("Accept-Language", "en-US,en;q=0.9").
        Header("user-agent", userAgent).
        Body(payload).
        DoC(emit.Status(http.StatusCreated), emit.IsJSON)

    if err != nil {
        return "", err
    }

    defer response.Body.Close()
    result, err := emit.ToMap(response)
    if err != nil {
        return "", err
    }

    if uid, ok := result["uuid"]; ok {
        if u, okey := uid.(string); okey {
            c.cid = u
            return u, nil
        }
    }

    return "", errors.New("failed to fetch the conversation")
}
