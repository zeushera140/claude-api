package claude

import (
	"time"  // 添加这个
	"fmt"   // 添加这个
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bincooo/emit.io"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
)

var (
	ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)

const (
	baseURL   = "https://claude.ai/api"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.79"
)


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

func (c *Chat) Reply(ctx context.Context, message string, attrs []Attachment) (chan PartialResponse, error) {
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
		r, err := c.PostMessage(message, attrs)
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

func (c *Chat) PostMessage(message string, attrs []Attachment) (*http.Response, error) {
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
    
    	// 构造新的payload格式
    	payload := map[string]interface{}{
    		"rendering_mode": "raw",
    		"files":          make([]string, 0),
    		"timezone":       "America/New_York",
    		"model":          c.opts.Model,
    		"prompt":         message,
    	}
    	
    	// 添加模式参数
    	if c.opts.Mode != "" {
    		payload["paprika_mode"] = c.opts.Mode
    	} else {
    		// 根据paste.txt信息，某些模型需要paprika_modes
    		if strings.Contains(c.opts.Model, "sonnet-4") || strings.Contains(c.opts.Model, "opus-4") {
    			payload["paprika_mode"] = "extended"
    		}
    	}
    	
    	// 添加附件
    	if len(attrs) > 0 {
    		payload["attachments"] = attrs
    	} else {
    		payload["attachments"] = []any{}
    	}
    
    	logrus.Infof("Sending payload: %+v", payload)
    
    	return emit.ClientBuilder(c.session).
    		Ja3().
    		CookieJar(c.opts.jar).
    		POST(baseURL+"/organizations/"+organizationId+"/chat_conversations/"+conversationId+"/completion").
    		Header("referer", "https://claude.ai").
    		Header("accept", "text/event-stream").
    		Header("accept-language", "en-US,en;q=0.9").
    		Header("cache-control", "no-cache").
    		Header("user-agent", userAgent).
    		Header("x-request-id", fmt.Sprintf("req_%d", time.Now().UnixNano())).
    		JHeader().
    		Body(payload).
    		DoC(emit.Status(http.StatusOK), emit.IsSTREAM)
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
    	logrus.Infof("Response Headers: %v", r.Header)
    	
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
    
    	var eventCount int
    	var lastDataReceived time.Time = time.Now()
    
    	// return true 结束轮询
    	handler := func() bool {
    		if !scanner.Scan() {
    			logrus.Warnf("Scanner stopped. Events processed: %d", eventCount)
    			return true
    		}
    
    		var event string
    		data := scanner.Text()
    		
    		// 记录所有原始数据
    		if strings.TrimSpace(data) != "" {
    			logrus.Infof("Raw line %d: %s", eventCount, data)
    			lastDataReceived = time.Now()
    		}
    
    		if len(data) < 7 || data[:7] != prefix1 {
    			// 可能是数据行或其他格式，继续处理
    			if strings.HasPrefix(data, "data: ") {
    				// 直接处理数据行
    				dataContent := data[6:]
    				logrus.Infof("Direct data line: %s", dataContent)
    				
    				// 尝试解析JSON
    				if err := c.parseAndSendResponse(dataContent, message); err != nil {
    					logrus.Errorf("Failed to parse direct data: %v", err)
    				}
    			}
    			return false
    		}
    		
    		event = data[7:]
    		logrus.Infof("Event type: %s", event)
    		eventCount++
    
    		if !scanner.Scan() {
    			logrus.Warn("No data line after event")
    			return true
    		}
    
    		dataBytes := scanner.Bytes()
    		logrus.Infof("Data bytes length: %d", len(dataBytes))
    		
    		if len(dataBytes) > 0 {
    			logrus.Infof("Raw data: %s", string(dataBytes))
    		}
    		
    		if len(dataBytes) < 6 || !bytes.HasPrefix(dataBytes, prefix2) {
    			logrus.Warnf("Data line doesn't start with 'data: '. Line: %s", string(dataBytes))
    			return false
    		}
    
    		dataContent := string(dataBytes[6:])
    		logrus.Infof("Processing event '%s' with data: %s", event, dataContent)
    
    		// 不再严格限制事件类型，尝试解析所有包含内容的事件
    		if event == "completion" || event == "content_block_delta" || event == "message_delta" || strings.Contains(event, "delta") {
    			if err := c.parseAndSendResponse(dataContent, message); err != nil {
    				logrus.Errorf("Failed to parse %s event: %v", event, err)
    				return false
    			}
    		} else {
    			logrus.Warnf("Unknown event type: %s, data: %s", event, dataContent)
    			// 尝试解析是否包含completion内容
    			if err := c.parseAndSendResponse(dataContent, message); err != nil {
    				logrus.Debugf("Data doesn't contain completion: %v", err)
    			}
    		}
    
    		return false // 继续处理更多事件
    	}
    
    	// 添加超时检测
    	ticker := time.NewTicker(30 * time.Second)
    	defer ticker.Stop()
    
    	for {
    		select {
    		case <-ctx.Done():
    			logrus.Warn("Context cancelled")
    			message <- PartialResponse{
    				Error: errors.New("resolve timeout"),
    			}
    			return
    		case <-ticker.C:
    			if time.Since(lastDataReceived) > 45*time.Second {
    				logrus.Warn("No data received for 45 seconds, ending stream")
    				return
    			}
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

func (c *Chat) getC(o string) (string, error) {
	if c.cid != "" {
		return c.cid, nil
	}

	payload := map[string]interface{}{
		"name": "",
		"uuid": uuid.New().String(),
	}

	pro, err := c.IsPro()
	if err != nil {
		return "", err
	}

	if pro {
		// 尊贵的pro
		payload["model"] = c.opts.Model
	} else {
		if strings.Contains(c.opts.Model, "opus") {
			return "", errors.New("failed to used pro model: " + c.opts.Model)
		}
	}

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
