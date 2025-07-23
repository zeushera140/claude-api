package claude

import (
	
	"fmt"   // 添加这个
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
)

var (
	ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)

const (
	baseURL   = "https://claude.ai/api"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.79"
)


// 原有的旧API响应结构体
type webClaude2Response struct {
	Id           string `json:"id"`
	Completion   string `json:"completion"`
	StopReason   string `json:"stop_reason"`
	Model        string `json:"model"`
	Type         string `json:"type"`
	Truncated    bool   `json:"truncated"`
	Stop         string `json:"stop"`
	LogId        string `json:"log_id"`
	Exception    string `json:"exception"`
	MessageLimit struct {
		Type string `json:"type"`
	} `json:"message_limit"`
}

// 新API的响应结构体
type ClaudeMessage struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Role         string        `json:"role"`
	Model        string        `json:"model"`
	ParentUUID   string        `json:"parent_uuid"`
	UUID         string        `json:"uuid"`
	Content      []interface{} `json:"content"`
	StopReason   interface{}   `json:"stop_reason"`
	StopSequence interface{}   `json:"stop_sequence"`
}

type MessageStartEvent struct {
	Type    string        `json:"type"`
	Message ClaudeMessage `json:"message"`
}

type ContentBlock struct {
	StartTimestamp string        `json:"start_timestamp"`
	StopTimestamp  interface{}   `json:"stop_timestamp"`
	Type           string        `json:"type"`
	Thinking       string        `json:"thinking"`
	Text           string        `json:"text"`
	Summaries      []interface{} `json:"summaries"`
	CutOff         bool          `json:"cut_off"`
}

type ContentBlockStartEvent struct {
	Type         string       `json:"type"`
	Index        int          `json:"index"`
	ContentBlock ContentBlock `json:"content_block"`
}

type ContentBlockDelta struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Thinking string `json:"thinking,omitempty"`
}

type ContentBlockDeltaEvent struct {
	Type  string            `json:"type"`
	Index int               `json:"index"`
	Delta ContentBlockDelta `json:"delta"`
}

type ContentBlockStopEvent struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type MessageStopEvent struct {
	Type string `json:"type"`
}

func Ja3(j string) {
	ja3 = j
}

// 保持原有的Options结构体不变
type Options struct {
	Retry int
	Model string
	Mode  string // paprika mode for Claude 3.x models
	jar   *http.CookieJar
}

// 修改Chat结构体，添加parentMessageUUID字段
type Chat struct {
	opts              *Options
	session           *emit.Session
	oid               string
	cid               string
	mu                sync.Mutex
	parentMessageUUID string // 新增：用于存储上一条消息的UUID
}

// 保持原有的PartialResponse结构体不变
type PartialResponse struct {
	Text    string
	RawData []byte
	Error   error
}

// 保持原有的Attachment结构体不变  
type Attachment struct {
	Content     string `json:"extracted_content"`
	FileName    string `json:"file_name"`
	FileSize    int    `json:"file_size"`
	FileType    string `json:"file_type"`
	TotalPages  int    `json:"total_pages,omitempty"`
	URL         string `json:"url,omitempty"`
	ID          string `json:"id,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
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

	// 检测模型类型，决定使用哪种API
	isNewAPI := c.isNewAPIModel(c.opts.Model)
	
	var payload map[string]interface{}
	var apiPath string
	
	if isNewAPI {
		// Claude 4 及新模型使用新API格式
		apiPath = baseURL + "/api/organizations/" + organizationId + "/chat_conversations/" + conversationId + "/completion"
		
		payload = map[string]interface{}{
			"prompt":              message,
			"parent_message_uuid": c.getParentMessageUUID(), // 获取或生成parent_message_uuid
			"timezone":            "Asia/Shanghai", // 使用实际的时区
			"personalized_styles": []map[string]interface{}{
				{
					"type":       "default",
					"key":        "Default", 
					"name":       "Normal",
					"nameKey":    "normal_style_name",
					"prompt":     "Normal",
					"summary":    "Default responses from Claude",
					"summaryKey": "normal_style_summary",
					"isDefault":  true,
				},
			},
			"locale": "en-US",
			"tools": []map[string]interface{}{
				{"type": "web_search_v0", "name": "web_search"},
				{"type": "artifacts_v0", "name": "artifacts"},
				{"type": "repl_v0", "name": "repl"},
			},
			"attachments":    []interface{}{},
			"files":          []interface{}{},
			"sync_sources":   []interface{}{},
			"rendering_mode": "messages",
		}
		
		if len(attrs) > 0 {
			payload["attachments"] = attrs
		}
		
	} else {
		// Claude 3.x 等旧模型使用旧API格式
		apiPath = baseURL + "/organizations/" + organizationId + "/chat_conversations/" + conversationId + "/completion"
		
		payload = map[string]interface{}{
			"rendering_mode": "raw",
			"files":          make([]string, 0),
			"timezone":       "America/New_York",
			"model":          c.opts.Model,
			"prompt":         message,
		}
		
		// 添加mode参数
		if c.opts.Mode != "" {
			payload["paprika_mode"] = c.opts.Mode
		}
		
		if len(attrs) > 0 {
			payload["attachments"] = attrs
		} else {
			payload["attachments"] = []any{}
		}
	}

	logrus.Infof("发送请求 - 模型: %s, API类型: %s, payload: %+v", c.opts.Model, 
		map[bool]string{true: "新API", false: "旧API"}[isNewAPI], payload)

	// 构建请求，根据API类型添加不同的headers
	requestBuilder := emit.ClientBuilder(c.session).
		Ja3().
		CookieJar(c.opts.jar).
		POST(apiPath).
		Header("referer", "https://claude.ai/chat/"+conversationId).
		Header("accept", "text/event-stream").
		Header("user-agent", userAgent).
		Header("origin", "https://claude.ai").
		JHeader().
		Body(payload)
	
	// 新API需要额外的headers
	if isNewAPI {
		requestBuilder = requestBuilder.
			Header("anthropic-client-platform", "web_claude_ai").
			Header("sec-fetch-dest", "empty").
			Header("sec-fetch-mode", "cors").
			Header("sec-fetch-site", "same-origin")
	}

	response, err := requestBuilder.DoC(emit.Status(http.StatusOK), emit.IsSTREAM)

	if err != nil {
		logrus.Errorf("请求失败 - 模型: %s, 错误类型: %T, 错误内容: %v", c.opts.Model, err, err)
	}

	return response, err
}

// 判断是否为新API模型
func (c *Chat) isNewAPIModel(model string) bool {
	newAPIModels := []string{
		"claude-sonnet-4",
		"claude-opus-4", 
		"claude-4",
	}
	
	for _, newModel := range newAPIModels {
		if strings.Contains(model, newModel) {
			return true
		}
	}
	return false
}

// 获取或生成parent_message_uuid
func (c *Chat) getParentMessageUUID() string {
	// 对于新对话，使用固定的UUID
	// 在实际实现中，这应该是上一条消息的UUID
	if c.parentMessageUUID == "" {
		c.parentMessageUUID = "00000000-0000-4000-8000-000000000000"
	}
	return c.parentMessageUUID
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
	isNewAPI := c.isNewAPIModel(c.opts.Model)
	
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

	// return true 结束轮询
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
		logrus.Trace("--------- ORIGINAL MESSAGE ---------")
		logrus.Trace(string(dataBytes))
		if len(dataBytes) < 6 || !bytes.HasPrefix(dataBytes, prefix2) {
			logrus.Debugf("Invalid data format: %s", string(dataBytes))
			return false
		}

		eventCount++

		if isNewAPI {
			// 处理新API事件格式（Claude 4）
			return c.handleNewAPIEvent(event, dataBytes[6:], message)
		} else {
			// 处理旧API事件格式（Claude 3.x）
			return c.handleOldAPIEvent(event, dataBytes[6:], message)
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

// 处理新API事件（Claude 4）
func (c *Chat) handleNewAPIEvent(event string, data []byte, message chan PartialResponse) bool {
	switch event {
	case "message_start":
		var msgStart MessageStartEvent
		if err := json.Unmarshal(data, &msgStart); err != nil {
			logrus.Errorf("Failed to parse message_start: %v", err)
			return false
		}
		logrus.Infof("Message started: %s", msgStart.Message.UUID)
		// 保存消息UUID用于后续请求
		c.parentMessageUUID = msgStart.Message.UUID
		return false

	case "content_block_start":
		var blockStart ContentBlockStartEvent
		if err := json.Unmarshal(data, &blockStart); err != nil {
			logrus.Errorf("Failed to parse content_block_start: %v", err)
			return false
		}
		logrus.Infof("Content block started: type=%s, index=%d", blockStart.ContentBlock.Type, blockStart.Index)
		return false

	case "content_block_delta":
		var blockDelta ContentBlockDeltaEvent
		if err := json.Unmarshal(data, &blockDelta); err != nil {
			logrus.Errorf("Failed to parse content_block_delta: %v", err)
			return false
		}
		
		// 发送内容增量
		var content string
		if blockDelta.Delta.Text != "" {
			content = blockDelta.Delta.Text
		} else if blockDelta.Delta.Thinking != "" {
			content = blockDelta.Delta.Thinking
		}
		
		if content != "" {
			message <- PartialResponse{
				Text:    content,
				RawData: data,
			}
		}
		return false

	case "content_block_stop":
		var blockStop ContentBlockStopEvent
		if err := json.Unmarshal(data, &blockStop); err != nil {
			logrus.Errorf("Failed to parse content_block_stop: %v", err)
			return false
		}
		logrus.Infof("Content block stopped: index=%d", blockStop.Index)
		return false

	case "message_stop":
		var msgStop MessageStopEvent
		if err := json.Unmarshal(data, &msgStop); err != nil {
			logrus.Errorf("Failed to parse message_stop: %v", err)
			return false
		}
		logrus.Info("Message completed")
		return true

	case "ping":
		logrus.Debug("Received ping event")
		return false

	case "error":
		logrus.Errorf("Received error event: %s", string(data))
		message <- PartialResponse{
			Error: fmt.Errorf("server error: %s", string(data)),
		}
		return true

	default:
		logrus.Warnf("Unknown new API event type: %s, data: %s", event, string(data))
		return false
	}
}

// 处理旧API事件（Claude 3.x）
func (c *Chat) handleOldAPIEvent(event string, data []byte, message chan PartialResponse) bool {
	switch event {
	case "completion":
		var response webClaude2Response
		if err := json.Unmarshal(data, &response); err != nil {
			logrus.Errorf("JSON parse error: %v, Raw: %s", err, string(data))
			return false
		}

		message <- PartialResponse{
			Text:    response.Completion,
			RawData: data,
		}

		return response.StopReason == "stop_sequence"

	case "ping":
		logrus.Debug("Received ping event")
		return false

	case "error":
		logrus.Errorf("Received error event: %s", string(data))
		message <- PartialResponse{
			Error: fmt.Errorf("server error: %s", string(data)),
		}
		return true

	default:
		logrus.Warnf("Unknown old API event type: %s, data: %s", event, string(data))
		
		// 尝试解析为completion格式
		var response webClaude2Response
		if err := json.Unmarshal(data, &response); err == nil && response.Completion != "" {
			logrus.Infof("Successfully parsed unknown event as completion")
			message <- PartialResponse{
				Text:    response.Completion,
				RawData: data,
			}
			return response.StopReason == "stop_sequence"
		}
		
		return false
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
