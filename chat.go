package claude

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bincooo/emit.io"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"net/textproto"  
)

var (
	ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)

const (
	baseURL   = "https://claude.ai/api"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.79"
)

// 文件处理类型
const (
    FileProcessTypeFiles       = "files"       // 使用files字段（图片、PDF等）
    FileProcessTypeAttachments = "attachments" // 使用attachments字段（文本、代码等）
    FileProcessTypeSpecial     = "special"     // 特殊处理（Excel等）
)

// 定义文件分类映射
var (
    // 使用 files 字段的文件类型（二进制文件）
    filesTypeExtensions = map[string]bool{
        ".jpg":  true,
        ".jpeg": true,
        ".png":  true,
        ".gif":  true,
        ".webp": true,
        ".pdf":  true,
    }
    
    // 使用 attachments 字段的文件类型（文本类文件）
    attachmentsTypeExtensions = map[string]bool{
        // 文档类
        ".txt":  true,
        ".md":   true,
        ".rtf":  true,
        ".tex":  true,
        ".latex": true,
        
        // 代码文件
        ".py":    true,
        ".ipynb": true,
        ".js":    true,
        ".jsx":   true,
        ".ts":    true,
        ".tsx":   true,
        ".mts":   true,
        ".cts":   true,
        ".html":  true,
        ".css":   true,
        ".java":  true,
        ".cs":    true,
        ".php":   true,
        ".c":     true,
        ".cc":    true,
        ".cpp":   true,
        ".cxx":   true,
        ".h":     true,
        ".hh":    true,
        ".hpp":   true,
        ".rs":    true,
        ".r":     true,
        ".rmd":   true,
        ".swift": true,
        ".go":    true,
        ".rb":    true,
        ".kt":    true,
        ".kts":   true,
        ".m":     true,
        ".mm":    true,
        ".scala": true,
        ".dart":  true,
        ".lua":   true,
        ".pl":    true,
        ".pm":    true,
        ".t":     true,
        ".sh":    true,
        ".bash":  true,
        ".zsh":   true,
        ".bat":   true,
        ".coffee": true,
        ".gd":    true,
        ".gdshader": true,
        
        // 配置文件
        ".ini":    true,
        ".cfg":    true,
        ".config": true,
        ".json":   true,
        ".yaml":   true,
        ".yml":    true,
        ".toml":   true,
        ".proto":  true,
        
        // 数据文件
        ".csv":    true,
        ".log":    true,
        ".sql":    true,
        
        // 其他文本格式
        ".tres":   true,
        ".tscn":   true,
    }
    
    // 需要特殊处理的文件类型
    specialTypeExtensions = map[string]bool{
        ".docx":  true,
        ".epub":  true,
        ".odt":   true,
        ".odp":   true,
        ".xls":   true,
        ".xlsx":  true,
        ".xlsb":  true,
        ".xlm":   true,
        ".xlsm":  true,
        ".xlt":   true,
        ".xltm":  true,
        ".xltx":  true,
        ".ods":   true,
    }
)

// GetFileProcessType 获取文件的处理类型
func GetFileProcessType(fileName string) string {
    ext := strings.ToLower(filepath.Ext(fileName))
    
    if filesTypeExtensions[ext] {
        return FileProcessTypeFiles
    }
    if attachmentsTypeExtensions[ext] {
        return FileProcessTypeAttachments
    }
    if specialTypeExtensions[ext] {
        return FileProcessTypeSpecial
    }
    
    // 默认作为附件处理
    return FileProcessTypeAttachments
}

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

// 文件上传响应结构
type FileUploadResponse struct {
	FileKind      string        `json:"file_kind"`
	FileUUID      string        `json:"file_uuid"`
	FileName      string        `json:"file_name"`
	CreatedAt     string        `json:"created_at"`
	ThumbnailURL  string        `json:"thumbnail_url"`
	PreviewURL    string        `json:"preview_url"`
	ThumbnailAsset *AssetInfo   `json:"thumbnail_asset,omitempty"`
	PreviewAsset   *AssetInfo   `json:"preview_asset,omitempty"`
}

type AssetInfo struct {
	URL         string `json:"url"`
	FileVariant string `json:"file_variant"`
	PrimaryColor string `json:"primary_color"`
	ImageWidth   int    `json:"image_width"`
	ImageHeight  int    `json:"image_height"`
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

func Ja3(j string) {
	ja3 = j
}

func NewDefaultOptions(cookies string, model string, mode string) (*Options, error) {
	options := Options{
		Retry: 2,
		Model: model,
		Mode:  mode,
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

// 修改 ReplyWithFiles 方法，新的签名
func (c *Chat) ReplyWithFiles(ctx context.Context, message string, fileUUIDs []string, attachments []Attachment) (chan PartialResponse, error) {
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
        r, err := c.PostMessageWithFiles(message, fileUUIDs, attachments)  // 这里修复了，添加了 attachments 参数
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

// 保持向后兼容
func (c *Chat) Reply(ctx context.Context, message string, attrs []Attachment) (chan PartialResponse, error) {
    return c.ReplyWithFiles(ctx, message, []string{}, attrs)
}


// 原始的PostMessage方法，保持向后兼容
func (c *Chat) PostMessage(message string, attrs []Attachment) (*http.Response, error) {
    return c.PostMessageWithFiles(message, []string{}, attrs)
}

func (c *Chat) PostMessageWithFiles(message string, fileUUIDs []string, attachments []Attachment) (*http.Response, error) {
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

    // 构建payload
    payload := map[string]interface{}{
        "prompt":               message,
        "parent_message_uuid":  "00000000-0000-4000-8000-000000000000",
        "timezone":             "Asia/Shanghai",
        "locale":               "en-US",
        "rendering_mode":       "messages",
        "attachments":          attachments,  // 文本类文件
        "files":                fileUUIDs,    // 二进制文件UUID
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

    // 只有特定模型才需要在completion请求中指定model
    if strings.Contains(c.opts.Model, "claude-3-7") || strings.Contains(c.opts.Model, "claude-3-5") || strings.Contains(c.opts.Model, "claude-3-opus") {
        payload["model"] = c.opts.Model
    }

    logrus.Infof("发送请求 - 模型: %s, files数: %d, attachments数: %d", 
        c.opts.Model, len(fileUUIDs), len(attachments))

    response, err := emit.ClientBuilder(c.session).
        Ja3().
        CookieJar(c.opts.jar).
        POST(baseURL+"/organizations/"+organizationId+"/chat_conversations/"+conversationId+"/completion").
        Header("referer", "https://claude.ai/chat/"+conversationId).
        Header("accept", "text/event-stream").
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


// 文件上传方法
func (c *Chat) UploadFile(fileName string, fileData []byte, contentType string) (*FileUploadResponse, error) {
	// 获取文件类型信息
	fileInfo := GetFileTypeInfo(fileName)
	if contentType == "" {
		contentType = fileInfo.MimeType
	}
	
	// 检查文件大小
	maxSize := GetMaxFileSizeForType(fileInfo.FileKind)
	if int64(len(fileData)) > maxSize {
		return nil, fmt.Errorf("file size %d exceeds maximum allowed size %d for %s files", 
			len(fileData), maxSize, fileInfo.FileKind)
	}
	
	// 获取组织ID
	oid, err := c.getO()
	if err != nil {
		return nil, fmt.Errorf("fetch organization failed: %v", err)
	}

	// 创建multipart writer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	

	// 手动创建带正确Content-Type的部分
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, fileName))
	h.Set("Content-Type", contentType) // 使用传入的contentType

	part, err := writer.CreatePart(h)
	if err != nil {
    		return nil, err
	}

	
	// 写入文件数据
	if _, err := part.Write(fileData); err != nil {
		return nil, err
	}
	
	// 关闭writer
	if err := writer.Close(); err != nil {
		return nil, err
	}
	
	logrus.Infof("Uploading file: %s (type: %s, kind: %s, size: %d bytes)", 
		fileName, contentType, fileInfo.FileKind, len(fileData))
	
	
	// 发送请求
	response, err := emit.ClientBuilder(c.session).
		POST(baseURL+"/"+oid+"/upload").
		Ja3().
		CookieJar(c.opts.jar).
		Header("content-type", writer.FormDataContentType()).
		Header("origin", "https://claude.ai").
		Header("referer", "https://claude.ai/new").
		Header("anthropic-client-platform", "web_claude_ai").
		Header("user-agent", userAgent).
		Bytes(body.Bytes()).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	
	if err != nil {
		return nil, err
	}
	
	defer response.Body.Close()
	
	var uploadResp FileUploadResponse
	if err := json.NewDecoder(response.Body).Decode(&uploadResp); err != nil {
		return nil, err
	}
	
	logrus.Infof("File uploaded successfully: UUID=%s, Kind=%s", uploadResp.FileUUID, uploadResp.FileKind)
	
	return &uploadResp, nil
}

// 批量上传文件的便捷方法
func (c *Chat) UploadFiles(files map[string][]byte) ([]*FileUploadResponse, error) {
	var responses []*FileUploadResponse
	
	for fileName, fileData := range files {
		resp, err := c.UploadFile(fileName, fileData, "")
		if err != nil {
			return responses, fmt.Errorf("failed to upload %s: %v", fileName, err)
		}
		responses = append(responses, resp)
	}
	
	return responses, nil
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
	logrus.Infof("Response Headers: %+v", r.Header)
	
	eventCount := 0
	var currentText strings.Builder
	
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

// 检查是否为Pro用户
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
		"model": c.opts.Model,
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
