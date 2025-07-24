package claude

import (
	"fmt"
	"github.com/bincooo/emit.io"
	"net/http"
	"sync"
)

type Chat struct {
	mu   sync.Mutex
	opts *Options

	oid string
	cid string

	session *emit.Session
}

// 在types.go文件中修改Attachment结构体
type Attachment struct {
    Content  string `json:"extracted_content"` // 可能为空，取决于文件类型
    FileName string `json:"file_name"`
    FileSize int    `json:"file_size"`
    FileType string `json:"file_type"`
    FileUUID string `json:"file_uuid,omitempty"` // 新增字段，用于引用已上传的文件
}

type Options struct {
    Retry   int    // 重试次数
    BotId   string // slack里的claude-id
    Model   string // 提供两个模型：slack 、 web-claude-2
    Mode    string // 思考模式: extended 或空
    Proxies string // 本地代理
    BaseURL string // 可代理转发
    jar     http.CookieJar
}

type PartialResponse struct {
	Error   error  `json:"-"`
	Text    string `json:"text"`
	RawData []byte `json:"-"`
}

type ErrorWrapper struct {
	ErrorType ErrorType `json:"error"`
	Detail    string    `json:"detail"`
}

type ErrorType struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (c ErrorWrapper) Error() string {
	return fmt.Sprintf("[ClaudeError::%s]%s: %s", c.ErrorType.Type, c.ErrorType.Message, c.Detail)
}
