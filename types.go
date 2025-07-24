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

type Attachment struct {
	Content  string `json:"extracted_content"`
	FileName string `json:"file_name"`
	FileSize int    `json:"file_size"`
	FileType string `json:"file_type"`
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

// 在 types.go 文件中添加以下结构体

// FileUploadResponse 文件上传响应
type FileUploadResponse struct {
    FileKind       string      `json:"file_kind"`
    FileUUID       string      `json:"file_uuid"`
    FileName       string      `json:"file_name"`
    CreatedAt      string      `json:"created_at"`
    ThumbnailURL   string      `json:"thumbnail_url"`
    PreviewURL     string      `json:"preview_url"`
    ThumbnailAsset *FileAsset  `json:"thumbnail_asset"`
    PreviewAsset   *FileAsset  `json:"preview_asset"`
}

// FileAsset 文件资源信息
type FileAsset struct {
    URL          string `json:"url"`
    FileVariant  string `json:"file_variant"`
    PrimaryColor string `json:"primary_color"`
    ImageWidth   int    `json:"image_width"`
    ImageHeight  int    `json:"image_height"`
}

// FileAttachment 用于发送消息时的文件附件
type FileAttachment struct {
    FileName string
    FileData []byte
    FileType string
}

func (c ErrorWrapper) Error() string {
	return fmt.Sprintf("[ClaudeError::%s]%s: %s", c.ErrorType.Type, c.ErrorType.Message, c.Detail)
}
