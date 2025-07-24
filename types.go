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

// UploadResponse 文件上传响应
type UploadResponse struct {
	FileKind      string         `json:"file_kind"`
	FileUUID      string         `json:"file_uuid"`
	FileName      string         `json:"file_name"`
	CreatedAt     string         `json:"created_at"`
	ThumbnailURL  string         `json:"thumbnail_url"`
	PreviewURL    string         `json:"preview_url"`
	ThumbnailAsset *AssetInfo    `json:"thumbnail_asset,omitempty"`
	PreviewAsset   *AssetInfo    `json:"preview_asset,omitempty"`
}

// AssetInfo 资源信息
type AssetInfo struct {
	URL          string `json:"url"`
	FileVariant  string `json:"file_variant"`
	PrimaryColor string `json:"primary_color"`
	ImageWidth   int    `json:"image_width"`
	ImageHeight  int    `json:"image_height"`
}

// FileAttachment 文件附件信息（用于发送消息时）
type FileAttachment struct {
	FileUUID     string `json:"file_uuid"`
	FileName     string `json:"file_name"`
	FileType     string `json:"file_type"`
	ExtractedContent string `json:"extracted_content,omitempty"`
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
