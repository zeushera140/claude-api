package claude

import (
	"fmt"
	"github.com/bincooo/emit.io"
	"net/http"
	"sync"
	 "path/filepath"
    	"strings"
)

// 文件类型常量
const (
    FileKindImage    = "image"
    FileKindDocument = "document"
    FileKindCode     = "code"
    FileKindData     = "data"
    FileKindArchive  = "archive"
    FileKindVideo    = "video"
    FileKindAudio    = "audio"
    FileKindText     = "text"
)

// 支持的文件扩展名映射
var (
    // 图片类型
    imageExtensions = map[string]string{
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png":  "image/png",
        ".gif":  "image/gif",
        ".webp": "image/webp",
        ".bmp":  "image/bmp",
        ".svg":  "image/svg+xml",
        ".ico":  "image/x-icon",
        ".tiff": "image/tiff",
        ".tif":  "image/tiff",
    }
    
    // 文档类型
    documentExtensions = map[string]string{
        ".pdf":  "application/pdf",
        ".doc":  "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls":  "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".ppt":  "application/vnd.ms-powerpoint",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".odt":  "application/vnd.oasis.opendocument.text",
        ".ods":  "application/vnd.oasis.opendocument.spreadsheet",
        ".odp":  "application/vnd.oasis.opendocument.presentation",
        ".rtf":  "application/rtf",
    }
    
    // 代码文件类型
    codeExtensions = map[string]string{
        ".py":     "text/x-python",
        ".js":     "application/javascript",
        ".ts":     "application/typescript",
        ".jsx":    "text/jsx",
        ".tsx":    "text/tsx",
        ".java":   "text/x-java",
        ".c":      "text/x-c",
        ".cpp":    "text/x-c++",
        ".cc":     "text/x-c++",
        ".cxx":    "text/x-c++",
        ".h":      "text/x-c",
        ".hpp":    "text/x-c++",
        ".cs":     "text/x-csharp",
        ".go":     "text/x-go",
        ".rs":     "text/x-rust",
        ".php":    "text/x-php",
        ".rb":     "text/x-ruby",
        ".swift":  "text/x-swift",
        ".kt":     "text/x-kotlin",
        ".scala":  "text/x-scala",
        ".r":      "text/x-r",
        ".m":      "text/x-objc",
        ".mm":     "text/x-objc++",
        ".pl":     "text/x-perl",
        ".sh":     "text/x-sh",
        ".bash":   "text/x-sh",
        ".zsh":    "text/x-sh",
        ".fish":   "text/x-sh",
        ".ps1":    "text/x-powershell",
        ".lua":    "text/x-lua",
        ".vim":    "text/x-vim",
        ".dart":   "text/x-dart",
        ".elm":    "text/x-elm",
        ".clj":    "text/x-clojure",
        ".ex":     "text/x-elixir",
        ".exs":    "text/x-elixir",
        ".erl":    "text/x-erlang",
        ".hrl":    "text/x-erlang",
        ".fs":     "text/x-fsharp",
        ".fsx":    "text/x-fsharp",
        ".fsi":    "text/x-fsharp",
        ".ml":     "text/x-ocaml",
        ".mli":    "text/x-ocaml",
        ".pas":    "text/x-pascal",
        ".pp":     "text/x-pascal",
        ".sql":    "text/x-sql",
        ".asm":    "text/x-asm",
        ".s":      "text/x-asm",
        ".wasm":   "application/wasm",
        ".wat":    "text/x-wat",
    }
    
    // 数据文件类型
    dataExtensions = map[string]string{
        ".json":   "application/json",
        ".xml":    "application/xml",
        ".csv":    "text/csv",
        ".tsv":    "text/tab-separated-values",
        ".yaml":   "text/yaml",
        ".yml":    "text/yaml",
        ".toml":   "text/toml",
        ".ini":    "text/plain",
        ".conf":   "text/plain",
        ".config": "text/plain",
        ".env":    "text/plain",
    }
    
    // 文本文件类型
    textExtensions = map[string]string{
        ".txt":      "text/plain",
        ".md":       "text/markdown",
        ".markdown": "text/markdown",
        ".rst":      "text/x-rst",
        ".tex":      "text/x-tex",
        ".log":      "text/plain",
        ".msg":      "text/plain",
        ".org":      "text/x-org",
        ".asciidoc": "text/asciidoc",
        ".adoc":     "text/asciidoc",
    }
    
    // 压缩文件类型
    archiveExtensions = map[string]string{
        ".zip":    "application/zip",
        ".tar":    "application/x-tar",
        ".gz":     "application/gzip",
        ".bz2":    "application/x-bzip2",
        ".xz":     "application/x-xz",
        ".7z":     "application/x-7z-compressed",
        ".rar":    "application/vnd.rar",
        ".tar.gz": "application/x-gzip",
        ".tar.bz2": "application/x-bzip2",
        ".tar.xz": "application/x-xz",
    }
    
    // 音频文件类型
    audioExtensions = map[string]string{
        ".mp3":  "audio/mpeg",
        ".wav":  "audio/wav",
        ".flac": "audio/flac",
        ".aac":  "audio/aac",
        ".ogg":  "audio/ogg",
        ".wma":  "audio/x-ms-wma",
        ".m4a":  "audio/x-m4a",
        ".opus": "audio/opus",
        ".amr":  "audio/amr",
        ".aiff": "audio/aiff",
        ".au":   "audio/basic",
        ".mid":  "audio/midi",
        ".midi": "audio/midi",
    }
    
    // 视频文件类型
    videoExtensions = map[string]string{
        ".mp4":  "video/mp4",
        ".avi":  "video/x-msvideo",
        ".mkv":  "video/x-matroska",
        ".mov":  "video/quicktime",
        ".wmv":  "video/x-ms-wmv",
        ".flv":  "video/x-flv",
        ".webm": "video/webm",
        ".m4v":  "video/x-m4v",
        ".mpg":  "video/mpeg",
        ".mpeg": "video/mpeg",
        ".3gp":  "video/3gpp",
        ".3g2":  "video/3gpp2",
        ".ogv":  "video/ogg",
    }
)

// FileTypeInfo 包含文件类型的详细信息
type FileTypeInfo struct {
    Extension string
    MimeType  string
    FileKind  string
}

// GetFileTypeInfo 根据文件名获取文件类型信息
func GetFileTypeInfo(fileName string) FileTypeInfo {
    ext := strings.ToLower(filepath.Ext(fileName))
    
    // 处理双扩展名（如 .tar.gz）
    if strings.HasSuffix(strings.ToLower(fileName), ".tar.gz") {
        ext = ".tar.gz"
    } else if strings.HasSuffix(strings.ToLower(fileName), ".tar.bz2") {
        ext = ".tar.bz2"
    } else if strings.HasSuffix(strings.ToLower(fileName), ".tar.xz") {
        ext = ".tar.xz"
    }
    
    // 检查各种类型
    if mimeType, ok := imageExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindImage}
    }
    if mimeType, ok := documentExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindDocument}
    }
    if mimeType, ok := codeExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindCode}
    }
    if mimeType, ok := dataExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindData}
    }
    if mimeType, ok := textExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindText}
    }
    if mimeType, ok := archiveExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindArchive}
    }
    if mimeType, ok := audioExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindAudio}
    }
    if mimeType, ok := videoExtensions[ext]; ok {
        return FileTypeInfo{ext, mimeType, FileKindVideo}
    }
    
    // 默认类型
    return FileTypeInfo{ext, "application/octet-stream", FileKindDocument}
}

// IsSupportedFileType 检查文件是否被支持
func IsSupportedFileType(fileName string) bool {
    info := GetFileTypeInfo(fileName)
    return info.MimeType != "application/octet-stream"
}

// GetMaxFileSizeForType 根据文件类型返回最大允许的文件大小（字节）
func GetMaxFileSizeForType(fileKind string) int64 {
    switch fileKind {
    case FileKindImage:
        return 10 * 1024 * 1024  // 10MB for images
    case FileKindDocument:
        return 25 * 1024 * 1024  // 25MB for documents
    case FileKindCode, FileKindText, FileKindData:
        return 10 * 1024 * 1024  // 10MB for text-based files
    case FileKindArchive:
        return 50 * 1024 * 1024  // 50MB for archives
    case FileKindVideo:
        return 100 * 1024 * 1024 // 100MB for videos
    case FileKindAudio:
        return 25 * 1024 * 1024  // 25MB for audio
    default:
        return 10 * 1024 * 1024  // 10MB default
    }
}

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

func (c ErrorWrapper) Error() string {
	return fmt.Sprintf("[ClaudeError::%s]%s: %s", c.ErrorType.Type, c.ErrorType.Message, c.Detail)
}

