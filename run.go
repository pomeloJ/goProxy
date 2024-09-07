package main

import (
        "bytes"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "strings"
        "time"
        "compress/gzip"
		"mime"
		"path"
		"regexp"
)

// 定義 Config 結構體
type Config struct {
        TargetURL            string `json:"target_url"`
        ElasticsearchURL     string `json:"elasticsearch_url"`
        ElasticsearchUsername string `json:"elasticsearch_username"`
        ElasticsearchPassword string `json:"elasticsearch_password"`
        ElasticsearchIndex    string `json:"elasticsearch_index"`
        ListenPort            string `json:"listen_port"`
}

type APILog struct {
        Method         string `json:"method"`
        URL            string `json:"url"`
        Headers        string `json:"headers"`
        Body           string `json:"body,omitempty"`
        FileSummary    string `json:"file_summary,omitempty"`
        ResponseStatus int    `json:"response_status"`
        ResponseBody   string `json:"response_body"`
        ResponseHeaders string `json:"response_headers,omitempty"` // 加入回應 headers
        DurationMs     int    `json:"duration_ms"`
        Timestamp      string `json:"@timestamp"`
}

func main() {
        // 讀取環境變數或參數設置

        // 讀取設定檔
        config, err := loadConfig("config.json")
        if err != nil {
                log.Fatalf("Failed to load config: %v", err)
        }

        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                startTime := time.Now()

                // 讀取請求資料
                body, err := ioutil.ReadAll(r.Body)
                if err != nil {
                        http.Error(w, "Failed to read request body", http.StatusBadRequest)
                        return
                }
                r.Body = ioutil.NopCloser(bytes.NewReader(body))

					// 獲取原始文件名
					originalFilename := getOriginalFilename(r.Header,r.URL.Path)

                // 將標頭轉換為 JSON
                headersJSON, err := json.Marshal(r.Header)
                if err != nil {
                        log.Printf("Failed to marshal headers to JSON: %v", err)
                        http.Error(w, "Server error", http.StatusInternalServerError)
                        return
                }

                // 判斷是否為二進位檔案，並處理
                var bodyContent string
                contentType := r.Header.Get("Content-Type")
                if strings.HasPrefix(contentType, "application/octet-stream") || isBinary(body,contentType) {
                        // 處理為二進位檔案
                        tempFile, err := ioutil.TempFile("", "upload-*")
                        if err != nil {
                                log.Printf("Failed to create temp file: %v", err)
                                http.Error(w, "Server error", http.StatusInternalServerError)
                                return
                        }
                        defer os.Remove(tempFile.Name())

                        if _, err := tempFile.Write(body); err != nil {
                                log.Printf("Failed to write to temp file: %v", err)
                                http.Error(w, "Server error", http.StatusInternalServerError)
                                return
                        }
                        bodyContent = fmt.Sprintf("Filename: %s, Size: %d bytes", originalFilename, len(body))
                } else {
                        // 處理為普通字串
                        bodyContent = string(body)
                }

                // 打印請求資訊到控制台
                log.Printf("Received request: Method=%s, URL=%s, Headers=%s, Body=%s", r.Method, r.URL.String(), headersJSON, bodyContent)

                // 構建最終的轉發 URL
                finalURL := config.TargetURL + r.URL.Path
                if r.URL.RawQuery != "" {
                finalURL += "?" + r.URL.RawQuery
                }

                log.Printf("Forwarding to URL: %s", finalURL)

                // 建立新的請求以轉發
                req, err := http.NewRequest(r.Method, finalURL, bytes.NewReader(body))
                if err != nil {
                        log.Printf("Failed to create request: %v", err)
                        http.Error(w, "Server error", http.StatusInternalServerError)
                        return
                }

                //
                req.Host = r.Host

                // 複製 header
                for name, values := range r.Header {
                        for _, value := range values {
                                req.Header.Add(name, value)
                        }
                }

                client := &http.Client{
		    CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不自動跟隨
		    },
		}
                resp, err := client.Do(req)
                if err != nil {
                        log.Printf("Failed to forward request: %v", err)
                        http.Error(w, "Server error", http.StatusInternalServerError)
                        return
                }
                defer resp.Body.Close()

                // 讀取回應資料
                respBody, err := ioutil.ReadAll(resp.Body)

                // 複製目標伺服器的 headers 到使用者的回應中
                for name, values := range resp.Header {
                        for _, value := range values {
                                w.Header().Add(name, value)
                        }
                }

                // 設置回應狀態碼並回傳給客戶端
                w.WriteHeader(resp.StatusCode)
                w.Write(respBody)

                // 計算請求處理時間
                durationMs := int(time.Since(startTime).Milliseconds())

                // 將回應 headers 轉為 JSON
                responseHeadersJSON, err := json.Marshal(resp.Header)
                if err != nil {
                        log.Printf("Failed to marshal response headers to JSON: %v", err)
                }

                // 讀取回應資料，並判斷是否需要解壓縮
                if err != nil {
                        log.Printf("Failed to read response body: %v", err)
                        http.Error(w, "Server error", http.StatusInternalServerError)
                        return
                }
				// 獲取原始文件名
				originalFilename = getOriginalFilename(resp.Header,resp.Request.URL.Path)

				// 從回應中獲取 Content-Type
				responseContentType := resp.Header.Get("Content-Type")

                var responseBodyContent string
                if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/octet-stream") || isBinary(respBody,responseContentType) {
                        tempRespFile, err := ioutil.TempFile("", "response-*")
                        if err != nil {
                                log.Printf("Failed to create response temp file: %v", err)
                                http.Error(w, "Server error", http.StatusInternalServerError)
                                return
                        }
                        defer os.Remove(tempRespFile.Name())

                        if _, err := tempRespFile.Write(respBody); err != nil {
                                log.Printf("Failed to write to response temp file: %v", err)
                                http.Error(w, "Server error", http.StatusInternalServerError)
                                return
                        }
                        responseBodyContent = fmt.Sprintf("Filename: %s, Size: %d bytes", originalFilename, len(respBody))
                } else {
                        var decompressedBody []byte
                        decompressedBody, err = decompressIfGzip(respBody, resp.Header.Get("Content-Encoding"))
                        if err != nil {
                                log.Printf("Failed to decompress response body: %v", err)
                                responseBodyContent = string(respBody) // 使用原始數據，如果解壓失敗
                        }else {
                                responseBodyContent = string(decompressedBody)
                        }
                }
			

                // 打印回應資訊到控制台
                log.Printf("Response: Status=%d, Body=%s, Duration=%dms", resp.StatusCode, string(responseBodyContent), durationMs)

                // 記錄 API 請求和回應
                apiLog := APILog{
                        Method:         r.Method,
                        URL:            r.URL.String(),
                        Headers:        string(headersJSON),
                        Body:           bodyContent,
                        ResponseStatus: resp.StatusCode,
                        ResponseBody:   string(responseBodyContent),
                        ResponseHeaders: string(responseHeadersJSON), // 記錄回應 headers
                        DurationMs:     durationMs,
                        Timestamp:      time.Now().Format(time.RFC3339),
                }

                // 發送到 Elasticsearch
                go sendToElasticsearch(config.ElasticsearchURL, config.ElasticsearchUsername, config.ElasticsearchPassword, config.ElasticsearchIndex, apiLog)
        })

        // 啟動 proxy 伺服器
        log.Printf("Starting proxy server on port %s", config.ListenPort)
        log.Fatal(http.ListenAndServe(":"+config.ListenPort, nil))
}

func sendToElasticsearch(elasticURL, username, password, index string, logEntry APILog) {
        // 將日誌轉換為 JSON 格式
        logJSON, err := json.Marshal(logEntry)
        if err != nil {
                log.Printf("Failed to marshal log entry to JSON: %v", err)
                return
        }

        // 發送到 Elasticsearch
        url := fmt.Sprintf("%s/%s/_doc", elasticURL, index)
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(logJSON))
        if err != nil {
                log.Printf("Failed to create request to Elasticsearch: %v", err)
                return
        }

        req.Header.Set("Content-Type", "application/json")

        // 添加基本驗證標頭
        auth := username + ":" + password
        req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                log.Printf("Failed to send log to Elasticsearch: %v", err)
                return
        }
        defer resp.Body.Close()

        // 讀取並檢查回應
        respBody, _ := ioutil.ReadAll(resp.Body)
        if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
                log.Printf("Elasticsearch response error: %s", string(respBody))
        } else {
                log.Printf("Log successfully sent to Elasticsearch: %s", string(respBody))
        }
}

func isBinary(data []byte, contentType string) bool {
	// 檢查 content type，如果是已知的文本類型，則直接返回 false
	if strings.HasPrefix(contentType, "text/") || 
		strings.Contains(contentType, "json") || 
		strings.Contains(contentType, "xml") || 
		strings.Contains(contentType, "javascript") || 
		strings.Contains(contentType, "html") {
		 return false
	 }

        // 簡單檢查內容是否為二進位資料
        for _, b := range data {
                if b == 0 {
                        return true
                }
        }
        return false
}

func getEnv(key, defaultValue string) string {
        if value, exists := os.LookupEnv(key); exists {
                return value
        }
        return defaultValue
}

// loadConfig 讀取並解析 JSON 配置檔案
func loadConfig(filePath string) (*Config, error) {
        file, err := os.Open(filePath)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        config := &Config{}
        decoder := json.NewDecoder(file)
        if err := decoder.Decode(config); err != nil {
                return nil, err
        }

        return config, nil
}

// 解壓縮 Gzip 回應
func decompressIfGzip(data []byte, contentEncoding string) ([]byte, error) {
    if contentEncoding == "gzip" {
        reader, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil, err
        }
        defer reader.Close()
        return ioutil.ReadAll(reader)
    }
    return data, nil
}

func getOriginalFilename(header http.Header, url string) string {
    // 首先嘗試從 Content-Disposition 獲取
    contentDisposition := header.Get("Content-Disposition")
    if contentDisposition != "" {
        _, params, err := mime.ParseMediaType(contentDisposition)
        if err == nil {
            if filename, ok := params["filename"]; ok {
                return filename
            }
        }
    }

    // 如果沒有 Content-Disposition，從 URL 提取
    urlPath := path.Base(url)
    
    // 移除查詢參數
    if idx := strings.Index(urlPath, "?"); idx != -1 {
        urlPath = urlPath[:idx]
    }

    // 處理動態路徑參數（如 [id]）
    re := regexp.MustCompile(`\[.*?\]`)
    urlPath = re.ReplaceAllString(urlPath, "dynamic")

    // 如果文件名以 hash 結尾，保留整個文件名
    if matched, _ := regexp.MatchString(`-[a-f0-9]{10,}\.`, urlPath); matched {
        return urlPath
    }

    // 否則，只保留基本名稱和擴展名
    return path.Base(urlPath)
}
