# 使用官方
FROM golang:1.21-alpine

# 設定工作目錄
WORKDIR /app

# 複製當前的go 相關檔案
COPY go.mod go.sum* ./

# 安裝依賴
RUN go mod download

# 將檔案複製到容器內
COPY run.go .
COPY config.json .

# 編譯使用
RUN go build -o main run.go

EXPOSE 8080

# 開始運行
CMD ["./main"]
