# 使用官方的 Golang 镜像作为基础镜像
FROM golang:1.21-alpine

# 设置工作目录
WORKDIR /app

# 将当前目录下的 go.mod 和 go.sum 文件（如果存在）复制到容器的工作目录
COPY go.mod go.sum* ./

# 下载依赖
RUN go mod download

# 将源代码复制到容器中
COPY run.go .
COPY config.json .

# 编译应用
RUN go build -o main run.go

EXPOSE 8080

# 运行应用
CMD ["./main"]
