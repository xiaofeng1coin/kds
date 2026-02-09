# 必须使用 Python 3.11，因为你的 so 文件是 3.11 编译的
FROM python:3.11-slim-bookworm

# 获取构建的目标架构参数 (amd64 或 arm64)
ARG TARGETARCH

# 设置时区
ENV TZ=Asia/Shanghai
RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. 复制源码和资源
COPY app.py .
COPY templates ./templates
COPY static ./static

# 3. 把两个架构的库都复制进去（暂时）
COPY libs-amd64 ./libs-amd64
COPY libs-arm64 ./libs-arm64

# 4. 【核心步骤】根据架构“移花接木”
# 如果是 amd64，就把 libs-amd64 里的 .so 移动出来
# 如果是 arm64，就把 libs-arm64 里的 .so 移动出来
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        echo "正在构建 x86_64 (AMD64) 镜像..." && \
        cp libs-amd64/*.so . ; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        echo "正在构建 ARM64 镜像..." && \
        cp libs-arm64/*.so . ; \
    else \
        echo "不支持的架构: $TARGETARCH" && exit 1; \
    fi && \
    # 移动完后，删除多余的文件夹，保持镜像干净
    rm -rf libs-amd64 libs-arm64

# 5. 配置数据存储目录
ENV IPTV_DATA_DIR=/data
ENV LOG_FILE=/data/info.log
VOLUME ["/data"]

EXPOSE 50085

# 6. 启动应用
# 使用 python 直接运行 app.py
CMD ["python", "app.py"]