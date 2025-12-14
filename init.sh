#!/bin/bash

apt install vim python3 python3-pip nginx

cp -f nginx.conf /etc/nginx/nginx.conf
pip install pycryptodome asyncio requests websockets

# 定义下载参数
DOWNLOAD_URL="https://download-installer.cdn.mozilla.net/pub/firefox/releases/146.0/linux-x86_64/zh-TW/firefox-146.0.tar.xz"
FILENAME="firefox-146.0.tar.xz"

echo "开始下载Firefox浏览器..."

# 使用wget下载（如果系统没有wget，会自动使用curl）
if command -v wget &> /dev/null; then
    wget -O "$FILENAME" "$DOWNLOAD_URL"
elif command -v curl &> /dev/null; then
    curl -L -o "$FILENAME" "$DOWNLOAD_URL"
else
    echo "错误：未找到wget或curl，请先安装其中一个下载工具"
    exit 1
fi

# 检查下载是否成功
if [ $? -eq 0 ] && [ -f "$FILENAME" ]; then
    echo "下载完成！文件大小：$(du -h "$FILENAME" | cut -f1)"

    # 解压文件到当前目录
    echo "正在解压文件..."
    tar -xf "$FILENAME"

    # 启动Firefox
    echo "启动Firefox浏览器..."
    ./firefox/firefox https://addons.mozilla.org/zh-TW/firefox/addon/tampermonkey/
else
    echo "下载失败，请检查网络连接和URL有效性"
    exit 1
fi
