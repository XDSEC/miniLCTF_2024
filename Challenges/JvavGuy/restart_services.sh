#!/bin/bash

# 进入到 Docker Compose 文件所在的目录
cd /root/dockerCTF
# 使用 Docker Compose 重启服务
docker-compose down
rm -r ruoyi/data
mkdir ruoyi/data
cp ruoyi/flag.txt ruoyi/data/flag.txt
cp ruoyi/ruoyi-admin.jar ruoyi/data/ruoyi-admin.jar
rm -r mysql/mysql/data
mkdir mysql/mysql/data
docker-compose up -d
sleep 15
docker-compose restart

