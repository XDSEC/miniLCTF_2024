#!/bin/bash

# 进入到 Docker Compose 文件所在的目录
cd /root/dockerCTF/InjectionS
# 使用 Docker Compose 重启服务
docker-compose down
rm -r InjectionS/data
mkdir InjectionS/data
cp -r data InjectionS
rm -r mysqllllll/mysql/data
mkdir mysqllllll/mysql/data
sleep 3
docker-compose up -d
sleep 15
docker-compose restart

