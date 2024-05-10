FROM postgres:9.6-alpine

ENV TZ=Asia/Shanghai
ENV POSTGRES_PASSWORD=Compl3xPAssw0rD

COPY SmartPark /SmartPark
COPY src.zip /tmp/src.zip
COPY flag /flag
COPY start-smartpark.sh /docker-entrypoint-initdb.d/

RUN chmod +x /SmartPark &\
    chmod +x /docker-entrypoint-initdb.d

EXPOSE 8080
