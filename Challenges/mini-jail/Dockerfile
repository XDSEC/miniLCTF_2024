FROM node:22-alpine

RUN apk add --no-cache socat
COPY main.js /

RUN rm /bin/busybox
ENTRYPOINT ["socat", "TCP-LISTEN:9999,fork,reuseaddr", "EXEC:'node ./main.js'"]