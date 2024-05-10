FROM openjdk:8u342-slim

RUN sed -i s@/deb.debian.org/@/mirrors.aliyun.com/@g /etc/apt/sources.list && apt-get -y update &&apt-get -y install gcc
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN groupadd -r admin && useradd -r -g admin admin
RUN mkdir /opt/app
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY ezfastjson-0.0.1-SNAPSHOT.jar /opt/app/ezfastjson-0.0.1-SNAPSHOT.jar
COPY list /list
COPY flag /flag
RUN chown admin:admin /list &&\
    chmod 111 /list &&\
    chmod g+s /list &&\
    chmod +x /docker-entrypoint.sh &&\
    chown admin:admin /flag && chmod 440 /flag


WORKDIR /opt/app
RUN rm -f /bin/chmod /usr/bin/chmod /bin/chown /usr/bin/chown
USER ctf
CMD ["java","-jar","/opt/app/ezfastjson-0.0.1-SNAPSHOT.jar"]
