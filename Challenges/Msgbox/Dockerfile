FROM python:3.10-alpine

WORKDIR /app

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple PyJWT flask selenium

COPY ./templates /app/templates
COPY app.py /app
COPY robot.py /app

EXPOSE 5000

CMD ["python3", "app.py"]
