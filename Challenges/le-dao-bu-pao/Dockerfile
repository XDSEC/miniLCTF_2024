FROM linux.xidian.edu.cn/docker/python:3.12-alpine

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install -i https://linux.xidian.edu.cn/mirrors/pypi/simple -r requirements.txt --no-cache-dir

COPY . .

CMD ["python", "backend.py"]
