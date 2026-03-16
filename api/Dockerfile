FROM python:3.10
WORKDIR /app
COPY . .

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive

# Install python packages
ENV PYTHONPATH="/usr/lib/python3/dist-packages":$PYTHONPATH
RUN pip install -r /app/requirements.txt --no-cache-dir

CMD chmod +x /app/entrypoint.sh && /app/entrypoint.sh