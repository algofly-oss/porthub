#!/bin/bash

cat > ./server.toml <<EOF
[server]
bind_addr = "0.0.0.0:${RATHOLE_PORT}"

[server.services.dummy]
token = "dummy"
bind_addr = "0.0.0.0:666666"
EOF
chmod 777 ./server.toml


if [ "$API_DEBUG" = "True" ]; then
    echo "Running Development Server"
    uvicorn main:app --reload --host 0.0.0.0 --port 8080
else
    echo "Running Production Server"
    uvicorn main:app --host 0.0.0.0 --port 8080 --workers ${API_NUM_WORKERS:-4}
fi