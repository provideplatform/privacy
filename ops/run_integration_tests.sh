#!/bin/bash

function cleanup {
    docker compose -f ./ops/docker-compose.yml down
    docker image rm -f privacy-integration
}
trap cleanup EXIT

docker build -t privacy-under-test .
docker build -f ./test/Dockerfile.integration -t privacy-integration .

docker compose -f ./ops/docker-compose.yml up -d --force-recreate
sleep 30

# database env provided so the test suite can connect directly
# to the privacy db to extract proving/verifiying key ids, which
# are not exposed by the API as they are internal to the service...

docker run -it \
           -e DATABASE_HOST=host.docker.internal \
           -e DATABASE_PASSWORD=privacy \
           -e DATABASE_USER=privacy \
           -e DATABASE_NAME=privacy_dev \
           -e IDENT_API_SCHEME=http \
           -e IDENT_API_HOST=host.docker.internal:8081 \
           -e PRIVACY_API_SCHEME=http \
           -e PRIVACY_API_HOST=host.docker.internal:8080 \
           -e VAULT_API_SCHEME=http \
           -e VAULT_API_HOST=host.docker.internal:8082 \
           privacy-integration
