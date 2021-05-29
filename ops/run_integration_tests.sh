#!/bin/bash

docker build -t privacy-under-test .
# docker build -f test/Dockerfile -t privacy-tests .

docker-compose -f ./ops/docker-compose-integration.yml build --no-cache
docker-compose -f ./ops/docker-compose-integration.yml up -d
TAGS=integration ./ops/run_local_tests.sh
# docker run -e "TAGS=integration" privacy-tests
docker-compose -f ./ops/docker-compose-integration.yml down
