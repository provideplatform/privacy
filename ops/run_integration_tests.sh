#!/bin/bash

docker-compose -f ./ops/docker-compose-integration.yml build --no-cache
docker-compose -f ./ops/docker-compose-integration.yml up -d
TAGS=integration ./ops/run_local_tests.sh
docker-compose -f ./ops/docker-compose-integration.yml down
