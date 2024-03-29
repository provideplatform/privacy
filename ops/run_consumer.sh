#!/bin/bash

#
# Copyright 2017-2022 Provide Technologies Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [[ -z "${CONSUME_NATS_STREAMING_SUBSCRIPTIONS}" ]]; then
  CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true
fi

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=debug
fi

if [[ -z "${DATABASE_HOST}" ]]; then
  DATABASE_HOST=localhost
fi

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=privacy_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=privacy
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD=
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

if [[ -z "${IDENT_API_HOST}" ]]; then
  IDENT_API_HOST=localhost:8081
fi

if [[ -z "${IDENT_API_SCHEME}" ]]; then
  IDENT_API_SCHEME=http
fi

if [[ -z "${VAULT_API_HOST}" ]]; then
  VAULT_API_HOST=localhost:8082
fi

if [[ -z "${VAULT_API_SCHEME}" ]]; then
  VAULT_API_SCHEME=http
fi

if [[ -z "${NATS_CLUSTER_ID}" ]]; then
  NATS_CLUSTER_ID=provide
fi

if [[ -z "${NATS_TOKEN}" ]]; then
  NATS_TOKEN=testtoken
fi

if [[ -z "${NATS_URL}" ]]; then
  NATS_URL=nats://localhost:4222
fi

if [[ -z "${NATS_JETSTREAM_URL}" ]]; then
  NATS_JETSTREAM_URL=nats://localhost:4222
fi

if [[ -z "${NATS_STREAMING_CONCURRENCY}" ]]; then
  NATS_STREAMING_CONCURRENCY=1
fi

if [[ -z "${NATS_FORCE_TLS}" ]]; then
  NATS_FORCE_TLS=false
fi

#NATS_ROOT_CA_CERTIFICATES=/Users/kt/selfsigned-ca/ca.pem \
#NATS_TLS_CERTIFICATES='{"/Users/kt/selfsigned-ca/peer.key": "/Users/kt/selfsigned-ca/peer.crt"}' \

if [[ -z "${REDIS_HOSTS}" ]]; then
  REDIS_HOSTS=localhost:6379
fi

if [[ -z "${REDIS_DB_INDEX}" ]]; then
  REDIS_DB_INDEX=1
fi

if [[ -z "${REDIS_LOG_LEVEL}" ]]; then
  REDIS_LOG_LEVEL=info
fi

DATABASE_HOST=$DATABASE_HOST DATABASE_USER=$DATABASE_USER DATABASE_PASSWORD=$DATABASE_PASSWORD DATABASE_NAME=$DATABASE_NAME DATABASE_SUPERUSER=$DATABASE_SUPERUSER DATABASE_SUPERUSER_PASSWORD=$DATABASE_SUPERUSER_PASSWORD ./ops/migrate.sh

CONSUME_NATS_STREAMING_SUBSCRIPTIONS=$CONSUME_NATS_STREAMING_SUBSCRIPTIONS \
NATS_CLUSTER_ID=$NATS_CLUSTER_ID \
NATS_TOKEN=$NATS_TOKEN \
NATS_URL=$NATS_URL \
NATS_STREAMING_CONCURRENCY=$NATS_STREAMING_CONCURRENCY \
NATS_JETSTREAM_URL=$NATS_JETSTREAM_URL \
NATS_FORCE_TLS=$NATS_FORCE_TLS \
DATABASE_HOST=$DATABASE_HOST \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_LOGGING=$DATABSE_LOGGING \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
IDENT_API_HOST=${IDENT_API_HOST} \
IDENT_API_SCHEME=${IDENT_API_SCHEME} \
VAULT_API_HOST=${VAULT_API_HOST} \
VAULT_API_SCHEME=${VAULT_API_SCHEME} \
LOG_LEVEL=$LOG_LEVEL \
REDIS_HOSTS=$REDIS_HOSTS \
REDIS_DB_INDEX=$REDIS_DB_INDEX \
SYSLOG_ENDPOINT=${SYSLOG_ENDPOINT} \
./.bin/consumer
