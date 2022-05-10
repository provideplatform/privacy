# privacy

[![Go Report Card](https://goreportcard.com/badge/github.com/provideplatform/privacy)](https://goreportcard.com/report/github.com/provideplatform/privacy)

Microservice providing a prover registry and compilation, trusted setup, verification and proving capabilities for zero-knowledge provers.

## Supported Prover Providers

The following zkSNARK toolboxes are supported:

- Gnark

## Usage

See the [privacy API Reference](https://docs.provide.services/privacy).

## Run your own privacy with Docker

Requires [Docker](https://www.docker.com/get-started)

```shell
/ops/docker-compose up
```

## Build privacy from source

Requires [GNU Make](https://www.gnu.org/software/make), [Go](https://go.dev/doc/install), [Postgres](https://www.postgresql.org/download), [Redis](https://redis.io/docs/getting-started/installation)

```shell
make build
```

## Executables

The project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description          |
|:----------:|----------------------|
| **`api`**  | Runs the API server. |
| `consumer` | Runs a consumer.     |
| `migrate`  | Runs migrations.     |
