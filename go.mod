module github.com/provideapp/privacy

go 1.15

require (
	github.com/consensys/gnark v0.3.9-0.20210323041009-9d45dc9fb3b0
	github.com/consensys/gurvy v0.3.8
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20210411034702-66a0af9aee2c
	github.com/kthomas/go-natsutil v0.0.0-20200602073459-388e1f070b05
	github.com/kthomas/go-redisutil v0.0.0-20200602073431-aa49de17e9ff
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/lib/pq v1.9.0 // indirect
	github.com/mattn/go-sqlite3 v2.0.1+incompatible // indirect
	github.com/nats-io/stan.go v0.7.0
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20210417062455-af87b626b04d
	github.com/stretchr/testify v1.7.0
)

replace github.com/provideapp/ident => ../ident
