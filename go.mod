module github.com/provideplatform/privacy

go 1.16

require (
	github.com/consensys/gnark v0.4.1-0.20210727143914-9bc74946a2e4
	github.com/consensys/gnark-crypto v0.4.1-0.20210727142540-bc4b1c7132dc
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-natsutil v0.0.0-20200602073459-388e1f070b05
	github.com/kthomas/go-redisutil v0.0.0-20200602073431-aa49de17e9ff
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/nats-io/stan.go v0.9.0
	github.com/onsi/ginkgo v1.16.3 // indirect
	github.com/onsi/gomega v1.13.0 // indirect
	github.com/providenetwork/smt v0.2.1-0.20210726073919-123ac1f043b8
	github.com/provideplatform/ident v0.0.0-00010101000000-000000000000
	github.com/provideplatform/provide-go v0.0.0-20210726092427-952b0a36af58
	github.com/stretchr/testify v1.7.0
)

replace github.com/provideplatform/ident => ../ident
