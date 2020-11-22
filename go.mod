module github.com/provideapp/privacy

go 1.15

require (
	github.com/consensys/gnark v0.3.5
	github.com/consensys/gurvy v0.3.5
	github.com/gin-gonic/gin v1.6.3
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20200602072946-d7d72dfc2531
	github.com/lib/pq v1.4.0 // indirect
	github.com/mattn/go-sqlite3 v2.0.1+incompatible // indirect
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/pkg/errors v0.9.1 // indirect
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20201110145856-2a98ad12dc52
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9 // indirect
)

replace github.com/provideapp/ident => ../ident
