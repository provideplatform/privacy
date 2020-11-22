package common

import (
	"os"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
)

var (
	// Log is the configured logger
	Log *logger.Logger
)

func init() {
	godotenv.Load()

	requireLogger()
}

func requireLogger() {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}

	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpt := os.Getenv("SYSLOG_ENDPOINT")
		endpoint = &endpt
	}

	Log = logger.NewLogger("privacy", lvl, endpoint)
}
