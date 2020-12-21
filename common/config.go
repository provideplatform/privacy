package common

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	"github.com/provideservices/provide-go/api/vault"
	"github.com/provideservices/provide-go/common/util"
)

var (
	// Log is the configured logger
	Log *logger.Logger

	// DefaultVault for this privacy instance
	DefaultVault *vault.Vault
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

func RequireVault() {
	util.RequireVault()

	vaults, err := vault.ListVaults(util.DefaultVaultAccessJWT, map[string]interface{}{})
	if err != nil {
		Log.Panicf("failed to fetch vaults for given privacy vault token; %s", err.Error())
	}

	if len(vaults) > 0 {
		// HACK
		DefaultVault = vaults[0]
		Log.Debugf("resolved default privacy vault instance: %s", DefaultVault.ID.String())
	} else {
		DefaultVault, err = vault.CreateVault(util.DefaultVaultAccessJWT, map[string]interface{}{
			"name":        fmt.Sprintf("privacy vault %d", time.Now().Unix()),
			"description": "default privacy vault",
		})
		if err != nil {
			Log.Panicf("failed to create default vaults for privacy instance; %s", err.Error())
		}
		Log.Debugf("created default privacy vault instance: %s", DefaultVault.ID.String())
	}
}
