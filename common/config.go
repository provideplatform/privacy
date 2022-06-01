/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common/util"
)

var (
	// Log is the configured logger
	Log *logger.Logger

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the privacy instance should consume NATS streamiung subscriptions
	ConsumeNATSStreamingSubscriptions bool

	// DefaultVault for this privacy instance
	DefaultVault *vault.Vault
)

func init() {
	godotenv.Load()
	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"

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

// RequireVault requires the vault service
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
