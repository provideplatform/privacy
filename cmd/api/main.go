package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/token"
	"github.com/provideplatform/privacy/circuit"
	privacycommon "github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/store"

	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond
const jwtVerifierRefreshInterval = 60 * time.Second
const jwtVerifierGracePeriod = 60 * time.Second

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func init() {
	util.RequireJWTVerifiers()
	util.RequireGin()

	privacycommon.RequireVault()
	common.EnableAPIAccounting()
}

func main() {
	common.Log.Debugf("starting privacy API...")
	installSignalHandlers()

	runAPI()

	startAt := time.Now()
	gracePeriodEndAt := startAt.Add(jwtVerifierGracePeriod)
	verifiersRefreshedAt := time.Now()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			now := time.Now()
			if now.Before(gracePeriodEndAt) {
				util.RequireJWTVerifiers()
			} else if now.After(verifiersRefreshedAt.Add(jwtVerifierRefreshInterval)) {
				verifiersRefreshedAt = now
				util.RequireJWTVerifiers()
			}
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting privacy API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for privacy API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down privacy API")
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/status", statusHandler)

	r.Use(token.AuthMiddleware())
	r.Use(common.AccountingMiddleware())
	r.Use(common.RateLimitingMiddleware())

	circuit.InstallAPI(r)
	store.InstallAPI(r)

	srv = &http.Server{
		Addr:    util.ListenAddr,
		Handler: r,
	}

	if util.ServeTLS {
		go srv.ListenAndServeTLS(util.CertificatePath, util.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", util.ListenAddr)
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
