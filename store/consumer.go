package store

import (

	// vault "github.com/provideplatform/provide-go/api/vault"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/provideplatform/privacy/common"
)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("store package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	// var waitGroup sync.WaitGroup
}
