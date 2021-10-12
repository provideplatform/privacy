// +build unit

package test

import (
	"fmt"
	"os"
	"sync"
	"time"

	// vault "github.com/provideplatform/provide-go/api/vault"

	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/privacy/common"
)

const natsCircuitNotificationNoteDeposit = "note.deposited"
const natsCircuitNotificationNoteNullified = "note.nullified"
const natsCircuitNotificationExit = "exit"

const natsCircuitNotificationMaxInFlight = 32
const natsCircuitNotificationAckWait = time.Hour * 1
const natsCircuitNotificationTimeout = int64(time.Hour * 1)
const natsCircuitNotificationMaxDeliveries = 5

func init() {
	if os.Getenv("PRIVACY_NOTIFICATION_ORGANIZATION_ID") == "" {
		common.Log.Debug("circuit consumer not configured to establish org subscriptions")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	// TODO-- setup stream

	var waitGroup sync.WaitGroup
	createNatsCircuitNotificationNoteDepositSubscription(&waitGroup)
	createNatsCircuitNotificationNoteNullifiedSubscription(&waitGroup)
	createNatsCircuitNotificationExitSubscription(&waitGroup)
}

func natsCircuitNotificationSubject(event string) (*string, error) {
	orgUUID, err := uuid.FromString(os.Getenv("PRIVACY_NOTIFICATION_ORGANIZATION_ID"))
	if err != nil {
		return nil, err
	}
	// return common.StringOrNil(NotificationsSubjectFactory(orgUUID, event)), nil
	return common.StringOrNil(fmt.Sprintf("org uuid %s event %s", orgUUID.String(), event)), nil
}

// createNatsCircuitNotificationNoteDepositSubscription
func createNatsCircuitNotificationNoteDepositSubscription(wg *sync.WaitGroup) {
	// subscribe to deposits...
	subject, err := natsCircuitNotificationSubject(natsCircuitNotificationNoteDeposit)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsCircuitNotificationAckWait,
		*subject,
		*subject,
		*subject,
		circuitNoteDepositHandler,
		natsCircuitNotificationAckWait,
		natsCircuitNotificationMaxInFlight,
		natsCircuitNotificationMaxDeliveries,
		nil,
	)
}

// createNatsCircuitNotificationNoteNullifiedSubscription
func createNatsCircuitNotificationNoteNullifiedSubscription(wg *sync.WaitGroup) {
	// subscribe to note nullifications...
	subject, err := natsCircuitNotificationSubject(natsCircuitNotificationNoteNullified)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsCircuitNotificationAckWait,
		*subject,
		*subject,
		*subject,
		circuitNoteNullifiedHandler,
		natsCircuitNotificationAckWait,
		natsCircuitNotificationMaxInFlight,
		natsCircuitNotificationMaxDeliveries,
		nil,
	)
}

// createNatsCircuitNotificationExitSubscription
func createNatsCircuitNotificationExitSubscription(wg *sync.WaitGroup) {
	// subscribe to exits...
	subject, err := natsCircuitNotificationSubject(natsCircuitNotificationExit)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsCircuitNotificationAckWait,
		*subject,
		*subject,
		*subject,
		circuitExitHandler,
		natsCircuitNotificationAckWait,
		natsCircuitNotificationMaxInFlight,
		natsCircuitNotificationMaxDeliveries,
		nil,
	)
}

func circuitNoteDepositHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit note deposit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func circuitNoteNullifiedHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit note nullified notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func circuitExitHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit exit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}
