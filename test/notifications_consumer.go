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

const natsProverNotificationNoteDeposit = "note.deposited"
const natsProverNotificationNoteNullified = "note.nullified"
const natsProverNotificationExit = "exit"

const natsProverNotificationMaxInFlight = 32
const natsProverNotificationAckWait = time.Hour * 1
const natsProverNotificationTimeout = int64(time.Hour * 1)
const natsProverNotificationMaxDeliveries = 5

func init() {
	if os.Getenv("PRIVACY_NOTIFICATION_ORGANIZATION_ID") == "" {
		common.Log.Debug("prover consumer not configured to establish org subscriptions")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	// TODO-- setup stream

	var waitGroup sync.WaitGroup
	createNatsProverNotificationNoteDepositSubscription(&waitGroup)
	createNatsProverNotificationNoteNullifiedSubscription(&waitGroup)
	createNatsProverNotificationExitSubscription(&waitGroup)
}

func natsProverNotificationSubject(event string) (*string, error) {
	orgUUID, err := uuid.FromString(os.Getenv("PRIVACY_NOTIFICATION_ORGANIZATION_ID"))
	if err != nil {
		return nil, err
	}
	// return common.StringOrNil(NotificationsSubjectFactory(orgUUID, event)), nil
	return common.StringOrNil(fmt.Sprintf("org uuid %s event %s", orgUUID.String(), event)), nil
}

// createNatsProverNotificationNoteDepositSubscription
func createNatsProverNotificationNoteDepositSubscription(wg *sync.WaitGroup) {
	// subscribe to deposits...
	subject, err := natsProverNotificationSubject(natsProverNotificationNoteDeposit)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsProverNotificationAckWait,
		*subject,
		*subject,
		*subject,
		proverNoteDepositHandler,
		natsProverNotificationAckWait,
		natsProverNotificationMaxInFlight,
		natsProverNotificationMaxDeliveries,
		nil,
	)
}

// createNatsProverNotificationNoteNullifiedSubscription
func createNatsProverNotificationNoteNullifiedSubscription(wg *sync.WaitGroup) {
	// subscribe to note nullifications...
	subject, err := natsProverNotificationSubject(natsProverNotificationNoteNullified)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsProverNotificationAckWait,
		*subject,
		*subject,
		*subject,
		proverNoteNullifiedHandler,
		natsProverNotificationAckWait,
		natsProverNotificationMaxInFlight,
		natsProverNotificationMaxDeliveries,
		nil,
	)
}

// createNatsProverNotificationExitSubscription
func createNatsProverNotificationExitSubscription(wg *sync.WaitGroup) {
	// subscribe to exits...
	subject, err := natsProverNotificationSubject(natsProverNotificationExit)
	if err != nil {
		panic(err)
	}

	natsutil.RequireNatsJetstreamSubscription(wg,
		natsProverNotificationAckWait,
		*subject,
		*subject,
		*subject,
		proverExitHandler,
		natsProverNotificationAckWait,
		natsProverNotificationMaxInFlight,
		natsProverNotificationMaxDeliveries,
		nil,
	)
}

func proverNoteDepositHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during prover note deposit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func proverNoteNullifiedHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during prover note nullified notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func proverExitHandler(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during prover exit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}
