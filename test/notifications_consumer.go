// +build unit

import (
	"os"
	"sync"
	"time"

	// vault "github.com/provideplatform/provide-go/api/vault"

	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideplatform/privacy/common"
)

const natsCircuitNotificationNoteDeposit = "note.deposited"
const natsCircuitNotificationNoteNullified = "note.nullified"
const natsCircuitNotificationExit = "exit"

const natsCircuitNotificationMaxInFlight = 32
const natsCircuitNotificationAckWait = time.Hour * 1
const natsCircuitNotificationTimeout = int64(time.Hour * 1)

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
	return common.StringOrNil(NotificationsSubjectFactory(orgUUID, event)), nil
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
		circuitNoteDepositHandler,
		natsCircuitNotificationAckWait,
		natsCircuitNotificationMaxInFlight,
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
		circuitNoteNullifiedHandler,
		natsCircuitNotificationAckWait,
		natsCreatedCircuitSetupMaxInFlight,
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
		circuitExitHandler,
		natsCircuitNotificationAckWait,
		natsCreatedCircuitSetupMaxInFlight,
		nil,
	)
}

func circuitNoteDepositHandler(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit note deposit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func circuitNoteNullifiedHandler(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit note nullified notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}

func circuitExitHandler(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit exit notification handler; %s", r)
			msg.Nak()
		}
	}()

	// TODO... process it and msg.Ack()
}
