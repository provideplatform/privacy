package circuit

import (
	"encoding/json"
	"sync"
	"time"

	// vault "github.com/provideservices/provide-go/api/vault"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/privacy/common"
)

const natsCircuitSetupCompleteSubject = "privacy.circuit.setup.complete"
const natsCircuitSetupFailedsSubject = "privacy.circuit.setup.failed"

const natsCreatedCircuitSetupSubject = "privacy.circuit.setup.pending"
const natsCreatedCircuitSetupMaxInFlight = 32
const createCircuitAckWait = time.Hour * 1
const createCircuitTimeout = int64(time.Hour * 1)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("circuit package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsCircuitSetupSubscriptions(&waitGroup)
}

func createNatsCircuitSetupSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			createCircuitAckWait,
			natsCreatedCircuitSetupSubject,
			natsCreatedCircuitSetupSubject,
			consumeCircuitSetupMsg,
			createCircuitAckWait,
			natsCreatedCircuitSetupMaxInFlight,
			nil,
		)
	}
}

func consumeCircuitSetupMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit setup; %s", r)
			natsutil.AttemptNack(msg, createCircuitTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS circuit setup message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal circuit setup message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	circuitID, circuitIDOk := params["circuit_id"].(string)
	if !circuitIDOk {
		common.Log.Warning("failed to unmarshal circuit_id during setup message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	circuit := &Circuit{}
	db.Where("id = ?", circuitID).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve circuit during async setup; circuit id: %s", circuitID)
		natsutil.AttemptNack(msg, createCircuitTimeout)
		return
	}

	if circuit.setup(db) {
		common.Log.Debugf("setup completed for circuit: %s", circuit.ID)
		msg.Ack()
	} else {
		common.Log.Warningf("setup failed for circuit: %s; %s", circuit.ID, err.Error())
		natsutil.AttemptNack(msg, createCircuitTimeout)
		circuit.updateStatus(db, circuitStatusFailed, common.StringOrNil(err.Error()))
	}
}
