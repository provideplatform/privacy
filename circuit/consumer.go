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
const natsCircuitSetupFailedSubject = "privacy.circuit.setup.failed"

const natsCircuitCompileSubject = "privacy.circuit.compile"
const compileCircuitAckWait = time.Hour * 1
const compileCircuitMaxInFlight = 32
const compileCircuitTimeout = int64(time.Hour * 1)

const natsCircuitSetupSubject = "privacy.circuit.setup"
const setupCircuitAckWait = time.Hour * 1
const setupCircuitMaxInFlight = 32
const setupCircuitTimeout = int64(time.Hour * 1)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("circuit package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsCircuitCompileSubscriptions(&waitGroup)
	createNatsCircuitSetupSubscriptions(&waitGroup)
}

func createNatsCircuitCompileSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			compileCircuitAckWait,
			natsCircuitCompileSubject,
			natsCircuitCompileSubject,
			consumeCircuitCompileMsg,
			compileCircuitAckWait,
			compileCircuitMaxInFlight,
			nil,
		)
	}
}

func createNatsCircuitSetupSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			setupCircuitAckWait,
			natsCircuitSetupSubject,
			natsCircuitSetupSubject,
			consumeCircuitSetupMsg,
			setupCircuitAckWait,
			setupCircuitMaxInFlight,
			nil,
		)
	}
}

func consumeCircuitCompileMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit compilation; %s", r)
			natsutil.AttemptNack(msg, compileCircuitTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS circuit compile message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal circuit compile message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	circuitID, circuitIDOk := params["circuit_id"].(string)
	if !circuitIDOk {
		common.Log.Warning("failed to unmarshal circuit_id during compile message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	circuit := &Circuit{}
	db.Where("id = ?", circuitID).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve circuit during async compilation; circuit id: %s", circuitID)
		natsutil.AttemptNack(msg, compileCircuitTimeout)
		return
	}

	if circuit.Source == nil {
		common.Log.Warningf("attempted to compile circuit without source; circuit id: %s", circuitID)
		natsutil.AttemptNack(msg, compileCircuitTimeout)
		return
	}

	// TODO: compile it...

}

func consumeCircuitSetupMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit setup; %s", r)
			natsutil.AttemptNack(msg, setupCircuitTimeout)
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
		natsutil.AttemptNack(msg, setupCircuitTimeout)
		return
	}

	if circuit.setup(db) {
		common.Log.Debugf("setup completed for circuit: %s", circuit.ID)
		circuit.updateStatus(db, circuitStatusProvisioned, nil)
		natsutil.NatsStreamingPublish(natsCircuitSetupCompleteSubject, msg.Data)
		msg.Ack()
	} else {
		common.Log.Warningf("setup failed for circuit: %s; %s", circuit.ID, err.Error())
		circuit.updateStatus(db, circuitStatusFailed, common.StringOrNil(err.Error()))
		natsutil.NatsStreamingPublish(natsCircuitSetupFailedSubject, msg.Data)
		natsutil.AttemptNack(msg, setupCircuitTimeout)
	}
}
