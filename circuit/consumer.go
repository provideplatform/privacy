package circuit

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/privacy/common"
)

const defaultNatsStream = "privacy"

const natsCircuitSetupCompleteSubject = "privacy.circuit.setup.complete"
const natsCircuitSetupFailedSubject = "privacy.circuit.setup.failed"

const natsCreatedCircuitSetupSubject = "privacy.circuit.setup.pending"
const natsCreatedCircuitSetupMaxInFlight = 32
const createCircuitAckWait = time.Hour * 1

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("circuit package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.*", defaultNatsStream),
	})

	var waitGroup sync.WaitGroup

	createNatsCircuitSetupSubscriptions(&waitGroup)
}

func createNatsCircuitSetupSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
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

func consumeCircuitSetupMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during circuit setup; %s", r)
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS circuit setup message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal circuit setup message; %s", err.Error())
		msg.Nak()
		return
	}

	circuitID, circuitIDOk := params["circuit_id"].(string)
	if !circuitIDOk {
		common.Log.Warning("failed to unmarshal circuit_id during setup message handler")
		msg.Nak()
		return
	}

	db := dbconf.DatabaseConnection()

	circuit := &Circuit{}
	db.Where("id = ?", circuitID).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve circuit during async setup; circuit id: %s", circuitID)
		msg.Nak()
		return
	}

	err = circuit.enrich()
	if err != nil {
		common.Log.Warningf("failed to enrich circuit; %s", err.Error())
	}

	if circuit.setup(db) {
		common.Log.Debugf("setup completed for circuit: %s", circuit.ID)
		circuit.updateStatus(db, circuitStatusProvisioned, nil)
		natsutil.NatsJetstreamPublish(natsCircuitSetupCompleteSubject, msg.Data)
		msg.Ack()
	} else {
		common.Log.Warningf("setup failed for circuit: %s", circuit.ID)
		err = fmt.Errorf("unspecified error")
		circuit.updateStatus(db, circuitStatusFailed, common.StringOrNil(err.Error()))
		natsutil.NatsJetstreamPublish(natsCircuitSetupFailedSubject, msg.Data)
		msg.Nak()
	}
}
