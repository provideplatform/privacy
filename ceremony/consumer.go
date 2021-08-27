package ceremony

import (
	"encoding/json"
	"sync"
	"time"

	// vault "github.com/provideplatform/provide-go/api/vault"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideplatform/privacy/common"
)

const natsCeremonyPendingSubject = "privacy.ceremony.pending"
const ceremonyPendingAckWait = time.Second * 5
const ceremonyPendingTimeout = int64(time.Minute * 1)
const ceremonyPendingMaxInFlight = 512

const natsCeremonyCompleteSubject = "privacy.ceremony.complete"
const ceremonyCompleteAckWait = time.Hour * 1
const ceremonyCompleteTimeout = int64(time.Hour * 1)
const ceremonyCompleteMaxInFlight = 512

const natsGenerateCeremonyEntropySubject = "privacy.ceremony.entropy.generate"
const ceremonyGenerateEntropyAckWait = time.Hour * 1
const ceremonyGenerateEntropyTimeout = int64(time.Hour * 6)
const ceremonyGenerateEntropyMaxInFlight = 1024

const ceremonyStatusComplete = "complete"
const ceremonyStatusCreated = "created"
const ceremonyStatusFailed = "failed"
const ceremonyStatusInit = "init"
const ceremonyStatusPending = "pending"

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("ceremony package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsCeremonyPendingSubscriptions(&waitGroup)
}

func createNatsCeremonyPendingSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			ceremonyPendingAckWait,
			natsCeremonyPendingSubject,
			natsCeremonyPendingSubject,
			consumeCeremonyPendingMsg,
			ceremonyPendingAckWait,
			ceremonyPendingMaxInFlight,
			nil,
		)
	}
}

func createNatsCeremonyCompleteSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			ceremonyPendingAckWait,
			natsCeremonyCompleteSubject,
			natsCeremonyCompleteSubject,
			consumeCeremonyCompleteMsg,
			ceremonyCompleteAckWait,
			ceremonyCompleteMaxInFlight,
			nil,
		)
	}
}

func createNatsGenerateCeremonyEntropySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			ceremonyGenerateEntropyAckWait,
			natsGenerateCeremonyEntropySubject,
			natsGenerateCeremonyEntropySubject,
			consumeCeremonyGenerateEntropyMsg,
			ceremonyPendingAckWait,
			ceremonyPendingMaxInFlight,
			nil,
		)
	}
}

func consumeCeremonyPendingMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during pending ceremony state transition; %s", r)
			natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS pending ceremony message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal pending ceremony message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	ceremonyID, ceremonyIDOk := params["ceremony_id"].(string)
	if !ceremonyIDOk {
		common.Log.Warning("failed to unmarshal ceremony_id during pending message message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	ceremony := &Ceremony{}
	db.Where("id = ?", ceremonyID).Find(&ceremony)

	if ceremony == nil || ceremony.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve ceremony during async pending message handler; ceremony id: %s", ceremonyID)
		natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		return
	}

	err = ceremony.enrich()
	if err != nil {
		common.Log.Warningf("failed to enrich ceremony; %s", err.Error())
	}

	for _, party := range ceremony.Parties {
		common.Log.Debugf("TODO-- dispatch point-to-point message to party: %s", string(party))
	}

	// FIXME... AttemptNack() if anything goes wrong in here...
	msg.Ack()
}

func consumeCeremonyCompleteMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during complete ceremony state transition; %s", r)
			natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS complete ceremony message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal complete ceremony message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	ceremonyID, ceremonyIDOk := params["ceremony_id"].(string)
	if !ceremonyIDOk {
		common.Log.Warning("failed to unmarshal ceremony_id during complete message message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	ceremony := &Ceremony{}
	db.Where("id = ?", ceremonyID).Find(&ceremony)

	if ceremony == nil || ceremony.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve ceremony during async complete message handler; ceremony id: %s", ceremonyID)
		natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		return
	}

	err = ceremony.enrich()
	if err != nil {
		common.Log.Warningf("failed to enrich ceremony; %s", err.Error())
	}

	common.Log.Debugf("TODO... sort %d parties alphanumerically and do something with the calculated entropy", len(ceremony.Parties))

	// FIXME... AttemptNack() if anything goes wrong in here...
	msg.Ack()
}

func consumeCeremonyGenerateEntropyMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during ceremony entropy message transition; %s", r)
			natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS ceremony entropy message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal ceremony entropy message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	ceremonyID, ceremonyIDOk := params["ceremony_id"].(string)
	if !ceremonyIDOk {
		common.Log.Warning("failed to unmarshal ceremony_id during entropy message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	ceremony := &Ceremony{}
	db.Where("id = ?", ceremonyID).Find(&ceremony)

	if ceremony == nil || ceremony.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve ceremony during async ceremony entropy handler; ceremony id: %s", ceremonyID)
		natsutil.AttemptNack(msg, ceremonyPendingTimeout)
		return
	}

	var entropy []byte
	if err != nil {
		common.Log.Warningf("failed to generate entropy for ceremony %s; %s", ceremony.ID, err.Error())
	}

	for _, party := range ceremony.Parties {
		common.Log.Debugf("TODO-- dispatch point-to-point message to party %s to share our calculated %d-byte entropy", string(party), len(entropy))
	}

	// FIXME... AttemptNack() if anything goes wrong in here...
	msg.Ack()
}
