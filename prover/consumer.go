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

package prover

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

const natsProverSetupCompleteSubject = "privacy.prover.setup.complete"
const natsProverSetupFailedSubject = "privacy.prover.setup.failed"

const natsCreatedProverSetupSubject = "privacy.prover.setup.pending"
const natsCreatedProverSetupMaxInFlight = 32
const createProverAckWait = time.Hour * 1
const createProverMaxDeliveries = 5

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("prover package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	var waitGroup sync.WaitGroup

	createNatsProverSetupSubscriptions(&waitGroup)
}

func createNatsProverSetupSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			createProverAckWait,
			natsCreatedProverSetupSubject,
			natsCreatedProverSetupSubject,
			natsCreatedProverSetupSubject,
			consumeProverSetupMsg,
			createProverAckWait,
			natsCreatedProverSetupMaxInFlight,
			createProverMaxDeliveries,
			nil,
		)
	}
}

func consumeProverSetupMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during prover setup; %s", r)
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS prover setup message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal prover setup message; %s", err.Error())
		msg.Nak()
		return
	}

	proverID, proverIDOk := params["prover_id"].(string)
	if !proverIDOk {
		common.Log.Warning("failed to unmarshal prover_id during setup message handler")
		msg.Nak()
		return
	}

	db := dbconf.DatabaseConnection()

	prover := &Prover{}
	db.Where("id = ?", proverID).Find(&prover)

	if prover == nil || prover.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve prover during async setup; prover id: %s", proverID)
		msg.Nak()
		return
	}

	err = prover.enrich()
	if err != nil {
		common.Log.Warningf("failed to enrich prover; %s", err.Error())
	}

	if prover.setup(db) {
		common.Log.Debugf("setup completed for prover: %s", prover.ID)
		prover.updateStatus(db, proverStatusProvisioned, nil)
		natsutil.NatsJetstreamPublish(natsProverSetupCompleteSubject, msg.Data)
		msg.Ack()
	} else {
		common.Log.Warningf("setup failed for prover: %s", prover.ID)
		err = fmt.Errorf("unspecified error")
		prover.updateStatus(db, proverStatusFailed, common.StringOrNil(err.Error()))
		natsutil.NatsJetstreamPublish(natsProverSetupFailedSubject, msg.Data)
		msg.Nak()
	}
}
