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

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/privacy/common"
)

const natsProverNotificationNoteDeposit = "note.deposited"
const natsProverNotificationNoteNullified = "note.nullified"
const natsProverNotificationExit = "exit"

// dispatchNotification broadcasts an event to qualified subjects
func (c *Prover) dispatchNotification(event string) (*nats.PubAck, error) {
	prefix := c.notificationsSubjectPrefix()
	if prefix == nil {
		return nil, fmt.Errorf("failed to dispatch event notification for prover %s; nil prefix", c.ID.String())
	}
	if event == "" {
		return nil, fmt.Errorf("failed to dispatch event notification for prover %s", c.ID.String())
	}
	subject := fmt.Sprintf("%s.%s", *prefix, event)
	payload, _ := json.Marshal(map[string]interface{}{})
	return natsutil.NatsJetstreamPublish(subject, payload)
}

// notificationsSubject returns a namespaced subject suitable for pub/sub subscriptions
func (c *Prover) notificationsSubject(suffix string) *string {
	prefix := c.notificationsSubjectPrefix()
	if prefix == nil {
		return nil
	}
	if suffix == "" {
		return prefix
	}
	return common.StringOrNil(fmt.Sprintf("%s.%s", *prefix, suffix))
}

// notificationsSubjectPrefix returns a hash for use as the pub/sub subject prefix for the prover
func (c *Prover) notificationsSubjectPrefix() *string {
	if c.ApplicationID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.prover.notification.%s.%s", c.ApplicationID.String(), c.ID.String()))
	} else if c.OrganizationID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.prover.notification.%s.%s", c.OrganizationID.String(), c.ID.String()))
	} else if c.UserID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.prover.notification.%s.%s", c.UserID.String(), c.ID.String()))
	}

	return nil
}
