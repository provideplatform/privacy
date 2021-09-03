package circuit

import (
	"encoding/json"
	"fmt"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/privacy/common"
)

const natsCircuitNotificationNoteDeposit = "note.deposited"
const natsCircuitNotificationNoteNullified = "note.nullified"
const natsCircuitNotificationExit = "exit"

// dispatchNotification broadcasts an event to qualified subjects
func (c *Circuit) dispatchNotification(event string) (*nats.PubAck, error) {
	prefix := c.notificationsSubjectPrefix()
	if prefix == nil {
		return nil, fmt.Errorf("failed to dispatch event notification for circuit %s; nil prefix", c.ID.String())
	}
	if event == "" {
		return nil, fmt.Errorf("failed to dispatch event notification for circuit %s", c.ID.String())
	}
	subject := fmt.Sprintf("%s.%s", *prefix, event)
	payload, _ := json.Marshal(map[string]interface{}{})
	return natsutil.NatsJetstreamPublish(subject, payload)
}

// notificationsSubject returns a namespaced subject suitable for pub/sub subscriptions
func (c *Circuit) notificationsSubject(suffix string) *string {
	prefix := c.notificationsSubjectPrefix()
	if prefix == nil {
		return nil
	}
	if suffix == "" {
		return prefix
	}
	return common.StringOrNil(fmt.Sprintf("%s.%s", *prefix, suffix))
}

// notificationsSubjectPrefix returns a hash for use as the pub/sub subject prefix for the circuit
func (c *Circuit) notificationsSubjectPrefix() *string {
	if c.ApplicationID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.circuit.notification.%s.%s", c.ApplicationID.String(), c.ID.String()))
	} else if c.OrganizationID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.circuit.notification.%s.%s", c.OrganizationID.String(), c.ID.String()))
	} else if c.UserID != nil {
		return common.StringOrNil(fmt.Sprintf("privacy.circuit.notification.%s.%s", c.UserID.String(), c.ID.String()))
	}

	return nil
}
