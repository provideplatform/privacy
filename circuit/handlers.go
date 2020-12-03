package circuit

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	provide "github.com/provideservices/provide-go/common"
	"github.com/provideservices/provide-go/common/util"
)

// InstallAPI registers the circuit registry API handlers with gin
func InstallAPI(r *gin.Engine) {
	r.GET("/api/v1/circuits", listCircuitsHandler)
	r.POST("/api/v1/circuits", createCircuitHandler)
	r.GET("/api/v1/circuits/:id", circuitDetailsHandler)
	r.POST("/api/v1/circuits/:id/verify", verifyCircuitHandler)
}

// list/query available circuits in the registry
func listCircuitsHandler(c *gin.Context) {

}

// compile, setup, export verifier
func createCircuitHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	if orgID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	circuit := &Circuit{}
	err = json.Unmarshal(buf, circuit)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if appID == nil {
		circuit.ApplicationID = appID
	}

	if orgID == nil {
		circuit.OrganizationID = orgID
	}

	if circuit.Create() {
		provide.Render(circuit, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = circuit.Errors
		provide.Render(obj, 422, c)
	}
}

// fetch circuit details
func circuitDetailsHandler(c *gin.Context) {

}

// verify circuit
func verifyCircuitHandler(c *gin.Context) {

}
