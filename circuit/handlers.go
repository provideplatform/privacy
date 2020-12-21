package circuit

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	"github.com/provideservices/provide-go/api/privacy"
	provide "github.com/provideservices/provide-go/common"
	"github.com/provideservices/provide-go/common/util"
)

func resolveCircuitsQuery(db *gorm.DB, circuitID, orgID, appID *uuid.UUID) *gorm.DB {
	query := db.Where("circuits.id = ?", circuitID)
	if orgID != nil {
		query = query.Where("circuits.organization_id = ?", orgID)
	}
	if appID != nil {
		query = query.Where("circuits.application_id = ?", appID)
	}
	return query
}

// InstallAPI registers the circuit registry API handlers with gin
func InstallAPI(r *gin.Engine) {
	r.GET("/api/v1/circuits", listCircuitsHandler)
	r.POST("/api/v1/circuits", createCircuitHandler)
	r.GET("/api/v1/circuits/:id", circuitDetailsHandler)
	r.POST("/api/v1/circuits/:id/prove", proveCircuitHandler)
	r.POST("/api/v1/circuits/:id/verify", verifyCircuitHandler)
}

// list/query available circuits in the registry
func listCircuitsHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	query := resolveCircuitsQuery(db, nil, orgID, appID)

	var circuits []*Circuit
	provide.Paginate(c, query, &Circuit{}).Find(&circuits)
	// for _, circuit := range circuits {
	// circuit.Enrich(db)
	// }
	provide.Render(circuits, 200, c)
}

// compile, setup, export verifier
func createCircuitHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
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

	if appID != nil {
		circuit.ApplicationID = appID
	}

	if orgID != nil {
		circuit.OrganizationID = orgID
	}

	if userID != nil {
		circuit.UserID = userID
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
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	circuitID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	circuit := &Circuit{}
	resolveCircuitsQuery(db, &circuitID, appID, orgID).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	// circuit.Enrich(db)
	provide.Render(circuit, 200, c)
}

// generate a proof
func proveCircuitHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	circuitID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	circuit := &Circuit{}
	resolveCircuitsQuery(db, &circuitID, appID, orgID).Find(&circuit)
	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	witness, witnessOk := params["witness"].(string)
	if !witnessOk {
		provide.RenderError("witness required for proof generation", 422, c)
		return
	}

	proof, err := circuit.Prove(witness)
	if err != nil {
		provide.RenderError("bad request", 500, c)
		return
	}

	common.Log.Debugf("generated proof: %v", proof)
	provide.Render(&privacy.ProveResponse{
		Proof: proof,
	}, 200, c)
}

// verify a proof
func verifyCircuitHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	circuitID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	circuit := &Circuit{}
	resolveCircuitsQuery(db, &circuitID, appID, orgID).Find(&circuit)
	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	proof, proofOk := params["proof"].(string)
	if !proofOk {
		provide.RenderError("proof required for verification", 422, c)
		return
	}

	witness, witnessOk := params["witness"].(string)
	if !witnessOk {
		provide.RenderError("witness required for verification", 422, c)
		return
	}

	result, err := circuit.Verify(proof, witness)
	if err != nil {
		// TODO: typecheck error
	}

	common.Log.Debugf("verification result: %v", result)
	provide.Render(&privacy.VerificationResponse{
		Result: result,
	}, 200, c)
}
