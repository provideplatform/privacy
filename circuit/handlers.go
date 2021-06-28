package circuit

import (
	"encoding/json"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/privacy"
	provide "github.com/provideplatform/provide-go/common"
	"github.com/provideplatform/provide-go/common/util"
)

func resolveCircuitsQuery(db *gorm.DB, circuitID, orgID, appID *uuid.UUID) *gorm.DB {
	query := db.Select("circuits.*")
	if circuitID != nil {
		query = query.Where("circuits.id = ?", circuitID)
	}
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
	// r.GET("/api/v1/circuits/:id/prove/:proofId", proofDetailsHandler)

	r.POST("/api/v1/circuits/:id/verify", verifyCircuitHandler)
	// r.GET("/api/v1/circuits/:id/verify/:verifyId", proofDetailsHandler)

	r.GET("/api/v1/circuits/:id/notes/:index", circuitNoteStoreValueHandler)
	r.GET("/api/v1/circuits/:id/proofs/:index", circuitProofStoreValueHandler)
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
	resolveCircuitsQuery(db, &circuitID, nil, nil).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.ApplicationID != nil && appID != nil && circuit.ApplicationID.String() != appID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if appID != nil && circuit.ApplicationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.OrganizationID != nil && orgID != nil && circuit.OrganizationID.String() != orgID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if orgID != nil && circuit.OrganizationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	circuit.enrich()
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
	resolveCircuitsQuery(db, &circuitID, nil, nil).Find(&circuit)
	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.ApplicationID != nil && appID != nil && circuit.ApplicationID.String() != appID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if appID != nil && circuit.ApplicationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.OrganizationID != nil && orgID != nil && circuit.OrganizationID.String() != orgID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if orgID != nil && circuit.OrganizationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	witness, witnessOk := params["witness"].(map[string]interface{}) // FIXME-- support string witness also?
	if !witnessOk {
		provide.RenderError("witness required for proof generation", 422, c)
		return
	}

	proof, err := circuit.Prove(witness)
	if err != nil {
		provide.Render(&privacy.ProveResponse{
			Errors: []*api.Error{{Message: common.StringOrNil(err.Error())}},
			Proof:  nil,
		}, 422, c)
		return
	}

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
	resolveCircuitsQuery(db, &circuitID, nil, nil).Find(&circuit)
	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.ApplicationID != nil && appID != nil && circuit.ApplicationID.String() != appID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if appID != nil && circuit.ApplicationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.OrganizationID != nil && orgID != nil && circuit.OrganizationID.String() != orgID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if orgID != nil && circuit.OrganizationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	proof, proofOk := params["proof"].(string)
	if !proofOk {
		provide.RenderError("proof required for verification", 422, c)
		return
	}

	witness, witnessOk := params["witness"].(map[string]interface{})
	if !witnessOk {
		provide.RenderError("witness required for verification", 422, c)
		return
	}

	store := false
	if _store, storeOk := params["store"].(bool); storeOk {
		store = _store
	}

	result, err := circuit.Verify(proof, witness, store)
	if err != nil {
		provide.Render(&privacy.VerificationResponse{
			Errors: []*api.Error{{Message: common.StringOrNil(err.Error())}},
			Result: false,
		}, 422, c)
		return
	}

	provide.Render(&privacy.VerificationResponse{
		Result: result,
	}, 200, c)
}

// circuit note store value hanbdler
func circuitNoteStoreValueHandler(c *gin.Context) {
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
	resolveCircuitsQuery(db, &circuitID, nil, nil).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.ApplicationID != nil && appID != nil && circuit.ApplicationID.String() != appID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if appID != nil && circuit.ApplicationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.OrganizationID != nil && orgID != nil && circuit.OrganizationID.String() != orgID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if orgID != nil && circuit.OrganizationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	index, err := strconv.ParseUint(c.Param("index"), 10, 64)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	value, err := circuit.NoteValueAt(index)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	provide.Render(map[string]interface{}{
		"value": value,
	}, 200, c)
}

// circuit proof store value hanbdler
func circuitProofStoreValueHandler(c *gin.Context) {
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
	resolveCircuitsQuery(db, &circuitID, nil, nil).Find(&circuit)

	if circuit == nil || circuit.ID == uuid.Nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.ApplicationID != nil && appID != nil && circuit.ApplicationID.String() != appID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if appID != nil && circuit.ApplicationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if circuit.OrganizationID != nil && orgID != nil && circuit.OrganizationID.String() != orgID.String() {
		provide.RenderError("circuit not found", 404, c)
		return
	} else if orgID != nil && circuit.OrganizationID == nil {
		provide.RenderError("circuit not found", 404, c)
		return
	}

	index, err := strconv.ParseUint(c.Param("index"), 10, 64)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	length, err := circuit.ProofStoreLength()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	value, err := circuit.StoreValueAt(index)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	root, err := circuit.StoreRoot()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	provide.Render(map[string]interface{}{
		"length": length,
		"root":   root,
		"value":  value,
	}, 200, c)
}
