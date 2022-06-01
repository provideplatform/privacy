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
	"encoding/base64"
	"encoding/hex"
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

func resolveProversQuery(db *gorm.DB, proverID, orgID, appID, userID *uuid.UUID) *gorm.DB {
	query := db.Select("provers.*")
	if proverID != nil {
		query = query.Where("provers.id = ?", proverID)
	}
	if orgID != nil {
		query = query.Where("provers.organization_id = ?", orgID)
	}
	if appID != nil {
		query = query.Where("provers.application_id = ?", appID)
	}
	if userID != nil {
		query = query.Where("provers.user_id = ?", userID)
	}
	return query
}

// InstallAPI registers the prover registry API handlers with gin
func InstallAPI(r *gin.Engine) {
	r.GET("/api/v1/provers", listProversHandler)
	r.POST("/api/v1/provers", createProverHandler)
	r.GET("/api/v1/provers/:id", proverDetailsHandler)

	r.POST("/api/v1/provers/:id/prove", proveProverHandler)
	// r.GET("/api/v1/provers/:id/prove/:proofId", proofDetailsHandler)

	r.POST("/api/v1/provers/:id/verify", verifyProverHandler)
	// r.GET("/api/v1/provers/:id/verify/:verifyId", proofDetailsHandler)

	r.GET("/api/v1/provers/:id/notes/:index", proverNoteStoreValueHandler)
	r.GET("/api/v1/provers/:id/nullifiers/:index", proverNullifierStoreValueHandler)
}

// list/query available provers in the registry
func listProversHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	query := resolveProversQuery(db, nil, orgID, appID, userID)

	var provers []*Prover
	provide.Paginate(c, query, &Prover{}).Find(&provers)
	provide.Render(provers, 200, c)
}

// compile, setup, export verifier
func createProverHandler(c *gin.Context) {
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

	prover := &Prover{}
	err = json.Unmarshal(buf, prover)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if appID != nil {
		prover.ApplicationID = appID
	}

	if orgID != nil {
		prover.OrganizationID = orgID
	}

	if userID != nil {
		prover.UserID = userID
	}

	if srs, ok := params["srs"].(string); ok {
		prover.srs, err = hex.DecodeString(srs)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
	}

	variables := params["variables"]

	if prover.Create(variables) {
		provide.Render(prover, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = prover.Errors
		provide.Render(obj, 422, c)
	}
}

// fetch prover details
func proverDetailsHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	proverID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	prover := &Prover{}
	resolveProversQuery(db, &proverID, orgID, appID, userID).Find(&prover)

	if prover == nil || prover.ID == uuid.Nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.ApplicationID != nil && appID != nil && prover.ApplicationID.String() != appID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if appID != nil && prover.ApplicationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.OrganizationID != nil && orgID != nil && prover.OrganizationID.String() != orgID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if orgID != nil && prover.OrganizationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	}

	prover.enrich()
	provide.Render(prover, 200, c)
}

// generate a proof
func proveProverHandler(c *gin.Context) {
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
	proverID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	prover := &Prover{}
	resolveProversQuery(db, &proverID, orgID, appID, userID).Find(&prover)
	if prover == nil || prover.ID == uuid.Nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.ApplicationID != nil && appID != nil && prover.ApplicationID.String() != appID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if appID != nil && prover.ApplicationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.OrganizationID != nil && orgID != nil && prover.OrganizationID.String() != orgID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if orgID != nil && prover.OrganizationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	}

	witness, witnessOk := params["witness"].(map[string]interface{}) // FIXME-- support string witness also?
	if !witnessOk {
		provide.RenderError("witness required for proof generation", 422, c)
		return
	}

	proof, err := prover.Prove(witness)
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
func verifyProverHandler(c *gin.Context) {
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
	proverID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	prover := &Prover{}
	resolveProversQuery(db, &proverID, orgID, appID, userID).Find(&prover)
	if prover == nil || prover.ID == uuid.Nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.ApplicationID != nil && appID != nil && prover.ApplicationID.String() != appID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if appID != nil && prover.ApplicationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.OrganizationID != nil && orgID != nil && prover.OrganizationID.String() != orgID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if orgID != nil && prover.OrganizationID == nil {
		provide.RenderError("prover not found", 404, c)
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

	result, err := prover.Verify(proof, witness, store)
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

// prover note store value hanbdler
func proverNoteStoreValueHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	proverID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	prover := &Prover{}
	resolveProversQuery(db, &proverID, orgID, appID, userID).Find(&prover)

	if prover == nil || prover.ID == uuid.Nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.ApplicationID != nil && appID != nil && prover.ApplicationID.String() != appID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if appID != nil && prover.ApplicationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.OrganizationID != nil && orgID != nil && prover.OrganizationID.String() != orgID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if orgID != nil && prover.OrganizationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	}

	index, err := strconv.ParseUint(c.Param("index"), 10, 64)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	root, err := prover.NoteStoreRoot()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	value, nullifierKey, err := prover.NoteValueAt(index)
	if err != nil {
		common.Log.Warningf("failed to retrieve note value at index: %d; %s", index, err.Error())
		provide.RenderError(err.Error(), 404, c)
		return
	}

	provide.Render(map[string]interface{}{
		"root":          root,
		"nullifier_key": base64.StdEncoding.EncodeToString(nullifierKey),
		"value":         base64.StdEncoding.EncodeToString(value),
	}, 200, c)
}

// prover proof store value hanbdler
func proverNullifierStoreValueHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	proverID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("bad request", 400, c)
		return
	}

	prover := &Prover{}
	resolveProversQuery(db, &proverID, orgID, appID, userID).Find(&prover)

	if prover == nil || prover.ID == uuid.Nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.ApplicationID != nil && appID != nil && prover.ApplicationID.String() != appID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if appID != nil && prover.ApplicationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	} else if prover.OrganizationID != nil && orgID != nil && prover.OrganizationID.String() != orgID.String() {
		provide.RenderError("prover not found", 404, c)
		return
	} else if orgID != nil && prover.OrganizationID == nil {
		provide.RenderError("prover not found", 404, c)
		return
	}

	root, err := prover.NullifierStoreRoot()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	key, err := hex.DecodeString(c.Param("index"))
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	value, err := prover.NullifierValueAt(key)
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	provide.Render(map[string]interface{}{
		// "height": height,
		"root":  root,
		"value": base64.StdEncoding.EncodeToString(value),
	}, 200, c)
}
