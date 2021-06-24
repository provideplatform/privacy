package store

import (
	"github.com/gin-gonic/gin"
	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

// InstallAPI registers the store API handlers with gin
func InstallAPI(r *gin.Engine) {
	r.GET("/api/v1/store", listStoresHandler)
	r.POST("/api/v1/store", createStoreHandler)

	r.GET("/api/v1/store/:id", listStoreItemsHandler)
	r.POST("/api/v1/store/:id", createStoreItemHandler)
}

func listStoresHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	// db := dbconf.DatabaseConnection()
	provide.RenderError("not implemented", 501, c)
}

func createStoreHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	// db := dbconf.DatabaseConnection()
	provide.RenderError("not implemented", 501, c)
}

func listStoreItemsHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	// db := dbconf.DatabaseConnection()
	provide.RenderError("not implemented", 501, c)
}

func createStoreItemHandler(c *gin.Context) {
	appID := util.AuthorizedSubjectID(c, "application")
	orgID := util.AuthorizedSubjectID(c, "organization")
	userID := util.AuthorizedSubjectID(c, "user")
	if appID == nil && orgID == nil && userID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	// db := dbconf.DatabaseConnection()
	provide.RenderError("not implemented", 501, c)
}
