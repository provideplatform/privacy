package circuit

import (
	"github.com/gin-gonic/gin"
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

}

// fetch circuit details
func circuitDetailsHandler(c *gin.Context) {

}

// verify circuit
func verifyCircuitHandler(c *gin.Context) {

}
