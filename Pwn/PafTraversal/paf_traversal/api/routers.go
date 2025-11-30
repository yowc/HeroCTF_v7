package main

import (
	"net/http"
	"paf-traversal/controllers"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()
	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.Static("/assets", "./assets/")
	router.LoadHTMLGlob("./templates/*")

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":  "route not found",
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"status": http.StatusNotFound,
		})
	})

	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"error":  "method not allowed",
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"status": http.StatusMethodNotAllowed,
		})
	})

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
	})

	apiGroup := router.Group("/api")
	{
		wordlistGroup := apiGroup.Group("/wordlist")
		{
			wordlistGroup.GET("", controllers.HandleListWordlist)
			wordlistGroup.POST("/download", controllers.HandleDownloadWordlist)
			wordlistGroup.POST("", controllers.HandleUploadWordlist)
			wordlistGroup.DELETE("", controllers.HandleDeleteWordlist)
		}
		bruteforceGroup := apiGroup.Group("/bruteforce")
		{
			bruteforceGroup.POST("", controllers.StartBruteforce)
		}
	}

	return router
}
