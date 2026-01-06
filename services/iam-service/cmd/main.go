package main

import (
	"github.com/gin-gonic/gin"
	"iam-service/handlers"
)

func main() {
	r := gin.Default()

	r.POST("/auth/register", handlers.Register)
	r.POST("/auth/login", handlers.Login)

	r.Run(":8080")
}
