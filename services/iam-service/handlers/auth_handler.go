package handlers

import (
	"iam-service/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)
func Register(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&req)

	hash, _ := utils.HashPassword(req.Password)
	_ = hash // DB later

	c.JSON(http.StatusCreated, gin.H{"message": "registered"})
}

func Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&req)

	if req.Email != "admin@bank.com" || req.Password != "123456" {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	token, _ := utils.GenerateToken("1", "admin")
	c.JSON(200, gin.H{"accessToken": token})
}

