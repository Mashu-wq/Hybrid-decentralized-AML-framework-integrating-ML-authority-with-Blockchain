// internal/security/jwt_manager.go
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secretKey       string
	accessDuration  time.Duration
	refreshDuration time.Duration
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func NewJWTManager(secretKey string, accessDuration, refreshDuration int) *JWTManager {
	return &JWTManager{
		secretKey:       secretKey,
		accessDuration:  time.Duration(accessDuration) * time.Second,
		refreshDuration: time.Duration(refreshDuration) * time.Second,
	}
}

// GenerateAccessToken creates a new access token
func (jm *JWTManager) GenerateAccessToken(userID, email, role string) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jm.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jm.secretKey))
}

// GenerateRefreshToken creates a new refresh token
func (jm *JWTManager) GenerateRefreshToken(userID string) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jm.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jm.secretKey))
}

// ValidateToken validates a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jm.secretKey), nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, jwt.ErrInvalidKey
}

// ExtractClaims extracts claims from token
func (jm *JWTManager) ExtractClaims(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jm.secretKey), nil
	})
	
	return claims, err
}

// HashToken creates a SHA256 hash of a token (for refresh tokens)
func (jm *JWTManager) HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// GenerateRandomSecret generates a cryptographically secure random string
func (jm *JWTManager) GenerateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// IsTokenExpired checks if token is expired
func (jm *JWTManager) IsTokenExpired(tokenString string) (bool, error) {
	claims, err := jm.ExtractClaims(tokenString)
	if err != nil {
		return true, err
	}
	
	expiry, err := claims.GetExpirationTime()
	if err != nil {
		return true, err
	}
	
	return expiry.Time.Before(time.Now()), nil
}

// GetTokenExpiry returns token expiry time
func (jm *JWTManager) GetTokenExpiry(tokenString string) (time.Time, error) {
	claims, err := jm.ExtractClaims(tokenString)
	if err != nil {
		return time.Time{}, err
	}
	
	expiry, err := claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, err
	}
	
	return expiry.Time, nil
}

// RefreshAccessToken refreshes an access token using refresh token
func (jm *JWTManager) RefreshAccessToken(refreshToken string) (string, error) {
	claims, err := jm.ExtractClaims(refreshToken)
	if err != nil {
		return "", errors.New("invalid refresh token")
	}
	
	// Check if refresh token is expired
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry.Time.Before(time.Now()) {
		return "", errors.New("refresh token expired")
	}
	
	// Generate new access token
	return jm.GenerateAccessToken(claims.UserID, claims.Email, claims.Role)
}