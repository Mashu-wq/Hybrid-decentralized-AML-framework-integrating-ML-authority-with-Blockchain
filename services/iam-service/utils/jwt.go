package utils

import "github.com/golang-jwt/jwt/v5"

var secret = []byte("super-secret")

func GenerateToken(id, role string) (string, error) {
 claims := jwt.MapClaims{
  "id": id,
  "role": role,
 }
 token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
 return token.SignedString(secret)
}
