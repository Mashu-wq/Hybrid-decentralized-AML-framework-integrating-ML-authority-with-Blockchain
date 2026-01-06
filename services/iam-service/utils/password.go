
package utils

import "golang.org/x/crypto/bcrypt"

func HashPassword(p string) (string, error) {
 bytes, err := bcrypt.GenerateFromPassword([]byte(p), 12)
 return string(bytes), err
}

func CheckPassword(hash, p string) bool {
 return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}
