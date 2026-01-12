// internal/security/password_policy.go
package security

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type PasswordPolicy struct {
	MinLength          int
	RequireUpper       bool
	RequireLower       bool
	RequireNumber      bool
	RequireSpecial     bool
	MaxRepeatedChars   int
	MinUniqueChars     int
	BlockCommon        bool
	MaxAgeDays         int
	HistorySize        int
	AllowUsernameMatch bool
}

var (
	commonPasswords = []string{
		"password", "123456", "qwerty", "admin", "welcome",
		"password123", "letmein", "monkey", "123456789", "12345678",
	}
	
	specialChars = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
	emailRegex   = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func NewDefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:          12,
		RequireUpper:       true,
		RequireLower:       true,
		RequireNumber:      true,
		RequireSpecial:     true,
		MaxRepeatedChars:   2,
		MinUniqueChars:     8,
		BlockCommon:        true,
		MaxAgeDays:         90,
		HistorySize:        5,
		AllowUsernameMatch: false,
	}
}

// Validate checks password against policy
func (p *PasswordPolicy) Validate(password string) (bool, []string) {
	var errors []string
	
	if len(password) < p.MinLength {
		errors = append(errors, "Password must be at least 12 characters")
	}
	
	if p.RequireUpper && !containsUpper(password) {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}
	
	if p.RequireLower && !containsLower(password) {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}
	
	if p.RequireNumber && !containsNumber(password) {
		errors = append(errors, "Password must contain at least one number")
	}
	
	if p.RequireSpecial && !containsSpecial(password) {
		errors = append(errors, "Password must contain at least one special character")
	}
	
	if p.MaxRepeatedChars > 0 && hasRepeatedChars(password, p.MaxRepeatedChars) {
		errors = append(errors, "Password contains too many repeated characters")
	}
	
	if p.MinUniqueChars > 0 && countUniqueChars(password) < p.MinUniqueChars {
		errors = append(errors, "Password must contain more unique characters")
	}
	
	if p.BlockCommon && isCommonPassword(password) {
		errors = append(errors, "Password is too common")
	}
	
	return len(errors) == 0, errors
}

// HashPassword creates bcrypt hash of password
func (p *PasswordPolicy) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash verifies password against hash
func (p *PasswordPolicy) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidateEmail validates email format
func (p *PasswordPolicy) ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// GenerateHash creates hash of any string (for tokens, etc.)
func (p *PasswordPolicy) GenerateHash(input string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	return string(bytes), err
}

// Helper functions
func containsUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLower(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsNumber(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	return specialChars.MatchString(s)
}

func hasRepeatedChars(s string, maxRepeated int) bool {
	if len(s) == 0 {
		return false
	}
	
	currentChar := rune(s[0])
	currentCount := 1
	
	for _, char := range s[1:] {
		if char == currentChar {
			currentCount++
			if currentCount > maxRepeated {
				return true
			}
		} else {
			currentChar = char
			currentCount = 1
		}
	}
	
	return false
}

func countUniqueChars(s string) int {
	seen := make(map[rune]bool)
	for _, char := range s {
		seen[char] = true
	}
	return len(seen)
}

func isCommonPassword(password string) bool {
	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return true
		}
	}
	return false
}