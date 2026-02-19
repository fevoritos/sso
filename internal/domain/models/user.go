package models

type User struct {
	ID           int64
	Emial        string
	PasswordHash []byte
}
