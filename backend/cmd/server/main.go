package main

import (
	"log"

	"github.com/starloader/backend/internal/config"
)

func main() {
	if _, err := config.Load(); err != nil {
		log.Fatal("configuration error: ", err)
	}
	log.Print("license service configuration loaded")
}
