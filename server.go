package main

import (
	"./auth"
	"./router"

	"net/http"
	"log"
	"time"
)

const address string = "localhost:8000"

func main() {
	authJwtMiddleware := auth.New()
	routerHandler := router.Handler(authJwtMiddleware)

	log.Print("Booting Server on " + address + "...")

	srv := &http.Server{
		Handler: routerHandler,
		Addr:    address,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
