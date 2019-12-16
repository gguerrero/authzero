package router

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/auth0/go-jwt-middleware"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"

	"../auth"
)

// Response message
type Response struct {
	Message string `json:"message"`
	StatusCode int `json:"statusCode"`
}

func Handler(authJwtMiddleware *jwtmiddleware.JWTMiddleware) *mux.Router {
	r := mux.NewRouter()

	// This route is always accessible
	r.HandleFunc("/api/public", apiPublicHandler)

	// This route is only accessible if the user has a valid Access Token
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token.
	r.Handle("/api/private", negroni.New(
		negroni.HandlerFunc(authJwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(apiPrivateHandler)),
	))

	// This route is only accessible if the user has a valid Access Token with the read:messages scope
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token and scope.
	r.Handle("/api/private-scoped", negroni.New(
		negroni.HandlerFunc(authJwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(apiPrivateScopedHandler)),
	))

	return r
}

func apiPublicHandler(w http.ResponseWriter, r *http.Request) {
	message := "Hello from a public endpoint! You don't need to be authenticated to see this."
	responseJSON(message, w, http.StatusOK)

	log.Print("GET /api/public 200[OK]")
}

func apiPrivateHandler(w http.ResponseWriter, r *http.Request) {
	message := "Hello from a private endpoint! You need to be authenticated to see this."
	responseJSON(message, w, http.StatusOK)

	log.Print("GET /api/private 200[OK]")
}

func apiPrivateScopedHandler(w http.ResponseWriter, r *http.Request) {
		accessToken := getBearerToken(r)
		hasScope := auth.CheckScope("read:messages", accessToken)

		if !hasScope {
			message := "Insufficient scope."
			responseJSON(message, w, http.StatusForbidden)

			log.Print("GET /api/private-scoped 403[Forbidden]")
		} else {
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)

			log.Print("GET /api/private-scoped 200[OK]")
		}
}

func responseJSON(message string, writer http.ResponseWriter, statusCode int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)

	// Add JSON encoder to the repsonse writer
	response := Response{message, statusCode}
	err := json.NewEncoder(writer).Encode(&response)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func getBearerToken(r *http.Request) string {
	return strings.Split(r.Header.Get("Authorization"), " ")[1]
}
