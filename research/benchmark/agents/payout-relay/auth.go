package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func requireOperator(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
