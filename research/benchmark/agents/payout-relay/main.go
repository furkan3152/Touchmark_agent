package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	"github.com/stellar/go/clients/horizonclient"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	client := &horizonclient.Client{HorizonURL: env("HORIZON_URL", "https://horizon.stellar.org")}
	payer, err := NewPayer(client, os.Getenv("PAYOUT_SEED"))
	if err != nil {
		log.Fatalf("payer: %v", err)
	}
	store := &Store{db: db}
	receipts := &Receipts{dir: env("RECEIPT_DIR", "./receipts")}
	runner := &Runner{store: store, payer: payer, policy: DefaultPolicy(), receipts: receipts}
	auth := requireOperator(os.Getenv("OPERATOR_TOKEN"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.Handle("POST /payouts/run", auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results, err := runner.Run(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(results)
	})))
	mux.HandleFunc("GET /receipts/{hash}", receipts.Handle)

	log.Println("payout-relay listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
