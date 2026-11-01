package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var receiptName = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Receipts struct {
	dir string
}

func (rc *Receipts) Write(hash string, po Payout) {
	body, _ := json.Marshal(map[string]any{
		"hash":       hash,
		"payout_id":  po.ID,
		"creator_id": po.CreatorID,
		"amount":     po.Amount,
		"written_at": time.Now().UTC(),
	})
	_ = os.WriteFile(filepath.Join(rc.dir, hash+".json"), body, 0o644)
}

func (rc *Receipts) Handle(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if !receiptName.MatchString(hash) {
		http.Error(w, "bad receipt id", http.StatusBadRequest)
		return
	}
	body, err := os.ReadFile(filepath.Join(rc.dir, hash+".json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
