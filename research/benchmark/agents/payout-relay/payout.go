package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/stellar/go/clients/horizonclient"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/network"
	"github.com/stellar/go/txnbuild"
)

var usdc = txnbuild.CreditAsset{
	Code:   "USDC",
	Issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
}

type Payer struct {
	client *horizonclient.Client
	kp     *keypair.Full
}

func NewPayer(client *horizonclient.Client, seed string) (*Payer, error) {
	kp, err := keypair.ParseFull(seed)
	if err != nil {
		return nil, fmt.Errorf("parse payout seed: %w", err)
	}
	return &Payer{client: client, kp: kp}, nil
}

func (p *Payer) Pay(destination string, amount *big.Rat, payoutID int64) (string, error) {
	account, err := p.client.AccountDetail(horizonclient.AccountRequest{AccountID: p.kp.Address()})
	if err != nil {
		return "", err
	}
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        &account,
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee * 2,
		Memo:                 txnbuild.MemoID(uint64(payoutID)),
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		Operations: []txnbuild.Operation{&txnbuild.Payment{
			Destination: destination,
			Amount:      amount.FloatString(7),
			Asset:       usdc,
		}},
	})
	if err != nil {
		return "", err
	}
	tx, err = tx.Sign(network.PublicNetworkPassphrase, p.kp)
	if err != nil {
		return "", err
	}
	resp, err := p.client.SubmitTransaction(tx)
	if err != nil {
		return "", err
	}
	return resp.Hash, nil
}

type Result struct {
	PayoutID int64  `json:"payout_id"`
	Hash     string `json:"hash"`
}

type Runner struct {
	store    *Store
	payer    *Payer
	policy   Policy
	receipts *Receipts
}

func (r *Runner) Run(ctx context.Context) ([]Result, error) {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	payouts, err := r.store.Approved(ctx, tx)
	if err != nil {
		return nil, err
	}
	paidToday, err := r.store.PaidToday(ctx, tx)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, po := range payouts {
		amount, err := r.policy.Check(po, paidToday)
		if err != nil {
			log.Printf("skip: %v", err)
			continue
		}
		hash, err := r.payer.Pay(po.Destination, amount, po.ID)
		if err != nil {
			return nil, fmt.Errorf("payout %d: %w", po.ID, err)
		}
		if err := r.store.MarkPaid(ctx, tx, po.ID, hash); err != nil {
			return nil, err
		}
		paidToday.Add(paidToday, amount)
		r.receipts.Write(hash, po)
		results = append(results, Result{PayoutID: po.ID, Hash: hash})
	}
	return results, tx.Commit()
}
