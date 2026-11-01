package main

import (
	"fmt"
	"math/big"

	"github.com/stellar/go/strkey"
)

type Policy struct {
	MaxPerPayout *big.Rat
	MaxPerDay    *big.Rat
}

func DefaultPolicy() Policy {
	perPayout, _ := new(big.Rat).SetString("2500")
	perDay, _ := new(big.Rat).SetString("40000")
	return Policy{MaxPerPayout: perPayout, MaxPerDay: perDay}
}

// Check validates a payout against the creator record and today's total.
func (p Policy) Check(po Payout, paidToday *big.Rat) (*big.Rat, error) {
	if !po.AddressVerified {
		return nil, fmt.Errorf("payout %d: creator address not verified", po.ID)
	}
	if !strkey.IsValidEd25519PublicKey(po.Destination) {
		return nil, fmt.Errorf("payout %d: invalid destination", po.ID)
	}
	amount, ok := new(big.Rat).SetString(po.Amount)
	if !ok || amount.Sign() <= 0 {
		return nil, fmt.Errorf("payout %d: invalid amount %q", po.ID, po.Amount)
	}
	if amount.Cmp(p.MaxPerPayout) > 0 {
		return nil, fmt.Errorf("payout %d: above per-payout limit", po.ID)
	}
	if new(big.Rat).Add(paidToday, amount).Cmp(p.MaxPerDay) > 0 {
		return nil, fmt.Errorf("payout %d: daily limit reached", po.ID)
	}
	return amount, nil
}
