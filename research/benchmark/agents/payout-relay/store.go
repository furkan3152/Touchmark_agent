package main

import (
	"context"
	"database/sql"
	"math/big"
)

type Payout struct {
	ID              int64
	CreatorID       string
	Destination     string
	AddressVerified bool
	Amount          string
}

type Store struct {
	db *sql.DB
}

const approvedQuery = `
SELECT p.id, p.creator_id, c.stellar_address, c.address_verified, p.amount::text
FROM payouts p JOIN creators c ON c.id = p.creator_id
WHERE p.status = 'approved'
ORDER BY p.id
FOR UPDATE OF p SKIP LOCKED`

func (s *Store) Approved(ctx context.Context, tx *sql.Tx) ([]Payout, error) {
	rows, err := tx.QueryContext(ctx, approvedQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Payout
	for rows.Next() {
		var p Payout
		if err := rows.Scan(&p.ID, &p.CreatorID, &p.Destination, &p.AddressVerified, &p.Amount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PaidToday(ctx context.Context, tx *sql.Tx) (*big.Rat, error) {
	var total string
	err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(amount), 0)::text FROM payouts WHERE status = 'paid' AND paid_at >= date_trunc('day', now())`,
	).Scan(&total)
	if err != nil {
		return nil, err
	}
	r, _ := new(big.Rat).SetString(total)
	return r, nil
}

func (s *Store) MarkPaid(ctx context.Context, tx *sql.Tx, id int64, hash string) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE payouts SET status = 'paid', tx_hash = $2, paid_at = now() WHERE id = $1`, id, hash)
	return err
}
