// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package sqlc

import (
	"context"
)

type Querier interface {
	MarkEmailVerified(ctx context.Context, arg MarkEmailVerifiedParams) error
	RegisterUser(ctx context.Context, arg RegisterUserParams) error
}

var _ Querier = (*Queries)(nil)
