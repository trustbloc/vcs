package ackstore

import redisapi "github.com/redis/go-redis/v9"

//go:generate mockgen -destination interfaces_mocks_test.go -package ackstore_test -source=interfaces.go

type redisClient interface {
	API() redisapi.UniversalClient
}

// nolint
type redisApi interface {
	redisapi.UniversalClient
}
