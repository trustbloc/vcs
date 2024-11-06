package dynamicwellknown

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	keyPrefix = "dynamic_well_known"
)

// Store stores claim data with expiration.
type Store struct {
	redisClient redisClient
	defaultTTL  time.Duration
}

// New creates presentation claims store.
func New(redisClient redisClient, ttl time.Duration) *Store {
	return &Store{
		redisClient: redisClient,
		defaultTTL:  ttl,
	}
}

func (s *Store) Upsert(
	ctx context.Context,
	profileID string,
	item map[string]*profileapi.CredentialsConfigurationSupported,
) error {
	currentValue, err := s.Get(ctx, profileID)
	if err != nil {
		return err
	}

	if currentValue == nil {
		currentValue = make(map[string]*profileapi.CredentialsConfigurationSupported)
	}

	for k, v := range item {
		currentValue[k] = v
	}

	b, err := json.Marshal(currentValue)
	if err != nil {
		return err
	}

	return s.redisClient.API().Set(ctx, s.resolveRedisKey(profileID), string(b), s.defaultTTL).Err()
}

func (s *Store) Get(ctx context.Context, id string) (map[string]*profileapi.CredentialsConfigurationSupported, error) {
	b, err := s.redisClient.API().Get(ctx, s.resolveRedisKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return map[string]*profileapi.CredentialsConfigurationSupported{}, nil
		}

		return nil, err
	}

	var result map[string]*profileapi.CredentialsConfigurationSupported
	if err = json.Unmarshal(b, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *Store) resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
