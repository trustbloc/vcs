package ackstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis/ackstore"
)

func TestCreate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		obj := &oidc4ci.Ack{
			HashedToken: "abcd",
		}

		api.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, s string, i interface{}, duration time.Duration) *redisapi.StatusCmd {
				assert.True(t, strings.HasPrefix(s, "oidc4ci_ack"))
				assert.Equal(t, 30*time.Second, duration)
				assert.Equal(t, obj, i)

				return &redisapi.StatusCmd{}
			})
		id, err := store.Create(context.TODO(), obj)
		assert.NoError(t, err)
		assert.NotEmpty(t, id)
	})

	t.Run("err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		obj := &oidc4ci.Ack{
			HashedToken: "abcd",
		}

		api.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(redisapi.NewStatusResult("", errors.New("unexpected err")))

		id, err := store.Create(context.TODO(), obj)
		assert.Empty(t, id)
		assert.ErrorContains(t, err, "unexpected err")
	})
}

func TestGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		obj := &oidc4ci.Ack{
			HashedToken: "abcd",
		}
		b, err := json.Marshal(obj)
		assert.NoError(t, err)

		api.EXPECT().Get(gomock.Any(), "oidc4ci_ack-1234").
			Return(redisapi.NewStringResult(string(b), nil))

		id, err := store.Get(context.TODO(), "1234")
		assert.NoError(t, err)
		assert.Equal(t, id.HashedToken, obj.HashedToken)
	})

	t.Run("unmarshal err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		api.EXPECT().Get(gomock.Any(), "oidc4ci_ack-1234").
			Return(redisapi.NewStringResult("[]", nil))

		id, err := store.Get(context.TODO(), "1234")
		assert.Nil(t, id)
		assert.ErrorContains(t, err, "cannot unmarshal array into Go value of type")
	})

	t.Run("err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		api.EXPECT().Get(gomock.Any(), "oidc4ci_ack-1234").
			Return(redisapi.NewStringResult("", redisapi.Nil))

		id, err := store.Get(context.TODO(), "1234")
		assert.Nil(t, id)
		assert.ErrorIs(t, err, redisapi.Nil)
	})
}

func TestDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		api.EXPECT().Del(gomock.Any(), "oidc4ci_ack-1234").
			Return(redisapi.NewIntResult(1, nil))

		err := store.Delete(context.TODO(), "1234")
		assert.NoError(t, err)
	})

	t.Run("err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := ackstore.New(cl, 30)

		api.EXPECT().Del(gomock.Any(), "oidc4ci_ack-1234").
			Return(redisapi.NewIntResult(0, errors.New("some error")))

		err := store.Delete(context.TODO(), "1234")
		assert.ErrorContains(t, err, "some error")
	})
}
