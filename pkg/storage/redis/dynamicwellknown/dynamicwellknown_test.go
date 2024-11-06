package dynamicwellknown_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/storage/redis/dynamicwellknown"
)

func TestUpsert(t *testing.T) {
	t.Run("no existing", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := dynamicwellknown.New(cl, time.Hour)

		api.EXPECT().Get(context.TODO(), "dynamic_well_known:1234").Return(
			redisapi.NewStringResult("", nil))

		api.EXPECT().Set(gomock.Any(), "dynamic_well_known:1234", gomock.Any(), time.Hour).
			Return(redisapi.NewStatusResult("", nil))

		assert.NoError(t, store.Upsert(context.TODO(), "1234",
			map[string]*profileapi.CredentialsConfigurationSupported{
				"key1": {},
			}),
		)
	})

	t.Run("err get", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := dynamicwellknown.New(cl, time.Hour)

		api.EXPECT().Get(context.TODO(), "dynamic_well_known:1234").Return(
			redisapi.NewStringResult("", errors.New("unexpected err")))

		assert.ErrorContains(t, store.Upsert(context.TODO(), "1234",
			map[string]*profileapi.CredentialsConfigurationSupported{
				"key1": {},
			}), "unexpected err")
	})

	t.Run("not found err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := dynamicwellknown.New(cl, time.Hour)
		api.EXPECT().Get(context.TODO(), "dynamic_well_known:1234").Return(
			redisapi.NewStringResult("", redisapi.Nil))

		resp, err := store.Get(context.TODO(), "1234")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("err", func(t *testing.T) {
		cl := NewMockredisClient(gomock.NewController(t))
		api := NewMockredisApi(gomock.NewController(t))

		cl.EXPECT().API().Return(api).AnyTimes()

		store := dynamicwellknown.New(cl, time.Hour)
		api.EXPECT().Get(context.TODO(), "dynamic_well_known:1234").Return(
			redisapi.NewStringResult("", errors.New("unexpected err")))

		resp, err := store.Get(context.TODO(), "1234")
		assert.ErrorContains(t, err, "unexpected err")
		assert.Nil(t, resp)
	})
}
