/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

func getNodeName() string {
	hostName, _ := os.Hostname()
	if v := os.Getenv("CUSTOM_HOST"); v != "" {
		hostName = v
	}

	return hostName
}

func getClusterMembers(ctx context.Context, rdb redis.UniversalClient) (map[string]string, error) {
	resp := rdb.HGetAll(ctx, orchestratorKey)
	if resp.Err() != nil {
		return nil, resp.Err()
	}

	result, err := resp.Result()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func getClusterResultKey(id string) string {
	return fmt.Sprintf("stress:cluster:result:%v", id)
}

func getResultKey(id string) string {
	return fmt.Sprintf("stress:result:%v", id)
}
