/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/makiuchi-d/gozxing"
	gozxingqr "github.com/makiuchi-d/gozxing/qrcode"
)

func readQRCode(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	img, _, err := image.Decode(f)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}

	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("create bitmap from image: %w", err)
	}

	result, err := gozxingqr.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return "", fmt.Errorf("decode bitmap: %w", err)
	}

	return result.String(), nil
}

type parsedCredentialOffer struct {
	CredentialOfferURL string
	Pin                string
}

func fetchCredentialOffer(issuerUrl string, httpClient *http.Client) (*parsedCredentialOffer, error) {
	resp, err := httpClient.Get(issuerUrl)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()

	offerURL := regexp.MustCompile(`(openid-credential-offer://\?[^<]+)`).FindString(string(body))

	offerURL, err = url.QueryUnescape(offerURL)
	if err != nil {
		return nil, err
	}

	offerURL = strings.ReplaceAll(offerURL, "&amp;", "&")

	pin := ""
	pinGroups := regexp.MustCompile(`<div id="pin">([^<]+)`).FindAllStringSubmatch(string(body), -1)
	if len(pinGroups) == 1 {
		if len(pinGroups[0]) == 2 {
			pin = pinGroups[0][1]
		}
	}

	return &parsedCredentialOffer{
		CredentialOfferURL: offerURL,
		Pin:                pin,
	}, nil
}
