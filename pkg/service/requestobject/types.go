package requestobject

import "errors"

type RequestObject struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

var ErrDataNotFound = errors.New("data not found")
