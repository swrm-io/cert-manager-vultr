package main

import "errors"

var (
	errInvalidProviderConfig = errors.New("invalid provider config")
	errInvalidVultrConfig    = errors.New("invalid vultr config")
)
