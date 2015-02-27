package registry

import (
	"net/url"
	"strings"
)

type Decoder struct {
	root string
	path string
}

func NewDecoder(registryPath string) *Decoder {
	regUrl, err := url.Parse(registryPath)
	if err != nil {
		return nil
	}

	path := strings.Replace(regUrl.Path[1:], `/`, `\`, -1)

	return &Decoder{
		root: strings.ToLower(regUrl.Host),
		path: path,
	}
}
