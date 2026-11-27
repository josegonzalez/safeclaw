package docker

import (
	"context"
	"encoding/json"
	"fmt"
)

// Image is the subset of `docker image inspect` output safeclaw uses.
type Image struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// InspectImage returns a local image's ID and labels, or nil if it does not
// exist.
func (c *Client) InspectImage(ctx context.Context, image string) (*Image, error) {
	out, err := c.R.Output(ctx, nil, "image", "inspect", "--format", "{{json .}}", image)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var img Image
	if err := json.Unmarshal(out, &img); err != nil {
		return nil, fmt.Errorf("parse docker image inspect: %w", err)
	}
	return &img, nil
}
