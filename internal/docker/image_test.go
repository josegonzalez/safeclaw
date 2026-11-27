package docker_test

import (
	"context"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

func TestInspectImage(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		return []byte(`{"Id":"sha256:abc","Config":{"Labels":{"safeclaw.variant":"sandbox"}}}` + "\n"), nil
	}}
	img, err := r.Client().InspectImage(context.Background(), "safeclaw:sandbox")
	if err != nil || img == nil {
		t.Fatalf("InspectImage = %v, %v", img, err)
	}
	if img.ID != "sha256:abc" || img.Config.Labels["safeclaw.variant"] != "sandbox" {
		t.Errorf("image = %+v", img)
	}
	if got := r.Commands(); len(got) != 1 || got[0] != "image inspect --format {{json .}} safeclaw:sandbox" {
		t.Errorf("commands = %q", got)
	}
}

func TestInspectImageMissing(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		return nil, dockertest.NotFound(args)
	}}
	img, err := r.Client().InspectImage(context.Background(), "safeclaw")
	if img != nil || err != nil {
		t.Errorf("InspectImage = %v, %v; want nil, nil", img, err)
	}
}
