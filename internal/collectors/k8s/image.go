package k8s

import (
	"sort"
	"strings"
)

// This file builds the cluster's component and version inventory from the
// container images on the watched pods. The agent makes no version judgment: it
// ships parsed image references and the server matches them against its catalog
// of components and latest stable versions, so the definition of "outdated"
// changes without an agent release.

// maxInventoryImages bounds the inventory so a pathological cluster cannot
// produce an unbounded snapshot. Real clusters have dozens of distinct images.
const maxInventoryImages = 500

// parseImageRef splits a container image reference into its parts:
//
//	[registry[:port]/]repository[:tag][@digest]
//
// The tag is the last colon-delimited segment after the final slash, so a
// registry port (reg.example.com:5000/app) is not mistaken for a tag. A ref
// with neither tag nor digest defaults to the implicit "latest".
func parseImageRef(image string) (repository, tag, digest string) {
	repository = image
	if at := strings.Index(repository, "@"); at >= 0 {
		digest = repository[at+1:]
		repository = repository[:at]
	}
	slash := strings.LastIndex(repository, "/")
	if colon := strings.LastIndex(repository, ":"); colon > slash {
		tag = repository[colon+1:]
		repository = repository[:colon]
	}
	if tag == "" && digest == "" {
		tag = "latest"
	}
	return repository, tag, digest
}

// componentInventory builds the deduplicated image inventory from the pod
// store, keyed by full image reference, recording which workloads
// ("namespace/Kind/name") use each. Excluded namespaces are left out.
// Deduping by image collapses a Deployment's many replicas to one entry.
func (c *Collector) componentInventory(pods []Pod) []map[string]any {
	type entry struct {
		repository string
		tag        string
		digest     string
		workloads  map[string]bool
	}
	byImage := map[string]*entry{}

	for _, p := range pods {
		if c.skip(p.Metadata.Namespace) {
			continue
		}
		// Namespace-qualified: this inventory spans the whole cluster, and two
		// namespaces' "Deployment/api" are different workloads.
		owner := workloadOwner(p, c.replicaSets.store)
		if owner == "" {
			owner = "Pod/" + p.Metadata.Name
		}
		owner = qualify(p.Metadata.Namespace, owner)
		for _, ctr := range p.Spec.Containers {
			if ctr.Image == "" {
				continue
			}
			e := byImage[ctr.Image]
			if e == nil {
				if len(byImage) >= maxInventoryImages {
					continue
				}
				repo, tag, digest := parseImageRef(ctr.Image)
				e = &entry{repository: repo, tag: tag, digest: digest, workloads: map[string]bool{}}
				byImage[ctr.Image] = e
			}
			e.workloads[owner] = true
		}
	}

	images := make([]string, 0, len(byImage))
	for img := range byImage {
		images = append(images, img)
	}
	sort.Strings(images)

	out := make([]map[string]any, 0, len(images))
	for _, img := range images {
		e := byImage[img]
		workloads := make([]string, 0, len(e.workloads))
		for w := range e.workloads {
			workloads = append(workloads, w)
		}
		sort.Strings(workloads)
		out = append(out, map[string]any{
			"image":      img,
			"repository": e.repository,
			"tag":        e.tag,
			"digest":     e.digest,
			"workloads":  workloads,
		})
	}
	return out
}
