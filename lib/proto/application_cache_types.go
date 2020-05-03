// This file is generated by "./lib/proto/cmd/gen"

package proto

// ApplicationCacheApplicationCacheResource Detailed application cache resource information.
type ApplicationCacheApplicationCacheResource struct {
	// URL Resource url.
	URL string `json:"url"`

	// Size Resource size.
	Size int64 `json:"size"`

	// Type Resource type.
	Type string `json:"type"`
}

// ApplicationCacheApplicationCache Detailed application cache information.
type ApplicationCacheApplicationCache struct {
	// ManifestURL Manifest URL.
	ManifestURL string `json:"manifestURL"`

	// Size Application cache size.
	Size float64 `json:"size"`

	// CreationTime Application cache creation time.
	CreationTime float64 `json:"creationTime"`

	// UpdateTime Application cache update time.
	UpdateTime float64 `json:"updateTime"`

	// Resources Application cache resources.
	Resources []*ApplicationCacheApplicationCacheResource `json:"resources"`
}

// ApplicationCacheFrameWithManifest Frame identifier - manifest URL pair.
type ApplicationCacheFrameWithManifest struct {
	// FrameID Frame identifier.
	FrameID *PageFrameID `json:"frameId"`

	// ManifestURL Manifest URL.
	ManifestURL string `json:"manifestURL"`

	// Status Application cache status.
	Status int64 `json:"status"`
}
