package model

const BlockTypeVideo = "video"

// Video declares direct browser-playable files with intrinsic dimensions and optional poster.
type Video struct {
	Animation   bool          `json:"animation,omitempty"`
	DarkSources []VideoSource `json:"dark_sources,omitempty"`
	DarkPoster  string        `json:"dark_poster,omitempty"`
	Sources     []VideoSource `json:"sources"`
	Width       int           `json:"width"`
	Height      int           `json:"height"`
	Poster      string        `json:"poster,omitempty"`
	Caption     string        `json:"caption,omitempty"`
}

// VideoSource provides one native video encoding, never an embedded third-party player.
type VideoSource struct {
	URL       string `json:"url"`
	MediaType string `json:"media_type"`
}
