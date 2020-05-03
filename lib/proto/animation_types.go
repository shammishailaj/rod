// This file is generated by "./lib/proto/cmd/gen"

package proto

// AnimationAnimation Animation instance.
type AnimationAnimation struct {
	// ID `Animation`'s id.
	ID string `json:"id"`

	// Name `Animation`'s name.
	Name string `json:"name"`

	// PausedState `Animation`'s internal paused state.
	PausedState bool `json:"pausedState"`

	// PlayState `Animation`'s play state.
	PlayState string `json:"playState"`

	// PlaybackRate `Animation`'s playback rate.
	PlaybackRate float64 `json:"playbackRate"`

	// StartTime `Animation`'s start time.
	StartTime float64 `json:"startTime"`

	// CurrentTime `Animation`'s current time.
	CurrentTime float64 `json:"currentTime"`

	// Type Animation type of `Animation`.
	Type string `json:"type"`

	// Source `Animation`'s source animation node.
	Source *AnimationAnimationEffect `json:"source,omitempty"`

	// CSSID A unique ID for `Animation` representing the sources that triggered this CSS
	// animation/transition.
	CSSID string `json:"cssId,omitempty"`
}

// AnimationAnimationEffect AnimationEffect instance
type AnimationAnimationEffect struct {
	// Delay `AnimationEffect`'s delay.
	Delay float64 `json:"delay"`

	// EndDelay `AnimationEffect`'s end delay.
	EndDelay float64 `json:"endDelay"`

	// IterationStart `AnimationEffect`'s iteration start.
	IterationStart float64 `json:"iterationStart"`

	// Iterations `AnimationEffect`'s iterations.
	Iterations float64 `json:"iterations"`

	// Duration `AnimationEffect`'s iteration duration.
	Duration float64 `json:"duration"`

	// Direction `AnimationEffect`'s playback direction.
	Direction string `json:"direction"`

	// Fill `AnimationEffect`'s fill mode.
	Fill string `json:"fill"`

	// BackendNodeID `AnimationEffect`'s target node.
	BackendNodeID *DOMBackendNodeID `json:"backendNodeId,omitempty"`

	// KeyframesRule `AnimationEffect`'s keyframes.
	KeyframesRule *AnimationKeyframesRule `json:"keyframesRule,omitempty"`

	// Easing `AnimationEffect`'s timing function.
	Easing string `json:"easing"`
}

// AnimationKeyframesRule Keyframes Rule
type AnimationKeyframesRule struct {
	// Name CSS keyframed animation's name.
	Name string `json:"name,omitempty"`

	// Keyframes List of animation keyframes.
	Keyframes []*AnimationKeyframeStyle `json:"keyframes"`
}

// AnimationKeyframeStyle Keyframe Style
type AnimationKeyframeStyle struct {
	// Offset Keyframe's time offset.
	Offset string `json:"offset"`

	// Easing `AnimationEffect`'s timing function.
	Easing string `json:"easing"`
}
