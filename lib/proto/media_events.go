// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// MediaPlayerPropertiesChanged This can be called multiple times, and can be used to set / override /
// remove player properties. A null propValue indicates removal.
type MediaPlayerPropertiesChanged struct {
	// PlayerID ...
	PlayerID *MediaPlayerID `json:"playerId"`

	// Properties ...
	Properties []*MediaPlayerProperty `json:"properties"`
}

// MethodName interface
func (evt MediaPlayerPropertiesChanged) MethodName() string {
	return "Media.playerPropertiesChanged"
}

// Load json
func (evt MediaPlayerPropertiesChanged) Load(b []byte) *MediaPlayerPropertiesChanged {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// MediaPlayerEventsAdded Send events as a list, allowing them to be batched on the browser for less
// congestion. If batched, events must ALWAYS be in chronological order.
type MediaPlayerEventsAdded struct {
	// PlayerID ...
	PlayerID *MediaPlayerID `json:"playerId"`

	// Events ...
	Events []*MediaPlayerEvent `json:"events"`
}

// MethodName interface
func (evt MediaPlayerEventsAdded) MethodName() string {
	return "Media.playerEventsAdded"
}

// Load json
func (evt MediaPlayerEventsAdded) Load(b []byte) *MediaPlayerEventsAdded {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// MediaPlayersCreated Called whenever a player is created, or when a new agent joins and recieves
// a list of active players. If an agent is restored, it will recieve the full
// list of player ids and all events again.
type MediaPlayersCreated struct {
	// Players ...
	Players []*MediaPlayerID `json:"players"`
}

// MethodName interface
func (evt MediaPlayersCreated) MethodName() string {
	return "Media.playersCreated"
}

// Load json
func (evt MediaPlayersCreated) Load(b []byte) *MediaPlayersCreated {
	E(json.Unmarshal(b, &evt))
	return &evt
}
