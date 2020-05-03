// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// ServiceWorkerWorkerErrorReported ...
type ServiceWorkerWorkerErrorReported struct {
	// ErrorMessage ...
	ErrorMessage *ServiceWorkerServiceWorkerErrorMessage `json:"errorMessage"`
}

// MethodName interface
func (evt ServiceWorkerWorkerErrorReported) MethodName() string {
	return "ServiceWorker.workerErrorReported"
}

// Load json
func (evt ServiceWorkerWorkerErrorReported) Load(b []byte) *ServiceWorkerWorkerErrorReported {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// ServiceWorkerWorkerRegistrationUpdated ...
type ServiceWorkerWorkerRegistrationUpdated struct {
	// Registrations ...
	Registrations []*ServiceWorkerServiceWorkerRegistration `json:"registrations"`
}

// MethodName interface
func (evt ServiceWorkerWorkerRegistrationUpdated) MethodName() string {
	return "ServiceWorker.workerRegistrationUpdated"
}

// Load json
func (evt ServiceWorkerWorkerRegistrationUpdated) Load(b []byte) *ServiceWorkerWorkerRegistrationUpdated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// ServiceWorkerWorkerVersionUpdated ...
type ServiceWorkerWorkerVersionUpdated struct {
	// Versions ...
	Versions []*ServiceWorkerServiceWorkerVersion `json:"versions"`
}

// MethodName interface
func (evt ServiceWorkerWorkerVersionUpdated) MethodName() string {
	return "ServiceWorker.workerVersionUpdated"
}

// Load json
func (evt ServiceWorkerWorkerVersionUpdated) Load(b []byte) *ServiceWorkerWorkerVersionUpdated {
	E(json.Unmarshal(b, &evt))
	return &evt
}
