package beacon

import (
	"encoding/json"
	"net/http"
	"strings"
)

// CallbackHandler provides an HTTP handler to receive and correlate asynchronous callbacks.
type CallbackHandler struct {
	correlator *Correlator
}

// NewCallbackHandler creates a new CallbackHandler instance.
func NewCallbackHandler(correlator *Correlator) *CallbackHandler {
	return &CallbackHandler{correlator: correlator}
}

// ServeHTTP handles incoming callback requests and checks for correlation IDs in headers or query parameters.
func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceID := r.Header.Get("X-Correlation-ID")
	if traceID == "" {
		traceID = r.URL.Query().Get("trace_id")
	}

	if traceID == "" {
		traceparent := r.Header.Get("traceparent")
		parts := strings.Split(traceparent, "-")
		if len(parts) >= 3 && len(parts[1]) == 32 {
			traceID = parts[1]
		}
	}

	if traceID == "" {
		http.Error(w, `{"error":"missing correlation identifier"}`, http.StatusBadRequest)
		return
	}

	token, found := h.correlator.Resolve(traceID)
	if !found {
		http.Error(w, `{"error":"unknown or expired trace token"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "correlated",
		"token_id": token.ID,
		"origin":   token.Origin,
		"latency":  token.ResolvedAt.Sub(token.CreatedAt).String(),
	})
}
