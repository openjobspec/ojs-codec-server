package main

import "net/http"

type keyInfo struct {
	ID      string `json:"id"`
	Current bool   `json:"current"`
}

// handleListKeys returns metadata about registered encryption keys.
func handleListKeys(provider *MultiKeyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		currentID := provider.CurrentKeyID()
		ids := provider.ListKeyIDs()
		keys := make([]keyInfo, len(ids))
		for i, id := range ids {
			keys[i] = keyInfo{ID: id, Current: id == currentID}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"keys":       keys,
			"total":      len(keys),
			"current_id": currentID,
		})
	}
}
