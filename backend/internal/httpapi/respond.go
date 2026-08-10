package httpapi

import (
	"encoding/json"
	"net/http"
)

type apiError struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	writeJSON(writer, status, apiError{
		OK:        false,
		Code:      code,
		Message:   message,
		RequestID: requestIDFromContext(request.Context()),
	})
}
