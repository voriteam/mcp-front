package cube

import (
	"context"
	"encoding/json"
	"strings"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListInlineTools(t *testing.T) {
	s := NewServer("http://localhost:4000/cubejs-api", "test-secret")
	tools := s.ListInlineTools()

	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %s has empty description", tool.Name)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %s has invalid input schema: %v", tool.Name, err)
		}
	}

	for _, name := range []string{"meta", "query", "dimension_search"} {
		if !names[name] {
			t.Errorf("missing tool %s", name)
		}
	}
}

func TestCallMeta(t *testing.T) {
	expected := map[string]any{"cubes": []any{}}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/cubejs-api/v1/meta" {
			t.Errorf("expected /cubejs-api/v1/meta, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "eyJ") {
			t.Errorf("expected JWT in Authorization header, got %s", auth)
		}
		json.NewEncoder(w).Encode(expected)
	}))
	defer ts.Close()

	s := NewServer(ts.URL+"/cubejs-api", "test-secret")
	result, err := s.CallInlineTool(context.Background(), "meta", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if _, exists := resultMap["cubes"]; !exists {
		t.Error("expected cubes key in result")
	}
}

func TestCallQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/cubejs-api/v1/load" {
			t.Errorf("expected /cubejs-api/v1/load, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("invalid request body: %v", err)
		}

		query, ok := envelope["query"].(map[string]any)
		if !ok {
			t.Fatalf("expected query envelope, got %v", envelope)
		}

		measures, ok := query["measures"].([]any)
		if !ok || len(measures) != 1 || measures[0] != "Orders.count" {
			t.Errorf("unexpected measures: %v", query["measures"])
		}

		json.NewEncoder(w).Encode(map[string]any{
			"data": []any{map[string]any{"Orders.count": "42"}},
		})
	}))
	defer ts.Close()

	s := NewServer(ts.URL+"/cubejs-api", "test-secret")
	result, err := s.CallInlineTool(context.Background(), "query", map[string]any{
		"measures":   []string{"Orders.count"},
		"dimensions": []string{"Orders.status"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if _, exists := resultMap["data"]; !exists {
		t.Error("expected data key in result")
	}
}

func TestCallDimensionSearch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("invalid request body: %v", err)
		}

		query, ok := envelope["query"].(map[string]any)
		if !ok {
			t.Fatalf("expected query envelope, got %v", envelope)
		}

		dimensions, ok := query["dimensions"].([]any)
		if !ok || len(dimensions) != 1 || dimensions[0] != "Stores.name" {
			t.Errorf("unexpected dimensions: %v", query["dimensions"])
		}

		filters, ok := query["filters"].([]any)
		if !ok || len(filters) != 1 {
			t.Fatalf("expected 1 filter, got %v", query["filters"])
		}
		filter := filters[0].(map[string]any)
		if filter["member"] != "Stores.name" {
			t.Errorf("expected filter member Stores.name, got %v", filter["member"])
		}
		if filter["operator"] != "contains" {
			t.Errorf("expected operator contains, got %v", filter["operator"])
		}
		values := filter["values"].([]any)
		if len(values) != 1 || values[0] != "Caribbean" {
			t.Errorf("expected filter value Caribbean, got %v", values)
		}

		limit, ok := query["limit"].(float64)
		if !ok || limit != 100 {
			t.Errorf("expected limit 100, got %v", query["limit"])
		}

		json.NewEncoder(w).Encode(map[string]any{
			"data": []any{
				map[string]any{"Stores.name": "Caribbean Supercenter"},
			},
		})
	}))
	defer ts.Close()

	s := NewServer(ts.URL+"/cubejs-api", "test-secret")
	result, err := s.CallInlineTool(context.Background(), "dimension_search", map[string]any{
		"dimension": "Stores.name",
		"query":     "Caribbean",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if _, exists := resultMap["data"]; !exists {
		t.Error("expected data key in result")
	}
}

func TestCallDimensionSearchValidation(t *testing.T) {
	s := NewServer("http://localhost:4000/cubejs-api", "test-secret")

	_, err := s.CallInlineTool(context.Background(), "dimension_search", map[string]any{
		"dimension": "Stores.name",
	})
	if err == nil {
		t.Error("expected error for missing query")
	}

	_, err = s.CallInlineTool(context.Background(), "dimension_search", map[string]any{
		"query": "Caribbean",
	})
	if err == nil {
		t.Error("expected error for missing dimension")
	}
}

func TestCallUnknownTool(t *testing.T) {
	s := NewServer("http://localhost:4000/cubejs-api", "test-secret")
	_, err := s.CallInlineTool(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer ts.Close()

	s := NewServer(ts.URL+"/cubejs-api", "test-secret")
	_, err := s.CallInlineTool(context.Background(), "meta", nil)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestTrailingSlashNormalization(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cubejs-api/v1/meta" {
			t.Errorf("expected /cubejs-api/v1/meta, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"cubes": []any{}})
	}))
	defer ts.Close()

	s := NewServer(ts.URL+"/cubejs-api/", "test-secret")
	_, err := s.CallInlineTool(context.Background(), "meta", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
