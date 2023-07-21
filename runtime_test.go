package sqlrisk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCpuUsage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [{
        "metric": {
          "env": "prod",
          "vip": "10.2.16.15"
        },
        "value": [1688372379, "10.0"]
      }
    ]
  }
}
`))
	})
	want := 10.0
	server := httptest.NewServer(handler)
	defer server.Close()
	ret, err := NewClient(server.URL).CpuUsage("10.2.16.15", time.Now())
	if err != nil {
		t.Fatalf("CpuUsage failed, got error: %s", err)
	}

	if ret != want {
		t.Fatalf("CpuUsage failed, got:%v, want:%v", ret, want)
	}
}

func TestNoDataPoints(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": []
  }
}
`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	_, err := NewClient(server.URL).CpuUsage("10.2.16.15", time.Now())
	if !strings.Contains(err.Error(), NoDataPointError.Error()) {
		t.Fatalf("TestNoDataPoints: got:%v, want:%v", err, NoDataPointError)
	}
}

func TestDiskUsage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [{
        "metric": {
          "env": "prod",
          "vip": "10.2.16.15"
        },
        "value": [1688372379, "60.0"]
      }
    ]
  }
}
`))
	})
	want := 60.0
	server := httptest.NewServer(handler)
	defer server.Close()
	ret, err := NewClient(server.URL).DiskUsage("10.2.16.15", time.Now())
	if err != nil {
		t.Fatalf("DiskUsage failed, got error: %s", err)
	}

	if ret != want {
		t.Fatalf("DiskUsage failed, got:%v, want:%v", ret, want)
	}
}

func TestDiskTotal(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [{
        "metric": {
          "env": "prod",
          "vip": "10.2.16.15"
        },
        "value": [1688372379, "1024.00"]
      }
    ]
  }
}
`))
	})
	want := 1024.00
	server := httptest.NewServer(handler)
	defer server.Close()
	ret, err := NewClient(server.URL).DiskTotal("10.2.16.15", time.Now())
	if err != nil {
		t.Fatalf("DiskTotal failed, got error: %s", err)
	}

	if ret != want {
		t.Fatalf("DiskTotal failed, got:%v, want:%v", ret, want)
	}
}

func TestDiskUsed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [{
        "metric": {
          "env": "prod",
          "vip": "10.2.16.15"
        },
        "value": [1688372379, "1024.00"]
      }
    ]
  }
}
`))
	})
	want := 1024.00
	server := httptest.NewServer(handler)
	defer server.Close()
	ret, err := NewClient(server.URL).DiskUsed("10.2.16.15", time.Now())
	if err != nil {
		t.Fatalf("DiskUsed failed, got error: %s", err)
	}

	if ret != want {
		t.Fatalf("DiskUsed failed, got:%v, want:%v", ret, want)
	}
}

func TestDiskFree(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [{
        "metric": {
          "env": "prod",
          "vip": "10.2.16.15"
        },
        "value": [1688372379, "1024.00"]
      }
    ]
  }
}
`))
	})
	want := 1024.00
	server := httptest.NewServer(handler)
	defer server.Close()
	ret, err := NewClient(server.URL).DiskFree("10.2.16.15", time.Now())
	if err != nil {
		t.Fatalf("DiskFree failed, got error: %s", err)
	}

	if ret != want {
		t.Fatalf("DiskFree failed, got:%v, want:%v", ret, want)
	}
}
