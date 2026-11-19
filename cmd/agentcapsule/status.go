package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type finding struct {
	Component  string `json:"component"`
	State      string `json:"state"`
	NextCheck  string `json:"next_check"`
	AgeSeconds *int64 `json:"observation_age_seconds,omitempty"`
}

func diagnosePlatform(data json.RawMessage) []finding {
	var report struct {
		Diagnostics struct {
			Hosts []struct {
				ID            string     `json:"host"`
				DataPressure  bool       `json:"data_pressure"`
				ImagePressure bool       `json:"image_pressure"`
				Observed      *time.Time `json:"pressure_observed_at"`
				Queue         []struct {
					Failing int `json:"failing"`
				} `json:"queue"`
			} `json:"hosts"`
		} `json:"diagnostics"`
	}
	if json.Unmarshal(data, &report) != nil {
		return []finding{{"api", "unknown", "check_diagnostics_response", nil}}
	}
	items := []finding{}
	if len(report.Diagnostics.Hosts) == 0 {
		items = append(items, finding{"worker", "unobserved", "check_worker_registration", nil})
	}
	for _, h := range report.Diagnostics.Hosts {
		item := finding{Component: h.ID, State: "unknown", NextCheck: "check_worker_metrics"}
		if h.Observed != nil {
			age := max(int64(0), int64(time.Since(*h.Observed).Seconds()))
			item.AgeSeconds = &age
			item.State = "observed"
			item.NextCheck = "none"
		}
		if h.DataPressure || h.ImagePressure {
			item.State = "storage_pressure"
			item.NextCheck = "check_worker_disk_space"
		}
		for _, q := range h.Queue {
			if q.Failing > 0 {
				items = append(items, finding{h.ID, "jobs_retrying", "check_worker_journal", nil})
				break
			}
		}
		items = append(items, item)
	}
	return items
}
func (cli console) archive(report any) error {
	if cli.outputFile == "" {
		return errors.New("support export requires --output-file PATH.tar.gz")
	}
	data, err := json.MarshalIndent(map[string]any{"version": 1, "observed_at": time.Now().UTC(), "report": report}, "", "  ")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	t := tar.NewWriter(gz)
	if err = t.WriteHeader(&tar.Header{Name: "diagnostics.json", Size: int64(len(data)), Mode: 0600}); err != nil {
		return err
	}
	if _, err = t.Write(data); err != nil {
		return err
	}
	if err = t.Close(); err != nil {
		return err
	}
	if err = gz.Close(); err != nil {
		return err
	}
	f, err := createPrivateFile(cli.outputFile)
	if err != nil {
		return err
	}
	if _, err = f.Write(buf.Bytes()); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(cli.outputFile)
		return err
	}
	path := cli.outputFile
	cli.outputFile = ""
	return cli.print(map[string]string{"archive": path}, "")
}
func (cli console) status(ctx context.Context, api *client, cmd string, watch bool) error {
	c := api.connection
	for {
		report := map[string]any{}
		r, readiness := api.request(ctx, "GET", "/v1/health/ready", "", "", nil)
		if readiness != nil {
			failure := finding{"api", "unreachable", "check_api_tls_and_connectivity", nil}
			var response *apiError
			if errors.As(readiness, &response) {
				failure.State = response.Code
				failure.NextCheck = "check_api_database_and_authority"
				if response.Code == "authority_unavailable" {
					failure.NextCheck = "check_authority_service"
				}
				r.RequestID = response.RequestID
			}
			report["api"] = failure
		} else {
			report["api"] = r.Data
			if err := api.compatible(ctx); err != nil {
				return err
			}
			// A watch can outlive an individual token. Sign again subject to
			// the same server-side membership and trust checks on each poll.
			if c.SigningKey != "" {
				var err error
				c.Token, err = signPersonal(c.SigningKey, c.Organization)
				if err != nil {
					return err
				}
			}
			who, err := api.verifyToken(ctx, c.Token)
			if err != nil {
				return err
			}
			if c.Kind == "platform" {
				r, err = api.request(ctx, "GET", "/v1/platform/diagnostics", "", c.Token, nil)
				if err != nil {
					return err
				}
				report["platform"] = r.Data
				report["checks"] = diagnosePlatform(r.Data)
			} else if cmd == "support export" {
				report["organization_session"] = "authenticated"
			} else {
				report["organization"] = who.Data
			}
		}
		if cmd == "support export" {
			if err := cli.archive(report); err != nil {
				return err
			}
			return readiness
		}
		if err := cli.print(report, r.RequestID); err != nil {
			return err
		}
		if !watch {
			return readiness
		}
		if err := wait(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}
