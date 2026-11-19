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

// These fields can be included in a support archive. New fields in an API
// response need an explicit review before leaving the operator's workstation.
type platformSummary struct {
	ObservedAt  time.Time `json:"observed_at"`
	Diagnostics struct {
		PostgresVersion   string `json:"postgresql_version"`
		ExpectedMigration int    `json:"expected_migration"`
		Hosts             []struct {
			ID              string     `json:"host"`
			RunningVMs      int64      `json:"running_vms"`
			StorageLimit    int64      `json:"storage_limit_mib"`
			StorageReserved int64      `json:"storage_reserved_mib"`
			DataPressure    bool       `json:"data_pressure"`
			ImagePressure   bool       `json:"image_pressure"`
			Observed        *time.Time `json:"pressure_observed_at,omitempty"`
			Queue           []struct {
				Kind    string `json:"kind"`
				Jobs    int64  `json:"jobs"`
				Due     int64  `json:"due"`
				Failing int64  `json:"failing"`
			} `json:"queue"`
		} `json:"hosts"`
	} `json:"diagnostics"`
}

func (report platformSummary) findings() []finding {
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
			var ready struct {
				Status    string `json:"status"`
				Authority string `json:"authority,omitempty"`
			}
			if err := json.Unmarshal(r.Data, &ready); err != nil || ready.Status != "ready" {
				return errors.New("invalid API readiness response")
			}
			report["api"] = ready
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
				var summary platformSummary
				if err := json.Unmarshal(r.Data, &summary); err != nil || summary.Diagnostics.Hosts == nil {
					return errors.New("invalid platform diagnostics response")
				}
				report["platform"] = r.Data
				if cmd == "support export" {
					report["platform"] = summary
				}
				report["checks"] = summary.findings()
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
