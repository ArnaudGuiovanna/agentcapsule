package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
)

func buildCorpusOptions(a *action, o options, body map[string]any, set func(string, any) error) error {
	switch a.name {
	case "source-credential create":
		if v := o.take("host"); v != "" {
			return set("host", v)
		}
	case "corpus create":
		if title := o.take("title"); title != "" {
			if err := set("title", title); err != nil {
				return err
			}
		}
		git := o.take("git")
		if git == "" {
			return nil
		}
		if _, ok := body["source"]; ok {
			return errors.New("supply the repository in the document or with --git")
		}
		u, err := url.Parse(git)
		if err != nil {
			return errors.New("invalid --git URL")
		}
		kind := o.take("kind")
		a.credentialRef = o.take("credential")
		if kind == "" {
			switch strings.ToLower(u.Hostname()) {
			case "github.com":
				kind = repository.GitHub
			case "gitlab.com":
				kind = repository.GitLab
			default:
				if a.credentialRef == "" {
					return errors.New("provide --kind github or gitlab for a custom forge")
				}
			}
		}
		if kind != "" {
			if _, err = repository.ParseURL(kind, git); err != nil {
				return err
			}
		}
		source := map[string]string{"url": git, "ref": o.take("ref"), "kind": kind}
		if source["ref"] == "" {
			return errors.New("provide --ref for the repository")
		}
		if v := o.take("path"); v != "" {
			source["path"] = v
		}
		body["source"] = source
	case "corpus build":
		for _, k := range []string{"ref", "commit"} {
			if v := o.take(k); v != "" {
				if err := set(k, v); err != nil {
					return err
				}
			}
		}
		if body["ref"] != nil && body["commit"] != nil {
			return errors.New("choose --ref or --commit")
		}
	case "corpus-build try":
		for k, field := range map[string]string{"agent": "agent_id", "mount": "mount"} {
			if v := o.take(k); v != "" {
				if err := set(field, v); err != nil {
					return err
				}
			}
		}
	case "corpus-build publish":
		if v := o.take("version"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return errors.New("expected a positive --version")
			}
			return set("version", n)
		}
	}
	return nil
}

// Names on the CLI resolve in the authenticated organization; the API
// receives immutable IDs. Source credentials expose metadata only.
func (c *client) resolveCorpusAction(ctx context.Context, a *action, token string) error {
	if a.corpusRef != "" && !corpusmeta.ValidID("cor", a.corpusRef) {
		r, err := c.request(ctx, "GET", "/v1/corpora?name="+url.QueryEscape(a.corpusRef), "", token, nil)
		if err != nil {
			return err
		}
		var page struct{ Items []struct{ ID, Name string } }
		if json.Unmarshal(r.Data, &page) != nil {
			return errors.New("invalid corpus listing")
		}
		if len(page.Items) != 1 || page.Items[0].Name != a.corpusRef {
			return &apiError{Status: 404, Code: "not_found", RequestID: r.RequestID}
		}
		id := page.Items[0].ID
		if !corpusmeta.ValidID("cor", id) {
			return errors.New("invalid corpus identifier")
		}
		u, _ := url.ParseRequestURI(a.path)
		q := u.Query()
		if q.Has("corpus_id") {
			q.Set("corpus_id", id)
			u.RawQuery = q.Encode()
			a.path = u.RequestURI()
		} else {
			a.path = strings.Replace(a.path, "/corpora/"+url.PathEscape(a.corpusRef), "/corpora/"+id, 1)
		}
	}
	if a.credentialRef == "" {
		return nil
	}
	var body map[string]json.RawMessage
	var src map[string]string
	if json.Unmarshal(a.body, &body) != nil || json.Unmarshal(body["source"], &src) != nil {
		return errors.New("invalid repository source")
	}
	if corpusmeta.ValidID("scr", a.credentialRef) && src["kind"] != "" {
		src["credential_id"] = a.credentialRef
	} else {
		after := ""
		for {
			route := "/v1/source-credentials?limit=200&after=" + url.QueryEscape(after)
			r, err := c.request(ctx, "GET", route, "", token, nil)
			if err != nil {
				return err
			}
			var page struct {
				Items []struct{ ID, Name, Kind string }
			}
			if json.Unmarshal(r.Data, &page) != nil {
				return errors.New("invalid source credential listing")
			}
			for _, m := range page.Items {
				if m.Name == a.credentialRef || m.ID == a.credentialRef {
					if !corpusmeta.ValidID("scr", m.ID) {
						return errors.New("invalid source credential identifier")
					}
					src["credential_id"] = m.ID
					if src["kind"] == "" {
						src["kind"] = m.Kind
					}
					break
				}
			}
			if src["credential_id"] != "" {
				break
			}
			if len(page.Items) < 200 {
				return &apiError{Status: 404, Code: "not_found", RequestID: r.RequestID}
			}
			cursor := page.Items[len(page.Items)-1].ID
			if cursor <= after {
				return errors.New("source credential pagination did not advance")
			}
			after = cursor
		}
	}
	if _, err := repository.ParseURL(src["kind"], src["url"]); err != nil {
		return err
	}
	body["source"], _ = json.Marshal(src)
	a.body, _ = json.Marshal(body)
	return nil
}

func (cli console) corpusReview(a action, r reply) error {
	if a.name == "corpus-build index" {
		if cli.outputFile == "" {
			return cli.print(string(r.Data), r.RequestID)
		}
		f, err := createPrivateFile(cli.outputFile)
		if err != nil {
			return err
		}
		_, err = f.Write(r.Data)
		return finishCredentialOutput(f, err)
	}
	report, err := corpusmeta.ParseReport(r.Data)
	if err != nil {
		return err
	}
	files := make([]corpusmeta.ReportEntry, 0, len(report.Files))
	for _, f := range report.Files {
		if a.fileStatus == "" || a.fileStatus == f.Status {
			files = append(files, f)
		}
	}
	return cli.print(map[string]any{"items": files}, r.RequestID)
}
