//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
)

type corpusMediaRefusals struct {
	alias, budget atomic.Int64
}

func (m *corpusMediaRefusals) ObserveLLM(e llmservice.CallEvent) {
	if e.Outcome == "refused" {
		switch e.Reason {
		case "alias_access":
			m.alias.Add(1)
		case "budget_cost":
			m.budget.Add(1)
		}
	}
}

// The two commits contain the same mixed corpus. The second adds a copy of the
// scanned PDF and of the audio at new paths, forcing fresh inference attempts.
func TestCorpusBuilderPaidInferenceOnKVM(t *testing.T) {
	config := os.Getenv("AGENTCAPSULE_KVM_CORPUS_METERING")
	raw, err := os.ReadFile(config)
	var fixtures []gitHubCorpusFixture
	if err != nil || json.Unmarshal(raw, &fixtures) != nil || len(fixtures) != 2 {
		t.Fatal("expected two synthetic corpus fixture descriptors")
	}
	for i := range fixtures {
		if !filepath.IsAbs(fixtures[i].Archive) {
			fixtures[i].Archive = filepath.Join(filepath.Dir(config), fixtures[i].Archive)
		}
	}
	target, err := url.Parse(os.Getenv("AGENTCAPSULE_KVM_CORPUS_MEDIA_URL"))
	if err != nil || target.Scheme != "http" || !net.ParseIP(target.Hostname()).IsLoopback() || target.Path != "" || target.User != nil {
		t.Fatal("expected the loopback origin of the test media provider")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var pages, clips atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ocr":
			pages.Add(1)
		case "/v1/audio/transcriptions":
			clips.Add(1)
		default:
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	setup := setupCorpusBuilder(t, fixtures, "")
	lab, owner := setup.lab, setup.owner
	service, err := llmservice.New(lab.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 110 * time.Second, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	var refusals corpusMediaRefusals
	service.Observe(&refusals)
	if err = lab.worker.EnableLLM(service); err != nil {
		t.Fatal(err)
	}
	var provider controlplane.LLMProvider
	lab.request(owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "media", Kind: "openai_compatible", BaseURL: upstream.URL + "/v1", AuthMode: "none"}, 201, &provider)
	pagePrice, minutePrice := int64(3000), int64(6000)
	for _, alias := range []controlplane.CreateLLMAliasInput{
		{Alias: "page", ProviderID: provider.ID, UpstreamModel: "tesseract", Operations: []string{"ocr"}, OCRMicroPerPage: &pagePrice},
		{Alias: "voice", ProviderID: provider.ID, UpstreamModel: "whisper", Operations: []string{"transcribe"}, AudioMicroPerMinute: &minutePrice},
	} {
		lab.request(owner(), "POST", "/v1/llm/aliases", "alias-"+alias.Alias, alias, 201, nil)
	}
	usage := func() controlplane.LLMUsageReport {
		var u controlplane.LLMUsageReport
		lab.request(owner(), "GET", "/v1/llm/usage?period=day", "", nil, 200, &u)
		return u
	}
	parseCosts := func(job controlplane.CorpusBuild) map[string]int64 {
		t.Helper()
		var values map[string]*int64
		if err := json.Unmarshal(job.Costs, &values); err != nil {
			t.Fatal(err)
		}
		out := map[string]int64{}
		for _, field := range []string{"llm_calls", "pages", "audio_seconds", "cost_micros", "input_tokens", "output_tokens"} {
			if values[field] == nil {
				t.Fatal("missing or unpriced build meter", field)
			}
			out[field] = *values[field]
		}
		return out
	}
	wanted := map[string]string{
		"docs/manual.docx": "converted", "docs/slides.pptx": "converted", "docs/budget.xlsx": "converted", "docs/values.csv": "converted", "docs/manual.md": "converted",
		"docs/scan.pdf": "converted", "docs/voice.wav": "converted", "docs/silent.mp4": "converted", "docs/diagram.png": "skipped",
	}
	checkFiles := func(report corpusmeta.Report, want map[string]string) {
		t.Helper()
		got := map[string]string{}
		for _, f := range report.Files {
			got[f.Path] = f.Status
			if f.Status == "failed" && f.Error != "inference_failed" {
				t.Error("refusal", f.Path, f.Error)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("file outcomes %+v, wanted %+v", report.Files, want)
		}
	}
	cold, report := setup.build(t, "paid-cold", fixtures[0], controlplane.RequestCorpusBuildInput{Commit: fixtures[0].Commit})
	checkFiles(report, wanted)
	markers := map[string]string{
		"docs/manual.docx": "DOCXMIXED", "docs/slides.pptx": "PPTXMIXED", "docs/budget.xlsx": "XLSXMIXED",
		"docs/values.csv": "CSVMIXED", "docs/manual.md": "CORRECTEDMIXED", "docs/scan.pdf": "LOUTRE-317", "docs/voice.wav": "température",
	}
	for _, f := range report.Files {
		if marker := markers[f.Path]; marker != "" {
			path := "/v1/corpus-builds/" + cold.ID + "/review-file?path=docs/" + f.DocID + "/README.md"
			reviewed := lab.request(owner(), "GET", path, "", nil, 200, nil)
			if !strings.Contains(strings.ToLower(string(reviewed)), strings.ToLower(marker)) {
				t.Errorf("review of %s lacks %q", f.Path, marker)
			} else {
				t.Logf("reviewed %s contains %q", f.Path, marker)
			}
		}
	}
	bill := parseCosts(cold)
	org := usage()
	seconds := bill["audio_seconds"]
	expectedCost := pagePrice + seconds*minutePrice/60
	if bill["llm_calls"] != 2 || bill["pages"] != 1 || seconds < 1 || bill["cost_micros"] != expectedCost || pages.Load() != 1 || clips.Load() != 1 ||
		org.Totals.Calls != 2 || org.Totals.SettledPages != 1 || org.Totals.SettledAudioSeconds != seconds || org.Totals.EstimatedCostMicro != expectedCost ||
		len(org.Lines) != 2 || org.Lines[0].AgentID == "" || org.Lines[0].AgentID != org.Lines[1].AgentID {
		t.Fatalf("cold build=%s org=%+v provider pages=%d clips=%d", cold.Costs, org, pages.Load(), clips.Load())
	}
	t.Logf("cold build=%s ledger=%+v provider OCR=%d transcription=%d", cold.Costs, org.Totals, pages.Load(), clips.Load())
	for path, status := range wanted {
		if status == "converted" {
			wanted[path] = "cached"
		}
	}
	warm, report := setup.build(t, "paid-warm", fixtures[0], controlplane.RequestCorpusBuildInput{Commit: fixtures[0].Commit})
	checkFiles(report, wanted)
	verifyFree := func(job controlplane.CorpusBuild) {
		t.Helper()
		for k, n := range parseCosts(job) {
			if n != 0 {
				t.Fatal("unexpected meter", k, n)
			}
		}
		if after := usage(); !reflect.DeepEqual(after, org) || pages.Load() != 1 || clips.Load() != 1 {
			t.Fatalf("unexpected usage %+v, provider OCR=%d transcription=%d", after, pages.Load(), clips.Load())
		}
		t.Logf("costs=%s provider OCR=%d transcription=%d", job.Costs, pages.Load(), clips.Load())
	}
	verifyFree(warm)
	if warm.ImageDigest != cold.ImageDigest {
		t.Fatal("identical source produced a different corpus")
	}
	// The organization owner obtains the actual caller ID from its usage API.
	// The normal alias administration routes suffice for the hidden agent.
	lab.request(owner(), "POST", "/v1/llm/aliases/voice/grants", "grant", controlplane.CreateLLMAliasGrantInput{AgentID: org.Lines[0].AgentID}, 201, nil)
	for _, alias := range []string{"voice", "page"} {
		lab.request(owner(), "POST", "/v1/llm/aliases/"+alias+"/access", "listed-"+alias, controlplane.SetLLMAliasAccessInput{Access: "listed"}, 200, nil)
	}
	lab.request(owner(), "POST", "/v1/llm/budgets", "hard", controlplane.CreateLLMBudgetInput{Alias: "voice", Period: "day", LimitCostMicro: 1, Mode: "hard"}, 201, nil)
	denied, report := setup.build(t, "paid-denied", fixtures[1], controlplane.RequestCorpusBuildInput{Commit: fixtures[1].Commit})
	wanted["docs/new-scan.pdf"] = "failed"
	wanted["docs/new-voice.wav"] = "failed"
	checkFiles(report, wanted)
	verifyFree(denied)
	if refusals.alias.Load() != 1 || refusals.budget.Load() != 1 {
		t.Fatal("wrong gateway refusals", refusals.alias.Load(), refusals.budget.Load())
	}
	t.Logf("new-scan.pdf alias_access=%d, new-voice.wav budget_cost=%d; report totals=%+v", refusals.alias.Load(), refusals.budget.Load(), report.Totals)
}
