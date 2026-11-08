package controlplane

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (il *invocationLab) upload(t *testing.T, p Principal, key, name string, body []byte, ttl int) (Attachment, APIReceipt, error) {
	t.Helper()
	r, err := il.c.UploadAttachment(t.Context(), p, il.agent, key, AttachmentUpload{Name: name, MediaType: "text/plain", TTLSeconds: ttl}, body)
	if err != nil {
		return Attachment{}, r, err
	}
	var v Attachment
	if err = json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	return v, r, nil
}

func (il *invocationLab) invokeWith(t *testing.T, p Principal, key string, files ...string) (Invocation, error) {
	t.Helper()
	r, err := il.c.CreateInvocation(t.Context(), p, il.agent, key, InvocationInput{OwnerInstruction: privateInstruction("see files"), Attachments: files})
	if err != nil {
		return Invocation{}, err
	}
	return decodeInvocation(t, r), nil
}

func (il *invocationLab) invoker(t *testing.T, subject string) Principal {
	t.Helper()
	m, p := il.person(t, subject)
	assign(t, il.tenantLab, il.owner, il.agent, CreateAssignmentInput{PrincipalID: m.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, "assign-"+subject)
	return p
}

func TestAttachmentReachesOnlyItsRunningInvocationEncrypted(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	data := randomBytes(t, 2*capsuleprotocol.AttachmentSegmentBytes+12345) // three segments
	att, _, err := il.upload(t, alice, "u1", "naïve-notes.bin", data, 0)
	sum := sha256.Sum256(data)
	if err != nil || att.State != "pending" || att.Size != int64(len(data)) || att.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("upload", att, err)
	}
	// Only ciphertext is stored, bound to its position.
	rows, err := il.s.pool.Query(t.Context(), "SELECT idx,ciphertext FROM attachment_segments WHERE attachment_id=$1 ORDER BY idx", att.ID)
	if err != nil {
		t.Fatal(err)
	}
	var segments [][]byte
	for rows.Next() {
		var i int
		var c []byte
		if err = rows.Scan(&i, &c); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(c, data[i*capsuleprotocol.AttachmentSegmentBytes:i*capsuleprotocol.AttachmentSegmentBytes+64]) {
			t.Fatal("plaintext stored", i)
		}
		segments = append(segments, c)
	}
	rows.Close()
	if len(segments) != 3 {
		t.Fatal("segments", len(segments))
	}

	gen := il.run(t)
	caller := VMCaller{AgentID: il.agent, HostID: "local", VMID: fmt.Sprintf("%016x", gen), Generation: gen}
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), caller, att.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("an unsent file was readable by the agent", err)
	}
	inv, err := il.invokeWith(t, alice, "i1", att.ID)
	if err != nil || !slices.Equal(inv.Attachments, []string{att.ID}) {
		t.Fatal("invoke", inv, err)
	}
	if got := mustGet(t, il, alice, inv.ID); !slices.Equal(got.Attachments, []string{att.ID}) {
		t.Fatal("invocation metadata does not list its file", got)
	}
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), caller, att.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("readable before the invocation runs", err)
	}

	var mbx string
	if err = il.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", inv.ID).Scan(&mbx); err != nil {
		t.Fatal(err)
	}
	attempt, envelope := claimInstruction(t, il.tr, mbx)
	decoded, err := capsuleprotocol.DecodeInvocation(envelope, il.agent)
	if err != nil || len(decoded.Attachments) != 1 {
		t.Fatal("envelope", err)
	}
	ref := decoded.Attachments[0]
	if ref.ID != att.ID || ref.Name != "naïve-notes.bin" || ref.Size != att.Size || ref.SHA256 != att.SHA256 || bytes.Contains(envelope.Body, data[:64]) {
		t.Fatal("envelope reference", ref)
	}
	// The running capsule reads every segment; the bytes match the reference.
	var got bytes.Buffer
	for i := 0; ; i++ {
		seg, err := il.tr.ReadAttachmentFromVM(t.Context(), caller, att.ID, i)
		if errors.Is(err, ErrNotFound) && i == 3 {
			break
		}
		if err != nil || seg.Index != i || seg.Total != 3 {
			t.Fatal("segment", i, err)
		}
		got.Write(seg.Data)
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("reassembled file differs")
	}
	stale := caller
	stale.Generation++
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), stale, att.ID, 0); !errors.Is(err, ErrPlacement) {
		t.Fatal("a stale VM read a file", err)
	}
	// A segment moved to another position no longer opens.
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE attachment_segments SET ciphertext=$2 WHERE attachment_id=$1 AND idx=0", att.ID, segments[1]); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), caller, att.ID, 0); !errors.Is(err, ErrTransitPayload) {
		t.Fatal("a swapped segment opened", err)
	}
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE attachment_segments SET ciphertext=$2 WHERE attachment_id=$1 AND idx=0", att.ID, segments[0]); err != nil {
		t.Fatal(err)
	}

	// Once the invocation is answered, the file is no longer readable.
	rt := instructionRuntimeLab(t, il.agent)
	r, err := rt.Invoke(t.Context(), il.agent, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = il.tr.AcknowledgeInstruction(t.Context(), mbx, attempt.Token, r.Result); err != nil {
		t.Fatal(err)
	}
	if _, err = il.tr.ReadAttachmentFromVM(t.Context(), caller, att.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("readable after the invocation completed", err)
	}
	// A used file cannot be sent again.
	if _, err = il.invokeWith(t, alice, "i2", att.ID); !errors.Is(err, ErrAttachment) {
		t.Fatal("a file was attached twice", err)
	}
	// Once the invocation has ended nobody can read the file: its bytes go.
	if n, err := il.s.PurgeAttachments(t.Context(), nil, 10); err != nil || n != 1 {
		t.Fatal("not purged once its invocation ended", n, err)
	}
	if il.count(t, "SELECT count(*) FROM attachment_segments WHERE attachment_id=$1", att.ID) != 0 {
		t.Fatal("bytes kept after purge")
	}
	if v, err := il.c.GetAttachment(t.Context(), alice, att.ID); err != nil || v.State != "purged" {
		t.Fatal("tombstone", v, err)
	}
}

func TestAttachmentUploadRulesAreEnforcedBeforeStoring(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	_, bob := il.person(t, "bob")
	body := []byte("hello")
	if _, _, err := il.upload(t, il.owner, "o1", "a.txt", body, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("an administrator without invoke uploaded", err)
	}
	if _, _, err := il.upload(t, bob, "b1", "a.txt", body, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("an unassigned member uploaded", err)
	}
	for name, try := range map[string]func() error{
		"too large": func() error {
			_, _, err := il.upload(t, alice, "big", "a.txt", make([]byte, capsuleprotocol.MaxAttachmentBytes+1), 0)
			return err
		},
		"empty": func() error { _, _, err := il.upload(t, alice, "e", "a.txt", nil, 0); return err },
		"name":  func() error { _, _, err := il.upload(t, alice, "n", "../a", body, 0); return err },
		"ttl":   func() error { _, _, err := il.upload(t, alice, "t", "a.txt", body, 30); return err },
		"type": func() error {
			_, err := il.c.UploadAttachment(t.Context(), alice, il.agent, "m", AttachmentUpload{Name: "a", MediaType: "Text/Plain"}, body)
			return err
		},
		"digest": func() error {
			_, err := il.c.UploadAttachment(t.Context(), alice, il.agent, "d", AttachmentUpload{Name: "a", MediaType: "text/plain", DeclaredSHA256: hex.EncodeToString(make([]byte, 32))}, body)
			return err
		},
	} {
		if err := try(); err == nil {
			t.Fatal("accepted:", name)
		}
	}
	if il.count(t, "SELECT count(*) FROM attachments") != 0 {
		t.Fatal("a refused upload left a row")
	}
	// Idempotency: same key and bytes replay; other bytes conflict.
	first, _, err := il.upload(t, alice, "k", "a.txt", body, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, r, err := il.upload(t, alice, "k", "a.txt", body, 0)
	if err != nil || !r.Replayed || again.ID != first.ID {
		t.Fatal("replay", err, r.Replayed)
	}
	if _, _, err = il.upload(t, alice, "k", "a.txt", []byte("other"), 0); !errors.Is(err, ErrConflict) {
		t.Fatal("same key, other bytes", err)
	}
	// Metadata: the uploader and an administrator; never another member.
	carol := il.invoker(t, "carol")
	if _, err = il.c.GetAttachment(t.Context(), carol, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member saw the file", err)
	}
	if v, err := il.c.GetAttachment(t.Context(), il.owner, first.ID); err != nil || v.ID != first.ID {
		t.Fatal("administrator metadata", err)
	}
	// Another member cannot send it; nothing is admitted when one file is unusable.
	ops := il.count(t, "SELECT count(*) FROM platform_operations WHERE agent_id=$1", il.agent)
	if _, err = il.invokeWith(t, carol, "c1", first.ID); !errors.Is(err, ErrAttachment) {
		t.Fatal("another member's file was sent", err)
	}
	mine, _, err := il.upload(t, carol, "c-file", "c.txt", body, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.invokeWith(t, carol, "c2", mine.ID, first.ID); !errors.Is(err, ErrAttachment) {
		t.Fatal("a partly unusable list was accepted", err)
	}
	if il.count(t, "SELECT count(*) FROM platform_operations WHERE agent_id=$1", il.agent) != ops ||
		il.count(t, "SELECT count(*) FROM attachments WHERE status='attached'") != 0 {
		t.Fatal("a refused invocation left an operation or a bound file")
	}
	if _, err = il.invokeWith(t, carol, "c3", mine.ID, mine.ID); !errors.Is(err, ErrInput) {
		t.Fatal("duplicate reference", err)
	}
	// Deletion: only the uploader, only while pending.
	if _, err = il.c.DeleteAttachment(t.Context(), carol, first.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("another member deleted the file", err)
	}
	if _, err = il.invokeWith(t, carol, "c4", mine.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.DeleteAttachment(t.Context(), carol, mine.ID, "del"); !errors.Is(err, ErrTransition) {
		t.Fatal("an attached file was deleted", err)
	}
	if _, err = il.c.DeleteAttachment(t.Context(), alice, first.ID, "del"); err != nil {
		t.Fatal(err)
	}
	if il.count(t, "SELECT count(*) FROM attachment_segments WHERE attachment_id=$1", first.ID) != 0 {
		t.Fatal("deleted bytes kept")
	}
	// Uploads and deletions are audited.
	if il.count(t, "SELECT count(*) FROM tenant_agent_audit WHERE action LIKE 'attachment.%'") != 3 { // two uploads, one deletion
		t.Fatal("attachment audit", il.count(t, "SELECT count(*) FROM tenant_agent_audit WHERE action LIKE 'attachment.%'"))
	}
}

func TestAttachmentQuotaHoldsUnderConcurrencyAndExpiryFreesIt(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	if _, err := il.a.SetQueueLimits(t.Context(), il.owner, "limits", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 10, MaxAttachmentBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := il.a.SetQueueLimits(t.Context(), il.owner, "too-small", QueueLimits{MaxPendingPerAgent: 10, MaxPendingTenant: 10, MaxAttachmentBytes: 1000}); !errors.Is(err, ErrInput) {
		t.Fatal("tiny storage quota accepted", err)
	}
	chunk := 300 << 10 // three fit in 1 MiB, four do not
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := il.upload(t, alice, fmt.Sprintf("q%d", i), "q.bin", randomBytes(t, chunk), 0)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrStorageQuota):
			t.Fatal(err)
		}
	}
	if ok != 3 || il.count(t, "SELECT coalesce(sum(size_bytes),0) FROM attachments WHERE status<>'purged'") > 1<<20 {
		t.Fatal("quota overshot", ok)
	}
	// An unused file expires; its space comes back and it can no longer be sent.
	if _, err := il.s.pool.Exec(t.Context(), "UPDATE attachments SET expires_at=clock_timestamp()-interval '1 second' WHERE status='pending'"); err != nil {
		t.Fatal(err)
	}
	var expired string
	if err := il.s.pool.QueryRow(t.Context(), "SELECT id FROM attachments LIMIT 1").Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if _, err := il.invokeWith(t, alice, "late", expired); !errors.Is(err, ErrAttachment) {
		t.Fatal("an expired file was sent", err)
	}
	later := time.Now().Add(time.Minute)
	if n, err := il.s.PurgeAttachments(t.Context(), &later, 10); err != nil || n != 3 {
		t.Fatal("expired files not purged", n, err)
	}
	if _, _, err := il.upload(t, alice, "after", "q.bin", randomBytes(t, chunk), 0); err != nil {
		t.Fatal("space did not come back", err)
	}
}

func TestDeletingAnAgentPurgesItsAttachmentsAtOnce(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	pending, _, err := il.upload(t, alice, "p", "p.txt", []byte("pending"), 0)
	if err != nil {
		t.Fatal(err)
	}
	sent, _, err := il.upload(t, alice, "s", "s.txt", []byte("sent"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = il.invokeWith(t, alice, "i", sent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = il.c.Delete(t.Context(), il.owner, il.agent, "delete"); err != nil {
		t.Fatal(err)
	}
	if il.count(t, "SELECT count(*) FROM attachment_segments") != 0 ||
		il.count(t, "SELECT count(*) FROM attachments WHERE status<>'purged'") != 0 {
		t.Fatal("files of a deleted agent kept their bytes", pending.ID, sent.ID)
	}
}

// Uploads and invocations read the organization row shared, then lock the agent;
// lifecycle commands take the organization row exclusively first. An upload
// audit that wrote the organization row after the agent lock deadlocked against
// concurrent uploads (fixed: attachments change no authorization policy).
func TestConcurrentUploadsInvocationsAndLifecycleDoNotDeadlock(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	if _, err := il.a.SetQueueLimits(t.Context(), il.owner, "limits", QueueLimits{MaxPendingPerAgent: 100, MaxPendingTenant: 100}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := range 8 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _, err := il.create(t, alice, fmt.Sprintf("inv-%d", i), "hello")
			errs <- err
		}()
		go func() {
			defer wg.Done()
			kind := []string{"wake", "sleep"}[i%2]
			_, err := il.c.RequestLifecycle(t.Context(), il.owner, il.agent, fmt.Sprintf("life-%d", i), kind)
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, _, err := il.upload(t, alice, fmt.Sprintf("file-%d", i), "f.txt", []byte("x"), 0)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("a concurrent request failed", err)
		}
	}
}
