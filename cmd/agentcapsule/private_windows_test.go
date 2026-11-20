package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func allowEveryone(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCredentialsRejectBroadACL(t *testing.T) {
	parent := t.TempDir()
	allowEveryone(t, parent)
	path := filepath.Join(parent, "bearer")
	f, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Check the handle before the first write in a world-accessible parent.
	if err := verifyPrivateFile(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	allowEveryone(t, path)
	if _, err := readFile(path, true); err == nil {
		t.Fatal("accepted a bearer file accessible to Everyone")
	}
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(parent, "config"))
	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	c := connection{URL: "https://example.test", Kind: "platform", Token: "secret"}
	if err := saveContext(dir, "test", c); err != nil {
		t.Fatal(err)
	}
	allowEveryone(t, contextPath(dir, "test"))
	if _, err := loadContext(dir, "test"); err == nil {
		t.Fatal("accepted context accessible to Everyone")
	}
	allowEveryone(t, dir)
	if _, err := configDir(); err == nil {
		t.Fatal("accepted config directory accessible to Everyone")
	}
}
