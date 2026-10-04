package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestCreateClaimRefreshAndRejectOtherDevice(t *testing.T) {
	s := openTest(t)
	d, err := s.Create("Phone", 6)
	if err != nil {
		t.Fatal(err)
	}
	if d.HWID != "" || d.Token == "" || d.UUID == "" {
		t.Fatalf("new device should be unbound with secrets, got %+v", d)
	}

	got, err := s.Claim(d.Token, "UE42LJXu4DbiCaBv", "iOS", "iPhone")
	if err != nil {
		t.Fatal(err)
	}
	if got.HWID != "ue42ljxu4dbicabv" {
		t.Fatalf("hwid stored lowercase, got %q", got.HWID)
	}

	again, err := s.Claim(d.Token, "ue42ljxu4dbicabv", "iOS", "iPhone")
	if err != nil {
		t.Fatal(err)
	}
	if again.UUID != got.UUID {
		t.Fatal("refresh must keep the same uuid")
	}

	if _, err := s.Claim(d.Token, "OtherDevice99", "", ""); err != ErrHWIDMismatch {
		t.Fatalf("other device: %v", err)
	}
	still, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if still[0].HWID != got.HWID || still[0].UUID != got.UUID {
		t.Fatal("rejected claim must not change the lock")
	}
}

func TestMissingHWIDDoesNotBind(t *testing.T) {
	s := openTest(t)
	d, err := s.Create("Laptop", 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(d.Token, "  ", "", ""); err != ErrHWIDRequired {
		t.Fatalf("empty hwid: %v", err)
	}
	if _, err := s.Claim(d.Token, "short", "", ""); err != ErrBadHWID {
		t.Fatalf("short hwid: %v", err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if list[0].HWID != "" {
		t.Fatal("failed claim bound the device")
	}
}

func TestUnbindRotatesUUID(t *testing.T) {
	s := openTest(t)
	d, err := s.Create("PC", 6)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := s.Claim(d.Token, "abcdefghij1234", "Windows", "PC")
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Unbind(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if next.UUID == bound.UUID || next.HWID != "" || next.Token != d.Token {
		t.Fatalf("unbind should rotate uuid, clear hwid, keep token: %+v", next)
	}
	rebound, err := s.Claim(d.Token, "zzzzzzzzzz9999", "Android", "Tablet")
	if err != nil {
		t.Fatal(err)
	}
	if rebound.UUID != next.UUID || rebound.HWID != "zzzzzzzzzz9999" {
		t.Fatalf("new device should lock the same url: %+v", rebound)
	}
}

func TestRevokeFreesSlotAndBlocksClaim(t *testing.T) {
	s := openTest(t)
	d, err := s.Create("TV", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("Extra", 1); err != ErrLimit {
		t.Fatalf("limit: %v", err)
	}
	if _, err := s.Revoke(d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(d.Token, "abcdefghij1234", "", ""); err != ErrRevoked {
		t.Fatalf("revoked claim: %v", err)
	}
	active, err := s.Active()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("revoked device still active: %+v", active)
	}
	if _, err := s.Create("Replacement", 1); err != nil {
		t.Fatal(err)
	}
}

func TestBadName(t *testing.T) {
	s := openTest(t)
	for _, name := range []string{"", "<script>", "a/b", "nope/name", stringsRepeat()} {
		if _, err := s.Create(name, 6); err != ErrBadName {
			t.Fatalf("name %q: %v", name, err)
		}
	}
}

func TestUnknownToken(t *testing.T) {
	s := openTest(t)
	if _, err := s.Claim("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "abcdefghij1234", "", ""); err != ErrNotFound {
		t.Fatal(err)
	}
}

func TestPersistReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Create("Phone", 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(d.Token, "abcdefghij1234", "iOS", "iPhone"); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s2.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].HWID != "abcdefghij1234" || list[0].Token != d.Token {
		t.Fatalf("reopen lost state: %+v", list)
	}
}

func TestParallelClaimOneWinner(t *testing.T) {
	s := openTest(t)
	d, err := s.Create("Race", 6)
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	hwids := []string{
		"aaaaaaaaaa1111", "bbbbbbbbbb2222", "cccccccccc3333", "dddddddddd4444",
		"eeeeeeeeee5555", "ffffffffff6666", "gggggggggg7777", "hhhhhhhhhh8888",
		"iiiiiiiiii9999", "jjjjjjjjjj0000", "kkkkkkkkkk1234", "llllllllll5678",
		"mmmmmmmmmm9012", "nnnnnnnnnn3456", "oooooooooo7890", "pppppppppp1357",
	}
	var wg sync.WaitGroup
	wins := make(chan string, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(hw string) {
			defer wg.Done()
			got, err := s.Claim(d.Token, hw, "Android", "Phone")
			if err == nil {
				wins <- got.HWID
				return
			}
			if err != ErrHWIDMismatch {
				errs <- err
			}
		}(hwids[i])
	}
	wg.Wait()
	close(wins)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var locked []string
	for h := range wins {
		locked = append(locked, h)
	}
	if len(locked) != 1 {
		t.Fatalf("winners: %v", locked)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if list[0].HWID != locked[0] {
		t.Fatalf("stored %s winner %s", list[0].HWID, locked[0])
	}
}

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stringsRepeat() string {
	return "abcdefghijklmnopqrstuvwxyz0123456789"
}
