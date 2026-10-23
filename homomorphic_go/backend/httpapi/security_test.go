package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"homomorphicgo/store"
)

type securityStore struct {
	StoreIface
	sessions       map[string]int64
	game           *store.Game
	movesCalled    bool
	messagesCalled bool
	applyCalled    bool
	joinCalled     bool
}

func (s *securityStore) UserIDBySession(_ context.Context, token string) (int64, error) {
	if uid, ok := s.sessions[token]; ok {
		return uid, nil
	}
	return 0, store.ErrNotFound
}

func (s *securityStore) UserByID(_ context.Context, id int64) (*store.User, error) {
	return &store.User{ID: id, Username: "user"}, nil
}

func (s *securityStore) GetGame(_ context.Context, _ int64) (*store.Game, error) {
	return s.game, nil
}

func (s *securityStore) Moves(_ context.Context, _ int64) ([]store.Move, error) {
	s.movesCalled = true
	return nil, nil
}

func (s *securityStore) Messages(_ context.Context, _ int64) ([]store.Message, error) {
	s.messagesCalled = true
	return nil, nil
}

func (s *securityStore) ApplyMove(_ context.Context, _, _ int64, _ []byte) error {
	s.applyCalled = true
	return nil
}

func (s *securityStore) JoinGame(_ context.Context, _, _ int64) error {
	s.joinCalled = true
	return nil
}

func request(t *testing.T, api *API, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: token})
	}
	w := httptest.NewRecorder()
	api.Routes().ServeHTTP(w, r)
	return w
}

func TestForgedLegacySessionIsRejected(t *testing.T) {
	st := &securityStore{sessions: map[string]int64{"opaque-token": 11}}
	api := &API{Store: st}

	if got := request(t, api, http.MethodGet, "/api/me", "", "NDI6MQ==").Code; got != http.StatusUnauthorized {
		t.Fatalf("forged legacy token status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := request(t, api, http.MethodGet, "/api/me", "", "opaque-token").Code; got != http.StatusOK {
		t.Fatalf("stored opaque token status = %d, want %d", got, http.StatusOK)
	}
}

func TestOutsiderCannotReadGameData(t *testing.T) {
	white := int64(22)
	st := &securityStore{
		sessions: map[string]int64{"outsider": 33},
		game:     &store.Game{ID: 7, BlackID: 11, WhiteID: &white, Status: "active"},
	}
	api := &API{Store: st}

	for _, path := range []string{"/api/games/7", "/api/games/7/moves", "/api/games/7/messages"} {
		if got := request(t, api, http.MethodGet, path, "", "outsider").Code; got != http.StatusForbidden {
			t.Errorf("GET %s status = %d, want %d", path, got, http.StatusForbidden)
		}
	}
	if st.movesCalled || st.messagesCalled {
		t.Fatal("sensitive game data queried for an outsider")
	}
}

func TestMoveRequiresCurrentPlayer(t *testing.T) {
	white := int64(22)
	st := &securityStore{
		sessions: map[string]int64{"black": 11, "white": 22},
		game:     &store.Game{ID: 7, BlackID: 11, WhiteID: &white, Status: "active", Turn: 0},
	}
	api := &API{Store: st}
	board := base64.StdEncoding.EncodeToString(make([]byte, boardLen))
	body := `{"board_c_b64":"` + board + `"}`

	if got := request(t, api, http.MethodPost, "/api/games/7/move", body, "white").Code; got != http.StatusConflict {
		t.Fatalf("out-of-turn move status = %d, want %d", got, http.StatusConflict)
	}
	if st.applyCalled {
		t.Fatal("out-of-turn move reached the store")
	}
	invalidBoard := make([]byte, boardLen)
	invalidBoard[0] = 251
	invalidBody := `{"board_c_b64":"` + base64.StdEncoding.EncodeToString(invalidBoard) + `"}`
	if got := request(t, api, http.MethodPost, "/api/games/7/move", invalidBody, "black").Code; got != http.StatusBadRequest {
		t.Fatalf("invalid field element status = %d, want %d", got, http.StatusBadRequest)
	}
	if st.applyCalled {
		t.Fatal("invalid field element reached the store")
	}
	if got := request(t, api, http.MethodPost, "/api/games/7/move", body, "black").Code; got != http.StatusOK {
		t.Fatalf("current-player move status = %d, want %d", got, http.StatusOK)
	}
	if !st.applyCalled {
		t.Fatal("current-player move did not reach the store")
	}
}

func TestCreatorCannotJoinOwnGame(t *testing.T) {
	st := &securityStore{
		sessions: map[string]int64{"creator": 11},
		game:     &store.Game{ID: 7, BlackID: 11, Status: "waiting"},
	}
	api := &API{Store: st}

	if got := request(t, api, http.MethodPost, "/api/games/7/join", `{}`, "creator").Code; got != http.StatusConflict {
		t.Fatalf("self-join status = %d, want %d", got, http.StatusConflict)
	}
	if st.joinCalled {
		t.Fatal("self-join reached the store")
	}
}
