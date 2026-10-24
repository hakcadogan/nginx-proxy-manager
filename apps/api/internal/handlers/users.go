package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/auth"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
)

// UserHandler — admin user management (REQ-AUTH-003, REQ-UI-009).
type UserHandler struct {
	Store *db.Store
}

type createUserReq struct {
	Email    string      `json:"email"`
	Password string      `json:"password"`
	Role     models.Role `json:"role"`
}

type patchUserReq struct {
	Role     *models.Role `json:"role,omitempty"`
	Password *string      `json:"password,omitempty"`
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) {
		WriteError(w, http.StatusBadRequest, "validation_failed", "email required")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	switch req.Role {
	case models.RoleAdmin, models.RoleOperator, models.RoleViewer:
	default:
		WriteError(w, http.StatusBadRequest, "validation_failed", "role must be admin|operator|viewer")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "hash failed")
		return
	}
	u, err := h.Store.CreateUser(r.Context(), req.Email, hash, req.Role)
	if err != nil {
		WriteError(w, http.StatusConflict, "conflict", "could not create user")
		return
	}
	writeAudit(h.Store, r, "user.create", "user", u.ID.String(), map[string]string{
		"email": u.Email, "role": string(u.Role),
	})
	WriteJSON(w, http.StatusCreated, map[string]any{"user": publicUser(u)})
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListUsers(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, u := range items {
		out = append(out, publicUser(u))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *UserHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	var req patchUserReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	if req.Role == nil && (req.Password == nil || *req.Password == "") {
		WriteError(w, http.StatusBadRequest, "validation_failed", "role or password required")
		return
	}

	existing, err := h.Store.GetUserByID(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}

	var u models.User = existing
	details := map[string]string{}

	if req.Role != nil {
		switch *req.Role {
		case models.RoleAdmin, models.RoleOperator, models.RoleViewer:
		default:
			WriteError(w, http.StatusBadRequest, "validation_failed", "invalid role")
			return
		}
		// Prevent demoting the last admin.
		if existing.Role == models.RoleAdmin && *req.Role != models.RoleAdmin {
			n, err := h.Store.CountAdmins(r.Context())
			if err != nil {
				WriteError(w, http.StatusInternalServerError, "internal", "count failed")
				return
			}
			if n <= 1 {
				WriteError(w, http.StatusConflict, "last_admin", "cannot demote the last admin")
				return
			}
		}
		u, err = h.Store.UpdateUserRole(r.Context(), id, *req.Role)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "role update failed")
			return
		}
		details["role"] = string(*req.Role)
	}

	if req.Password != nil && *req.Password != "" {
		if err := auth.ValidatePassword(*req.Password); err != nil {
			WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "hash failed")
			return
		}
		u, err = h.Store.UpdateUserPassword(r.Context(), id, hash)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "password update failed")
			return
		}
		details["password"] = "rotated"
	}

	writeAudit(h.Store, r, "user.update", "user", id.String(), details)
	WriteJSON(w, http.StatusOK, map[string]any{"user": publicUser(u)})
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	sess, ok := middleware.SessionFrom(r.Context())
	if ok && sess.UserID == id {
		WriteError(w, http.StatusConflict, "self_delete", "cannot delete your own account")
		return
	}
	existing, err := h.Store.GetUserByID(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	if existing.Role == models.RoleAdmin {
		n, err := h.Store.CountAdmins(r.Context())
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal", "count failed")
			return
		}
		if n <= 1 {
			WriteError(w, http.StatusConflict, "last_admin", "cannot delete the last admin")
			return
		}
	}
	if err := h.Store.DeleteUser(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	writeAudit(h.Store, r, "user.delete", "user", id.String(), map[string]string{"email": existing.Email})
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *UserHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	u, err := h.Store.UnlockUser(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "unlock failed")
		return
	}
	writeAudit(h.Store, r, "user.unlock", "user", id.String(), map[string]string{})
	WriteJSON(w, http.StatusOK, map[string]any{"user": publicUser(u)})
}
