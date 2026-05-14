import { useCallback, useEffect, useState, type FormEvent } from "react";

import * as api from "../api";
import { useAuth } from "../auth-context";
import type { User } from "../types";

export default function UsersPage() {
  const { user: currentUser } = useAuth();
  const isAdmin = currentUser?.role === "admin";

  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "user">("user");
  const [submitError, setSubmitError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!isAdmin) return;
    try {
      const data = await api.getUsers();
      setUsers(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Admin-only page — backend also enforces, but we short-circuit the UI to
  // avoid loading admin data unnecessarily.
  if (!isAdmin) {
    return (
      <div className="page-container">
        <h1>Access denied</h1>
        <p>You must be an administrator to view this page.</p>
      </div>
    );
  }

  const handleAddUser = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    try {
      await api.createUser({ email: newEmail, password: newPassword, role: newRole });
      setNewEmail("");
      setNewPassword("");
      setNewRole("user");
      setShowForm(false);
      await refresh();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Failed to create user");
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this user? This cannot be undone.")) return;
    try {
      await api.deleteUser(id);
      await refresh();
    } catch (err) {
      window.alert(err instanceof Error ? err.message : "Failed to delete");
    }
  };

  const handleToggleStatus = async (u: User) => {
    const next = u.status === "active" ? "disabled" : "active";
    try {
      await api.updateUser(u.id, { status: next });
      await refresh();
    } catch (err) {
      window.alert(err instanceof Error ? err.message : "Failed to update");
    }
  };

  if (loading) return <div className="page-container">Loading users…</div>;
  if (error)
    return (
      <div className="page-container" style={{ color: "#c00" }}>
        Error: {error}
      </div>
    );

  return (
    <div className="page-container">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 16,
        }}
      >
        <h1>User Management</h1>
        <button className="btn-primary" onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "Add User"}
        </button>
      </div>

      {showForm && (
        <div
          style={{
            border: "1px solid #ddd",
            padding: 16,
            marginBottom: 20,
            background: "#fafafa",
          }}
        >
          <h3 style={{ marginBottom: 12 }}>New User</h3>
          <form onSubmit={handleAddUser}>
            <div style={{ marginBottom: 8 }}>
              <label>Email</label>
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="user@penguwave.local"
                required
                autoComplete="off"
              />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Password (min 12 chars)</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                minLength={12}
                autoComplete="new-password"
              />
            </div>
            <div style={{ marginBottom: 12 }}>
              <label>Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as "admin" | "user")}
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            {submitError && (
              <div style={{ color: "#c00", fontSize: 13, marginBottom: 12 }}>
                {submitError}
              </div>
            )}
            <button type="submit" className="btn-primary">
              Create User
            </button>
          </form>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const isSelf = u.id === currentUser?.id;
            return (
              <tr key={u.id}>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>
                  <span style={{ color: u.status === "active" ? "green" : "#999" }}>
                    {u.status}
                  </span>
                </td>
                <td>
                  <button
                    onClick={() => handleToggleStatus(u)}
                    style={{ marginRight: 8, fontSize: 12 }}
                    disabled={isSelf}
                    title={isSelf ? "Can't disable yourself" : ""}
                  >
                    {u.status === "active" ? "Disable" : "Enable"}
                  </button>
                  <button
                    onClick={() => handleDelete(u.id)}
                    style={{ color: "#c00", fontSize: 12 }}
                    disabled={isSelf}
                    title={isSelf ? "Can't delete yourself" : ""}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {users.length === 0 && <p style={{ color: "#999" }}>No users.</p>}
    </div>
  );
}
