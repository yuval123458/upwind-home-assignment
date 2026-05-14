import { Link, useLocation } from "react-router-dom";

import { useAuth } from "../auth-context";

export default function Navbar() {
  const { user, logout } = useAuth();
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Link to="/events" style={{ textDecoration: "none", color: "inherit" }}>
          PenguWave 🐧
        </Link>
      </div>
      <div className="navbar-links">
        <Link
          to="/events"
          className={location.pathname.startsWith("/events") ? "active" : ""}
        >
          Events
        </Link>
        {user?.role === "admin" && (
          <Link
            to="/users"
            className={location.pathname === "/users" ? "active" : ""}
          >
            Users
          </Link>
        )}
        {user && (
          <span style={{ fontSize: 13, color: "#666", marginLeft: 12 }}>
            {user.email} ({user.role})
          </span>
        )}
        <button onClick={() => void logout()} className="navbar-login-btn">
          Logout
        </button>
      </div>
    </nav>
  );
}
