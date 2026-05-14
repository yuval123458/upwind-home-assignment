import { Routes, Route, Navigate } from "react-router-dom";

import { useAuth } from "./auth-context";
import LoginModal from "./components/LoginModal";
import Navbar from "./components/Navbar";
import EventsPage from "./pages/EventsPage";
import NotFound from "./pages/NotFound";
import UsersPage from "./pages/UsersPage";

function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: "center", color: "#666" }}>
        Loading…
      </div>
    );
  }

  if (!user) {
    return <LoginModal />;
  }

  return (
    <>
      <Navbar />
      <div className="container">
        <Routes>
          <Route path="/" element={<Navigate to="/events" replace />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
    </>
  );
}

export default App;
