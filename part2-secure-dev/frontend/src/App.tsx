import { useState, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import LoginModal from "./components/LoginModal";
import WelcomeBanner from "./components/WelcomeBanner";
import EventsPage from "./pages/EventsPage";
import UsersPage from "./pages/UsersPage";
import NotFound from "./pages/NotFound";

function App() {
  const [showLogin, setShowLogin] = useState(false);

  // Show login modal on first visit
  useEffect(() => {
    const dismissed = sessionStorage.getItem("login-dismissed");
    if (!dismissed) {
      setShowLogin(true);
    }
  }, []);

  const handleCloseLogin = () => {
    sessionStorage.setItem("login-dismissed", "true");
    setShowLogin(false);
  };

  return (
    <>
      <Navbar onLoginClick={() => setShowLogin(true)} />
      <div className="container">
        <WelcomeBanner />
        <Routes>
          <Route path="/" element={<Navigate to="/events" replace />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
      {showLogin && <LoginModal onClose={handleCloseLogin} />}
    </>
  );
}

export default App;
