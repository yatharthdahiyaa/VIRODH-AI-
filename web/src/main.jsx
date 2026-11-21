import "@fontsource/instrument-serif/400.css";
import "@fontsource/instrument-serif/400-italic.css";
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "./styles.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./api.js";
import { Loading } from "./ui.jsx";
import Landing from "./pages/Landing.jsx";
import { SignIn, SignUp } from "./pages/Auth.jsx";
import Docs from "./pages/Docs.jsx";
import AppLayout from "./pages/app/Layout.jsx";
import Home from "./pages/app/Home.jsx";
import Playground from "./pages/app/Playground.jsx";
import TestLab from "./pages/app/TestLab.jsx";
import Evaluation from "./pages/app/Evaluation.jsx";
import Keys from "./pages/app/Keys.jsx";
import Policies from "./pages/app/Policies.jsx";
import Requests from "./pages/app/Requests.jsx";
import Usage from "./pages/app/Usage.jsx";
import Users from "./pages/app/Users.jsx";
import System from "./pages/app/System.jsx";
import Account from "./pages/app/Account.jsx";

function Protected({ admin, children }) {
  const { loading, user } = useAuth();
  const loc = useLocation();
  if (loading) return <Loading />;
  if (!user) return <Navigate to={`/signin?next=${encodeURIComponent(loc.pathname)}`} replace />;
  if (admin && user.role !== "admin") return <Navigate to="/app" replace />;
  return children;
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/signin" element={<SignIn />} />
      <Route path="/signup" element={<SignUp />} />
      <Route path="/developers" element={<Docs />} />
      <Route
        path="/app"
        element={
          <Protected>
            <AppLayout />
          </Protected>
        }
      >
        <Route index element={<Home />} />
        <Route path="playground" element={<Playground />} />
        <Route path="test-lab" element={<TestLab />} />
        <Route path="evaluation" element={<Evaluation />} />
        <Route path="keys" element={<Keys />} />
        <Route path="policies" element={<Policies />} />
        <Route path="requests" element={<Requests />} />
        <Route
          path="usage"
          element={
            <Protected admin>
              <Usage />
            </Protected>
          }
        />
        <Route
          path="users"
          element={
            <Protected admin>
              <Users />
            </Protected>
          }
        />
        <Route
          path="system"
          element={
            <Protected admin>
              <System />
            </Protected>
          }
        />
        <Route path="account" element={<Account />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
