import React from "react";
import { createRoot } from "react-dom/client";
import AuthApp from "./auth/AuthApp.jsx";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthApp />
  </React.StrictMode>
);
