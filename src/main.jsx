import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.jsx";
import { ensureNodeGlobals } from "./polyfills.js";

async function bootstrap() {
  await ensureNodeGlobals();

  createRoot(document.getElementById("root")).render(
    <StrictMode>
      <App />
    </StrictMode>
  );
}

bootstrap();

