"use client";

import { useState, type ReactNode } from "react";

/**
 * The default dark theme is the mandatory high-contrast one; the light theme is
 * the optional second theme and shares all state and layout logic.
 */
export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  return (
    <button
      type="button"
      onClick={() => {
        const next = theme === "dark" ? "light" : "dark";
        setTheme(next);
        document.documentElement.dataset.theme = next;
      }}
      aria-label={`Switch to the ${theme === "dark" ? "light" : "dark"} theme`}
      data-testid="theme-toggle"
    >
      Theme: {theme}
    </button>
  );
}
