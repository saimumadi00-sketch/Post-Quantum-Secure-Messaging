/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "var(--color-ink)",
        "on-primary": "var(--color-on-primary)",
        body: "var(--color-body)",
        mute: "var(--color-mute)",
        hairline: "var(--color-hairline)",
        "hairline-strong": "var(--color-hairline-strong)",
        canvas: "var(--color-canvas)",
        "canvas-soft": "var(--color-canvas-soft)",
        "canvas-soft-2": "var(--color-canvas-soft-2)",
        link: "var(--color-link)",
        "link-deep": "var(--color-link-deep)",
        "link-bg-soft": "var(--color-link-bg-soft)",
        error: "var(--color-error)",
        "error-soft": "var(--color-error-soft)",
        "error-deep": "var(--color-error-deep)",
        warning: "var(--color-warning)",
        "warning-soft": "var(--color-warning-soft)",
        "warning-deep": "var(--color-warning-deep)"
      },
      fontFamily: {
        sans: ["Geist Variable", "Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["Geist Mono Variable", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "monospace"]
      },
      boxShadow: {
        hairline: "var(--shadow-hairline)",
        subtle: "var(--shadow-subtle)",
        soft: "var(--shadow-soft)",
        modal: "var(--shadow-modal)"
      }
    }
  },
  plugins: []
};
