/** @type {import("prettier").Config} */
const config = {
  // Explicit: the repository-wide .editorconfig uses 4 spaces (Python backend).
  tabWidth: 2,
  useTabs: false,
  printWidth: 100,
  plugins: ["prettier-plugin-tailwindcss"],
  tailwindStylesheet: "./src/styles/globals.css",
  tailwindFunctions: ["cn", "cva"],
};

export default config;
