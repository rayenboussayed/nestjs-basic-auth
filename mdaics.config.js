import { defineConfig } from "mdaics";

// mdaics reads src/ + dist/ (built first by the `docs` script) and writes one
// Markdown API reference per documented source file into docs/.
export default defineConfig({
  rootSrcDir: "src",
  rootDistDir: "dist",
  outDirName: "docs",
});
