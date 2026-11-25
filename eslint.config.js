import tseslint from "typescript-eslint";

export default [{ ignores: ["coverage/", "dist/", "node_modules/"] }, ...tseslint.configs.recommended];
