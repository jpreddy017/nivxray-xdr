import { mergeConfig } from "vite";
import existing from "./vite.config.js";
export default mergeConfig(existing({ mode: "test" }), {
  define: { "process.env.REACT_APP_PRODUCT_SCOPE": JSON.stringify("edr"), "process.env.NIVX_TEST_PRODUCT": JSON.stringify("edr") },
  test: { include: ["src/nivxforge/**/*.test.{js,jsx}", "src/lib/**/*.test.{js,jsx}"] },
});
