import { runStdioServer } from "./server.js";

runStdioServer().catch((error) => {
  console.error("Fatal error running SYMB server:", error);
  process.exit(1);
});
