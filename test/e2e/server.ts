import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "fixtures");

let server: Server | null = null;

export async function startServer(): Promise<number> {
  return new Promise((resolve) => {
    server = createServer(async (req, res) => {
      const filename = req.url?.replace(/^\//, "") ?? "";

      try {
        const content = await readFile(join(FIXTURES_DIR, filename), "utf-8");
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(content);
      } catch {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not found");
      }
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server!.address();
      const port =
        typeof address === "object" && address ? address.port : 0;
      resolve(port);
    });
  });
}

export async function stopServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      server.close(() => resolve());
    } else {
      resolve();
    }
  });
}
