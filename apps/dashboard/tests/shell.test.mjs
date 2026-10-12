import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";

test("starter HTML exposes an accessible entry point", async () => {
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<title>AgentGuard/);
  assert.match(html, /id="root"/);
});

test("frontend is a starter shell with React Flow available for later work", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.ok(pkg.dependencies["@xyflow/react"]);
  assert.ok(pkg.scripts.typecheck);
});
