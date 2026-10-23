import assert from "node:assert/strict";
import test from "node:test";
import { value } from "./clockwork.js";
import { SqlVisitor } from "./foundry.js";

test("SQL string literals escape apostrophes", () => {
  const sql = value("' OR '1'='1").accept(new SqlVisitor());

  assert.equal(sql, "''' OR ''1''=''1'");
});

test("ordinary SQL string literals keep their value", () => {
  const sql = value("ordinary-session-token").accept(new SqlVisitor());

  assert.equal(sql, "'ordinary-session-token'");
});
