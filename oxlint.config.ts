import { defineConfig } from "oxlint";
import base from "@browsercore/dev/oxlint";

// The rule set lives in @browsercore/dev so every package lints identically —
// drift here is how the polyrepo rots. Package-specific exceptions go in
// `rules` below `extends`, never by editing the base.
export default defineConfig({
    extends: [base],
});
