import { definePackageConfig } from "@browsercore/dev/vitest";

export default definePackageConfig({
    name: "@browsercore/proxy",
    coverage: {
        // CI's own gate reads coverage-summary.json at >=93%; this package holds
        // itself to the stricter local bar of 94% statements / 92% branches.
        thresholds: { statements: 94, branches: 92, functions: 94, lines: 94 },
    },
});
