import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { memoryE2eeRepo } from "../src/ds/index";
import { describeE2eeRepoConformance } from "../src/ds/testing";

describeE2eeRepoConformance(
  { name: "memory", open: () => ({ repo: memoryE2eeRepo(), close: () => {} }) },
  { describe, test, beforeEach, afterEach, expect },
);
