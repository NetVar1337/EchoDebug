import { beforeEach, describe, expect, it } from "vitest";
import { canRedo, canUndo, clearHistory, redo, undo } from "./history";
import { useNames } from "@/store/names";
import { useTypes } from "@/store/types";

describe("undo / redo", () => {
  beforeEach(() => {
    useNames.setState({ names: [] });
    useTypes.setState({ types: [] });
    clearHistory();
  });

  it("undoes and redoes renames and comments in order", () => {
    const n = useNames.getState();
    n.rename("0x1000", "main");
    n.comment("0x1000", "entry");
    n.rename("0x1000", "WinMain");
    expect(useNames.getState().nameOf("0x1000")).toBe("WinMain");
    expect(undo()).toBe("rename 0x1000");
    expect(useNames.getState().nameOf("0x1000")).toBe("main");
    expect(useNames.getState().commentOf("0x1000")).toBe("entry");
    undo();
    expect(useNames.getState().commentOf("0x1000")).toBe("");
    expect(canRedo()).toBe(true);
    redo();
    redo();
    expect(useNames.getState().nameOf("0x1000")).toBe("WinMain");
    expect(redo()).toBeNull();
  });

  it("a new edit clears the redo stack; no-op type syncs are not recorded", () => {
    const t = useTypes.getState();
    const id = t.add("Player", [{ type: "i32", name: "hp" }]);
    t.update(id, { name: "Player" }); // unchanged
    t.update(id, { fields: [{ type: "f32", name: "hp" }] });
    undo();
    expect(useTypes.getState().types[0].fields[0].type).toBe("i32");
    useNames.getState().rename("0x2000", "x");
    expect(canRedo()).toBe(false);
    undo(); // rename
    undo(); // add
    expect(useTypes.getState().types).toEqual([]);
    expect(canUndo()).toBe(false);
  });
});
