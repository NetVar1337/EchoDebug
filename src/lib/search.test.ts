import { describe, expect, it } from "vitest";
import { flatten, fuzzyMatch, highlight, matchAll, searchAll, type SearchItem } from "./search";

const score = (q: string, t: string) => fuzzyMatch(q, t)?.score ?? -Infinity;

describe("fuzzyMatch", () => {
  it("matches subsequences case-insensitively", () => {
    expect(fuzzyMatch("ghp", "GetHealthPtr")).not.toBeNull();
    expect(fuzzyMatch("xyz", "GetHealthPtr")).toBeNull();
    expect(fuzzyMatch("health", "GetHealthPtr")!.hits).toEqual([3, 4, 5, 6, 7, 8]);
  });

  it("ranks exact > prefix > word start > inside > scattered", () => {
    const exact = score("player", "player");
    const prefix = score("player", "player_update");
    const word = score("player", "update_player");
    const inside = score("player", "multiplayers");
    const scattered = score("player", "p_l_a_y_e_r_thing");
    expect(exact).toBeGreaterThan(prefix);
    expect(prefix).toBeGreaterThan(word);
    expect(word).toBeGreaterThan(inside);
    expect(inside).toBeGreaterThan(scattered);
  });

  it("prefers camelCase humps for scattered matches", () => {
    expect(score("gHP", "GetHealthPtr")).toBeGreaterThan(score("gHP", "ghostship"));
    const m = fuzzyMatch("ghp", "GetHealthPtr")!;
    expect(m.hits).toEqual([0, 3, 9]);
  });

  it("prefers shorter texts for the same match", () => {
    expect(score("hp", "hp_max")).toBeGreaterThan(score("hp", "hp_max_value_for_the_local_player"));
  });
});

describe("matchAll", () => {
  const item: SearchItem = { kind: "name", text: "CPlayer::TakeDamage", detail: "game.exe", address: "0x7ff6a0001230" };
  it("requires every token", () => {
    expect(matchAll("player damage", item)).not.toBeNull();
    expect(matchAll("player heal", item)).toBeNull();
  });
  it("ranks items at stale addresses below live ones", () => {
    expect(matchAll("player", { ...item, stale: true })!.score).toBeLessThan(matchAll("player", item)!.score);
  });
  it("matches the detail weakly and addresses strongly", () => {
    const viaDetail = matchAll("game", item)!;
    const viaText = matchAll("take", item)!;
    expect(viaText.score).toBeGreaterThan(viaDetail.score);
    expect(matchAll("0x7ff6a0001230", item)!.score).toBeGreaterThan(viaText.score);
    expect(matchAll("7ff6a000", item)).not.toBeNull();
  });
});

describe("searchAll", () => {
  const items: SearchItem[] = [
    { kind: "name", text: "health_decrement", address: "0x1000" },
    { kind: "export", text: "GetHealth", detail: "engine.dll", address: "0x2000" },
    { kind: "string", text: "Health: %d", address: "0x3000" },
    { kind: "comment", text: "reduces health by the damage value", address: "0x1004" },
    { kind: "type", text: "PlayerState", ref: "t1" },
    { kind: "bookmark", text: "unrelated", address: "0x5000" },
  ];

  it("groups by kind, best group first, and limits per group", () => {
    const g = searchAll(items, "health");
    expect(g.map((x) => x.kind)).not.toContain("bookmark");
    expect(g.map((x) => x.kind)).not.toContain("type");
    // "health_decrement" (prefix) and "Health: %d" (prefix) beat "GetHealth" (word start)
    expect(["name", "string"]).toContain(g[0].kind);
    const many: SearchItem[] = Array.from({ length: 30 }, (_, i) => ({ kind: "string", text: `health ${i}` }));
    const lim = searchAll(many, "health", 5);
    expect(lim[0].results.length).toBe(5);
    expect(lim[0].total).toBe(30);
  });

  it("flattens in display order and returns nothing for an empty query", () => {
    const g = searchAll(items, "health");
    expect(flatten(g).length).toBe(g.reduce((n, x) => n + x.results.length, 0));
    expect(searchAll(items, "  ")).toEqual([]);
  });

  it("sorts within a group by score", () => {
    const g = searchAll([
      { kind: "name", text: "xx_player_xx" },
      { kind: "name", text: "player" },
      { kind: "name", text: "playerList" },
    ], "player");
    expect(g[0].results.map((r) => r.item.text)).toEqual(["player", "playerList", "xx_player_xx"]);
  });
});

describe("highlight", () => {
  it("splits into runs", () => {
    expect(highlight("abcd", [1, 2])).toEqual([{ s: "a", hit: false }, { s: "bc", hit: true }, { s: "d", hit: false }]);
  });
});
