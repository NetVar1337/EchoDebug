import { describe, expect, it } from "vitest";
import { demangle } from "./vtable";

describe("vtable resolver", () => {
  it("demangles the type-descriptor names", () => {
    expect(demangle(".?AVPlayerController@@")).toBe("PlayerController");
    expect(demangle(".?AVFoo@Bar@@")).toBe("Foo::Bar");
    expect(demangle(".?AU<Foo@Bar>@@")).toBe("Foo::Bar");
    expect(demangle("")).toBe("");
    expect(demangle("plain")).toBe("plain");
  });

  it("strips the template arity", () => {
    expect(demangle(".?AVFoo@@")).toBe("Foo");
  });
});
