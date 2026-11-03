// Engine struct presets (x64). Offsets marked "typical" hold for most shipping builds of the named
// versions but move with engine version, build flags and game-side patches: verify before relying.
import type { Field } from "./struct";
import { fromOffsets } from "./structguess";

export type Preset = { id: string; engine: "Unreal" | "Unity IL2CPP" | "Source 2"; name: string; description: string; fields: Field[] };

const uobject: [number, Field["type"], string][] = [
  [0x00, "ptr", "VTable"], [0x08, "i32", "ObjectFlags"], [0x0c, "i32", "InternalIndex"],
  [0x10, "ptr", "ClassPrivate"], [0x18, "i32", "NameIndex"], [0x1c, "i32", "NameNumber"], [0x20, "ptr", "OuterPrivate"],
];

export const kPresets: Preset[] = [
  {
    id: "ue-uobject", engine: "Unreal", name: "UObject",
    description: "UObjectBase header, UE4.x and UE5.x shipping: vtable, flags, GUObjectArray index, class, FName, outer (0x28). Stable across versions; builds with FNAME_OUTLINE_NUMBER or editor data differ.",
    fields: fromOffsets(0x28, uobject),
  },
  {
    id: "ue-fname", engine: "Unreal", name: "FName",
    description: "ComparisonIndex (an FNamePool handle on UE4.23+, a GNames index before) + Number (stored +1; 0 = no _N suffix). 8 bytes typical; some UE5 builds outline the number (4 bytes).",
    fields: fromOffsets(8, [[0, "i32", "ComparisonIndex"], [4, "i32", "Number"]]),
  },
  {
    id: "ue-fnameentry", engine: "Unreal", name: "FNameEntry (pool)",
    description: "FNamePool entry, UE4.23+/UE5: u16 header { bIsWide:1, LowercaseProbeHash:5, Len:10 } then Len chars (ANSI or UTF-16). No terminator. Header bit layout is typical; some games reorder it.",
    fields: [{ type: "hex16", name: "Header" }, { type: "ascii", name: "AnsiName" }],
  },
  {
    id: "ue-fnamepool", engine: "Unreal", name: "FNamePool",
    description: "NamePoolData, UE4.23+/UE5: FRWLock, CurrentBlock, CurrentByteCursor, then Blocks[8192] (typical 0x10). Block = handle >> 16, entry = Blocks[block] + (handle & 0xFFFF) * 2.",
    fields: fromOffsets(0x50, [[0x00, "ptr", "Lock"], [0x08, "u32", "CurrentBlock"], [0x0c, "u32", "CurrentByteCursor"], [0x10, "ptr", "Blocks0"], [0x18, "ptr", "Blocks1"]]),
  },
  {
    id: "ue-tarray", engine: "Unreal", name: "TArray<T>",
    description: "Data, Num, Max (0x10). Same in UE4 and UE5 with the default allocator.",
    fields: fromOffsets(0x10, [[0, "ptr", "Data"], [8, "i32", "Num"], [0xc, "i32", "Max"]]),
  },
  {
    id: "ue-fstring", engine: "Unreal", name: "FString",
    description: "TArray<TCHAR>: Data points at UTF-16 text, Num counts characters including the terminator (0x10).",
    fields: fromOffsets(0x10, [[0, "ptr", "Data"], [8, "i32", "Num"], [0xc, "i32", "Max"]]),
  },
  {
    id: "ue-fuobjectarray", engine: "Unreal", name: "FUObjectArray",
    description: "GUObjectArray, UE4.20+/UE5: GC bookkeeping then the chunked ObjObjects (Objects at 0x10, NumElements at 0x24 typical; 65536 FUObjectItem of 0x18 per chunk). UE4.19 and older use a flat array (Objects 0x10, Num 0x1C).",
    fields: fromOffsets(0x30, [[0x00, "i32", "ObjFirstGCIndex"], [0x04, "i32", "ObjLastNonGCIndex"], [0x08, "i32", "MaxObjectsNotConsideredByGC"], [0x0c, "u8", "OpenForDisregardForGC"], [0x10, "ptr", "Objects"], [0x18, "ptr", "PreAllocatedObjects"], [0x20, "i32", "MaxElements"], [0x24, "i32", "NumElements"], [0x28, "i32", "MaxChunks"], [0x2c, "i32", "NumChunks"]]),
  },
  {
    id: "ue-fuobjectitem", engine: "Unreal", name: "FUObjectItem",
    description: "Object, Flags, ClusterRootIndex, SerialNumber: 0x18 typical; 0x10 without serial numbers, larger with stats.",
    fields: fromOffsets(0x18, [[0, "ptr", "Object"], [8, "i32", "Flags"], [0xc, "i32", "ClusterRootIndex"], [0x10, "i32", "SerialNumber"]]),
  },
  {
    id: "ue-uworld", engine: "Unreal", name: "UWorld (basics)",
    description: "UObject header + PersistentLevel at 0x30 (typical UE4.2x/UE5). Later members (GameState, Levels, OwningGameInstance) move with every version: find them with auto-detect.",
    fields: fromOffsets(0x40, [...uobject, [0x30, "ptr", "PersistentLevel"], [0x38, "ptr", "NetDriver"]]),
  },
  {
    id: "ue-ulevel", engine: "Unreal", name: "ULevel (basics)",
    description: "UObject header + Actors TArray at 0x98 (typical UE4.2x; often 0xA0 in UE5). OwningWorld follows the actor arrays and varies.",
    fields: fromOffsets(0xa8, [...uobject, [0x98, "ptr", "Actors.Data"], [0xa0, "i32", "Actors.Num"], [0xa4, "i32", "Actors.Max"]]),
  },
  {
    id: "ue-aactor", engine: "Unreal", name: "AActor (basics)",
    description: "UObject header only. RootComponent is typically 0x130 (UE4.2x) or 0x198 (UE5.x) and Instigator/Owner sit nearby; varies per build.",
    fields: fromOffsets(0x28, uobject),
  },
  {
    id: "il2cpp-object", engine: "Unity IL2CPP", name: "Il2CppObject",
    description: "klass + monitor (0x10). Every managed object starts with this; fields of the C# class follow.",
    fields: fromOffsets(0x10, [[0, "ptr", "klass"], [8, "ptr", "monitor"]]),
  },
  {
    id: "il2cpp-string", engine: "Unity IL2CPP", name: "Il2CppString",
    description: "Il2CppObject, int32 length, UTF-16 chars at 0x14 (no terminator needed).",
    fields: fromOffsets(0x14 + 64, [[0, "ptr", "klass"], [8, "ptr", "monitor"], [0x10, "i32", "length"], [0x14, "utf16", "chars"]]),
  },
  {
    id: "il2cpp-array", engine: "Unity IL2CPP", name: "Il2CppArray",
    description: "Il2CppObject, bounds (null for 1-D), max_length (uintptr), elements from 0x20.",
    fields: fromOffsets(0x28, [[0, "ptr", "klass"], [8, "ptr", "monitor"], [0x10, "ptr", "bounds"], [0x18, "u64", "max_length"], [0x20, "hex64", "vector0"]]),
  },
  {
    id: "il2cpp-class", engine: "Unity IL2CPP", name: "Il2CppClass (basics)",
    description: "image, gc_desc, name, namespaze are stable (0x00–0x18). byval_arg/this_arg, parent (0x58) and static_fields (0xB8) are typical for Unity 2019–2022 (metadata v24–v29) and move in other versions.",
    fields: fromOffsets(0xc0, [[0x00, "ptr", "image"], [0x08, "ptr", "gc_desc"], [0x10, "ptr", "name"], [0x18, "ptr", "namespaze"], [0x20, "ptr", "byval_arg.data"], [0x30, "ptr", "this_arg.data"], [0x40, "ptr", "element_class"], [0x48, "ptr", "castClass"], [0x50, "ptr", "declaringType"], [0x58, "ptr", "parent"], [0xb8, "ptr", "static_fields"]]),
  },
  {
    id: "s2-entityidentity", engine: "Source 2", name: "CEntityIdentity",
    description: "Entity list entry (stride 0x78 typical in CS2): instance pointer, class info, handle, name/designer name symbols, flags, linked-list neighbours. Offsets after 0x10 are typical for CS2 2023–2025 builds; check against a schema dump.",
    fields: fromOffsets(0x78, [[0x00, "ptr", "m_pInstance"], [0x08, "ptr", "m_pClassInfo"], [0x10, "u32", "m_EHandle"], [0x14, "i32", "m_nameStringableIndex"], [0x18, "ptr", "m_name"], [0x20, "ptr", "m_designerName"], [0x30, "u32", "m_flags"], [0x58, "ptr", "m_pPrev"], [0x60, "ptr", "m_pNext"], [0x68, "ptr", "m_pPrevByClass"], [0x70, "ptr", "m_pNextByClass"]]),
  },
  {
    id: "s2-entityinstance", engine: "Source 2", name: "CEntityInstance",
    description: "vtable, m_iszPrivateVScripts, m_pEntity (CEntityIdentity*) at 0x10 typical; game-specific members follow.",
    fields: fromOffsets(0x18, [[0, "ptr", "vtable"], [8, "ptr", "m_iszPrivateVScripts"], [0x10, "ptr", "m_pEntity"]]),
  },
];
