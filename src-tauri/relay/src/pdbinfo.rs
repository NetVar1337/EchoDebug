//! A whole PDB read into owned data: symbols (publics, procedures with sizes and prototypes,
//! global data), the type stream (TPI) and line information (RVA ↔ file:line).
//!
//! Reading happens once per file (kept in a small in-memory cache); the `pdb_*` verbs in
//! `symbols.rs` answer queries from this model.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use pdb::FallibleIterator;
use serde_json::{json, Map, Value};

/// One symbol: a function (procedure or public in code) or a data item.
#[derive(Clone, Debug, Default)]
pub struct Sym {
    pub rva: u32,
    /// code size for procedures, type size for data; 0 when the PDB does not say
    pub size: u32,
    pub name: String,
    pub kind: &'static str,
    /// type index of the procedure / data item
    pub ty: Option<u32>,
    /// parameter names and type indices (procedures with private symbols)
    pub params: Vec<(String, u32)>,
    /// decorated public name when it differs from `name`
    pub mangled: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineRec {
    pub rva: u32,
    pub len: u32,
    pub file: u32,
    pub line: u32,
}

/// A member of a field list.
#[derive(Clone, Debug)]
pub enum Member {
    Data { name: String, ty: u32, offset: u64 },
    Base { ty: u32, offset: u64 },
    VBase { ty: u32 },
    VTable { ty: u32 },
    Enumerate { name: String, value: i64 },
    Static { name: String, ty: u32 },
    Method { name: String },
    Nested { name: String, ty: u32 },
}

/// One type record, owned.
#[derive(Clone, Debug)]
pub enum Ty {
    Ptr { to: u32, size: u32, reference: bool, konst: bool },
    Mod { to: u32, konst: bool, vol: bool },
    Array { elem: u32, size: u32, dims: Vec<u32> },
    Bitfield { to: u32, len: u8, pos: u8 },
    Udt { kind: &'static str, name: String, unique: Option<String>, size: u64, fields: Option<u32>, forward: bool },
    Enum { name: String, unique: Option<String>, underlying: u32, fields: u32, forward: bool },
    Proc { ret: Option<u32>, args: u32, cc: u8, class: Option<u32> },
    Args(Vec<u32>),
    Fields { members: Vec<Member>, cont: Option<u32> },
    Other,
}

/// The type stream plus a name index of full definitions.
#[derive(Default, Debug)]
pub struct TypeDb {
    pub first: u32,
    pub types: Vec<Ty>,
    /// definition (not forward reference) by unique name and by name
    pub by_name: HashMap<String, u32>,
    /// typedefs (S_UDT) by name
    pub typedefs: HashMap<String, u32>,
}

pub struct Loaded {
    pub path: PathBuf,
    pub key: String,
    pub guid: String,
    pub age: u32,
    pub machine: String,
    /// sorted by RVA, one entry per RVA
    pub syms: Vec<Sym>,
    pub types: TypeDb,
    /// sorted by RVA
    pub lines: Vec<LineRec>,
    pub files: Vec<String>,
}

fn e2s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// GUID+age key (the symbol-store directory name) and the GUID as text.
pub fn identity_key((d1, d2, d3, d4): (u32, u16, u16, &[u8; 8]), age: u32) -> (String, String) {
    let tail: String = d4.iter().map(|b| format!("{b:02X}")).collect();
    (format!("{d1:08X}{d2:04X}{d3:04X}{tail}{age:X}"), format!("{d1:08X}-{d2:04X}-{d3:04X}-{}-{}", &tail[..4], &tail[4..]))
}

// ------------------------------------------------------------------------------------------------
// primitives

/// Name, size and pointer size (when the index is a pointer to a primitive) of a CodeView
/// primitive type index (< 0x1000): `kind = idx & 0xff`, `mode = (idx >> 8) & 0xf`.
pub fn primitive(idx: u32) -> (String, u32) {
    let kind = idx & 0xff;
    let mode = (idx >> 8) & 0xf;
    let (name, size) = match kind {
        0x00 => ("<no type>", 0),
        0x03 => ("void", 0),
        0x08 => ("HRESULT", 4),
        0x10 => ("signed char", 1),
        0x20 => ("unsigned char", 1),
        0x70 => ("char", 1),
        0x71 => ("wchar_t", 2),
        0x7a => ("char16_t", 2),
        0x7b => ("char32_t", 4),
        0x7c => ("char8_t", 1),
        0x68 => ("__int8", 1),
        0x69 => ("unsigned __int8", 1),
        0x11 => ("short", 2),
        0x21 => ("unsigned short", 2),
        0x72 => ("__int16", 2),
        0x73 => ("unsigned __int16", 2),
        0x12 => ("long", 4),
        0x22 => ("unsigned long", 4),
        0x74 => ("int", 4),
        0x75 => ("unsigned int", 4),
        0x13 | 0x76 => ("__int64", 8),
        0x23 | 0x77 => ("unsigned __int64", 8),
        0x14 | 0x78 => ("__int128", 16),
        0x24 | 0x79 => ("unsigned __int128", 16),
        0x46 => ("_Float16", 2),
        0x40 => ("float", 4),
        0x45 => ("float", 4),
        0x44 => ("__float48", 6),
        0x41 => ("double", 8),
        0x42 => ("long double", 10),
        0x43 => ("__float128", 16),
        0x30 => ("bool", 1),
        0x31 => ("__bool16", 2),
        0x32 => ("__bool32", 4),
        0x33 => ("__bool64", 8),
        _ => ("<primitive>", 0),
    };
    match mode {
        0 => (name.to_owned(), size),
        4 | 5 => (format!("{name}*"), 4),
        6 => (format!("{name}*"), 8),
        7 => (format!("{name}*"), 16),
        _ => (format!("{name}*"), 2),
    }
}

/// Scalar class of a primitive for the UI's field types: i8..u64, f32, f64, bool, char, wchar, void, ptr.
fn scalar_of_primitive(idx: u32) -> &'static str {
    if (idx >> 8) & 0xf != 0 {
        return "ptr";
    }
    match idx & 0xff {
        0x03 | 0x00 => "void",
        0x70 | 0x10 | 0x68 => "i8",
        0x20 | 0x69 | 0x7c => "u8",
        0x71 | 0x7a => "wchar",
        0x11 | 0x72 => "i16",
        0x21 | 0x73 => "u16",
        0x12 | 0x74 | 0x08 => "i32",
        0x22 | 0x75 | 0x7b => "u32",
        0x13 | 0x76 => "i64",
        0x23 | 0x77 => "u64",
        0x40 | 0x45 => "f32",
        0x41 => "f64",
        0x30..=0x33 => "bool",
        _ => "other",
    }
}

// ------------------------------------------------------------------------------------------------
// the type stream

fn variant_i64(v: &pdb::Variant) -> i64 {
    use pdb::Variant::*;
    match *v {
        U8(x) => x as i64,
        U16(x) => x as i64,
        U32(x) => x as i64,
        U64(x) => x as i64,
        I8(x) => x as i64,
        I16(x) => x as i64,
        I32(x) => x as i64,
        I64(x) => x,
    }
}

fn member_of(d: pdb::TypeData<'_>) -> Option<Member> {
    use pdb::TypeData as T;
    Some(match d {
        T::Member(m) => Member::Data { name: m.name.to_string().into_owned(), ty: m.field_type.0, offset: m.offset },
        T::BaseClass(b) => Member::Base { ty: b.base_class.0, offset: b.offset as u64 },
        T::VirtualBaseClass(v) => Member::VBase { ty: v.base_class.0 },
        T::VirtualFunctionTablePointer(v) => Member::VTable { ty: v.table.0 },
        T::Enumerate(e) => Member::Enumerate { name: e.name.to_string().into_owned(), value: variant_i64(&e.value) },
        T::StaticMember(s) => Member::Static { name: s.name.to_string().into_owned(), ty: s.field_type.0 },
        T::Method(m) => Member::Method { name: m.name.to_string().into_owned() },
        T::OverloadedMethod(m) => Member::Method { name: m.name.to_string().into_owned() },
        T::Nested(n) => Member::Nested { name: n.name.to_string().into_owned(), ty: n.nested_type.0 },
        _ => return None,
    })
}

fn owned(d: pdb::TypeData<'_>) -> Ty {
    use pdb::TypeData as T;
    let s = |r: pdb::RawString<'_>| r.to_string().into_owned();
    match d {
        T::Class(c) => Ty::Udt {
            kind: match c.kind {
                pdb::ClassKind::Class => "class",
                pdb::ClassKind::Struct => "struct",
                pdb::ClassKind::Interface => "interface",
            },
            name: s(c.name),
            unique: c.unique_name.map(s),
            size: c.size,
            fields: c.fields.map(|f| f.0),
            forward: c.properties.forward_reference(),
        },
        T::Union(u) => Ty::Udt { kind: "union", name: s(u.name), unique: u.unique_name.map(s), size: u.size, fields: Some(u.fields.0), forward: u.properties.forward_reference() },
        T::Enumeration(e) => Ty::Enum { name: s(e.name), unique: e.unique_name.map(s), underlying: e.underlying_type.0, fields: e.fields.0, forward: e.properties.forward_reference() },
        T::Pointer(p) => Ty::Ptr { to: p.underlying_type.0, size: p.attributes.size() as u32, reference: p.attributes.is_reference(), konst: p.attributes.is_const() },
        T::Modifier(m) => Ty::Mod { to: m.underlying_type.0, konst: m.constant, vol: m.volatile },
        T::Array(a) => Ty::Array { elem: a.element_type.0, size: a.dimensions.last().copied().unwrap_or(0), dims: a.dimensions },
        T::Bitfield(b) => Ty::Bitfield { to: b.underlying_type.0, len: b.length, pos: b.position },
        T::Procedure(p) => Ty::Proc { ret: p.return_type.map(|r| r.0), args: p.argument_list.0, cc: p.attributes.calling_convention(), class: None },
        T::MemberFunction(m) => Ty::Proc { ret: Some(m.return_type.0), args: m.argument_list.0, cc: m.attributes.calling_convention(), class: Some(m.class_type.0) },
        T::ArgumentList(a) => Ty::Args(a.arguments.into_iter().map(|x| x.0).collect()),
        T::FieldList(f) => Ty::Fields { members: f.fields.into_iter().filter_map(member_of).collect(), cont: f.continuation.map(|c| c.0) },
        _ => Ty::Other,
    }
}

const DEPTH: usize = 24;
/// Type records `name` visits at most for one spelling.
const NAME_BUDGET: usize = 256;

impl TypeDb {
    /// Builds the name index after `types` is filled.
    pub fn index(&mut self) {
        for (i, t) in self.types.iter().enumerate() {
            let idx = self.first + i as u32;
            let (name, unique, forward) = match t {
                Ty::Udt { name, unique, forward, .. } | Ty::Enum { name, unique, forward, .. } => (name, unique, *forward),
                _ => continue,
            };
            if forward {
                continue;
            }
            if let Some(u) = unique {
                self.by_name.entry(u.clone()).or_insert(idx);
            }
            self.by_name.entry(name.clone()).or_insert(idx);
        }
    }

    pub fn get(&self, idx: u32) -> Option<&Ty> {
        if idx < self.first {
            return None;
        }
        self.types.get((idx - self.first) as usize)
    }

    /// A forward reference resolved to its definition (by unique name, then name).
    pub fn resolve(&self, idx: u32) -> u32 {
        match self.get(idx) {
            Some(Ty::Udt { name, unique, forward: true, .. }) | Some(Ty::Enum { name, unique, forward: true, .. }) => unique
                .as_ref()
                .and_then(|u| self.by_name.get(u))
                .or_else(|| self.by_name.get(name))
                .copied()
                .unwrap_or(idx),
            _ => idx,
        }
    }

    /// Strips const/volatile modifiers and resolves forward references.
    pub fn strip(&self, mut idx: u32) -> u32 {
        for _ in 0..DEPTH {
            match self.get(idx) {
                Some(Ty::Mod { to, .. }) => idx = *to,
                _ => return self.resolve(idx),
            }
        }
        idx
    }

    pub fn size(&self, idx: u32) -> u64 {
        self.size_d(idx, 0)
    }

    fn size_d(&self, idx: u32, d: usize) -> u64 {
        if d > DEPTH {
            return 0;
        }
        if idx < self.first {
            return primitive(idx).1 as u64;
        }
        match self.get(self.resolve(idx)) {
            Some(Ty::Ptr { size, .. }) => if *size == 0 { 8 } else { *size as u64 },
            Some(Ty::Mod { to, .. }) => self.size_d(*to, d + 1),
            Some(Ty::Array { size, .. }) => *size as u64,
            Some(Ty::Bitfield { to, .. }) => self.size_d(*to, d + 1),
            Some(Ty::Udt { size, .. }) => *size,
            Some(Ty::Enum { underlying, .. }) => self.size_d(*underlying, d + 1),
            _ => 0,
        }
    }

    /// Members of a field list, following continuations.
    pub fn members(&self, list: u32) -> Vec<&Member> {
        let mut out = Vec::new();
        let mut cur = Some(list);
        let mut guard = 0;
        let mut seen = std::collections::HashSet::new();
        while let Some(i) = cur {
            guard += 1;
            // a continuation that loops back would list the same members up to 4096 times
            if guard > 4096 || !seen.insert(i) {
                break;
            }
            match self.get(i) {
                Some(Ty::Fields { members, cont }) => {
                    out.extend(members.iter());
                    cur = *cont;
                }
                _ => break,
            }
        }
        out
    }

    pub fn args(&self, idx: u32) -> Vec<u32> {
        match self.get(idx) {
            Some(Ty::Args(a)) => a.clone(),
            _ => Vec::new(),
        }
    }

    /// C-like spelling of a type.
    pub fn name(&self, idx: u32) -> String {
        self.name_d(idx, 0, &std::cell::Cell::new(NAME_BUDGET))
    }

    /// `work` counts the records visited: depth alone does not bound a type graph whose function
    /// types list the same pointer-to-function argument many times (fan-out ^ DEPTH; a hostile
    /// PDB hung `name` there).
    fn name_d(&self, idx: u32, d: usize, work: &std::cell::Cell<usize>) -> String {
        if d > DEPTH || work.get() == 0 {
            return "…".into();
        }
        work.set(work.get() - 1);
        if idx < self.first {
            return primitive(idx).0;
        }
        match self.get(idx) {
            Some(Ty::Ptr { to, reference, konst, .. }) => {
                let star = if *reference { "&" } else { "*" };
                let c = if *konst { " const" } else { "" };
                if let Some(Ty::Proc { ret, args, .. }) = self.get(*to) {
                    return format!("{} (*{c})({})", ret.map(|r| self.name_d(r, d + 1, work)).unwrap_or_else(|| "void".into()), self.arg_names(*args, d + 1, work));
                }
                format!("{}{star}{c}", self.name_d(*to, d + 1, work))
            }
            Some(Ty::Mod { to, konst, vol }) => {
                let mut s = String::new();
                if *konst {
                    s.push_str("const ");
                }
                if *vol {
                    s.push_str("volatile ");
                }
                s + &self.name_d(*to, d + 1, work)
            }
            Some(Ty::Array { elem, size, .. }) => {
                let es = self.size(*elem).max(1);
                format!("{}[{}]", self.name_d(*elem, d + 1, work), *size as u64 / es)
            }
            Some(Ty::Bitfield { to, len, .. }) => format!("{} : {len}", self.name_d(*to, d + 1, work)),
            Some(Ty::Udt { name, .. }) | Some(Ty::Enum { name, .. }) => name.clone(),
            Some(Ty::Proc { ret, args, .. }) => format!("{} ({})", ret.map(|r| self.name_d(r, d + 1, work)).unwrap_or_else(|| "void".into()), self.arg_names(*args, d + 1, work)),
            Some(Ty::Args(_)) => format!("({})", self.arg_names(idx, d + 1, work)),
            _ => format!("<type 0x{idx:x}>"),
        }
    }

    fn arg_names(&self, args: u32, d: usize, work: &std::cell::Cell<usize>) -> String {
        let a = self.args(args);
        if a.is_empty() {
            return "void".into();
        }
        let mut out: Vec<String> = Vec::new();
        for x in &a {
            if work.get() == 0 {
                out.push("…".into());
                break;
            }
            out.push(if *x == 0 { "...".into() } else { self.name_d(*x, d, work) });
        }
        out.join(", ")
    }

    /// Kind word for listings.
    pub fn kind(&self, idx: u32) -> &'static str {
        if idx < self.first {
            return if (idx >> 8) & 0xf != 0 { "pointer" } else { "primitive" };
        }
        match self.get(idx) {
            Some(Ty::Ptr { .. }) => "pointer",
            Some(Ty::Mod { .. }) => "modifier",
            Some(Ty::Array { .. }) => "array",
            Some(Ty::Bitfield { .. }) => "bitfield",
            Some(Ty::Udt { kind, .. }) => kind,
            Some(Ty::Enum { .. }) => "enum",
            Some(Ty::Proc { .. }) => "function",
            _ => "other",
        }
    }

    /// Description of a type as the UI's struct importer consumes it:
    /// `{type, size, category, scalar?, udt?, count?, elem?, points_to?}`.
    pub fn desc(&self, idx: u32) -> Map<String, Value> {
        self.desc_d(idx, 0)
    }

    fn desc_d(&self, idx: u32, d: usize) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("type".into(), self.name(idx).into());
        m.insert("type_index".into(), idx.into());
        m.insert("size".into(), self.size(idx).into());
        if d > 8 {
            m.insert("category".into(), "other".into());
            return m;
        }
        let base = self.strip(idx);
        if base < self.first {
            let sc = scalar_of_primitive(base);
            m.insert("category".into(), if sc == "ptr" { "pointer" } else { "primitive" }.into());
            m.insert("scalar".into(), sc.into());
            return m;
        }
        match self.get(base) {
            Some(Ty::Ptr { to, .. }) => {
                m.insert("category".into(), "pointer".into());
                m.insert("scalar".into(), "ptr".into());
                let t = self.strip(*to);
                if matches!(self.get(t), Some(Ty::Udt { .. })) {
                    m.insert("points_to".into(), t.into());
                }
                if matches!(self.get(t), Some(Ty::Proc { .. })) {
                    m.insert("function".into(), true.into());
                }
            }
            Some(Ty::Array { elem, size, .. }) => {
                let es = self.size(*elem);
                m.insert("category".into(), "array".into());
                m.insert("count".into(), (*size as u64).checked_div(es).unwrap_or(0).into());
                m.insert("elem".into(), Value::Object(self.desc_d(*elem, d + 1)));
            }
            Some(Ty::Udt { .. }) => {
                m.insert("category".into(), "udt".into());
                m.insert("udt".into(), base.into());
            }
            Some(Ty::Enum { underlying, .. }) => {
                m.insert("category".into(), "enum".into());
                m.insert("udt".into(), base.into());
                m.insert("scalar".into(), scalar_of_primitive(self.strip(*underlying)).into());
            }
            Some(Ty::Bitfield { to, .. }) => {
                m.insert("category".into(), "bitfield".into());
                m.insert("scalar".into(), scalar_of_primitive(self.strip(*to)).into());
            }
            Some(Ty::Proc { .. }) => {
                m.insert("category".into(), "function".into());
            }
            _ => {
                m.insert("category".into(), "other".into());
            }
        }
        m
    }

    /// Full layout of a struct / class / union / enum: fields with offsets, sizes, bitfields and
    /// the nested type each field refers to.
    pub fn layout(&self, idx: u32) -> Option<Value> {
        let idx = self.strip(idx);
        match self.get(idx)? {
            Ty::Udt { kind, name, size, fields, forward, .. } => {
                let mut out = Vec::new();
                if let Some(list) = fields {
                    for mb in self.members(*list) {
                        match mb {
                            Member::Data { name, ty, offset } => {
                                let mut f = self.desc(*ty);
                                f.insert("name".into(), name.clone().into());
                                f.insert("offset".into(), (*offset).into());
                                f.insert("kind".into(), "member".into());
                                if let Some(Ty::Bitfield { len, pos, .. }) = self.get(self.strip(*ty)) {
                                    f.insert("bit_pos".into(), (*pos).into());
                                    f.insert("bit_len".into(), (*len).into());
                                }
                                out.push(Value::Object(f));
                            }
                            Member::Base { ty, offset } => {
                                let mut f = self.desc(*ty);
                                f.insert("name".into(), format!("base_{}", self.name(*ty).replace(|c: char| !c.is_ascii_alphanumeric(), "_")).into());
                                f.insert("offset".into(), (*offset).into());
                                f.insert("kind".into(), "base".into());
                                out.push(Value::Object(f));
                            }
                            Member::VTable { .. } => {
                                out.push(json!({ "name": "vftable", "offset": 0, "size": 8, "type": "void**", "category": "pointer", "scalar": "ptr", "kind": "vtable" }));
                            }
                            _ => {}
                        }
                    }
                }
                Some(json!({ "index": idx, "name": name, "kind": kind, "size": size, "forward": forward, "fields": out }))
            }
            Ty::Enum { name, underlying, fields, forward, .. } => {
                let values: Vec<Value> = self
                    .members(*fields)
                    .into_iter()
                    .filter_map(|m| match m {
                        Member::Enumerate { name, value } => Some(json!({ "name": name, "value": value })),
                        _ => None,
                    })
                    .collect();
                Some(json!({ "index": idx, "name": name, "kind": "enum", "size": self.size(*underlying), "underlying": self.name(*underlying), "forward": forward, "values": values }))
            }
            _ => None,
        }
    }

    /// The layout plus every struct/union/enum it embeds by value (not through pointers),
    /// breadth-first up to `depth` levels.
    pub fn layout_with_nested(&self, idx: u32, depth: usize) -> Option<Value> {
        let top = self.layout(idx)?;
        let mut seen = vec![self.strip(idx)];
        let mut nested = Vec::new();
        let mut frontier = vec![top.clone()];
        for _ in 0..depth {
            let mut next = Vec::new();
            for l in &frontier {
                for f in l["fields"].as_array().into_iter().flatten() {
                    let mut f = f;
                    while f["category"] == "array" {
                        f = &f["elem"];
                    }
                    if let Some(u) = f["udt"].as_u64() {
                        let u = u as u32;
                        if !seen.contains(&u) {
                            seen.push(u);
                            if let Some(n) = self.layout(u) {
                                next.push(n);
                            }
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            nested.extend(next.iter().cloned());
            frontier = next;
        }
        let mut v = top;
        v["nested"] = Value::Array(nested);
        Some(v)
    }

    /// Named, defined structs/classes/unions/enums (and typedefs), filtered by substring.
    pub fn list(&self, filter: &str, max: usize) -> (usize, Vec<Value>) {
        let f = filter.to_lowercase();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut total = 0;
        // member counts per field list: hostile types all share one huge list
        let mut counts: HashMap<(u32, bool), usize> = HashMap::new();
        let mut count_of = |list: u32, data_only: bool| -> usize {
            *counts.entry((list, data_only)).or_insert_with(|| self.members(list).iter().filter(|m| !data_only || matches!(m, Member::Data { .. })).count())
        };
        for (i, t) in self.types.iter().enumerate() {
            let idx = self.first + i as u32;
            let (name, kind, size, count) = match t {
                Ty::Udt { name, kind, size, fields, forward: false, .. } => (name, *kind, *size, fields.map(|l| count_of(l, true)).unwrap_or(0)),
                Ty::Enum { name, underlying, fields, forward: false, .. } => (name, "enum", self.size(*underlying), count_of(*fields, false)),
                _ => continue,
            };
            if (!f.is_empty() && !name.to_lowercase().contains(&f)) || !seen.insert(name.clone()) {
                continue;
            }
            total += 1;
            if out.len() < max {
                out.push(json!({ "index": idx, "name": name, "kind": kind, "size": size, "fields": count }));
            }
        }
        let mut tds: Vec<_> = self.typedefs.iter().filter(|(n, _)| f.is_empty() || n.to_lowercase().contains(&f)).collect();
        tds.sort();
        for (n, idx) in tds {
            if seen.contains(n) {
                continue;
            }
            total += 1;
            if out.len() < max {
                out.push(json!({ "index": idx, "name": n, "kind": "typedef", "size": self.size(*idx), "target": self.name(*idx) }));
            }
        }
        (total, out)
    }

    /// Type index by name: definitions first, then typedefs.
    pub fn find(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied().or_else(|| self.typedefs.get(name).copied())
    }
}

fn read_types(pdb: &mut pdb::PDB<'_, fs::File>) -> Result<TypeDb, String> {
    let tpi = pdb.type_information().map_err(e2s)?;
    let mut db = TypeDb::default();
    let mut it = tpi.iter();
    while let Some(item) = it.next().map_err(e2s)? {
        let idx = item.index().0;
        if db.types.is_empty() {
            db.first = idx;
        }
        let at = idx.saturating_sub(db.first) as usize;
        while db.types.len() < at {
            db.types.push(Ty::Other);
        }
        db.types.push(item.parse().map(owned).unwrap_or(Ty::Other));
    }
    db.index();
    Ok(db)
}

// ------------------------------------------------------------------------------------------------
// loading

/// Runs a `pdb` crate reader over a file that came from a symbol server or the disk. The crate
/// indexes and slices with sizes taken from the file (`names_buf[name_offset..]`,
/// `stream[start..start + size]`) and panics on a damaged one, in release builds too; the panic
/// becomes an error instead of taking the relay's worker down.
pub fn guarded<T>(what: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| Err(format!("{}: damaged PDB (the reader gave up)", what.display())))
}

/// Reads everything we use from a PDB.
pub fn load(path: &Path) -> Result<Loaded, String> {
    guarded(path, || load_unguarded(path))
}

fn load_unguarded(path: &Path) -> Result<Loaded, String> {
    let file = fs::File::open(path).map_err(e2s)?;
    let mut pdb = pdb::PDB::open(file).map_err(e2s)?;
    let info = pdb.pdb_information().map_err(e2s)?;
    let dbi = pdb.debug_information().map_err(e2s)?;
    // the DBI stream's age is the one the image's CodeView entry carries
    let age = dbi.age().unwrap_or(info.age);
    let (key, guid) = identity_key(info.guid.as_fields(), age);
    let machine = dbi.machine_type().map(|m| format!("{m:?}")).unwrap_or_default();
    let map = pdb.address_map().map_err(e2s)?;
    let mut types = read_types(&mut pdb).unwrap_or_default();
    let strings = pdb.string_table().ok();

    let mut by_rva: HashMap<u32, Sym> = HashMap::new();
    let mut publics: Vec<(u32, String, bool)> = Vec::new();
    let mut datas: Vec<(u32, String, u32)> = Vec::new();

    let globals = pdb.global_symbols().map_err(e2s)?;
    let mut it = globals.iter();
    while let Some(sym) = it.next().map_err(e2s)? {
        match sym.parse() {
            Ok(pdb::SymbolData::Public(p)) => {
                if let Some(rva) = p.offset.to_rva(&map) {
                    publics.push((rva.0, p.name.to_string().into_owned(), p.function || p.code));
                }
            }
            Ok(pdb::SymbolData::Data(d)) => {
                if let Some(rva) = d.offset.to_rva(&map) {
                    datas.push((rva.0, d.name.to_string().into_owned(), d.type_index.0));
                }
            }
            Ok(pdb::SymbolData::ThreadStorage(t)) => {
                if let Some(rva) = t.offset.to_rva(&map) {
                    datas.push((rva.0, t.name.to_string().into_owned(), t.type_index.0));
                }
            }
            Ok(pdb::SymbolData::UserDefinedType(u)) => {
                types.typedefs.entry(u.name.to_string().into_owned()).or_insert(u.type_index.0);
            }
            _ => {}
        }
    }

    // procedures, module-local data and line programs live in the module streams
    let mut lines: Vec<LineRec> = Vec::new();
    let mut files: Vec<String> = Vec::new();
    let mut file_ids: HashMap<String, u32> = HashMap::new();
    let mut modules = dbi.modules().map_err(e2s)?;
    while let Some(m) = modules.next().map_err(e2s)? {
        let Ok(Some(info)) = pdb.module_info(&m) else { continue };
        if let Ok(mut syms) = info.symbols() {
            // the procedure whose top-level scope we are in, and the scope depth
            let mut cur: Option<u32> = None;
            let mut depth = 0usize;
            let mut regrel: Vec<(String, u32)> = Vec::new();
            let finish = |by_rva: &mut HashMap<u32, Sym>, cur: Option<u32>, regrel: &mut Vec<(String, u32)>, types: &TypeDb| {
                if let Some(rva) = cur {
                    if let Some(s) = by_rva.get_mut(&rva) {
                        // MSVC describes parameters as register-relative locals, first in the scope
                        if s.params.is_empty() && !regrel.is_empty() {
                            let n = s.ty.and_then(|t| match types.get(t) {
                                Some(Ty::Proc { args, .. }) => Some(types.args(*args).len()),
                                _ => None,
                            });
                            if let Some(n) = n {
                                s.params = regrel.iter().take(n).cloned().collect();
                            }
                        }
                    }
                }
                regrel.clear();
            };
            while let Ok(Some(sym)) = syms.next() {
                let Ok(data) = sym.parse() else { continue };
                match data {
                    pdb::SymbolData::Procedure(p) => {
                        finish(&mut by_rva, cur, &mut regrel, &types);
                        cur = None;
                        if let Some(rva) = p.offset.to_rva(&map) {
                            by_rva.insert(rva.0, Sym { rva: rva.0, size: p.len, name: p.name.to_string().into_owned(), kind: "function", ty: Some(p.type_index.0), params: Vec::new(), mangled: None });
                            cur = Some(rva.0);
                        }
                        depth = 1;
                    }
                    pdb::SymbolData::Block(_) | pdb::SymbolData::InlineSite(_) | pdb::SymbolData::Thunk(_) | pdb::SymbolData::SeparatedCode(_) => depth += 1,
                    pdb::SymbolData::ScopeEnd | pdb::SymbolData::ProcedureEnd | pdb::SymbolData::InlineSiteEnd => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            finish(&mut by_rva, cur, &mut regrel, &types);
                            cur = None;
                        }
                    }
                    // `this` is not part of a member function's argument list
                    pdb::SymbolData::Local(l) if depth == 1 && l.flags.isparam && l.name.as_bytes() != b"this" => {
                        if let Some(s) = cur.and_then(|r| by_rva.get_mut(&r)) {
                            s.params.push((l.name.to_string().into_owned(), l.type_index.0));
                        }
                    }
                    pdb::SymbolData::RegisterRelative(r) if depth == 1 && r.name.as_bytes() != b"this" => regrel.push((r.name.to_string().into_owned(), r.type_index.0)),
                    pdb::SymbolData::Data(d) if depth == 0 => {
                        if let Some(rva) = d.offset.to_rva(&map) {
                            datas.push((rva.0, d.name.to_string().into_owned(), d.type_index.0));
                        }
                    }
                    _ => {}
                }
            }
            finish(&mut by_rva, cur, &mut regrel, &types);
        }
        if let Ok(prog) = info.line_program() {
            let mut names: HashMap<u32, u32> = HashMap::new();
            let mut it = prog.lines();
            while let Ok(Some(l)) = it.next() {
                let Some(rva) = l.offset.to_rva(&map) else { continue };
                let fid = *names.entry(l.file_index.0).or_insert_with(|| {
                    let n = prog
                        .get_file_info(l.file_index)
                        .ok()
                        .and_then(|f| strings.as_ref().and_then(|s| f.name.to_string_lossy(s).ok().map(|c| c.into_owned())))
                        .unwrap_or_else(|| "?".into());
                    *file_ids.entry(n.clone()).or_insert_with(|| {
                        files.push(n);
                        (files.len() - 1) as u32
                    })
                });
                lines.push(LineRec { rva: rva.0, len: l.length.unwrap_or(0), file: fid, line: l.line_start });
            }
        }
    }

    for (rva, name, ty) in datas {
        let size = types.size(ty) as u32;
        by_rva.entry(rva).or_insert(Sym { rva, size, name, kind: "data", ty: Some(ty), params: Vec::new(), mangled: None });
    }
    for (rva, name, code) in publics {
        match by_rva.get_mut(&rva) {
            Some(s) => {
                if s.name != name && s.mangled.is_none() {
                    s.mangled = Some(name);
                }
            }
            None => {
                by_rva.insert(rva, Sym { rva, size: 0, name, kind: if code { "function" } else { "data" }, ty: None, params: Vec::new(), mangled: None });
            }
        }
    }
    let mut syms: Vec<Sym> = by_rva.into_values().collect();
    syms.sort_by_key(|s| s.rva);

    lines.sort_by_key(|l| (l.rva, l.line));
    lines.dedup_by_key(|l| l.rva);
    for i in 0..lines.len() {
        if lines[i].len == 0 {
            if let Some(n) = lines.get(i + 1) {
                lines[i].len = n.rva - lines[i].rva;
            }
        }
    }
    Ok(Loaded { path: path.to_owned(), key, guid, age, machine, syms, types, lines, files })
}

impl Loaded {
    /// The function symbol whose range contains `rva`.
    pub fn function_at(&self, rva: u32) -> Option<&Sym> {
        let i = self.syms.partition_point(|s| s.rva <= rva);
        self.syms[..i].iter().rev().take(64).find(|s| s.kind == "function" && rva < s.rva + s.size.max(1))
    }

    /// Line records overlapping `[rva, rva+size)` (or the one containing `rva` when `size` is 0).
    pub fn lines_in(&self, rva: u32, size: u32, max: usize) -> Vec<&LineRec> {
        let end = rva.saturating_add(size.max(1));
        let start = self.lines.partition_point(|l| l.rva + l.len.max(1) <= rva);
        self.lines[start..].iter().take_while(|l| l.rva < end).take(max).collect()
    }

    /// JSON for one symbol, with its prototype when known.
    pub fn sym_json(&self, s: &Sym) -> Value {
        let mut v = json!({ "rva": s.rva, "name": s.name, "kind": s.kind, "size": s.size });
        if let Some(m) = &s.mangled {
            v["mangled"] = m.clone().into();
        }
        if let Some(t) = s.ty {
            v["type"] = self.types.name(t).into();
            if let Some(Ty::Proc { ret, args, cc, .. }) = self.types.get(t) {
                let arg_types = self.types.args(*args);
                v["ret"] = ret.map(|r| self.types.name(r)).unwrap_or_else(|| "void".into()).into();
                v["cc"] = (*cc).into();
                let params: Vec<Value> = arg_types
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        let name = s.params.get(i).map(|p| p.0.clone()).unwrap_or_else(|| format!("a{}", i + 1));
                        json!({ "name": name, "type": if *a == 0 { "...".into() } else { self.types.name(*a) }, "size": self.types.size(*a) })
                    })
                    .collect();
                v["params"] = Value::Array(params);
            }
        }
        v
    }

    pub fn line_json(&self, l: &LineRec) -> Value {
        json!({ "rva": l.rva, "size": l.len, "file": self.files.get(l.file as usize).cloned().unwrap_or_default(), "line": l.line })
    }
}

// ------------------------------------------------------------------------------------------------
// cache

type Entry = (PathBuf, Option<std::time::SystemTime>, u64, Arc<Loaded>);

fn cache() -> &'static Mutex<Vec<Entry>> {
    static C: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Vec::new()))
}

/// The parsed PDB at `path`, read once and kept while the file is unchanged (last 6 files).
pub fn open(path: &Path) -> Result<Arc<Loaded>, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (mtime, len) = (meta.modified().ok(), meta.len());
    {
        let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = c.iter().position(|e| e.0 == path && e.1 == mtime && e.2 == len) {
            let e = c.remove(i);
            let l = e.3.clone();
            c.push(e);
            return Ok(l);
        }
    }
    let l = Arc::new(load(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
    c.retain(|e| e.0 != path);
    c.push((path.to_owned(), mtime, len, l.clone()));
    while c.len() > 6 {
        c.remove(0);
    }
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn types_pdb() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdbtypes/types.pdb")
    }

    #[test]
    fn primitive_indices() {
        assert_eq!(primitive(0x74), ("int".into(), 4));
        assert_eq!(primitive(0x0603), ("void*".into(), 8));
        assert_eq!(primitive(0x0470), ("char*".into(), 4));
        assert_eq!(primitive(0x40), ("float".into(), 4));
        assert_eq!(scalar_of_primitive(0x23), "u64");
        assert_eq!(scalar_of_primitive(0x0670), "ptr");
    }

    #[test]
    fn reads_procedures_with_sizes_prototypes_and_params() {
        let l = load(&types_pdb()).unwrap();
        let score = l.syms.iter().find(|s| s.name == "entity_score").unwrap();
        assert_eq!(score.kind, "function");
        assert_eq!(score.size, 28);
        assert_eq!(score.rva, 0x1000);
        let j = l.sym_json(score);
        assert_eq!(j["type"], "int (Entity*, int)");
        assert_eq!(j["ret"], "int");
        assert_eq!(j["params"][0]["name"], "e");
        assert_eq!(j["params"][0]["type"], "Entity*");
        assert_eq!(j["params"][1]["name"], "bonus");
        let init = l.sym_json(l.syms.iter().find(|s| s.name == "entity_init").unwrap());
        assert_eq!(init["params"][1]["name"], "id");
        assert_eq!(init["params"][1]["type"], "unsigned __int64");
        assert_eq!(init["ret"], "void");
        // static function (S_LPROC32) and globals with their type sizes
        assert!(l.syms.iter().any(|s| s.name == "hit" && s.kind == "function"));
        let g = l.syms.iter().find(|s| s.name == "g_entities").unwrap();
        assert_eq!(g.kind, "data");
        assert_eq!(g.size as u64, 2 * l.types.size(l.types.find("Entity").unwrap()));
        assert_eq!(l.function_at(score.rva + 5).unwrap().name, "entity_score");
    }

    #[test]
    fn reads_line_information() {
        let l = load(&types_pdb()).unwrap();
        assert!(l.files.iter().any(|f| f.ends_with("types.c")), "{:?}", l.files);
        let score = l.syms.iter().find(|s| s.name == "entity_score").unwrap();
        let lines = l.lines_in(score.rva, score.size, 100);
        assert!(!lines.is_empty());
        // entity_score's body spans types.c lines 40..44
        assert!(lines.iter().all(|x| (39..=45).contains(&x.line)), "{lines:?}");
        assert_eq!(l.line_json(lines[0])["file"].as_str().unwrap().rsplit(['/', '\\']).next(), Some("types.c"));
    }

    #[test]
    fn lays_out_structs_with_nested_types_bitfields_unions_and_enums() {
        let l = load(&types_pdb()).unwrap();
        let t = &l.types;
        let e = t.find("Entity").unwrap();
        let v = t.layout_with_nested(e, 8).unwrap();
        assert_eq!(v["kind"], "struct");
        let f = |n: &str| v["fields"].as_array().unwrap().iter().find(|x| x["name"] == n).unwrap().clone();
        assert_eq!(f("next")["category"], "pointer");
        assert_eq!(f("next")["points_to"], e);
        assert_eq!(f("pos")["offset"], 8);
        assert_eq!(f("pos")["category"], "udt");
        assert_eq!(f("path")["category"], "array");
        assert_eq!(f("path")["count"], 4);
        assert_eq!(f("path")["elem"]["type"], "Vec3");
        assert_eq!(f("name")["type"], "char[16]");
        assert_eq!(f("on_hit")["type"], "int (*)(int, void*)");
        assert_eq!(f("label")["type"], "const char*");
        assert_eq!(f("color")["category"], "enum");
        let nested: Vec<&str> = v["nested"].as_array().unwrap().iter().map(|n| n["name"].as_str().unwrap()).collect();
        for n in ["Vec3", "Flags", "Value", "Color"] {
            assert!(nested.contains(&n), "{nested:?}");
        }
        let flags = t.layout(t.find("Flags").unwrap()).unwrap();
        let kind = flags["fields"].as_array().unwrap().iter().find(|x| x["name"] == "kind").unwrap();
        assert_eq!((kind["bit_pos"].as_u64(), kind["bit_len"].as_u64(), kind["offset"].as_u64()), (Some(1), Some(3), Some(0)));
        let value = t.layout(t.find("Value").unwrap()).unwrap();
        assert_eq!(value["kind"], "union");
        assert!(value["fields"].as_array().unwrap().iter().all(|x| x["offset"] == 0));
        let color = t.layout(t.find("Color").unwrap()).unwrap();
        assert_eq!(color["values"], json!([{ "name": "COLOR_RED", "value": 1 }, { "name": "COLOR_GREEN", "value": 2 }, { "name": "COLOR_BLUE", "value": 4 }]));
        let (_, list) = t.list("ent", 10);
        assert!(list.iter().any(|x| x["name"] == "Entity"));
        assert_eq!(t.name(t.find("Callback").unwrap()), "int (*)(int, void*)");
    }
}
