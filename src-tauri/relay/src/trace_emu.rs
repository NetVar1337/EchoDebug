//! Native trace recording inside a Unicorn session (the local Emu Debugger): hooks capture each
//! instruction's register changes and every memory read (bytes read) and write (bytes before and
//! after), exactly, including string instructions and stack traffic.

#[cfg(target_os = "linux")]
pub use imp::record;

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::RefCell;
    use std::rc::Rc;

    use serde_json::Value;
    use unicorn_engine::unicorn_const::HookType;
    use unicorn_engine::{RegisterX86, Unicorn};

    use crate::trace::{Builder, Meta, RawAccess, Regs, Trace, NREG};
    use crate::trace_rec::{Limits, PROGRESS};

    const REGS: [RegisterX86; NREG] = [
        RegisterX86::RAX, RegisterX86::RBX, RegisterX86::RCX, RegisterX86::RDX, RegisterX86::RSI, RegisterX86::RDI, RegisterX86::RBP, RegisterX86::RSP,
        RegisterX86::R8, RegisterX86::R9, RegisterX86::R10, RegisterX86::R11, RegisterX86::R12, RegisterX86::R13, RegisterX86::R14, RegisterX86::R15,
        RegisterX86::RIP, RegisterX86::EFLAGS, RegisterX86::FS_BASE, RegisterX86::GS_BASE,
    ];

    fn regs<D>(uc: &Unicorn<'_, D>) -> Regs {
        let mut r = [0u64; NREG];
        for (v, reg) in r.iter_mut().zip(REGS) {
            *v = uc.reg_read(reg).unwrap_or(0);
        }
        r
    }

    struct Pending {
        pc: u64,
        code: Vec<u8>,
        accs: Vec<RawAccess>,
    }

    struct Rec {
        b: Builder,
        pending: Option<Pending>,
        lim: Limits,
        stop: Option<&'static str>,
    }

    impl Rec {
        /// The pending instruction finished: its writes' new bytes are in memory now.
        fn finalize<D>(&mut self, uc: &Unicorn<'_, D>, after: &Regs) {
            let Some(mut p) = self.pending.take() else { return };
            for a in p.accs.iter_mut().filter(|a| a.write) {
                let mut n = vec![0u8; a.old.len()];
                if uc.mem_read(a.addr, &mut n).is_ok() {
                    a.new = n;
                }
            }
            self.b.step(p.pc, &p.code, after, &p.accs);
            let n = self.b.len() as u64;
            if n.is_multiple_of(256) {
                PROGRESS.store(n, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Records while `run(uc, max_steps)` executes (the session's own run loop, which keeps its
    /// breakpoints, watchpoints, stand-ins and cancel). Returns the trace and run's stop value.
    /// `backing` reads what a not-yet-mapped page will be faulted in with (memory hooks run before
    /// the unmapped-page handler), so the first access to a page still has its bytes.
    pub fn record<D: 'static>(
        uc: &mut Unicorn<'static, D>,
        mut meta: Meta,
        lim: &Limits,
        backing: impl Fn(&Unicorn<'_, D>, u64, &mut [u8]) -> bool + 'static,
        run: impl FnOnce(&mut Unicorn<'static, D>, usize) -> Value,
    ) -> Result<(Trace, Value), String> {
        let init = regs(uc);
        let rec = Rc::new(RefCell::new(Rec { b: Builder::new(Meta::default(), init, lim.keyframe), pending: None, lim: lim.clone(), stop: None }));
        PROGRESS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut hooks = Vec::new();
        let r1 = rec.clone();
        hooks.push(uc.add_code_hook(1, 0, move |uc, addr, size| {
            let now = regs(uc);
            let mut r = r1.borrow_mut();
            r.finalize(uc, &now);
            if r.stop.is_some() {
                return;
            }
            if r.b.len() >= r.lim.max_steps {
                r.stop = Some("count");
            } else if r.b.size_bytes() >= r.lim.max_bytes {
                r.stop = Some("size limit");
            } else if crate::trace_rec::cancelled() {
                r.stop = Some("cancelled");
            }
            if r.stop.is_some() {
                let _ = uc.emu_stop();
                return;
            }
            let code = if r.b.has_code(addr) { Vec::new() } else { uc.mem_read_as_vec(addr, (size as usize).clamp(1, 15)).unwrap_or_default() };
            r.pending = Some(Pending { pc: addr, code, accs: Vec::new() });
        }).map_err(|e| format!("{e:?}"))?);
        let r2 = rec.clone();
        hooks.push(uc.add_mem_hook(HookType::MEM_READ | HookType::MEM_WRITE, 1, 0, move |uc, ty, addr, size, _v| {
            let write = matches!(ty, unicorn_engine::unicorn_const::MemType::WRITE);
            let mut old = vec![0u8; size.clamp(1, 4096)];
            if uc.mem_read(addr, &mut old).is_err() && !backing(uc, addr, &mut old) {
                return true;
            }
            if let Some(p) = r2.borrow_mut().pending.as_mut() {
                p.accs.push(RawAccess { addr, write, old, new: Vec::new() });
            }
            true
        }).map_err(|e| format!("{e:?}"))?);
        let stop = run(uc, lim.max_steps.saturating_add(1));
        for h in hooks {
            let _ = uc.remove_hook(h);
        }
        let now = regs(uc);
        let mut r = Rc::try_unwrap(rec).map_err(|_| "recorder still referenced".to_owned())?.into_inner();
        // the last instruction ran unless the run stopped in front of it (breakpoint, limit) or it faulted
        let ran = match &r.pending {
            Some(p) => stop["reason"] != "fault" && !(now[16] == p.pc && p.accs.is_empty()),
            None => false,
        };
        if ran {
            r.finalize(uc, &now);
        }
        meta.stop_reason = match r.stop {
            Some(s) => s.to_owned(),
            None => stop["reason"].as_str().unwrap_or("stopped").to_owned(),
        };
        meta.truncated = r.stop == Some("size limit");
        let mut t = r.b.finish();
        t.meta = meta;
        Ok((t, stop))
    }
}
