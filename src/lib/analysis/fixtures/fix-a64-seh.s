// A function whose unwind data cannot be packed (it names an exception handler), so its .pdata
// entry points at .xdata. Linked into fix-a64.exe next to fix-a64.c (see README.md).
        .text
        .globl  with_handler
        .p2align 2
        .def    with_handler; .scl 2; .type 32; .endef
        .seh_proc with_handler
with_handler:
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        .seh_endprologue
        bl      entry
        .seh_startepilogue
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        .seh_endepilogue
        ret
        .seh_handler my_handler, @except
        .seh_endproc

        .globl  my_handler
        .p2align 2
my_handler:
        mov     w0, #1
        ret
