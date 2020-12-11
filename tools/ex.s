	.text
	.intel_syntax noprefix
	.file	"execve.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 48
	xor	eax, eax
	mov	edx, eax
	lea	rsi, [rbp - 32]
	mov	dword ptr [rbp - 4], 0
	mov	rcx, qword ptr [.L__const.main.argv]
	mov	qword ptr [rbp - 32], rcx
	mov	rcx, qword ptr [.L__const.main.argv+8]
	mov	qword ptr [rbp - 24], rcx
	movabs	rdi, offset .L.str.1
	mov	al, 0
	call	execve
	mov	r8d, 1
	mov	dword ptr [rbp - 36], eax # 4-byte Spill
	mov	eax, r8d
	add	rsp, 48
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.zero	1
	.size	.L.str, 1

	.type	.L__const.main.argv,@object # @__const.main.argv
	.section	.rodata,"a",@progbits
	.p2align	4
.L__const.main.argv:
	.quad	.L.str
	.quad	0
	.size	.L__const.main.argv, 16

	.type	.L.str.1,@object        # @.str.1
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str.1:
	.asciz	"/system/bin/sh"
	.size	.L.str.1, 15

	.ident	"clang version 10.0.0-4ubuntu1 "
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym execve
