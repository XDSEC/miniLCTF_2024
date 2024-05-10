	.file	"main.c"
	.intel_syntax noprefix
	.text
	.globl	enc
	.data
	.align 32
	.type	enc, @object
	.size	enc, 44
enc:
	.ascii	"\273\277\271\276\303\314\316\334\236\217\235\233\247\214\327"
	.ascii	"\225\260\255\275\264\210\257\222\320\317\241\243\222\267\264"
	.ascii	"\311\236\224\247\256\360\241\231\300\343\264\264\277\343"
	.section	.rodata
.LC0:
	.string	"LD_PRELOAD"
.LC1:
	.string	"hacker XD:"
.LC2:
	.string	"r"
.LC3:
	.string	"/proc/self/status"
.LC4:
	.string	"TracerPid"
	.text
	.globl	anti_debug
	.type	anti_debug, @function
anti_debug:
.LFB6:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 304
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
	xor	eax, eax
	lea	rax, .LC0[rip]
	mov	rdi, rax
	call	getenv@PLT
	test	rax, rax
	je	.L2
	lea	rax, .LC1[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	edi, 1
	call	exit@PLT
.L2:
	lea	rax, .LC2[rip]
	mov	rsi, rax
	lea	rax, .LC3[rip]
	mov	rdi, rax
	call	fopen@PLT
	mov	QWORD PTR -288[rbp], rax
	lea	rax, -272[rbp]
	mov	QWORD PTR -280[rbp], rax
	jmp	.L3
.L4:
	mov	rax, QWORD PTR -280[rbp]
	lea	rdx, .LC4[rip]
	mov	rsi, rdx
	mov	rdi, rax
	call	strstr@PLT
	test	rax, rax
	je	.L3
	mov	DWORD PTR -292[rbp], 0
	mov	rax, QWORD PTR -280[rbp]
	mov	rdi, rax
	call	strlen@PLT
	lea	rdx, -3[rax]
	mov	rax, QWORD PTR -280[rbp]
	add	rax, rdx
	mov	rdi, rax
	call	atoi@PLT
	mov	DWORD PTR -292[rbp], eax
	cmp	DWORD PTR -292[rbp], 0
	je	.L3
	lea	rax, .LC1[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	edi, 1
	call	exit@PLT
.L3:
	mov	rdx, QWORD PTR -288[rbp]
	mov	rax, QWORD PTR -280[rbp]
	mov	esi, 256
	mov	rdi, rax
	call	fgets@PLT
	test	rax, rax
	jne	.L4
	nop
	mov	rax, QWORD PTR -8[rbp]
	sub	rax, QWORD PTR fs:40
	je	.L5
	call	__stack_chk_fail@PLT
.L5:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	anti_debug, .-anti_debug
	.section	.init_array,"aw"
	.align 8
	.quad	anti_debug
	.text
	.globl	encrypt
	.type	encrypt, @function
encrypt:
.LFB7:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 240
	mov	QWORD PTR -232[rbp], rdi
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
	xor	eax, eax
	mov	DWORD PTR -212[rbp], 0
	jmp	.L7
.L8:
	mov	eax, DWORD PTR -212[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR -232[rbp]
	add	rax, rdx
	movzx	ecx, BYTE PTR [rax]
	mov	eax, DWORD PTR -212[rbp]
	cdqe
	lea	rdx, 1[rax]
	mov	rax, QWORD PTR -232[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	add	eax, ecx
	mov	BYTE PTR -213[rbp], al
	mov	eax, DWORD PTR -212[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR -232[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	mov	edx, DWORD PTR -212[rbp]
	movsx	rcx, edx
	mov	rdx, QWORD PTR -232[rbp]
	add	rdx, rcx
	xor	al, BYTE PTR -213[rbp]
	mov	BYTE PTR [rdx], al
	mov	eax, DWORD PTR -212[rbp]
	cdqe
	lea	rdx, 1[rax]
	mov	rax, QWORD PTR -232[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	mov	edx, DWORD PTR -212[rbp]
	movsx	rdx, edx
	lea	rcx, 1[rdx]
	mov	rdx, QWORD PTR -232[rbp]
	add	rdx, rcx
	xor	al, BYTE PTR -213[rbp]
	mov	BYTE PTR [rdx], al
	add	DWORD PTR -212[rbp], 2
.L7:
	cmp	DWORD PTR -212[rbp], 43
	jle	.L8
	nop
	mov	rax, QWORD PTR -8[rbp]
	sub	rax, QWORD PTR fs:40
	je	.L9
	call	__stack_chk_fail@PLT
.L9:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	encrypt, .-encrypt
	.section	.rodata
.LC5:
	.string	"checking..."
.LC6:
	.string	"Wrong!"
.LC7:
	.string	"Right"
	.text
	.globl	check
	.type	check, @function
check:
.LFB8:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 240
	mov	QWORD PTR -232[rbp], rdi
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
	xor	eax, eax
	mov	DWORD PTR -212[rbp], 0
	jmp	.L11
.L13:
	lea	rax, .LC5[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	eax, DWORD PTR -212[rbp]
	add	eax, eax
	mov	edi, eax
	call	sleep@PLT
	mov	eax, DWORD PTR -212[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR -232[rbp]
	add	rax, rdx
	movzx	edx, BYTE PTR [rax]
	mov	eax, DWORD PTR -212[rbp]
	cdqe
	lea	rcx, enc[rip]
	movzx	eax, BYTE PTR [rax+rcx]
	cmp	dl, al
	je	.L12
	lea	rax, .LC6[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	edi, 1
	call	exit@PLT
.L12:
	add	DWORD PTR -212[rbp], 1
.L11:
	cmp	DWORD PTR -212[rbp], 43
	jle	.L13
	lea	rax, .LC7[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	edi, 0
	call	exit@PLT
	.cfi_endproc
.LFE8:
	.size	check, .-check
	.section	.rodata
.LC8:
	.string	"input your flag:"
.LC9:
	.string	"%44s"
.LC10:
	.string	"ok, let's go"
	.text
	.globl	main
	.type	main, @function
main:
.LFB9:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 64
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
	xor	eax, eax
	lea	rax, .LC8[rip]
	mov	rdi, rax
	call	puts@PLT
	lea	rax, -64[rbp]
	mov	rsi, rax
	lea	rax, .LC9[rip]
	mov	rdi, rax
	mov	eax, 0
	call	__isoc99_scanf@PLT
	lea	rax, .LC10[rip]
	mov	rdi, rax
	call	puts@PLT
	lea	rax, -64[rbp]
	mov	rdi, rax
	call	encrypt
	lea	rax, -64[rbp]
	mov	rdi, rax
	call	check
	mov	eax, 0
	mov	rdx, QWORD PTR -8[rbp]
	sub	rdx, QWORD PTR fs:40
	je	.L17
	call	__stack_chk_fail@PLT
.L17:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	main, .-main
	.ident	"GCC: (GNU) 13.2.1 20230801"
	.section	.note.GNU-stack,"",@progbits
