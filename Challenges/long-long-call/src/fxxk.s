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
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_register 6
	sub	rsp, 304
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	eax, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC0[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	getenv@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	test	rax, rax
	je	.L2
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC1[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edi, 1
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	exit@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L2:
	lea	rax, .LC2[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rsi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC3[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	fopen@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	QWORD PTR -288[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, -272[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	QWORD PTR -280[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	jmp	.L3
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L4:
	mov	rax, QWORD PTR -280[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rdx, .LC4[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rsi, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	strstr@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	test	rax, rax
	je	.L3
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	DWORD PTR -292[rbp], 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -280[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	strlen@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rdx, -3[rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -280[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	atoi@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	DWORD PTR -292[rbp], eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	cmp	DWORD PTR -292[rbp], 0
	je	.L3
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC1[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edi, 1
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	exit@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L3:
	mov	rdx, QWORD PTR -288[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -280[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	esi, 256
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	fgets@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	test	rax, rax
	jne	.L4
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	nop
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -8[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	sub	rax, QWORD PTR fs:40
	je	.L5
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	__stack_chk_fail@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L5:
	leave
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa 7, 8
	ret
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
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
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_register 6
	sub	rsp, 240
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	QWORD PTR -232[rbp], rdi
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	eax, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	DWORD PTR -212[rbp], 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	jmp	.L7
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L8:
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movsx	rdx, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	ecx, BYTE PTR [rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	cdqe
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rdx, 1[rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	eax, BYTE PTR [rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	eax, ecx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	BYTE PTR -213[rbp], al
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movsx	rdx, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	eax, BYTE PTR [rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edx, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movsx	rcx, edx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdx, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rdx, rcx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	al, BYTE PTR -213[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	BYTE PTR [rdx], al
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	cdqe
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rdx, 1[rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	eax, BYTE PTR [rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edx, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movsx	rdx, edx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rcx, 1[rdx]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdx, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rdx, rcx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	al, BYTE PTR -213[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	BYTE PTR [rdx], al
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	DWORD PTR -212[rbp], 2
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L7:
	cmp	DWORD PTR -212[rbp], 43
	jle	.L8
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	nop
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -8[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	sub	rax, QWORD PTR fs:40
	je	.L9
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	__stack_chk_fail@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L9:
	leave
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa 7, 8
	ret
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
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
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_register 6
	sub	rsp, 240
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	QWORD PTR -232[rbp], rdi
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	eax, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	DWORD PTR -212[rbp], 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	jmp	.L11
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L13:
	lea	rax, .LC5[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	eax, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edi, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	sleep@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movsx	rdx, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR -232[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	add	rax, rdx
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	edx, BYTE PTR [rax]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, DWORD PTR -212[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	cdqe
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rcx, enc[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	movzx	eax, BYTE PTR [rax+rcx]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	cmp	dl, al
	je	.L12
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC6[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edi, 1
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	exit@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L12:
	add	DWORD PTR -212[rbp], 1
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L11:
	cmp	DWORD PTR -212[rbp], 43
	jle	.L13
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC7[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	edi, 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	exit@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
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
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa_register 6
	sub	rsp, 64
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	xor	eax, eax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC8[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, -64[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rsi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC9[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	__isoc99_scanf@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, .LC10[rip]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	puts@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, -64[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	encrypt
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	lea	rax, -64[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdi, rax
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	check
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	eax, 0
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	mov	rdx, QWORD PTR -8[rbp]
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	sub	rdx, QWORD PTR fs:40
	je	.L17
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	call	__stack_chk_fail@PLT
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.L17:
	leave
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_def_cfa 7, 8
	ret
    pushfq
    call	$+7
    leave
    ret
    add	rsp, 8
    popfq
	.cfi_endproc
	.LFE9:
	.size	main, .-main
	.ident	"GCC: (GNU) 13.2.1 20230801"
	.section	.note.GNU-stack,"",@progbits
