# camelcamelcamel (19 solves, 483 points)

> camel calling convention all the way down

## Attachments:

[`camelcamelcamel`](./camelcamelcamel)

```
camelcamelcamel: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=169155241088205be61453d58e40f23a8ff1ba7f, for GNU/Linux 3.2.0, stripped
```

## Analysis

Since we have just an executable, let's decompile it. It seems that Binary Ninja
placed us directly at `libc_start_main`:

```
0002d890  int64_t _start(int64_t arg1, int64_t arg2, void (* arg3)()) __noreturn

0002d8a1      int64_t stack_end_1
0002d8a1      int64_t stack_end = stack_end_1
0002d8af      __libc_start_main(main: main, argc: __return_addr.d, ubp_av: &ubp_av, init: nullptr, fini: nullptr, rtld_fini: arg3, stack_end: &stack_end)
0002d8af      noreturn
```

We can follow this trail:

```
0002d870  int32_t main(int32_t argc, char** argv, char** envp)

0002d87d      caml_main(argv)
0002d884      caml_do_exit(0)
0002d884      noreturn
```

Ah, this seems to be an OCaml binary. From here, we can do a bit of educated guessing (peak rev)
to find our real main function:

```
0006ea00  int64_t caml_main(int64_t* arg1)

0006ea0a      int64_t rax = caml_startup_common(arg1, 0)
0006ea19      if (zx.q(rax.d & 3) == 2)
0006ea27          caml_fatal_uncaught_exception(rax & 0xfffffffffffffffc)
0006ea27          noreturn
0006ea1f      return rax
```

`caml_startup_common` makes the most sense...

```
0006e870  int64_t caml_startup_common(int64_t* arg1, int32_t arg2)

0006e875      int32_t rbp = arg2
0006e87f      caml_parse_ocamlrunparam()
0006e898      if (data_a4110.q != 0)
0006e898          rbp = 1
0006e8a9      if (caml_startup_aux(rbp) == 0)
0006e8b4          return 1
0006e8b8      caml_init_codefrag()
0006e8bd      caml_init_locale()
0006e8c2      caml_init_custom_operations()
0006e8c7      caml_init_os_params()
0006e8cc      caml_init_gc()
0006e8d1      caml_runtime_events_init()
0006e8d6      void* i = data_90be0
0006e8dd      void* caml_code_segments_1 = caml_code_segments
0006e8e4      void* rsi = data_90bd8
0006e8ee      if (i != 0)
0006e8f0          int32_t rcx_1 = 1
0006e8fc          int64_t rax_2 = 1
0006e933          do
0006e90b              if (caml_code_segments_1 u> i)
0006e90b                  caml_code_segments_1 = i
0006e913              void* rax_4 = (&data_90bd8)[rax_2 * 2]
0006e91b              if (rsi u< rax_4)
0006e91b                  rsi = rax_4
0006e91f              rcx_1 = rcx_1 + 1
0006e922              rax_2 = sx.q(rcx_1)
0006e92c              i = (&caml_code_segments)[rax_2 * 2]
0006e928          while (i != 0)
0006e939      caml_register_code_fragment(caml_code_segments_1, rsi, 0, nullptr)
0006e953      caml_register_code_fragment(&caml_hot.code_begin, &caml_system__code_end, 3, nullptr)
0006e958      caml_init_signals()
0006e962      char* rbp_1 = *arg1
0006e96f      if (rbp_1 == 0)
0006e96f          rbp_1 = &data_77572[0x1a]
0006e973      int32_t (* rax_5)[0x4] = caml_executable_name()
0006e978      int32_t (* rdi_1)[0x4] = rax_5
0006e97e      if (rax_5 == 0)
0006e9b8          rdi_1 = caml_search_exe_in_path(rbp_1)
0006e983      caml_sys_init(rdi_1, arg1)
0006e988      caml_maybe_expand_stack()
0006e998      void* fsbase
0006e998      int64_t rax_6 = caml_start_program(*fsbase)
0006e9a0      caml_terminate_signals()
0006e9ae      return rax_6
```

A little hidden at the end, but `caml_start_program`

```
0006ef84  int64_t caml_start_program(int64_t* arg1)

0006ef84      int64_t rbx
0006ef84      int64_t var_8 = rbx
0006ef85      int64_t rbp
0006ef85      int64_t var_10 = rbp
0006ef86      int64_t r12
0006ef86      int64_t var_18 = r12
0006ef88      int64_t r13
0006ef88      int64_t var_20 = r13
0006ef8a      int64_t r14
0006ef8a      int64_t var_28 = r14
0006ef8c      int64_t r15
0006ef8c      int64_t var_30 = r15
0006ef98      int64_t r15_1 = arg1[1]
0006efa0      int64_t var_48 = 0
0006efa8      int64_t var_40 = 0
0006efb5      int64_t var_38 = arg1[8]
0006efba      arg1[8] = &var_48
0006efc5      int64_t** r10_2 = *arg1[5] - 0x10
0006efc9      *r10_2 = &var_48
0006efd0      r10_2[1] = arg1[0xb]
0006efdf      *(r10_2 - 8) = &data_6f034
0006efe7      *(r10_2 - 0x10) = arg1[6]
0006efea      arg1[6] = r10_2 - 0x10
0006eff1      caml_program(arg1)
0006eff8      arg1[6] = *(r10_2 - 0x10)
0006f005      arg1[0xb] = r10_2[1]
0006f00d      arg1[1] = r15_1
0006f015      *arg1[5] = &r10_2[2]
0006f018      void* rsp_1 = arg1[8]
0006f021      arg1[8] = *(rsp_1 + 0x10)
0006f029      *(rsp_1 + 0x18)
0006f02b      *(rsp_1 + 0x20)
0006f02d      *(rsp_1 + 0x28)
0006f02f      *(rsp_1 + 0x30)
0006f031      *(rsp_1 + 0x38)
0006f032      *(rsp_1 + 0x40)
0006f033      return 1
```

`caml_program` probably is the right one.

```
0002d980  int64_t caml_program(int64_t* arg1 @ r14)

0002d98c      void var_140
0002d98c      void* r15
0002d98c      int64_t rax

// a variable for each register...

0002d98c      int64_t zmm15
0002d98c      if (&var_140 u< arg1[5])
0002da9a          caml_call_realloc_stack(rdi, rsi, rdx, rcx, r8, r9, rax, rbx, rbp, &var_140, r11, r12, r13, arg1, r15, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, 0x21)
0002d992      camlCamlinternalFormatBasics.entry()
0002d99e      caml_globals_inited = caml_globals_inited + 1
0002d9a2      camlStdlib.entry(r15)
0002d9ae      caml_globals_inited = caml_globals_inited + 1
0002d9b2      camlStdlib__Sys.entry(r15)
0002d9be      caml_globals_inited = caml_globals_inited + 1
0002d9c2      camlStdlib__Obj.entry(r15)
0002d9ce      caml_globals_inited = caml_globals_inited + 1
0002d9d2      camlStdlib__Atomic.entry()
0002d9de      caml_globals_inited = caml_globals_inited + 1
0002d9e2      camlCamlinternalLazy.entry(r15)
0002d9ee      caml_globals_inited = caml_globals_inited + 1
0002d9f2      camlStdlib__Lazy.entry()
0002d9fe      caml_globals_inited = caml_globals_inited + 1
0002da02      camlStdlib__Seq.entry(r15)
0002da0e      caml_globals_inited = caml_globals_inited + 1
0002da12      camlStdlib__Char.entry()
0002da1e      caml_globals_inited = caml_globals_inited + 1
0002da22      camlStdlib__Uchar.entry()
0002da2e      caml_globals_inited = caml_globals_inited + 1
0002da32      camlStdlib__List.entry()
0002da3e      caml_globals_inited = caml_globals_inited + 1
0002da42      camlStdlib__Int.entry()
0002da4e      caml_globals_inited = caml_globals_inited + 1
0002da52      camlStdlib__Bytes.entry()
0002da5e      caml_globals_inited = caml_globals_inited + 1
0002da62      camlStdlib__String.entry()
0002da6e      caml_globals_inited = caml_globals_inited + 1
0002da72      camlDune__exe__Main.entry(arg1, r15)
0002da7e      caml_globals_inited = caml_globals_inited + 1
0002da82      camlStd_exit.entry(arg1)
0002da8e      caml_globals_inited = caml_globals_inited + 1
0002da97      return 1
```

So much setup 😭, but we now see `Main.entry`!

```
0002e1d0  int64_t camlDune__exe__Main.fun_612(void* arg1, int64_t arg2 @ rbx, void* arg3 @ r14)

0002e1dc      void var_148
0002e1dc      int64_t* rax

// a variable for each register...

0002e1dc      int64_t zmm15
0002e1dc      if (&var_148 u< *(arg3 + 0x28))
0002e20b          rax, arg1 = caml_call_realloc_stack(arg1, rsi, rdx, rcx, r8, r9, rax, arg2, rbp, &var_148, r11, r12, r13, arg3, r15, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, 0x22)
0002e1f3      int64_t rax_1 = camlDune__exe__Main.update_274(arg2, rax, **(arg1 + 0x18))
0002e1fc      int64_t* rbx_3 = *(arg1 + 0x18)
0002e200      *rbx_3 = *rbx_3 + 2
0002e208      return rax_1
```

...and we're here!

```
0002e220  int64_t camlDune__exe__Main.entry(int64_t* arg1 @ r14, void* arg2 @ r15)

0002e22c      void var_148
0002e22c      int64_t rax

// a variable for each register...

0002e22c      int64_t zmm15
0002e22c      if (&var_148 u< arg1[5])
0002e469          caml_call_realloc_stack(rdi, rsi, rdx, rcx, r8, r9, rax, rbx, rbp, &var_148, r11, r12, r13, arg1, arg2, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, 0x22)
0002e24f      caml_initialize(&data_91180, &data_91118)
0002e257      caml_alloc1(arg1, arg2)
0002e260      *arg2 = 0x400
0002e273      *(arg2 + 8) = data_91180
0002e27d      caml_initialize(&camlDune__exe__Main, arg2 + 8)
0002e29e      caml_initialize(&data_91160, &camlDune__exe__Main.40)
0002e2bf      caml_initialize(&data_91168, &camlDune__exe__Main.55)
0002e32b      int64_t* rax_8 = camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, camlStdlib.$40_196(&camlDune__exe__Main.55, &camlDune__exe__Main.55, arg1, arg2), arg1, arg2), arg1, arg2), arg1, arg2), arg1, arg2), arg1, arg2), arg1, arg2)
0002e345      caml_initialize(&data_91170, rax_8)
0002e366      caml_initialize(&data_91178, &camlDune__exe__Main.95)
0002e37d      int64_t* rax_12 = camlStdlib__List.of_seq_1022(camlStdlib__Bytes.to_seq_620(camlStdlib.read_line_396(), arg1, arg2), arg1, arg2)
0002e385      caml_alloc1(arg1, arg2)
0002e392      *arg2 = 0x400
0002e39a      *(arg2 + 8) = 1
0002e3af      camlStdlib__List.map2_392(&camlDune__exe__Main.40, &data_91138, rax_12, arg1, arg2)
0002e3bb      int64_t* rdi_2 = caml_allocN(arg1, arg2 - 0x28)
0002e3c4      *(arg2 - 0x28) = 0x10f7
0002e3d3      *(arg2 - 0x20) = caml_curry2
0002e3e0      *(arg2 - 0x18) = 0x200000000000007
0002e3eb      *(arg2 - 0x10) = camlDune__exe__Main.fun_612
0002e3f3      *(arg2 - 8) = arg2 + 8
0002e425      if (camlStdlib__List.equal_875(camlStdlib__List.map2_392(rdi_2, arg2 - 0x20, data_91170, arg1, arg2 - 0x28), data_9ee10, &camlDune__exe__Main.95, arg1, arg2 - 0x28) == 1)
0002e451          data_93648
0002e458          camlStdlib.output_string_253("Incorrect!\n")
0002e435      else
0002e435          data_93648
0002e43c          camlStdlib.output_string_253("Correct!\n")
0002e466      return 1
```

It seems like our decompiler is _really_ struggling with this, but we can start
to understand a bit of the control flow. Switching Binary Ninja to Medium Level IL
actually helped a bit here:

```
   6 @ 0002e24f  caml_initialize(&data_91180, &data_91118)
   7 @ 0002e257  caml_alloc1(arg1, arg2)
   8 @ 0002e25c  rsi_1 = arg2 + 8
   9 @ 0002e260  [rsi_1 - 8].q = 0x400
  10 @ 0002e26f  rax_1 = [&data_91180].q
  11 @ 0002e273  [rsi_1].q = rax_1
  12 @ 0002e27d  caml_initialize(&camlDune__exe__Main, rsi_1)
  13 @ 0002e29e  caml_initialize(&data_91160, &camlDune__exe__Main.40)
  14 @ 0002e2bf  caml_initialize(&data_91168, &camlDune__exe__Main.55)
  15 @ 0002e2d1  rax_2 = camlStdlib.$40_196(&camlDune__exe__Main.55, &camlDune__exe__Main.55, arg1, arg2)
  16 @ 0002e2d6  rbx_1 = rax_2
  17 @ 0002e2e0  rax_3 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_1, arg1, arg2)
  18 @ 0002e2e5  rbx_2 = rax_3
  19 @ 0002e2ef  rax_4 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_2, arg1, arg2)
  20 @ 0002e2f4  rbx_3 = rax_4
  21 @ 0002e2fe  rax_5 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_3, arg1, arg2)
  22 @ 0002e303  rbx_4 = rax_5
  23 @ 0002e30d  rax_6 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_4, arg1, arg2)
  24 @ 0002e312  rbx_5 = rax_6
  25 @ 0002e31c  rax_7 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_5, arg1, arg2)
  26 @ 0002e321  rbx_6 = rax_7
  27 @ 0002e32b  rax_8 = camlStdlib.$40_196(&camlDune__exe__Main.55, rbx_6, arg1, arg2)
  28 @ 0002e33b  rsi_2 = rax_8
  29 @ 0002e345  caml_initialize(&data_91170, rsi_2)
  30 @ 0002e366  caml_initialize(&data_91178, &camlDune__exe__Main.95)
  31 @ 0002e36e  rax_9 = 1
  32 @ 0002e373  rax_10 = camlStdlib.read_line_396()
  33 @ 0002e378  rax_11 = camlStdlib__Bytes.to_seq_620(rax_10, arg1, arg2)
  34 @ 0002e37d  rax_12 = camlStdlib__List.of_seq_1022(rax_11, arg1, arg2)
  35 @ 0002e382  rbx_7 = rax_12
  36 @ 0002e385  caml_alloc1(arg1, arg2)
  37 @ 0002e38a  rax_13 = arg2 + 8
  38 @ 0002e38e  var_8_1 = rax_13
  39 @ 0002e392  [rax_13 - 8].q = 0x400
  40 @ 0002e39a  [rax_13].q = 1
  41 @ 0002e3af  rax_14 = camlStdlib__List.map2_392(&camlDune__exe__Main.40, &data_91138, rbx_7, arg1, arg2)
  42 @ 0002e3b4  rdi_1 = rax_14
  43 @ 0002e3b7  r15 = arg2 - 0x28
  44 @ 0002e3bb  rdi_2 = caml_allocN(arg1, r15)
  45 @ 0002e3c0  rax_15 = r15 + 8
  46 @ 0002e3c4  [rax_15 - 8].q = 0x10f7
  47 @ 0002e3d3  [rax_15].q = caml_curry2
  48 @ 0002e3e0  [rax_15 + 8].q = 0x200000000000007
  49 @ 0002e3eb  [rax_15 + 0x10].q = camlDune__exe__Main.fun_612
  50 @ 0002e3ef  rbx_8 = var_8_1
  51 @ 0002e3f3  [rax_15 + 0x18].q = rbx_8
  52 @ 0002e3fe  rbx_9 = [&data_91170].q
  53 @ 0002e402  rax_16 = camlStdlib__List.map2_392(rdi_2, rax_15, rbx_9, arg1, r15)
  54 @ 0002e407  rdi_3 = rax_16
  55 @ 0002e418  rax_17 = [&data_9ee10].q
  56 @ 0002e41c  rax_18 = camlStdlib__List.equal_875(rdi_3, rax_17, &camlDune__exe__Main.95, arg1, r15)
  57 @ 0002e425  if (rax_18 == 1) then 58 @ 0x2e451 else 61 @ 0x2e435

  58 @ 0002e451  rax_20 = [&data_93648].q
  59 @ 0002e458  camlStdlib.output_string_253("Incorrect!\n")
  60 @ 0002e458  goto 64 @ 0x2e45d

  61 @ 0002e435  rax_19 = [&data_93648].q
  62 @ 0002e43c  camlStdlib.output_string_253("Correct!\n")
  63 @ 0002e441  goto 64 @ 0x2e45d
```

Here, we see that we're reading in a flag from standard input, and converting it
to what seems like a list of bytes. Next, we call List.map2 on it, followed by
some other stuff. Then, we call List.map2 again, and then a List.equal call.

## Dynamically Reversing

At this point, this is going to be tough to go through. Let's analyze this dynamically
instead!

### Testing Inputs

To start, let's see how the program behaves:

```console
> ./camel
squ1rrel{test}
Fatal error: exception Invalid_argument("List.map2")
```

Interesting.

If we look at the OCaml documentation for [List](https://ocaml.org/manual/5.3/api/List.html), we see:

> val map2 : ('a -> 'b -> 'c) -> 'a list -> 'b list -> 'c list  
map2 f [a1; ...; an] [b1; ...; bn] is [f a1 b1; ...; f an bn].  
**Raises Invalid_argument if the two lists are determined to have different lengths.**

(emphasis mine)

Let's try a longer flag:

```console
> echo 'squ1rrel{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}' | ./camel
Incorrect!
```

Okay, so this is likely the correct length of our flag. Now, how does this get processed?

## A Crash Course in OCaml

More specifically, what it ends up getting compiled to.

OCaml uses a few different tricks for representing its datatypes. I'll cover these
mainly as they become relevant, but one key representation to understand before
jumping in is how OCaml stores values. [This blog post](https://dev.realworldocaml.org/runtime-memory-layout.html) gives a really good overview of the general value representations. For now,
the most important part is **integer tagging**.

At runtime, OCaml "boxes" all integers by storing them as the raw value `2*x+1`. This allows us
to read the upper 63 bits as the integer value, while the low bit is always set to `1`. By doing this,
we're able to know that we're looking at an integer, and not some other primitive.

Let's start `gdb`ing this binary! We'll set a breakpoint at `camlDune__exe__Main.entry` and work our way through

```console
pwndbg> b camlDune__exe__Main.entry
Breakpoint 1 at 0x2e220
pwndbg> r
Starting program: /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/rev/camel
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x0000555555582220 in camlDune__exe__Main.entry ()

(many, many, `ni`s later)

pwndbg>
0x0000555555582373 in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  1
 RBX  0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
 RCX  4
 RDX  0x7ffff7c6f0e8 ◂— 0
 RDI  0x5555555e5178 (camlDune__exe__Main+32) —▸ 0x5555555e51d0 (camlDune__exe__Main.95) ◂— 0x163d5
 RSI  0x5555555e51d0 (camlDune__exe__Main.95) ◂— 0x163d5
 R8   0x5555555e99b0 (camlStdlib__Obj.data_begin+448) —▸ 0x555555581e50 (caml_curry3) ◂— sub r15, 0x30
 R9   0x5555555e9990 (camlStdlib__Obj.data_begin+416) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 R10  0x555555623498 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
 R12  0x5555555eee90 (camlStdlib__List.data_begin+1904) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 R13  1
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dff900 ◂— 0x800
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
*RIP  0x555555582373 (camlDune__exe__Main.entry+339) ◂— call camlStdlib.read_line_396
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x55555558235f <camlDune__exe__Main.entry+319>    mov    rbx, rsp                        RBX => 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
   0x555555582362 <camlDune__exe__Main.entry+322>    mov    rsp, qword ptr [r14 + 0x40]     RSP, [0x55555560a4e0] => 0x7fffffffe860 —▸ 0x55555561b5f0 ◂— 0x5555556235f8
   0x555555582366 <camlDune__exe__Main.entry+326>    call   caml_initialize             <caml_initialize>

   0x55555558236b <camlDune__exe__Main.entry+331>    mov    rsp, rbx     RSP => 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
   0x55555558236e <camlDune__exe__Main.entry+334>    mov    eax, 1       EAX => 1
 ► 0x555555582373 <camlDune__exe__Main.entry+339>    call   camlStdlib.read_line_396    <camlStdlib.read_line_396>
        rdi: 0x5555555e5178 (camlDune__exe__Main+32) —▸ 0x5555555e51d0 (camlDune__exe__Main.95) ◂— 0x163d5
        rsi: 0x5555555e51d0 (camlDune__exe__Main.95) ◂— 0x163d5
        rdx: 0x7ffff7c6f0e8 ◂— 0
        rcx: 4

   0x555555582378 <camlDune__exe__Main.entry+344>    call   camlStdlib__Bytes.to_seq_620 <camlStdlib__Bytes.to_seq_620>

   0x55555558237d <camlDune__exe__Main.entry+349>    call   camlStdlib__List.of_seq_1022 <camlStdlib__List.of_seq_1022>

   0x555555582382 <camlDune__exe__Main.entry+354>    mov    rbx, rax
   0x555555582385 <camlDune__exe__Main.entry+357>    call   caml_alloc1                 <caml_alloc1>

   0x55555558238a <camlDune__exe__Main.entry+362>    lea    rax, [r15 + 8]
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rbx rsp 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
01:0008│         0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│         0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│         0x555555623610 ◂— 0
04:0020│         0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│         0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— ...
06:0030│         0x555555623628 ◂— 0
07:0038│         0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x555555582373 camlDune__exe__Main.entry+339
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

Now, we're about to call `read_line`. We'll continue stepping until we make the List.

```
pwndbg>
0x0000555555582382 in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x7fffe7dfea90 ◂— 0xe7
*RBX  0x7fffe7dff7b8 ◂— 0xe3
 RCX  0x51
*RDX  0x51
*RDI  0xe7
*RSI  1
 R8   0
 R9   0
*R10  0x555555623480 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— test al, 1
*R12  0x7fffe7dfeac0 ◂— 0xfb
*R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
*R15  0x7fffe7dfea88 ◂— 0x800
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
*RIP  0x555555582382 (camlDune__exe__Main.entry+354) ◂— mov rbx, rax
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x55555558236b <camlDune__exe__Main.entry+331>    mov    rsp, rbx     RSP => 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
   0x55555558236e <camlDune__exe__Main.entry+334>    mov    eax, 1       EAX => 1
   0x555555582373 <camlDune__exe__Main.entry+339>    call   camlStdlib.read_line_396    <camlStdlib.read_line_396>

   0x555555582378 <camlDune__exe__Main.entry+344>    call   camlStdlib__Bytes.to_seq_620 <camlStdlib__Bytes.to_seq_620>

   0x55555558237d <camlDune__exe__Main.entry+349>    call   camlStdlib__List.of_seq_1022 <camlStdlib__List.of_seq_1022>

 ► 0x555555582382 <camlDune__exe__Main.entry+354>    mov    rbx, rax     RBX => 0x7fffe7dfea90 ◂— 0xe7
   0x555555582385 <camlDune__exe__Main.entry+357>    call   caml_alloc1                 <caml_alloc1>

   0x55555558238a <camlDune__exe__Main.entry+362>    lea    rax, [r15 + 8]
   0x55555558238e <camlDune__exe__Main.entry+366>    mov    qword ptr [rsp], rax
   0x555555582392 <camlDune__exe__Main.entry+370>    mov    qword ptr [rax - 8], 0x400
   0x55555558239a <camlDune__exe__Main.entry+378>    mov    qword ptr [rax], 1
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f8 —▸ 0x555555597c7b (camlStdlib__Bytes.entry+475) ◂— lea rdi, [rip + 0x5bfb6]
01:0008│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│     0x555555623610 ◂— 0
04:0020│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— ...
06:0030│     0x555555623628 ◂— 0
07:0038│     0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x555555582382 camlDune__exe__Main.entry+354
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

## You called?

Now, we need to understand the calling convention OCaml uses. When we put this binary into Binary Ninja,
the decompiler becomes very confused. That's because C and OCaml use very different calling conventions!

The C calling convention that Binary Ninja expects (by default) is the System V ABI, which passes parameters
in `rdi, rsi, rdx, rcx, r8, r9`, then on the stack. Values are returned in `rax`.

However, OCaml uses a different calling convention, which I found at https://stackoverflow.com/questions/11322163/ocaml-calling-convention-is-this-an-accurate-summary.

> The first 10 integer and pointer arguments are passed in the registers rax, rbx, rdi, rsi, rdx, rcx, r8, r9, r10 and r11  
  ...  
  The return value is passed back in rax if it is an integer or pointer, and in xmm0 if it is a float

Thus, we know our return value is in `rax`. This calling convention will come in useful soon.

Let's take a look at the List that should be returned! We notice that `rax` is a pointer,
which should point to a List object. This object will have a value, and a next pointer,
forming a linked list in memory.

```
pwndbg> x/16bx $rax
0x7fffe7dfea90:	0xe7	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffe7dfea98:	0xb8	0xf7	0xdf	0xe7	0xff	0x7f	0x00	0x00
```

We see here that we have our value, `0xe7`, and a pointer `0x7fffe7dff7`. However,
`0xe7` definitely isn't a character we entered! Remember, though, that we box integer
values in memory, so `0xe7` actually corresponds to:

```
pwndbg> p/c 0xe7>>1
$1 = 115 's'
```

the first character of our flag. Now, we can walk the linked list, knowing where
the next node is:

```
pwndbg> x/16bx 0x7fffe7dff7b8
0x7fffe7dff7b8:	0xe3	0x00	0x00	0x00	0x00	0x00	0x00	0x00    # boxed value = 0xe3
0x7fffe7dff7c0:	0x08	0xf7	0xdf	0xe7	0xff	0x7f	0x00	0x00    # next = 0x7fffe7dff708
pwndbg> p/c 0xe3>>1
$2 = 113 'q'

pwndbg> x/16bx 0x7fffe7dff708
0x7fffe7dff708:	0xeb	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffe7dff710:	0x20	0xf7	0xdf	0xe7	0xff	0x7f	0x00	0x00
pwndbg> p/c 0xeb>>1
$3 = 117 'u'
```

(and so on).

Let's take a look at what the program does with this list, though. We'll step
ahead to the `List.map2` call:

```
pwndbg>
0x00005555555823af in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RBX  0x7fffe7dfea90 ◂— 0xe7
 RCX  0x51
 RDX  0x51
 RDI  0x5555555e5798 (camlDune__exe__Main.40) ◂— 0x14f
 RSI  1
 R8   0
 R9   0
 R10  0x555555623480 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— test al, 1
 R12  0x7fffe7dfeac0 ◂— 0xfb
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfea78 ◂— 0x400
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
*RIP  0x5555555823af (camlDune__exe__Main.entry+399) ◂— call camlStdlib__List.map2_392
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x55555558238e <camlDune__exe__Main.entry+366>    mov    qword ptr [rsp], rax           [0x5555556235f8] <= 0x7fffe7dfea80 ◂— 0
   0x555555582392 <camlDune__exe__Main.entry+370>    mov    qword ptr [rax - 8], 0x400     [0x7fffe7dfea78] <= 0x400
   0x55555558239a <camlDune__exe__Main.entry+378>    mov    qword ptr [rax], 1             [0x7fffe7dfea80] <= 1
   0x5555555823a1 <camlDune__exe__Main.entry+385>    lea    rdi, [rip + 0x633f0]           RDI => 0x5555555e5798 (camlDune__exe__Main.40) ◂— 0x14f
   0x5555555823a8 <camlDune__exe__Main.entry+392>    lea    rax, [rip + 0x62d89]           RAX => 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 ► 0x5555555823af <camlDune__exe__Main.entry+399>    call   camlStdlib__List.map2_392   <camlStdlib__List.map2_392>
        rdi: 0x5555555e5798 (camlDune__exe__Main.40) ◂— 0x14f
        rsi: 1
        rdx: 0x51
        rcx: 0x51

   0x5555555823b4 <camlDune__exe__Main.entry+404>    mov    rdi, rax
   0x5555555823b7 <camlDune__exe__Main.entry+407>    sub    r15, 0x28
   0x5555555823bb <camlDune__exe__Main.entry+411>    call   caml_alloc                  <caml_alloc>

   0x5555555823c0 <camlDune__exe__Main.entry+416>    lea    rax, [r15 + 8]
   0x5555555823c4 <camlDune__exe__Main.entry+420>    mov    qword ptr [rax - 8], 0x10f7
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
01:0008│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│     0x555555623610 ◂— 0
04:0020│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— ...
06:0030│     0x555555623628 ◂— 0
07:0038│     0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x5555555823af camlDune__exe__Main.entry+399
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

Since `pwndbg` isn't aware of the new calling convention, we'll have to understand it ourselves. We know our parameters
are passed in `rax`, `rbx`, and `rdi`; and that `List.map2` takes three arguments from its documentation. We see our flag
list being passed as the second argument. The third parameter also seems like another list, and we can walk it in a similar
manner. However, we see that the `rax` points to `caml_curry2`.

In functional programming, *currying* refers to transforming a multi-argument function into a sequence of functions which
take a single parameter each.

Obligatory XKCD:
![obligatory xkcd](https://imgs.xkcd.com/comics/college_athletes_2x.png)

This tells us that we're likely dealing with some function which has the signature `int -> int -> ???`, taking
two integers and returning a value.

Let's take a leap of faith, and step into `List.map2`. I'm going to show the disassembly from Binary Ninja here, since
it's cleaner than `pwndbg` output and there's a lot we're going to skip over. I've annoted a little bit of the code
to hopefully help explain the control flow.

```
0003a100  int64_t* camlStdlib__List.map2_392(int64_t* arg1, int64_t* arg2 @ rax, int64_t* arg3 @ rbx, int64_t* arg4 @ r14, int64_t arg5 @ r15)

0003a100  4c8d942498feffff   lea     r10, [rsp-0x168 {var_168}]
0003a108  4d3b5628           cmp     r10 {var_168}, qword [r14+0x28]
0003a10c  0f8271010000       jb      0x3a283

// Set up the stack frame, move the function we want to apply to rsi
0003a112  4883ec28           sub     rsp, 0x28
0003a116  4889c6             mov     rsi, rax
// Check if rbx (first arg) is tagged with a pointer.
0003a119  f6c301             test    bl, 0x1
0003a11c  7416               je      0x3a134

// If first arg is an integer, if second arg is a pointer, throw an exception
0003a11e  40f6c701           test    dil, 0x1
0003a122  0f8430010000       je      0x3a258 (throw exception)

// Return 0x1 (boxed integer 0)
0003a128  b801000000         mov     eax, 0x1
0003a12d  4883c428           add     rsp, 0x28
0003a131  c3                 retn     {__return_addr}

// ----------------------------

// Load `next` pointer into rdx
0003a134  488b5308           mov     rdx, qword [rbx+0x8]
// Load value into rax
0003a138  488b03             mov     rax, qword [rbx]
// If end of list, handle different sizes (I think)
0003a13b  f6c201             test    dl, 0x1
0003a13e  7450               je      0x3a190

// Check that second arg is also a pointer
0003a140  40f6c701           test    dil, 0x1
0003a144  0f850e010000       jne     0x3a258 (throw exception)

// End of list check again
0003a14a  488b5f08           mov     rbx, qword [rdi+0x8]
0003a14e  f6c301             test    bl, 0x1
0003a151  0f8401010000       je      0x3a258

// Load value into rbx
0003a157  488b1f             mov     rbx, qword [rdi]
// Move function pointer into rdi
0003a15a  4889f7             mov     rdi, rsi
// apply2(first->value, second->value, function)
0003a15d  e8ae3effff         call    caml_apply2

// Allocate a new node for us
0003a162  4983ef18           sub     r15, 0x18
// Out of space check
0003a166  4d3b3e             cmp     r15, qword [r14]
0003a169  0f820a010000       jb      0x3a279

// Populate new node, and return it
0003a16f  498d5f08           lea     rbx, [r15+0x8]
0003a173  48c743f800080000   mov     qword [rbx-0x8], 0x800
0003a17b  488903             mov     qword [rbx], rax
0003a17e  48c7430801000000   mov     qword [rbx+0x8], 0x1
0003a186  4889d8             mov     rax, rbx
0003a189  4883c428           add     rsp, 0x28
0003a18d  c3                 retn     {__return_addr}
```

Back to `gdb`, we can step forward until we hit `caml_apply2`:

```
pwndbg>
0x000055555558e1bb in camlStdlib__List.map2_392 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0xe7
 RBX  0x14f
 RCX  0x51
 RDX  0x7fffe7dff7b8 ◂— 0xe3
*RDI  0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RSI  0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 R8   0
 R9   0
 R10  0x555555623488 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— test al, 1
 R12  0x7fffe7dfeac0 ◂— 0xfb
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfea78 ◂— 0x400
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235c8 —▸ 0x5555555e57c8 (camlDune__exe__Main.39) ◂— 0x19
*RIP  0x55555558e1bb (camlStdlib__List.map2_392+187) ◂— call caml_apply2
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x55555558e1a7 <camlStdlib__List.map2_392+167>    mov    qword ptr [rsp], rbx            [0x5555556235c8] <= 0x5555555e57c8 (camlDune__exe__Main.39) ◂— 0x19
   0x55555558e1ab <camlStdlib__List.map2_392+171>    mov    qword ptr [rsp + 8], rdx        [0x5555556235d0] <= 0x7fffe7dff7b8 ◂— 0xe3
   0x55555558e1b0 <camlStdlib__List.map2_392+176>    mov    qword ptr [rsp + 0x10], rsi     [0x5555556235d8] <= 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x55555558e1b5 <camlStdlib__List.map2_392+181>    mov    rbx, qword ptr [rdi]            RBX, [camlDune__exe__Main.40] => 0x14f
   0x55555558e1b8 <camlStdlib__List.map2_392+184>    mov    rdi, rsi                        RDI => 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 ► 0x55555558e1bb <camlStdlib__List.map2_392+187>    call   caml_apply2                 <caml_apply2>
        rdi: 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
        rsi: 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
        rdx: 0x7fffe7dff7b8 ◂— 0xe3
        rcx: 0x51

   0x55555558e1c0 <camlStdlib__List.map2_392+192>    mov    qword ptr [rsp + 0x20], rax
   0x55555558e1c5 <camlStdlib__List.map2_392+197>    mov    rax, qword ptr [rsp]
   0x55555558e1c9 <camlStdlib__List.map2_392+201>    mov    rbx, qword ptr [rax]
   0x55555558e1cc <camlStdlib__List.map2_392+204>    mov    rax, qword ptr [rsp + 8]
   0x55555558e1d1 <camlStdlib__List.map2_392+209>    mov    rax, qword ptr [rax]
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235c8 —▸ 0x5555555e57c8 (camlDune__exe__Main.39) ◂— 0x19
01:0008│     0x5555556235d0 —▸ 0x7fffe7dff7b8 ◂— 0xe3
02:0010│     0x5555556235d8 —▸ 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
03:0018│     0x5555556235e0 —▸ 0x7fffe7dff7b8 ◂— 0xe3
04:0020│     0x5555556235e8 ◂— 0xe7
05:0028│     0x5555556235f0 —▸ 0x5555555823b4 (camlDune__exe__Main.entry+404) ◂— mov rdi, rax
06:0030│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
07:0038│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x55555558e1bb camlStdlib__List.map2_392+187
   1   0x5555555823b4 camlDune__exe__Main.entry+404
   2   0x555555581a77 caml_program+247
   3   0x5555555c2ff4 caml_start_program+112
   4   0x5555555c299d caml_startup_common+301
   5   0x5555555c2a0f caml_main+15
   6   0x555555581882 main+18
   7   0x7ffff7cda488 __libc_start_call_main+120
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

We see that we have `0xe7` and `0x147` being passed into `caml_apply2`, as well as
the function `camlDune__exe__Main.data_begin+40` being passed as the function to apply.

Stepping in gives us:

```
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x555555582010 <caml_apply2>       lea    r10, [rsp - 0x148]              R10 => 0x555555623478 ◂— 0
   0x555555582018 <caml_apply2+8>     cmp    r10, qword ptr [r14 + 0x28]     0x555555623478 - 0x55555561b5f0     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x55555558201c <caml_apply2+12>    jb     caml_apply2+72              <caml_apply2+72>

   0x55555558201e <caml_apply2+14>    sub    rsp, 8                       RSP => 0x5555556235b8 (0x5555556235c0 - 0x8)
   0x555555582022 <caml_apply2+18>    mov    rsi, qword ptr [rdi + 8]     RSI, [camlDune__exe__Main.data_begin+48] => 0x200000000000007
   0x555555582026 <caml_apply2+22>    sar    rsi, 0x38
   0x55555558202a <caml_apply2+26>    cmp    rsi, 2                       2 - 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558202e <caml_apply2+30>    jne    caml_apply2+44              <caml_apply2+44>

   0x555555582030 <caml_apply2+32>    mov    rsi, qword ptr [rdi + 0x10]     RSI, [camlDune__exe__Main.data_begin+56] => 0x5555555821c0 (camlDune__exe__Main.fun_615) ◂— xor rax, rbx
   0x555555582034 <caml_apply2+36>    add    rsp, 8                          RSP => 0x5555556235c0 (0x5555556235b8 + 0x8)
   0x555555582038 <caml_apply2+40>    jmp    rsi                         <camlDune__exe__Main.fun_615>
```

`pwndbg` helpfully simulates the execution of these instructions, meaning that we can see exactly how this works. In the end, we jump to `camlDune__exe__Main.fun_615`.
Back to Binary Ninja!

Luckily, this is a very simple function:

```
0002e1c0  int64_t camlDune__exe__Main.fun_615(int64_t arg1 @ rax, int64_t arg2 @ rbx) __pure

0002e1c0  4831d8             xor     rax, rbx
0002e1c3  4883c801           or      rax, 0x1
0002e1c7  c3                 retn     {__return_addr}
```

This takes two values, and returns `(a ^ b) | 1`.

The attentive reader may notice something interesting: how do we reverse `| 1`?

The real answer is: we don't. This is where value boxing again appears. Remember that
if we have two raw integers $x$ and $y$, the boxed representations $b_x$ and $b_y$ are $(x << 1) | 1$ and $(y << 1) | 1$, respectively.
This function does not receive $x$ and $y$, but rather $b_x$ and $b_y$. Thus, when we perform the bitwise XOR,
bits 63 through 1 XOR as normal to give us $(x \textasciicircum y) << 1$. However, since our low bits are both `1`, we end up XORing to `0`,
meaning that we lose our tag bit. Thus, we need to `OR` with `1` again to restore this bit.

Thus, our first call XORs the flag with a key.

Next, we need to understand the second `List.map2`. Let's skip past the first one,
since we already know what is happening. As we go past it, we can check out the return value:

```
pwndbg> ni
0x00005555555823b4 in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x7fffe7dfe6c0 ◂— 0x1a9
*RBX  0x7fffe7dfea68 ◂— 0xfb
 RCX  0x51
*RDX  1
*RDI  0x1a9
 RSI  1
 R8   0
 R9   0
*R10  0x555555623440 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
*R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
*R15  0x7fffe7dfe6b8 ◂— 0x800
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
*RIP  0x5555555823b4 (camlDune__exe__Main.entry+404) ◂— mov rdi, rax
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x555555582392 <camlDune__exe__Main.entry+370>    mov    qword ptr [rax - 8], 0x400     [0x7fffe7dfea78] <= 0x400
   0x55555558239a <camlDune__exe__Main.entry+378>    mov    qword ptr [rax], 1             [0x7fffe7dfea80] <= 1
   0x5555555823a1 <camlDune__exe__Main.entry+385>    lea    rdi, [rip + 0x633f0]           RDI => 0x5555555e5798 (camlDune__exe__Main.40) ◂— 0x14f
   0x5555555823a8 <camlDune__exe__Main.entry+392>    lea    rax, [rip + 0x62d89]           RAX => 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x5555555823af <camlDune__exe__Main.entry+399>    call   camlStdlib__List.map2_392   <camlStdlib__List.map2_392>

 ► 0x5555555823b4 <camlDune__exe__Main.entry+404>    mov    rdi, rax      RDI => 0x7fffe7dfe6c0 ◂— 0x1a9
   0x5555555823b7 <camlDune__exe__Main.entry+407>    sub    r15, 0x28     R15 => 0x7fffe7dfe690 (0x7fffe7dfe6b8 - 0x28)
   0x5555555823bb <camlDune__exe__Main.entry+411>    call   caml_alloc                  <caml_alloc>

   0x5555555823c0 <camlDune__exe__Main.entry+416>    lea    rax, [r15 + 8]
   0x5555555823c4 <camlDune__exe__Main.entry+420>    mov    qword ptr [rax - 8], 0x10f7
   0x5555555823cc <camlDune__exe__Main.entry+428>    lea    rbx, [rip - 0x493]              RBX => 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
01:0008│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│     0x555555623610 ◂— 0
04:0020│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— ...
06:0030│     0x555555623628 ◂— 0
07:0038│     0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x5555555823b4 camlDune__exe__Main.entry+404
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/16bx $rax
0x7fffe7dfe6c0:	0xa9	0x01	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffe7dfe6c8:	0x68	0xea	0xdf	0xe7	0xff	0x7f	0x00	0x00
pwndbg> p/x 0x01a9 >> 1
$1 = 0xd4
pwndbg> p/x (0xe7 >> 1) ^ (0x14f >> 1)
$2 = 0xd4
pwndbg>
```

which shows our actual value matches our expectations.

## The Two `List.map2`s

```
pwndbg>
0x0000555555582402 in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
*RBX  0x7fffe7dff908 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RCX  0x51
 RDX  1
 RDI  0x7fffe7dfe6c0 ◂— 0x1a9
 RSI  1
 R8   0
 R9   0
 R10  0x555555623440 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
 R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfe690 ◂— 0x10f7
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
*RIP  0x555555582402 (camlDune__exe__Main.entry+482) ◂— call camlStdlib__List.map2_392
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x5555555823eb <camlDune__exe__Main.entry+459>    mov    qword ptr [rax + 0x10], rbx     [0x7fffe7dfe6a8] <= 0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
   0x5555555823ef <camlDune__exe__Main.entry+463>    mov    rbx, qword ptr [rsp]            RBX, [0x5555556235f8] => 0x7fffe7dfea80 ◂— 1
   0x5555555823f3 <camlDune__exe__Main.entry+467>    mov    qword ptr [rax + 0x18], rbx     [0x7fffe7dfe6b0] <= 0x7fffe7dfea80 ◂— 1
   0x5555555823f7 <camlDune__exe__Main.entry+471>    lea    rbx, [rip + 0x62d5a]            RBX => 0x5555555e5158 (camlDune__exe__Main) —▸ 0x7fffe7dffc50 —▸ 0x5555555e5118 (camlDune__exe__Main.data_begin+8) ◂— ...
   0x5555555823fe <camlDune__exe__Main.entry+478>    mov    rbx, qword ptr [rbx + 0x18]     RBX, [camlDune__exe__Main+24] => 0x7fffe7dff908 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 ► 0x555555582402 <camlDune__exe__Main.entry+482>    call   camlStdlib__List.map2_392   <camlStdlib__List.map2_392>
        rdi: 0x7fffe7dfe6c0 ◂— 0x1a9
        rsi: 1
        rdx: 1
        rcx: 0x51

   0x555555582407 <camlDune__exe__Main.entry+487>    mov    rdi, rax
   0x55555558240a <camlDune__exe__Main.entry+490>    lea    rbx, [rip + 0x62dbf]            RBX => 0x5555555e51d0 (camlDune__exe__Main.95)
   0x555555582411 <camlDune__exe__Main.entry+497>    lea    rax, [rip + 0x709c0]            RAX => 0x5555555f2dd8 (camlStdlib__Int)
   0x555555582418 <camlDune__exe__Main.entry+504>    mov    rax, qword ptr [rax + 0x38]
   0x55555558241c <camlDune__exe__Main.entry+508>    call   camlStdlib__List.equal_875  <camlStdlib__List.equal_875>
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
01:0008│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│     0x555555623610 ◂— 0
04:0020│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— ...
06:0030│     0x555555623628 ◂— 0
07:0038│     0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x555555582402 camlDune__exe__Main.entry+482
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

With our experience from the first function call, we can quickly piece together what's happening
in the second. `rdi` has the result of our previous XOR, while `rbx` has a new list from memory.
Let's take a look at the list that `rbx` points to:

```
pwndbg> x/16bx $rbx
0x7fffe7dff908:	0x60	0x57	0x5e	0x55	0x55	0x55	0x00	0x00
0x7fffe7dff910:	0x20	0xf9	0xdf	0xe7	0xff	0x7f	0x00	0x00
```

This isn't an integer list anymore... it's a list with another pointer! Let's look
at what is at that address:

```
pwndbg> x/16bx 0x5555555e5760
0x5555555e5760:	0xad	0x01	0x00	0x00	0x00	0x00	0x00	0x00
0x5555555e5768:	0x80	0x57	0x5e	0x55	0x55	0x55	0x00	0x00
```

At first glance, this seems to be a list of list of integers. However, if we check
the next pointer, we actually see:

```
pwndbg> x/16bx 0x5555555e5780
0x5555555e5780:	0x76	0x5a	0x71	0x56	0x44	0x65	0x51	0x64
0x5555555e5788:	0x70	0x55	0x00	0x00	0x00	0x00	0x00	0x05
```

which is string data. Thus, we're not working with a list of lists, but rather
a list of structures, which contain an integer and a string.

Let's continue into the `map` call, following a similar process until we get to the `apply` call.

```
pwndbg>
0x000055555558e1bb in camlStdlib__List.map2_392 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RBX  0x1a9
 RCX  0x51
 RDX  0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
*RDI  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RSI  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 R8   0
 R9   0
 R10  0x555555623488 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
 R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfe690 ◂— 0x10f7
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235c8 —▸ 0x7fffe7dfea68 ◂— 0xfb
*RIP  0x55555558e1bb (camlStdlib__List.map2_392+187) ◂— call caml_apply2
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x55555558e1a7 <camlStdlib__List.map2_392+167>    mov    qword ptr [rsp], rbx            [0x5555556235c8] <= 0x7fffe7dfea68 ◂— 0xfb
   0x55555558e1ab <camlStdlib__List.map2_392+171>    mov    qword ptr [rsp + 8], rdx        [0x5555556235d0] <= 0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
   0x55555558e1b0 <camlStdlib__List.map2_392+176>    mov    qword ptr [rsp + 0x10], rsi     [0x5555556235d8] <= 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x55555558e1b5 <camlStdlib__List.map2_392+181>    mov    rbx, qword ptr [rdi]            RBX, [0x7fffe7dfe6c0] => 0x1a9
   0x55555558e1b8 <camlStdlib__List.map2_392+184>    mov    rdi, rsi                        RDI => 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 ► 0x55555558e1bb <camlStdlib__List.map2_392+187>    call   caml_apply2                 <caml_apply2>
        rdi: 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
        rsi: 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
        rdx: 0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
        rcx: 0x51

   0x55555558e1c0 <camlStdlib__List.map2_392+192>    mov    qword ptr [rsp + 0x20], rax
   0x55555558e1c5 <camlStdlib__List.map2_392+197>    mov    rax, qword ptr [rsp]
   0x55555558e1c9 <camlStdlib__List.map2_392+201>    mov    rbx, qword ptr [rax]
   0x55555558e1cc <camlStdlib__List.map2_392+204>    mov    rax, qword ptr [rsp + 8]
   0x55555558e1d1 <camlStdlib__List.map2_392+209>    mov    rax, qword ptr [rax]
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235c8 —▸ 0x7fffe7dfea68 ◂— 0xfb
01:0008│     0x5555556235d0 —▸ 0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
02:0010│     0x5555556235d8 —▸ 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
03:0018│     0x5555556235e0 —▸ 0x7fffe7dfea68 ◂— 0xfb
04:0020│     0x5555556235e8 ◂— 0x1a9
05:0028│     0x5555556235f0 —▸ 0x555555582407 (camlDune__exe__Main.entry+487) ◂— mov rdi, rax
06:0030│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
07:0038│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x55555558e1bb camlStdlib__List.map2_392+187
   1   0x555555582407 camlDune__exe__Main.entry+487
   2   0x555555581a77 caml_program+247
   3   0x5555555c2ff4 caml_start_program+112
   4   0x5555555c299d caml_startup_common+301
   5   0x5555555c2a0f caml_main+15
   6   0x555555581882 main+18
   7   0x7ffff7cda488 __libc_start_call_main+120
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

When we're about to call `apply`, we see our two arguments are:

1. `rax` = the struct from before
2. `rbx` = `0x1a9`, our result from XORing.

`rdi` again points to `curry_2`, so let's step through that:

```
pwndbg>
0x0000555555582038 in caml_apply2 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RBX  0x1a9
 RCX  0x51
 RDX  0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
 RDI  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RSI  0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
 R8   0
 R9   0
 R10  0x555555623478 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
 R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfe690 ◂— 0x10f7
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
*RSP  0x5555556235c0 —▸ 0x55555558e1c0 (camlStdlib__List.map2_392+192) ◂— mov qword ptr [rsp + 0x20], rax
*RIP  0x555555582038 (caml_apply2+40) ◂— jmp rsi
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x555555582026 <caml_apply2+22>                    sar    rsi, 0x38
   0x55555558202a <caml_apply2+26>                    cmp    rsi, 2                       2 - 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558202e <caml_apply2+30>                    jne    caml_apply2+44              <caml_apply2+44>

   0x555555582030 <caml_apply2+32>                    mov    rsi, qword ptr [rdi + 0x10]     RSI, [0x7fffe7dfe6a8] => 0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
   0x555555582034 <caml_apply2+36>                    add    rsp, 8                          RSP => 0x5555556235c0 (0x5555556235b8 + 0x8)
 ► 0x555555582038 <caml_apply2+40>                    jmp    rsi                         <camlDune__exe__Main.fun_612>
    ↓
   0x5555555821d0 <camlDune__exe__Main.fun_612>       lea    r10, [rsp - 0x148]              R10 => 0x555555623478 ◂— 0
   0x5555555821d8 <camlDune__exe__Main.fun_612+8>     cmp    r10, qword ptr [r14 + 0x28]     0x555555623478 - 0x55555561b5f0     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x5555555821dc <camlDune__exe__Main.fun_612+12>    jb     camlDune__exe__Main.fun_612+57 <camlDune__exe__Main.fun_612+57>

   0x5555555821de <camlDune__exe__Main.fun_612+14>    sub    rsp, 8       RSP => 0x5555556235b8 (0x5555556235c0 - 0x8)
   0x5555555821e2 <camlDune__exe__Main.fun_612+18>    mov    rsi, rbx     RSI => 0x1a9
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235c0 —▸ 0x55555558e1c0 (camlStdlib__List.map2_392+192) ◂— mov qword ptr [rsp + 0x20], rax
01:0008│     0x5555556235c8 —▸ 0x7fffe7dfea68 ◂— 0xfb
02:0010│     0x5555556235d0 —▸ 0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
03:0018│     0x5555556235d8 —▸ 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
04:0020│     0x5555556235e0 —▸ 0x7fffe7dfea68 ◂— 0xfb
05:0028│     0x5555556235e8 ◂— 0x1a9
06:0030│     0x5555556235f0 —▸ 0x555555582407 (camlDune__exe__Main.entry+487) ◂— mov rdi, rax
07:0038│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x555555582038 caml_apply2+40
   1   0x55555558e1c0 camlStdlib__List.map2_392+192
   2   0x555555582407 camlDune__exe__Main.entry+487
   3   0x555555581a77 caml_program+247
   4   0x5555555c2ff4 caml_start_program+112
   5   0x5555555c299d caml_startup_common+301
   6   0x5555555c2a0f caml_main+15
   7   0x555555581882 main+18
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Back to Binary Ninja again! Again, I've added annotations.

```
// fun_612(struct* arg1 = rax, int arg2 = rbx)
0002e1d0  int64_t camlDune__exe__Main.fun_612(void* arg1, int64_t arg2 @ rbx, void* arg3 @ r14)

0002e1d0  4c8d9424b8feffff   lea     r10, [rsp-0x148 {var_148}]
0002e1d8  4d3b5628           cmp     r10 {var_148}, qword [r14+0x28]
0002e1dc  722b               jb      0x2e209

// Allocate stack frame, store second argument in rsi
0002e1de  4883ec08           sub     rsp, 0x8
0002e1e2  4889de             mov     rsi, rbx
0002e1e5  48893c24           mov     qword [rsp {var_8_1}], rdi
0002e1e9  488b5f18           mov     rbx, qword [rdi+0x18]
0002e1ed  488b1b             mov     rbx, qword [rbx]
0002e1f0  4889f7             mov     rdi, rsi
```

Here, we load a value from `[rdi+0x18]`, and then load a value from that pointer.
If we trace back this value, this is part of a structure that holds the function we
want to apply. We see that this value is assigned during Main:

```
pwndbg>
0x00005555555823ef in camlDune__exe__Main.entry ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RBX  0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
 RCX  0x51
 RDX  1
 RDI  0x7fffe7dfe6c0 ◂— 0x1a9
 RSI  1
 R8   0
 R9   0
 R10  0x555555623440 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
 R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfe690 ◂— 0x10f7
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
*RIP  0x5555555823ef (camlDune__exe__Main.entry+463) ◂— mov rbx, qword ptr [rsp]
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x5555555823d3 <camlDune__exe__Main.entry+435>    mov    qword ptr [rax], rbx            [0x7fffe7dfe698] <= 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x5555555823d6 <camlDune__exe__Main.entry+438>    movabs rbx, 0x200000000000007          RBX => 0x200000000000007
   0x5555555823e0 <camlDune__exe__Main.entry+448>    mov    qword ptr [rax + 8], rbx        [0x7fffe7dfe6a0] <= 0x200000000000007
   0x5555555823e4 <camlDune__exe__Main.entry+452>    lea    rbx, [rip - 0x21b]              RBX => 0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
   0x5555555823eb <camlDune__exe__Main.entry+459>    mov    qword ptr [rax + 0x10], rbx     [0x7fffe7dfe6a8] <= 0x5555555821d0 (camlDune__exe__Main.fun_612) ◂— lea r10, [rsp - 0x148]
 ► 0x5555555823ef <camlDune__exe__Main.entry+463>    mov    rbx, qword ptr [rsp]            RBX, [0x5555556235f8] => 0x7fffe7dfea80 ◂— 1
   0x5555555823f3 <camlDune__exe__Main.entry+467>    mov    qword ptr [rax + 0x18], rbx     [0x7fffe7dfe6b0] <= 0x7fffe7dfea80 ◂— 1
   0x5555555823f7 <camlDune__exe__Main.entry+471>    lea    rbx, [rip + 0x62d5a]            RBX => 0x5555555e5158 (camlDune__exe__Main) —▸ 0x7fffe7dffc50 —▸ 0x5555555e5118 (camlDune__exe__Main.data_begin+8) ◂— ...
   0x5555555823fe <camlDune__exe__Main.entry+478>    mov    rbx, qword ptr [rbx + 0x18]     RBX, [camlDune__exe__Main+24] => 0x7fffe7dff908 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
   0x555555582402 <camlDune__exe__Main.entry+482>    call   camlStdlib__List.map2_392   <camlStdlib__List.map2_392>

   0x555555582407 <camlDune__exe__Main.entry+487>    mov    rdi, rax
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
01:0008│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
02:0010│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
03:0018│     0x555555623610 ◂— 0
04:0020│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
05:0028│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— ...
06:0030│     0x555555623628 ◂— 0
07:0038│     0x555555623630 ◂— 1
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x5555555823ef camlDune__exe__Main.entry+463
   1   0x555555581a77 caml_program+247
   2   0x5555555c2ff4 caml_start_program+112
   3   0x5555555c299d caml_startup_common+301
   4   0x5555555c2a0f caml_main+15
   5   0x555555581882 main+18
   6   0x7ffff7cda488 __libc_start_call_main+120
   7   0x7ffff7cda54c __libc_start_main+140
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

If we look through the code of `main` more, we see that the value at `[rsp]` is set earlier:

```
0002e385  call    caml_alloc1
0002e38a  lea     rax, [r15+0x8]
0002e38e  mov     qword [rsp {var_8_1}], rax
0002e392  mov     qword [rax-0x8], 0x400
0002e39a  mov     qword [rax], 0x1
0002e3a1  lea     rdi, [rel camlDune__exe__Main.40]
0002e3a8  lea     rax, [rel data_91138]
```

where we allocate 16 bytes, and save the raw value 0x1 (boxed integer 0x0) into its field. Thus, this is probably some sort of state that we're passing along.
This seems to be closure-like behavior, where we have a variable that is attached along with the function. Now, we're able to use this between function calls.

Coming back to `camlDune__exe__Main.fun_612`, we 

```
// fun_612(struct* arg1 = rax, int arg2 = rbx)
0002e1d0  int64_t camlDune__exe__Main.fun_612(void* arg1, int64_t arg2 @ rbx, void* arg3 @ r14)

0002e1d0  4c8d9424b8feffff   lea     r10, [rsp-0x148 {var_148}]
0002e1d8  4d3b5628           cmp     r10 {var_148}, qword [r14+0x28]
0002e1dc  722b               jb      0x2e209

// Allocate stack frame, store second argument in rsi
0002e1de  4883ec08           sub     rsp, 0x8
0002e1e2  4889de             mov     rsi, rbx
0002e1e5  48893c24           mov     qword [rsp {var_8_1}], rdi

// Load closure variables
0002e1e9  488b5f18           mov     rbx, qword [rdi+0x18]
// Load first closure variable
0002e1ed  488b1b             mov     rbx, qword [rbx]
0002e1f0  4889f7             mov     rdi, rsi

// rax = struct* arg1
// rbx = closure variable
// rdi = xor'd value
0002e1f3  e8a8feffff         call    camlDune__exe__Main.update_274

// Load closure variables
0002e1f8  488b1c24           mov     rbx, qword [rsp {var_8_1}]
0002e1fc  488b5b18           mov     rbx, qword [rbx+0x18]

// Increment first closure variable (adding 1 to boxed value)
0002e200  48830302           add     qword [rbx], 0x2
0002e204  4883c408           add     rsp, 0x8
0002e208  c3                 retn     {__return_addr}

0002e209  6a22               push    0x22 {var_8_2}
0002e20b  e860080400         call    caml_call_realloc_stack
0002e210  415a               pop     r10 {var_8_2}
0002e212  ebca               jmp     0x2e1de
```

Finally, we just need to understand what `camlDune__exe__Main.update_274` does.
Let's take a look at the general disassembly. The graph view in Binary Ninja
does a great job here, allowing us to visualize the CFG of the function. We start
with a common basic block:

```
// rax = struct* obj
// rbx = boxed closure variable i
// rdi = boxed xor'd value k
camlDune__exe__Main.update_274:

// r8 = obj
0002e0a0  mov     r8, rax
// rsi = obj->value
0002e0a3  mov     rsi, qword [r8]

// rax = unboxed obj->value
0002e0a6  mov     rax, rsi
0002e0a9  sar     rax, 0x1

// rdx = get sign bit of rax
0002e0ac  mov     rdx, rax
0002e0af  shr     rdx, 0x3f

// rcx = unboxed obj->value + sign bit
// : if obj->value >= 0: obj->value
// : if obj->value <  0: obj->value + 1
0002e0b3  mov     rcx, rax
0002e0b6  add     rcx, rdx
0002e0b9  and     rcx, 0xfffffffffffffffe
0002e0bd  sub     rax, rcx

// rax is equal to ((rcx + sign) & ~1) - rcx
// 1 if rcx % 2 != 0 and 0 otherwise

// rax = rax << 1 + 1: re-box rax
0002e0c0  lea     rax, [rax+rax+0x1]

// this is a rather silly set of comparisons that i'm surprised the compiler
// didn't write better ngl
// rax = 1 if boxed rax = boxed 0 else 0
0002e0c5  cmp     rax, 0x1
0002e0c9  sete    al
// (sign extend byte to qword)
0002e0cc  movzx   rax, al
// box the comparison result...
0002e0d0  lea     rax, [rax+rax+0x1]
// and then compare to boxed 0 (why LOL)
0002e0d5  cmp     rax, 0x1
// if the comparison is true... which means that rax was ORIGINALLY not zero, jump
// thus, we jump if rcx % 2 != 0
0002e0d9  je      0x2e0ec
```

We now have an if/else statement. If `rax` was `1` (`obj->value` is an odd negative value):

```
// rax = boxed -k
0002e0ec  mov     eax, 0x2
0002e0f1  sub     rax, rdi
// unbox rax
0002e0f4  sar     rax, 0x1

// rsi originally was boxed obj->value
// rsi - 1 will be unboxed obj->value * 2
0002e0f7  dec     rsi
// rsi * rax = 2 * (unboxed -k) * (unboxed obj->value)
0002e0fa  imul    rsi, rax
// rsi * rax + 1 = 2 * (unboxed -k) * (unboxed obj->value) + 1
// thus rsi = boxed (-k * obj->value)
0002e0fe  inc     rsi
```

otherwise:

```
// unbox k
0002e0db  sar     rdi, 0x1
// rsi = k * obj->value by same logic as before
0002e0de  dec     rsi
0002e0e1  imul    rsi, rdi
0002e0e5  inc     rsi
0002e0e8  jmp     0x2e101
```

Our control flow now rejoins again:

```
// rax = obj->string
0002e101  mov     rax, qword [r8+0x8]
// rdi = string->length in words (shifting by 10 to skip 2 color and 8 tag bits)
0002e105  mov     rdi, qword [rax-0x8]
0002e109  shr     rdi, 0xa
// one word is 8 bytes, get size - 1
0002e10d  lea     rcx, [rdi*8-0x1]
// load byte at obj->string[obj->string.size - 1]: this is our padding amount
0002e115  movzx   rax, byte [rax+rcx]
// subtract off to get the actual string length
0002e11a  sub     rcx, rax
// fix sign bit shenanigans
0002e11d  shl     rcx, 0x1
0002e120  sar     rcx, 0x1
// unbox closure variable i
0002e123  mov     rax, rbx
0002e126  sar     rax, 0x1
0002e129  test    rcx, rcx
0002e12c  je      0x2e138
```

This is then followed by a division by zero check, which we'll skip.

From x86 documentation, we know that `idiv` performs:

> Signed divide RDX:RAX by r/m64, with result stored in RAX := Quotient, RDX := Remainder.

Thus, we're using the remainder here.

```
0002e12e  cqo     
0002e130  idiv    rcx
// rdx = i % length
0002e133  jmp     0x2e144
...
// box rdx
0002e144  shl     rdx, 0x1
0002e147  inc     rdx

// rdx = obj->string pointer, unboxed
0002e14a  mov     rax, qword [r8+0x8]
0002e14e  sar     rdx, 0x1
// same thing again, find length of string
0002e151  mov     rbx, qword [rax-0x8]
0002e155  shr     rbx, 0xa
0002e159  lea     rbx, [rbx*8-0x1]
0002e161  movzx   rdi, byte [rax+rbx]
0002e166  sub     rbx, rdi

// index of out bounds check
0002e169  cmp     rbx, rdx
0002e16c  jbe     0x2e1b7

// rax = obj->string[i % length]
0002e16e  movzx   rax, byte [rax+rdx]

// box rax
0002e173  lea     rax, [rax+rax+0x1]

// rax = rax + product from earlier
0002e178  lea     rax, [rsi+rax-0x1]

// rbx = obj->tag
0002e17d  mov     rbx, qword [r8+0x10]
0002e181  cmp     rbx, 0x85  (boxed 0x42)
0002e188  je      0x2e1ac

// if (obj->tag == 0x42)
0002e1ac  xor     rax, 0x1b1
0002e1b2  or      rax, 0x1
// return (rax + product from earlier) ^ 0xd8
0002e1b6  retn     {__return_addr}

// else if (obj->tag >= 0x43)
0002e18a  cmp     rbx, 0x87  (boxed 0x43)
0002e191  jl      0x2e1a0

0002e193  xor     rax, 0x179
0002e199  or      rax, 0x1
// return (rax + product from earlier) ^ 0xbc
0002e19d  retn     {__return_addr}

// else

0002e1a0  xor     rax, 0x89
0002e1a6  or      rax, 0x1
// return (rax + product from earlier) ^ 0x44
0002e1aa  retn     {__return_addr}
```

Let's consolidate this all into transpiled Python:

```python
def firstListMap(flag, key):
    return [a^b for a,b in zip(flag, key)]


def update(obj, i, k):
    prod = None
    if obj.value % 2 != 0:
        prod = -k * obj.value
    else:
        prod = k * obj.value
    total = obj.string[i % len(obj.string)] + prod
    if obj.tag == 0x42:
        return total ^ 0xd8
    elif obj.tag >= 0x43:
        return total ^ 0xbc
    else:
        return total ^ 0x44


def secondListMap(objs, ks):
    res = []
    for i in range(len(objs)):
        res.append(update(objs[i], i, ks[i]))


def main():
    l = firstListMap(FLAG, KEY)
    l2 = secondListMap(OBJS, l)
    if l2 == TARGET:
        print('correct!')
```

At this point, we just need to go through and extract each of the strings.

## Scripting `gdb`

It's pretty annoying to have to type the same gdb commands over and over. Let's fix that.

We'll start by extracting the `KEY` that is XOR'd with the flag during our first map. Let's set a
breakpoint at the call to `List.map2`:

```
pwndbg> b camlStdlib__List.map2_392
Breakpoint 1 at 0x3a100
pwndbg> r
Starting program: /home/daniel/Desktop/ctf-2025/squ1rrelctf-2025/rev/camel
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
squ1rrel{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}

Breakpoint 1, 0x000055555558e100 in camlStdlib__List.map2_392 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RBX  0x7fffe7dfea90 ◂— 0xe7
 RCX  0x51
 RDX  0x51
 RDI  0x5555555e5798 (camlDune__exe__Main.40) ◂— 0x14f
 RSI  1
 R8   0
 R9   0
 R10  0x555555623480 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— test al, 1
 R12  0x7fffe7dfeac0 ◂— 0xfb
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfea78 ◂— 0x400
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f0 —▸ 0x5555555823b4 (camlDune__exe__Main.entry+404) ◂— mov rdi, rax
 RIP  0x55555558e100 (camlStdlib__List.map2_392) ◂— lea r10, [rsp - 0x168]
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x55555558e100 <camlStdlib__List.map2_392>       lea    r10, [rsp - 0x168]              R10 => 0x555555623488 ◂— 0
   0x55555558e108 <camlStdlib__List.map2_392+8>     cmp    r10, qword ptr [r14 + 0x28]     0x555555623488 - 0x55555561b5f0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x55555558e10c <camlStdlib__List.map2_392+12>    jb     camlStdlib__List.map2_392+387 <camlStdlib__List.map2_392+387>

   0x55555558e112 <camlStdlib__List.map2_392+18>    sub    rsp, 0x28     RSP => 0x5555556235c8 (0x5555556235f0 - 0x28)
   0x55555558e116 <camlStdlib__List.map2_392+22>    mov    rsi, rax      RSI => 0x5555555e5138 (camlDune__exe__Main.data_begin+40) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x55555558e119 <camlStdlib__List.map2_392+25>    test   bl, 1         0x90 & 0x1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558e11c <camlStdlib__List.map2_392+28>  ✔ je     camlStdlib__List.map2_392+52 <camlStdlib__List.map2_392+52>
    ↓
   0x55555558e134 <camlStdlib__List.map2_392+52>    mov    rdx, qword ptr [rbx + 8]     RDX, [0x7fffe7dfea98] => 0x7fffe7dff7b8 ◂— 0xe3
   0x55555558e138 <camlStdlib__List.map2_392+56>    mov    rax, qword ptr [rbx]         RAX, [0x7fffe7dfea90] => 0xe7
   0x55555558e13b <camlStdlib__List.map2_392+59>    test   dl, 1                        0xb8 & 0x1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558e13e <camlStdlib__List.map2_392+62>  ✔ je     camlStdlib__List.map2_392+144 <camlStdlib__List.map2_392+144>
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f0 —▸ 0x5555555823b4 (camlDune__exe__Main.entry+404) ◂— mov rdi, rax
01:0008│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
02:0010│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
03:0018│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
04:0020│     0x555555623610 ◂— 0
05:0028│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
06:0030│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x5555555929ed (camlStdlib__List.of_seq_dps_1184+45) ◂— ...
07:0038│     0x555555623628 ◂— 0
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x55555558e100 camlStdlib__List.map2_392
   1   0x5555555823b4 camlDune__exe__Main.entry+404
   2   0x555555581a77 caml_program+247
   3   0x5555555c2ff4 caml_start_program+112
   4   0x5555555c299d caml_startup_common+301
   5   0x5555555c2a0f caml_main+15
   6   0x555555581882 main+18
   7   0x7ffff7cda488 __libc_start_call_main+120
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Since this is the first call, we know that the key is passed in as the second argument. Let's start with what we want to
do at each iteration:

```
pwndbg> set $node = $rdi
pwndbg> p/x (*(int64_t*)$node)>>1
$3 = 0xa7
pwndbg> p/x (*(void**)($node+8))
$4 = 0x5555555e57c8
```

Here, we're able to get the value and the next pointer! Now, let's turn this into a `gdb` function:

```
pwndbg> define dumpnode
Type commands for definition of "dumpnode".
End with a line saying just "end".
>p/x (*(int64_t*)$node)>>1
>set $node = *(void**)($node+8)
>p/x $node
>end
```

Now, we can use `dumpnode` and autorepeat to quickly print the entire key:

```
pwndbg> dumpnode
$5 = 0xa7
$6 = 0x5555555e57c8
pwndbg>
$7 = 0xc
$8 = 0x5555555e57e0
pwndbg>
$9 = 0x46
$10 = 0x5555555e57f8
pwndbg>
$11 = 0x21
$12 = 0x5555555e5810
pwndbg>
$13 = 0x22
$14 = 0x5555555e5828
pwndbg>
$15 = 0x85
$16 = 0x5555555e5840
pwndbg>
$17 = 0xc9
$18 = 0x5555555e5858
pwndbg>
$19 = 0x23
$20 = 0x5555555e5870
pwndbg>
$21 = 0x64
$22 = 0x5555555e5888
pwndbg>
$23 = 0x7d
$24 = 0x5555555e58a0
pwndbg>
$25 = 0xb7
$26 = 0x5555555e58d0
pwndbg>
$27 = 0xda
$28 = 0x5555555e58e8
pwndbg>
$29 = 0x9e
$30 = 0x5555555e5900
pwndbg>
$31 = 0x4e
$32 = 0x5555555e5918
pwndbg>
$33 = 0x39
$34 = 0x5555555e5930
pwndbg>
$35 = 0x85
$36 = 0x5555555e5948
pwndbg>
$37 = 0x45
$38 = 0x5555555e5960
pwndbg>
$39 = 0x38
$40 = 0x5555555e5978
pwndbg>
$41 = 0xda
$42 = 0x5555555e5990
pwndbg>
$43 = 0xd2
$44 = 0x5555555e59a8
pwndbg>
$45 = 0xc7
$46 = 0x5555555e59d8
pwndbg>
$47 = 0x80
$48 = 0x5555555e59f0
pwndbg>
$49 = 0x83
$50 = 0x5555555e5a08
pwndbg>
$51 = 0x4a
$52 = 0x5555555e5a20
pwndbg>
$53 = 0x34
$54 = 0x5555555e5a38
pwndbg>
$55 = 0x4
$56 = 0x5555555e5a50
pwndbg>
$57 = 0x83
$58 = 0x5555555e5a68
pwndbg>
$59 = 0x1
$60 = 0x5555555e5a80
pwndbg>
$61 = 0x5d
$62 = 0x5555555e5a98
pwndbg>
$63 = 0x4c
$64 = 0x5555555e5ab0
pwndbg>
$65 = 0x7
$66 = 0x5555555e5260
pwndbg>
$67 = 0x1d
$68 = 0x5555555e5368
pwndbg>
$69 = 0xa9
$70 = 0x5555555e5470
pwndbg>
$71 = 0xad
$72 = 0x5555555e5578
pwndbg>
$73 = 0xa6
$74 = 0x5555555e5688
pwndbg>
$75 = 0xf8
$76 = 0x5555555e57b0
pwndbg>
$77 = 0x29
$78 = 0x5555555e58b8
pwndbg>
$79 = 0xaa
$80 = 0x5555555e59c0
pwndbg>
$81 = 0x94
$82 = 0x5555555e5ac8
pwndbg>
$83 = 0xb1
$84 = 0x1
```

We can quickly convert this into a list:

```python
KEY = [0xa7, 0xc, 0x46, 0x21, 0x22, 0x85, 0xc9, 0x23, 0x64, 0x7d, 0xb7, 0xda, 0x9e, 0x4e, 0x39, 0x85, 0x45, 0x38, 0xda, 0xd2, 0xc7, 0x80, 0x83, 0x4a, 0x34, 0x4, 0x83, 0x1, 0x5d, 0x4c, 0x7, 0x1d, 0xa9, 0xad, 0xa6, 0xf8, 0x29, 0xaa, 0x94, 0xb1]
```

Next, we need to dump the objects. We'll continue to jump to the next call of `List.map2`:

```
pwndbg> c
Continuing.

Breakpoint 1, 0x000055555558e100 in camlStdlib__List.map2_392 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
*RBX  0x7fffe7dff908 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RCX  0x51
*RDX  1
*RDI  0x7fffe7dfe6c0 ◂— 0x1a9
 RSI  1
 R8   0
 R9   0
*R10  0x555555623440 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— 0x197
*R12  0x7fffe7dfe6f0 ◂— 0x199
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
*R15  0x7fffe7dfe690 ◂— 0x10f7
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f0 —▸ 0x555555582407 (camlDune__exe__Main.entry+487) ◂— mov rdi, rax
 RIP  0x55555558e100 (camlStdlib__List.map2_392) ◂— lea r10, [rsp - 0x168]
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x55555558e100 <camlStdlib__List.map2_392>       lea    r10, [rsp - 0x168]              R10 => 0x555555623488 ◂— 0
   0x55555558e108 <camlStdlib__List.map2_392+8>     cmp    r10, qword ptr [r14 + 0x28]     0x555555623488 - 0x55555561b5f0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x55555558e10c <camlStdlib__List.map2_392+12>    jb     camlStdlib__List.map2_392+387 <camlStdlib__List.map2_392+387>

   0x55555558e112 <camlStdlib__List.map2_392+18>    sub    rsp, 0x28     RSP => 0x5555556235c8 (0x5555556235f0 - 0x28)
   0x55555558e116 <camlStdlib__List.map2_392+22>    mov    rsi, rax      RSI => 0x7fffe7dfe698 —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x55555558e119 <camlStdlib__List.map2_392+25>    test   bl, 1         8 & 1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558e11c <camlStdlib__List.map2_392+28>  ✔ je     camlStdlib__List.map2_392+52 <camlStdlib__List.map2_392+52>
    ↓
   0x55555558e134 <camlStdlib__List.map2_392+52>    mov    rdx, qword ptr [rbx + 8]     RDX, [0x7fffe7dff910] => 0x7fffe7dff920 —▸ 0x5555555e5728 (camlDune__exe__Main.44) ◂— 0xa1
   0x55555558e138 <camlStdlib__List.map2_392+56>    mov    rax, qword ptr [rbx]         RAX, [0x7fffe7dff908] => 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
   0x55555558e13b <camlStdlib__List.map2_392+59>    test   dl, 1                        0x20 & 0x1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x55555558e13e <camlStdlib__List.map2_392+62>  ✔ je     camlStdlib__List.map2_392+144 <camlStdlib__List.map2_392+144>
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f0 —▸ 0x555555582407 (camlDune__exe__Main.entry+487) ◂— mov rdi, rax
01:0008│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 1
02:0010│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
03:0018│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
04:0020│     0x555555623610 ◂— 0
05:0028│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
06:0030│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe720 ◂— ...
07:0038│     0x555555623628 ◂— 0
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x55555558e100 camlStdlib__List.map2_392
   1   0x555555582407 camlDune__exe__Main.entry+487
   2   0x555555581a77 caml_program+247
   3   0x5555555c2ff4 caml_start_program+112
   4   0x5555555c299d caml_startup_common+301
   5   0x5555555c2a0f caml_main+15
   6   0x555555581882 main+18
   7   0x7ffff7cda488 __libc_start_call_main+120
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can script this similarly:

```
pwndbg> define walknode2
Type commands for definition of "walknode2".
End with a line saying just "end".
>set $struct = *(void**)$node
>p/x (*(int64_t*)$struct)>>1
>p/s (*(char**)($struct+8))
>p/x (*(int64_t*)($struct+16))>>1
>set $node = *(void**)($node+8)
>p/x $node
>end
pwndbg> set $node = $rbx
pwndbg> walknode2
$91 = 0xd6
$92 = 0x5555555e5780 "vZqVDeQdpU"
$93 = 0x41
$94 = 0x7fffe7dff920
pwndbg>
$95 = 0x50
$96 = 0x5555555e5748 "bN9uKboZWc"
$97 = 0x42
$98 = 0x7fffe7dff968
pwndbg>
$99 = 0xab
$100 = 0x5555555e5710 "QgcA2ih74Y"
$101 = 0x41
$102 = 0x7fffe7dff938
pwndbg>
$103 = 0xb5
$104 = 0x5555555e56d8 "HllqMBG4ej"
$105 = 0x43
$106 = 0x7fffe7dff950
pwndbg>
$107 = 0xac
$108 = 0x5555555e56a0 "6X6iqasroj"
$109 = 0x42
$110 = 0x7fffe7dff980
pwndbg>
$111 = 0xd6
$112 = 0x5555555e5780 "vZqVDeQdpU"
$113 = 0x41
$114 = 0x7fffe7dff998
pwndbg>
$115 = 0x50
$116 = 0x5555555e5748 "bN9uKboZWc"
$117 = 0x42
$118 = 0x7fffe7dff9e0
pwndbg>
$119 = 0xab
$120 = 0x5555555e5710 "QgcA2ih74Y"
$121 = 0x41
$122 = 0x7fffe7dff9b0
pwndbg>
$123 = 0xb5
$124 = 0x5555555e56d8 "HllqMBG4ej"
$125 = 0x43
$126 = 0x7fffe7dff9c8
pwndbg>
$127 = 0xac
$128 = 0x5555555e56a0 "6X6iqasroj"
$129 = 0x42
$130 = 0x7fffe7dff9f8
pwndbg>
$131 = 0xd6
$132 = 0x5555555e5780 "vZqVDeQdpU"
$133 = 0x41
$134 = 0x7fffe7dffa10
pwndbg>
$135 = 0x50
$136 = 0x5555555e5748 "bN9uKboZWc"
$137 = 0x42
$138 = 0x7fffe7dffa58
pwndbg>
$139 = 0xab
$140 = 0x5555555e5710 "QgcA2ih74Y"
$141 = 0x41
$142 = 0x7fffe7dffa28
pwndbg>
$143 = 0xb5
$144 = 0x5555555e56d8 "HllqMBG4ej"
$145 = 0x43
$146 = 0x7fffe7dffa40
pwndbg>
$147 = 0xac
$148 = 0x5555555e56a0 "6X6iqasroj"
$149 = 0x42
$150 = 0x7fffe7dffa70
pwndbg>
$151 = 0xd6
$152 = 0x5555555e5780 "vZqVDeQdpU"
$153 = 0x41
$154 = 0x7fffe7dffa88
pwndbg>
$155 = 0x50
$156 = 0x5555555e5748 "bN9uKboZWc"
$157 = 0x42
$158 = 0x7fffe7dffad0
pwndbg>
$159 = 0xab
$160 = 0x5555555e5710 "QgcA2ih74Y"
$161 = 0x41
$162 = 0x7fffe7dffaa0
pwndbg>
$163 = 0xb5
$164 = 0x5555555e56d8 "HllqMBG4ej"
$165 = 0x43
$166 = 0x7fffe7dffab8
pwndbg>
$167 = 0xac
$168 = 0x5555555e56a0 "6X6iqasroj"
$169 = 0x42
$170 = 0x7fffe7dffae8
pwndbg>
$171 = 0xd6
$172 = 0x5555555e5780 "vZqVDeQdpU"
$173 = 0x41
$174 = 0x7fffe7dffb00
pwndbg>
$175 = 0x50
$176 = 0x5555555e5748 "bN9uKboZWc"
$177 = 0x42
$178 = 0x7fffe7dffb48
pwndbg>
$179 = 0xab
$180 = 0x5555555e5710 "QgcA2ih74Y"
$181 = 0x41
$182 = 0x7fffe7dffb18
pwndbg>
$183 = 0xb5
$184 = 0x5555555e56d8 "HllqMBG4ej"
$185 = 0x43
$186 = 0x7fffe7dffb30
pwndbg>
$187 = 0xac
$188 = 0x5555555e56a0 "6X6iqasroj"
$189 = 0x42
$190 = 0x7fffe7dffb60
pwndbg>
$191 = 0xd6
$192 = 0x5555555e5780 "vZqVDeQdpU"
$193 = 0x41
$194 = 0x7fffe7dffb78
pwndbg>
$195 = 0x50
$196 = 0x5555555e5748 "bN9uKboZWc"
$197 = 0x42
$198 = 0x7fffe7dffbc0
pwndbg>
$199 = 0xab
$200 = 0x5555555e5710 "QgcA2ih74Y"
$201 = 0x41
$202 = 0x7fffe7dffb90
pwndbg>
$203 = 0xb5
$204 = 0x5555555e56d8 "HllqMBG4ej"
$205 = 0x43
$206 = 0x7fffe7dffba8
pwndbg>
$207 = 0xac
$208 = 0x5555555e56a0 "6X6iqasroj"
$209 = 0x42
$210 = 0x7fffe7dffbd8
pwndbg>
$211 = 0xd6
$212 = 0x5555555e5780 "vZqVDeQdpU"
$213 = 0x41
$214 = 0x7fffe7dffbf0
pwndbg>
$215 = 0x50
$216 = 0x5555555e5748 "bN9uKboZWc"
$217 = 0x42
$218 = 0x7fffe7dffc38
pwndbg>
$219 = 0xab
$220 = 0x5555555e5710 "QgcA2ih74Y"
$221 = 0x41
$222 = 0x7fffe7dffc08
pwndbg>
$223 = 0xb5
$224 = 0x5555555e56d8 "HllqMBG4ej"
$225 = 0x43
$226 = 0x7fffe7dffc20
pwndbg>
$227 = 0xac
$228 = 0x5555555e56a0 "6X6iqasroj"
$229 = 0x42
$230 = 0x5555555e55f0
pwndbg>
$231 = 0xd6
$232 = 0x5555555e5780 "vZqVDeQdpU"
$233 = 0x41
$234 = 0x5555555e5608
pwndbg>
$235 = 0x50
$236 = 0x5555555e5748 "bN9uKboZWc"
$237 = 0x42
$238 = 0x5555555e5620
pwndbg>
$239 = 0xab
$240 = 0x5555555e5710 "QgcA2ih74Y"
$241 = 0x41
$242 = 0x5555555e5638
pwndbg>
$243 = 0xb5
$244 = 0x5555555e56d8 "HllqMBG4ej"
$245 = 0x43
$246 = 0x5555555e5650
pwndbg>
$247 = 0xac
$248 = 0x5555555e56a0 "6X6iqasroj"
$249 = 0x42
$250 = 0x1
```

and transform it into the format we want:

```python
OBJS = [
    (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43),
    (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41),
    (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42),
    (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41),
    (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42),
    (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43),
    (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41),
    (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42),
    (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41),
    (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42)
]
```

Lastly, we need to set a breakpoint at `List.equals`, to check what our target is after this:

This time, we have another list of integers:

```
Breakpoint 1, 0x0000555555592760 in camlStdlib__List.equal_875 ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0x5555555f2cf0 (camlStdlib__Int.data_begin+32) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
 RBX  0x5555555e51d0 (camlDune__exe__Main.95) ◂— 0x163d5
 RCX  0xa
 RDX  1
 RDI  0x7fffe7dfe2d8 ◂— 0x163d5
 RSI  1
 R8   0x5555555e5668 (camlDune__exe__Main.50) ◂— 0x159
 R9   0
 R10  0x555555623440 ◂— 0
 R11  0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe338 ◂— 0xfffffffffffef1b5
 R12  0x7fffe7dfe308 ◂— 0x11345
 R13  0x7fffe7dfead8 ◂— 0xfb
 R14  0x55555560a4a0 —▸ 0x7fffe7d00000 ◂— 0
 R15  0x7fffe7dfe2d0 ◂— 0x800
 RBP  0x7fffe7dff980 —▸ 0x5555555e5760 (camlDune__exe__Main.42) ◂— 0x1ad
 RSP  0x5555556235f0 —▸ 0x555555582421 (camlDune__exe__Main.entry+513) ◂— cmp rax, 1
 RIP  0x555555592760 (camlStdlib__List.equal_875) ◂— lea r10, [rsp - 0x158]
────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x555555592760 <camlStdlib__List.equal_875>       lea    r10, [rsp - 0x158]              R10 => 0x555555623498 ◂— 0
   0x555555592768 <camlStdlib__List.equal_875+8>     cmp    r10, qword ptr [r14 + 0x28]     0x555555623498 - 0x55555561b5f0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x55555559276c <camlStdlib__List.equal_875+12>    jb     camlStdlib__List.equal_875+149 <camlStdlib__List.equal_875+149>

   0x555555592772 <camlStdlib__List.equal_875+18>    sub    rsp, 0x18                RSP => 0x5555556235d8 (0x5555556235f0 - 0x18)
   0x555555592776 <camlStdlib__List.equal_875+22>    mov    rsi, rax                 RSI => 0x5555555f2cf0 (camlStdlib__Int.data_begin+32) —▸ 0x555555581f40 (caml_curry2) ◂— sub r15, 0x28
   0x555555592779 <camlStdlib__List.equal_875+25>    cmp    r15, qword ptr [r14]     0x7fffe7dfe2d0 - 0x7fffe7d00000     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x55555559277c <camlStdlib__List.equal_875+28>    jbe    camlStdlib__List.equal_875+142 <camlStdlib__List.equal_875+142>

   0x55555559277e <camlStdlib__List.equal_875+30>    test   bl, 1                    0xd0 & 0x1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x555555592781 <camlStdlib__List.equal_875+33>  ✔ je     camlStdlib__List.equal_875+52 <camlStdlib__List.equal_875+52>
    ↓
   0x555555592794 <camlStdlib__List.equal_875+52>    test   dil, 1                   0xd8 & 0x1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x555555592798 <camlStdlib__List.equal_875+56>    jne    camlStdlib__List.equal_875+132 <camlStdlib__List.equal_875+132>
──────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────
00:0000│ rsp 0x5555556235f0 —▸ 0x555555582421 (camlDune__exe__Main.entry+513) ◂— cmp rax, 1
01:0008│     0x5555556235f8 —▸ 0x7fffe7dfea80 ◂— 0x51 /* 'Q' */
02:0010│     0x555555623600 —▸ 0x555555581a77 (caml_program+247) ◂— lea rax, [rip + 0x766ba]
03:0018│     0x555555623608 —▸ 0x5555555c2ff4 (caml_start_program+112) ◂— mov r11, qword ptr [rsp]
04:0020│     0x555555623610 ◂— 0
05:0028│     0x555555623618 —▸ 0x5555555c3034 (caml_start_program+176) ◂— or rax, 2
06:0030│     0x555555623620 —▸ 0x7fffffffe860 —▸ 0x55555561b5f0 —▸ 0x5555556235b8 —▸ 0x7fffe7dfe338 ◂— ...
07:0038│     0x555555623628 ◂— 0
────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► 0   0x555555592760 camlStdlib__List.equal_875
   1   0x555555582421 camlDune__exe__Main.entry+513
   2   0x555555581a77 caml_program+247
   3   0x5555555c2ff4 caml_start_program+112
   4   0x5555555c299d caml_startup_common+301
   5   0x5555555c2a0f caml_main+15
   6   0x555555581882 main+18
   7   0x7ffff7cda488 __libc_start_call_main+120
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> set $node = $rbx
pwndbg> dumpnode
$1 = 0xb1ea
$2 = 0x5555555e51e8
pwndbg>
$3 = 0x2786
$4 = 0x5555555e5200
pwndbg>
$5 = 0xffffffffffffde16
$6 = 0x5555555e5218
pwndbg>
$7 = 0xfffffffffffff59d
$8 = 0x5555555e5230
pwndbg>
$9 = 0x36e9
$10 = 0x5555555e5248
pwndbg>
$11 = 0xce9b
$12 = 0x5555555e5278
pwndbg>
$13 = 0x36f7
$14 = 0x5555555e5290
pwndbg>
$15 = 0xffffffffffffcb36
$16 = 0x5555555e52a8
pwndbg>
$17 = 0xffffffffffffeac6
$18 = 0x5555555e52c0
pwndbg>
$19 = 0x34fe
$20 = 0x5555555e52d8
pwndbg>
$21 = 0xb1ea
$22 = 0x5555555e52f0
pwndbg>
$23 = 0x3a66
$24 = 0x5555555e5308
pwndbg>
$25 = 0xffffffffffff5e56
$26 = 0x5555555e5320
pwndbg>
$27 = 0xffffffffffffe8db
$28 = 0x5555555e5338
pwndbg>
$29 = 0x4421
$30 = 0x5555555e5350
pwndbg>
$31 = 0x9699
$32 = 0x5555555e5380
pwndbg>
$33 = 0x1197
$34 = 0x5555555e5398
pwndbg>
$35 = 0xffffffffffffbb2e
$36 = 0x5555555e53b0
pwndbg>
$37 = 0xffffffffffff7d24
$38 = 0x5555555e53c8
pwndbg>
$39 = 0x989a
$40 = 0x5555555e53e0
pwndbg>
$41 = 0xceb4
$42 = 0x5555555e53f8
pwndbg>
$43 = 0x4ad6
$44 = 0x5555555e5410
pwndbg>
$45 = 0xffffffffffff6d2b
$46 = 0x5555555e5428
pwndbg>
$47 = 0xffffffffffffa7e7
$48 = 0x5555555e5440
pwndbg>
$49 = 0x3c31
$50 = 0x5555555e5458
pwndbg>
$51 = 0x50e1
$52 = 0x5555555e5488
pwndbg>
$53 = 0x45f7
$54 = 0x5555555e54a0
pwndbg>
$55 = 0xffffffffffffb121
$56 = 0x5555555e54b8
pwndbg>
$57 = 0xffffffffffffd871
$58 = 0x5555555e54d0
pwndbg>
$59 = 0x54be
$60 = 0x5555555e54e8
pwndbg>
$61 = 0x6200
$62 = 0x5555555e5500
pwndbg>
$63 = 0x26c6
$64 = 0x5555555e5518
pwndbg>
$65 = 0xffffffffffff5c55
$66 = 0x5555555e5530
pwndbg>
$67 = 0xffffffffffff762e
$68 = 0x5555555e5548
pwndbg>
$69 = 0xa36d
$70 = 0x5555555e5560
pwndbg>
$71 = 0xa0a1
$72 = 0x5555555e5590
pwndbg>
$73 = 0x2367
$74 = 0x5555555e55a8
pwndbg>
$75 = 0xffffffffffff9a40
$76 = 0x5555555e55c0
pwndbg>
$77 = 0xffffffffffff66ff
$78 = 0x5555555e55d8
pwndbg>
$79 = 0x89a2
$80 = 0x1
```

giving us a target of

```python
TARGET = [ 0xb1ea, 0x2786, 0xffffffffffffde16, 0xfffffffffffff59d, 0x36e9, 0xce9b, 0x36f7, 0xffffffffffffcb36, 0xffffffffffffeac6, 0x34fe, 0xb1ea, 0x3a66, 0xffffffffffff5e56, 0xffffffffffffe8db, 0x4421, 0x9699, 0x1197, 0xffffffffffffbb2e, 0xffffffffffff7d24, 0x989a, 0xceb4, 0x4ad6, 0xffffffffffff6d2b, 0xffffffffffffa7e7, 0x3c31, 0x50e1, 0x45f7, 0xffffffffffffb121, 0xffffffffffffd871, 0x54be, 0x6200, 0x26c6, 0xffffffffffff5c55, 0xffffffffffff762e, 0xa36d, 0xa0a1, 0x2367, 0xffffffffffff9a40, 0xffffffffffff66ff, 0x89a2 ]
```

Finally, we can set up a solve script:

```python
KEY = [0xa7, 0xc, 0x46, 0x21, 0x22, 0x85, 0xc9, 0x23, 0x64, 0x7d, 0xb7, 0xda, 0x9e, 0x4e, 0x39, 0x85, 0x45, 0x38, 0xda, 0xd2, 0xc7, 0x80, 0x83, 0x4a, 0x34, 0x4, 0x83, 0x1, 0x5d, 0x4c, 0x7, 0x1d, 0xa9, 0xad, 0xa6, 0xf8, 0x29, 0xaa, 0x94, 0xb1]
OBJS = [
    (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43),
    (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41),
    (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42),
    (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41),
    (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42),
    (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43),
    (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41),
    (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41), (0x50, "bN9uKboZWc", 0x42),
    (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42), (0xd6, "vZqVDeQdpU", 0x41),
    (0x50, "bN9uKboZWc", 0x42), (0xab, "QgcA2ih74Y", 0x41), (0xb5, "HllqMBG4ej", 0x43), (0xac, "6X6iqasroj", 0x42)
]
TARGET = [ 0xb1ea, 0x2786, 0xffffffffffffde16, 0xfffffffffffff59d, 0x36e9, 0xce9b, 0x36f7, 0xffffffffffffcb36, 0xffffffffffffeac6, 0x34fe, 0xb1ea, 0x3a66, 0xffffffffffff5e56, 0xffffffffffffe8db, 0x4421, 0x9699, 0x1197, 0xffffffffffffbb2e, 0xffffffffffff7d24, 0x989a, 0xceb4, 0x4ad6, 0xffffffffffff6d2b, 0xffffffffffffa7e7, 0x3c31, 0x50e1, 0x45f7, 0xffffffffffffb121, 0xffffffffffffd871, 0x54be, 0x6200, 0x26c6, 0xffffffffffff5c55, 0xffffffffffff762e, 0xa36d, 0xa0a1, 0x2367, 0xffffffffffff9a40, 0xffffffffffff66ff, 0x89a2 ]

# Start by fixing up the 2's complement in TARGET

for i in range(len(KEY)):
    second_xor = 0
    if OBJS[i][2] == 0x42:
        second_xor = 0xd8
    elif OBJS[i][2] >= 0x43:
        second_xor = 0xbc
    else:
        second_xor = 0x44

    t = TARGET[i] ^ second_xor
    total = (t - 0x10000000000000000) if (t & 0x8000000000000000 != 0) else t
    product = abs(total - ord(OBJS[i][1][i % 10]))
    print(chr((product // OBJS[i][0]) ^ KEY[i]), end='')
print()
# squ1rrel{0caml_1s_c00l_4nd_we1rd_nU8X3N}
```

## Cheesing

There's an interesting way to solve this challenge without having to reverse
through every single detail (if the 2k+ lines of markdown so far feel like a little
too much). We can recognize that each character of the flag affects the final compared string
independently: one wrong character early in the flag won't change the output later on.
This was the method I actually used in the CTF.

We can use this to set up a brute force script. We walk the lists the same way as previously
described, and generate:

```python
import re
from pwn import *

context.binary = './camel'
context.terminal = ["tmux", "splitw", "-v"]
# flag = 'squ1rrel{??????????????????????????????}'
# flag = 'squ1rrel{0?????1???00????????1???????3?}'
# flag = 'squ1rrel{0?????1???00??4?????1?????8?3?}'
flag = 'squ1rrel{0caml_1s_c00l_4nd_we1rd_n?8?3?}'
flag = 'squ1rrel{0caml_1s_c00l_4nd_we1rd_nU8X3N}'
addr = 0x55555558241c

target = [0xb1ea ,0x2786 ,0xffffde17 ,0xfffff59e ,0x36e9 ,0xce9b ,0x36f7 ,0xffffcb37 ,0xffffeac7 ,0x34fe ,0xb1ea ,0x3a66 ,0xffff5e57 ,0xffffe8dc ,0x4421 ,0x9699 ,0x1197 ,0xffffbb2f ,0xffff7d25 ,0x989a ,0xceb4 ,0x4ad6 ,0xffff6d2c ,0xffffa7e8 ,0x3c31 ,0x50e1 ,0x45f7 ,0xffffb122 ,0xffffd872 ,0x54be ,0x6200 ,0x26c6 ,0xffff5c56 ,0xffff762f ,0xa36d ,0xa0a1 ,0x2367 ,0xffff9a41 ,0xffff6700 ,0x89a2]

def test(c):
    global flag
    test_flag = re.sub(r'\?', c, flag)
    con = gdb.debug('./camel', api=True)

    con.gdb.Breakpoint('camlStdlib__List.equal_875')

    con.sendline(test_flag.encode())
    con.gdb.continue_and_wait()
    node = con.gdb.parse_and_eval('$rdi')
    for i in range(40):
        count = con.gdb.parse_and_eval('(*(int32_t*)' + hex(node) + ') >> 1')
        val = count + 2**32 + 1 if count < 0 else count
        if val == target[i] and flag[i] == '?':
            flag = flag[0:i] + c + flag[i+1:]
        node = con.gdb.parse_and_eval('*(void**)(' + hex(node) + '+8)')
    con.gdb.continue_nowait()
    con.close()

for c in string.ascii_letters + string.digits + '_':
    print(flag)
    print(c)
    test(c)
    input()
print(flag)
```

By setting a breakpoint at our `List.equal` call, and walking the result we are
about to compare, we can check which positions are correct, and update those to
the brute force character. After ~60 iterations, we can also get the flag!

A fun little trick in case you ever don't feel like doing the real rev.
