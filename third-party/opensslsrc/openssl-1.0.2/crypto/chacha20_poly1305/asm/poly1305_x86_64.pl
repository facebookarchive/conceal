##############################################################################
#                                                                            #
# Copyright 2016 CloudFlare LTD                                              #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License");            #
# you may not use this file except in compliance with the License.           #
# You may obtain a copy of the License at                                    #
#                                                                            #
#    http://www.apache.org/licenses/LICENSE-2.0                              #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#                                                                            #
##############################################################################
#                                                                            #
# Author:  Vlad Krasnov                                                      #
#                                                                            #
##############################################################################

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
                =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
        $avx = ($1>=2.19) + ($1>=2.22);
}

if ($win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
            `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
        $avx = ($1>=2.09) + ($1>=2.10);
}

if ($win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
            `ml64 2>&1` =~ /Version ([0-9]+)\./) {
        $avx = ($1>=10) + ($1>=11);
}

if (`$ENV{CC} -v 2>&1` =~ /(^clang version|based on LLVM) ([3-9])\.([0-9]+)/) {
        my $ver = $2 + $3/100.0;        # 3.1->3.01, 3.10->3.10
        $avx = ($ver>=3.0) + ($ver>=3.01);
}


{
{

my ($state, $key)
   =("%rdi", "%rsi");

$code.=<<___;

.LrSet:
.align 16
.quad 0x0FFFFFFC0FFFFFFF, 0x0FFFFFFC0FFFFFFC
###############################################################################
# void poly1305_init_x64(void *state, uint8_t key[32])

.globl poly1305_init_x64
.type poly1305_init_x64, \@function, 2
.align 64
poly1305_init_x64:

  xor %rax, %rax
  mov %rax, 8*0($state)
  mov %rax, 8*1($state)
  mov %rax, 8*2($state)

  movdqu 16*0($key), %xmm0
  movdqu 16*1($key), %xmm1
  pand .LrSet(%rip), %xmm0

  movdqu %xmm0, 8*3($state)
  movdqu %xmm1, 8*3+16($state)
  movq  \$0, 8*7($state)

  ret
.size poly1305_init_x64,.-poly1305_init_x64
___
}

{

my ($state, $inp)
   =("%rdi", "%rsi");

my ($acc0, $acc1, $acc2, $inl, $t0, $t1, $t2, $t3, $r0)
   =("%rcx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15");

my ($r1)
   =("8*4($state)");

$code.=<<___;
###############################################################################
# void* poly1305_update_x64(void* state, void* in, uint64_t in_len)
.globl poly1305_update_x64
.type poly1305_update_x64, \@function, 2
.align 64
poly1305_update_x64:

  push  %r11
  push  %r12
  push  %r13
  push  %r14
  push  %r15

  mov %rdx, $inl

  mov 8*0($state), $acc0
  mov 8*1($state), $acc1
  mov 8*2($state), $acc2
  mov 8*3($state), $r0

  cmp   \$16, $inl
  jb    2f
  jmp   1f

.align 64
1:
############################
  add   8*0($inp), $acc0
  adc   8*1($inp), $acc1
  lea   16($inp), $inp
  adc   \$1, $acc2

5:
  mov   $r0, %rax
  mulq  $acc0
  mov   %rax, $t0
  mov   %rdx, $t1

  mov   $r0, %rax
  mulq  $acc1
  add   %rax, $t1
  adc   \$0, %rdx

  mov   $r0, $t2
  imul  $acc2, $t2
  add   %rdx, $t2
############################
  mov   $r1, %rax
  mulq  $acc0
  add   %rax, $t1
  adc   \$0, %rdx
  mov   %rdx, $acc0

  mov   $r1, %rax
  mulq  $acc1
  add   $acc0, $t2
  adc   \$0, %rdx
  add   %rax, $t2
  adc   \$0, %rdx

  mov   $r1, $t3
  imul  $acc2, $t3
  add   %rdx, $t3
############################

  mov   $t0, $acc0
  mov   $t1, $acc1
  mov   $t2, $acc2
  and   \$3, $acc2

  mov   $t2, $t0
  mov   $t3, $t1

  and   \$-4, $t0
  shrd  \$2, $t3, $t2
  shr   \$2, $t3

  add   $t0, $acc0
  adc   $t1, $acc1
  adc   \$0, $acc2

  add   $t2, $acc0
  adc   $t3, $acc1
  adc   \$0, $acc2

  sub   \$16, $inl
  cmp   \$16, $inl
  jae   1b

2:
  test  $inl, $inl
  jz    3f

  mov   \$1, $t0
  xor   $t1, $t1
  xor   $t2, $t2
  add   $inl, $inp

4:
  shld  \$8, $t0, $t1
  shl   \$8, $t0
  movzxb  -1($inp), $t2
  xor   $t2, $t0
  dec   $inp
  dec   $inl
  jnz   4b

  add   $t0, $acc0
  adc   $t1, $acc1
  adc   \$0, $acc2

  mov   \$16, $inl
  jmp   5b

3:

  mov $acc0, 8*0($state)
  mov $acc1, 8*1($state)
  mov $acc2, 8*2($state)

  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %r11
  ret
.size poly1305_update_x64, .-poly1305_update_x64
___
}

{

my ($mac, $state)=("%rsi", "%rdi");

my ($acc0, $acc1, $acc2, $t0, $t1, $t2)
   =("%rcx", "%rax", "%rdx", "%r8", "%r9", "%r10");

$code.=<<___;
###############################################################################
# void poly1305_finish_x64(void* state, uint64_t mac[2]);
.type poly1305_finish_x64,\@function, 2
.align 64
.globl poly1305_finish_x64
poly1305_finish_x64:

  mov 8*0($state), $acc0
  mov 8*1($state), $acc1
  mov 8*2($state), $acc2

  mov $acc0, $t0
  mov $acc1, $t1
  mov $acc2, $t2

  sub \$-5, $acc0
  sbb \$-1, $acc1
  sbb \$3, $acc2

  cmovc $t0, $acc0
  cmovc $t1, $acc1
  cmovc $t2, $acc2

  add 8*5($state), $acc0
  adc 8*6($state), $acc1
  mov $acc0, ($mac)
  mov $acc1, 8($mac)

  ret
.size poly1305_finish_x64, .-poly1305_finish_x64
___
}
}
$code =~ s/\`([^\`]*)\`/eval($1)/gem;
print $code;
close STDOUT;
