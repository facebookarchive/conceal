#!/usr/bin/env perl

##############################################################################
#                                                                            #
# Copyright 2014 Intel Corporation                                           #
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
#  Developers and authors:                                                   #
#  Shay Gueron (1, 2), and Vlad Krasnov (1)                                  #
#  (1) Intel Corporation, Israel Development Center                          #
#  (2) University of Haifa                                                   #
#                                                                            #
# Related work:                                                              #
# M. Goll, S. Gueron, "Vectorization on ChaCha Stream Cipher", IEEE          #
#          Proceedings of 11th International Conference on Information       #
#          Technology: New Generations (ITNG 2014), 612-615 (2014).          #
# M. Goll, S. Gueron, "Vectorization on Poly1305 Message Authentication Code"#
#           to be published.                                                 #
# A. Langley, chacha20poly1305 for the AEAD head                             #
# https://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=9a8646510b3d0a48e950748f7a2aaa12ed40d5e0  #
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
  my $ver = $2 + $3/100.0;  # 3.1->3.01, 3.10->3.10
  $avx = ($ver>=3.0) + ($ver>=3.01);
}

{

my ($rol8, $rol16, $state_cdef, $tmp,
    $v0, $v1, $v2, $v3, $v4, $v5, $v6, $v7,
    $v8, $v9, $v10, $v11)=map("%xmm$_",(0..15));

sub chacha_qr {

my ($a,$b,$c,$d)=@_;
$code.=<<___;
  paddd  $b, $a            # a += b
  pxor   $a, $d            # d ^= a
  pshufb $rol16, $d        # d <<<= 16

  paddd  $d, $c            # c += d
  pxor   $c, $b            # b ^= c

  movdqa $b, $tmp
  pslld  \$12, $tmp
  psrld  \$20, $b
  pxor   $tmp, $b          # b <<<= 12

  paddd  $b, $a            # a += b
  pxor   $a, $d            # d ^= a
  pshufb $rol8, $d         # d <<<= 8

  paddd  $d, $c            # c += d
  pxor   $c, $b            # b ^= c

  movdqa $b, $tmp
  pslld  \$7, $tmp
  psrld  \$25, $b
  pxor   $tmp, $b          # b <<<= 7
___

}

$code.=<<___;
.text
.align 16
chacha20_consts:
.byte 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
.rol8:
.byte 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
.rol16:
.byte 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
.avxInc:
.quad 1,0
___

{
my ($out, $in, $in_len, $key_ptr, $nr)
   =("%rdi", "%rsi", "%rdx", "%rcx", "%r8");

$code.=<<___;
.globl chacha_20_core_asm
.type  chacha_20_core_asm ,\@function,2
.align 64
chacha_20_core_asm:

  # Init state
  movdqa  .rol8(%rip), $rol8
  movdqa  .rol16(%rip), $rol16
  movdqu  2*16($key_ptr), $state_cdef

2:
  cmp  \$3*64, $in_len
  jb   2f

  movdqa  chacha20_consts(%rip), $v0
  movdqu  0*16($key_ptr), $v1
  movdqu  1*16($key_ptr), $v2
  movdqa  $state_cdef, $v3
  movdqa  $v0, $v4
  movdqa  $v0, $v8
  movdqa  $v1, $v5
  movdqa  $v1, $v9
  movdqa  $v2, $v6
  movdqa  $v2, $v10
  movdqa  $v3, $v7
  paddd  .avxInc(%rip), $v7
  movdqa  $v7, $v11
  paddd  .avxInc(%rip), $v11

  mov  \$10, $nr

  1:
___
    &chacha_qr( $v0, $v1, $v2, $v3);
    &chacha_qr( $v4, $v5, $v6, $v7);
    &chacha_qr( $v8, $v9,$v10,$v11);
$code.=<<___;
    palignr  \$4,  $v1,  $v1
    palignr  \$8,  $v2,  $v2
    palignr \$12,  $v3,  $v3
    palignr  \$4,  $v5,  $v5
    palignr  \$8,  $v6,  $v6
    palignr \$12,  $v7,  $v7
    palignr  \$4,  $v9,  $v9
    palignr  \$8, $v10, $v10
    palignr \$12, $v11, $v11
___
    &chacha_qr( $v0, $v1, $v2, $v3);
    &chacha_qr( $v4, $v5, $v6, $v7);
    &chacha_qr( $v8, $v9,$v10,$v11);
$code.=<<___;
    palignr \$12,  $v1,  $v1
    palignr  \$8,  $v2,  $v2
    palignr  \$4,  $v3,  $v3
    palignr \$12,  $v5,  $v5
    palignr  \$8,  $v6,  $v6
    palignr  \$4,  $v7,  $v7
    palignr \$12,  $v9,  $v9
    palignr  \$8, $v10, $v10
    palignr  \$4, $v11, $v11
    dec  $nr

  jnz  1b
  paddd  chacha20_consts(%rip), $v0
  paddd  chacha20_consts(%rip), $v4
  paddd  chacha20_consts(%rip), $v8

  movdqu 16*0($key_ptr), $tmp
  paddd  $tmp, $v1
  paddd  $tmp, $v5
  paddd  $tmp, $v9

  movdqu 16*1($key_ptr), $tmp
  paddd  $tmp, $v2
  paddd  $tmp, $v6
  paddd  $tmp, $v10

  paddd  $state_cdef, $v3
  paddq  .avxInc(%rip), $state_cdef
  paddd  $state_cdef, $v7
  paddq  .avxInc(%rip), $state_cdef
  paddd  $state_cdef, $v11
  paddq  .avxInc(%rip), $state_cdef

  movdqu 16*0($in), $tmp
  pxor $tmp, $v0
  movdqu 16*1($in), $tmp
  pxor $tmp, $v1
  movdqu 16*2($in), $tmp
  pxor $tmp, $v2
  movdqu 16*3($in), $tmp
  pxor $tmp, $v3

  movdqu  $v0, 16*0($out)
  movdqu  $v1, 16*1($out)
  movdqu  $v2, 16*2($out)
  movdqu  $v3, 16*3($out)

  movdqu 16*4($in), $tmp
  pxor $tmp, $v4
  movdqu 16*5($in), $tmp
  pxor $tmp, $v5
  movdqu 16*6($in), $tmp
  pxor $tmp, $v6
  movdqu 16*7($in), $tmp
  pxor $tmp, $v7

  movdqu  $v4, 16*4($out)
  movdqu  $v5, 16*5($out)
  movdqu  $v6, 16*6($out)
  movdqu  $v7, 16*7($out)

  movdqu 16*8($in), $tmp
  pxor $tmp, $v8
  movdqu 16*9($in), $tmp
  pxor $tmp, $v9
  movdqu 16*10($in), $tmp
  pxor $tmp, $v10
  movdqu 16*11($in), $tmp
  pxor $tmp, $v11

  movdqu  $v8, 16*8($out)
  movdqu  $v9, 16*9($out)
  movdqu  $v10, 16*10($out)
  movdqu  $v11, 16*11($out)

  lea  16*12($in), $in
  lea  16*12($out), $out
  sub  \$16*12, $in_len

  jmp  2b

2:
  cmp  \$2*64, $in_len
  jb   2f

  movdqa  chacha20_consts(%rip), $v0
  movdqa  chacha20_consts(%rip), $v4
  movdqu  16*0($key_ptr), $v1
  movdqu  16*0($key_ptr), $v5
  movdqu  16*1($key_ptr), $v2
  movdqu  16*1($key_ptr), $v6
  movdqa  $state_cdef, $v3
  movdqa  $v3, $v7
  paddd   .avxInc(%rip), $v7

  mov  \$10, $nr
  1:
___
    &chacha_qr($v0,$v1,$v2,$v3);
    &chacha_qr($v4,$v5,$v6,$v7);
$code.=<<___;
    palignr  \$4, $v1, $v1
    palignr  \$8, $v2, $v2
    palignr \$12, $v3, $v3
    palignr  \$4, $v5, $v5
    palignr  \$8, $v6, $v6
    palignr \$12, $v7, $v7
___
    &chacha_qr($v0,$v1,$v2,$v3);
    &chacha_qr($v4,$v5,$v6,$v7);
$code.=<<___;
    palignr \$12, $v1, $v1
    palignr  \$8, $v2, $v2
    palignr  \$4, $v3, $v3
    palignr \$12, $v5, $v5
    palignr  \$8, $v6, $v6
    palignr  \$4, $v7, $v7
    dec  $nr
  jnz  1b

  paddd  chacha20_consts(%rip), $v0
  paddd  chacha20_consts(%rip), $v4

  movdqu 16*0($key_ptr), $tmp
  paddd  $tmp, $v1
  paddd  $tmp, $v5

  movdqu 16*1($key_ptr), $tmp
  paddd  $tmp, $v2
  paddd  $tmp, $v6

  paddd  $state_cdef, $v3
  paddq  .avxInc(%rip), $state_cdef
  paddd  $state_cdef, $v7
  paddq  .avxInc(%rip), $state_cdef

  movdqu 16*0($in), $tmp
  pxor $tmp, $v0
  movdqu 16*1($in), $tmp
  pxor $tmp, $v1
  movdqu 16*2($in), $tmp
  pxor $tmp, $v2
  movdqu 16*3($in), $tmp
  pxor $tmp, $v3

  movdqu  $v0, 16*0($out)
  movdqu  $v1, 16*1($out)
  movdqu  $v2, 16*2($out)
  movdqu  $v3, 16*3($out)

  movdqu 16*4($in), $tmp
  pxor $tmp, $v4
  movdqu 16*5($in), $tmp
  pxor $tmp, $v5
  movdqu 16*6($in), $tmp
  pxor $tmp, $v6
  movdqu 16*7($in), $tmp
  pxor $tmp, $v7

  movdqu  $v4, 16*4($out)
  movdqu  $v5, 16*5($out)
  movdqu  $v6, 16*6($out)
  movdqu  $v7, 16*7($out)

  lea  16*8($in), $in
  lea  16*8($out), $out
  sub  \$16*8, $in_len

  jmp  2b
2:
  cmp  \$64, $in_len
  jb  2f

  movdqa  chacha20_consts(%rip), $v0
  movdqu  16*0($key_ptr), $v1
  movdqu  16*1($key_ptr), $v2
  movdqa  $state_cdef, $v3

  mov  \$10, $nr

  1:
___
    &chacha_qr($v0,$v1,$v2,$v3);
$code.=<<___;
    palignr   \$4, $v1, $v1
    palignr   \$8, $v2, $v2
    palignr  \$12, $v3, $v3
___
    &chacha_qr($v0,$v1,$v2,$v3);
$code.=<<___;
    palignr  \$12, $v1, $v1
    palignr   \$8, $v2, $v2
    palignr   \$4, $v3, $v3
    dec  $nr
  jnz  1b

  paddd  chacha20_consts(%rip), $v0

  movdqu 16*0($key_ptr), $tmp
  paddd  $tmp, $v1

  movdqu 16*1($key_ptr), $tmp
  paddd  $tmp, $v2

  paddd  $state_cdef, $v3
  paddq  .avxInc(%rip), $state_cdef

  movdqu 16*0($in), $tmp
  pxor $tmp, $v0
  movdqu 16*1($in), $tmp
  pxor $tmp, $v1
  movdqu 16*2($in), $tmp
  pxor $tmp, $v2
  movdqu 16*3($in), $tmp
  pxor $tmp, $v3

  movdqu  $v0, 16*0($out)
  movdqu  $v1, 16*1($out)
  movdqu  $v2, 16*2($out)
  movdqu  $v3, 16*3($out)

  lea  16*4($in), $in
  lea  16*4($out), $out
  sub  \$16*4, $in_len
  jmp  2b

2:
  movdqu  $state_cdef, 16*2($key_ptr)
  ret
.size  chacha_20_core_asm,.-chacha_20_core_asm
___
}
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
