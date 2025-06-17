#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

######################################################################
# Here is register layout for LOONGARCH ABIs.
# The return value is placed in $v0($a0).

($zero,$ra,$tp,$sp,$fp)=map("\$r$_",(0..3,22));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$r$_",(4..11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8)=map("\$r$_",(12..20));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$r$_",(23..31));


$PTR_ADD="addi.d";
$REG_S="st.d";
$REG_L="ld.d";
$SZREG=8;

######################################################################

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$LD="ld.d";
$ST="st.d";
$MULD="mul.d";
$MULHD="mulh.du";
$ADDU="add.d";
$SUBU="sub.d";
$BNSZ=8;
$LDX="ldx.d";

# int bn_mul_mont(
$rp=$a0;	# BN_ULONG *rp,
$ap=$a1;	# const BN_ULONG *ap,
$bp=$a2;	# const BN_ULONG *bp,
$np=$a3;	# const BN_ULONG *np,
$n0=$a4;	# const BN_ULONG *n0,
$num=$a5;	# int num);

$lo0=$a6;
$hi0=$a7;
$lo1=$t1;
$hi1=$t2;
$aj=$t3;
$bi=$t4;
$nj=$t5;
$tp=$t6;
$alo=$t7;
$ahi=$s0;
$nlo=$s1;
$nhi=$s2;
$tj=$s3;
$i=$s4;
$j=$s5;
$m1=$s6;

$code=<<___;
.text
.align  5
.globl	bn_mul_mont
bn_mul_mont:
___
$code.=<<___;
	slti	$t8,$num,4
	bnez	$t8,1f
	slti	$t8,$num,17
	bnez	$t8,bn_mul_mont_internal
1:	li.d	$a0,0
	jr	$ra

.align	5
bn_mul_mont_internal:
	addi.d	$t8,$num,-4
	beqz	$t8,__bn256_mul_mont
	addi.d	$sp,$sp,-64
	$REG_S	$fp,$sp,$SZREG*0
	$REG_S	$s0,$sp,$SZREG*1
	$REG_S	$s1,$sp,$SZREG*2
	$REG_S	$s2,$sp,$SZREG*3
	$REG_S	$s3,$sp,$SZREG*4
	$REG_S	$s4,$sp,$SZREG*5
	$REG_S	$s5,$sp,$SZREG*6
	$REG_S	$s6,$sp,$SZREG*7
___
$code.=<<___;
	move	$fp,$sp
	$LD	$n0,$n0,0
	$LD	$bi,$bp,0	# bp[0]
	$LD	$aj,$ap,0	# ap[0]
	$LD	$nj,$np,0	# np[0]

	$PTR_ADD	$sp,$sp,-2*$BNSZ	# place for two extra words
	slli.d	$num,$num,`log($BNSZ)/log(2)`
	li.d	$t8,-4096
	$SUBU	$sp,$sp,$num
	and	$sp,$sp,$t8

	$LD	$ahi,$ap,$BNSZ
	$LD	$nhi,$np,$BNSZ
	$MULD	$lo0,$aj,$bi
	$MULHD	$hi0,$aj,$bi
	$MULD	$m1,$lo0,$n0

	$MULD	$alo,$ahi,$bi
	$MULHD	$ahi,$ahi,$bi

	$MULD	$lo1,$nj,$m1
	$MULHD	$hi1,$nj,$m1
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	$MULD	$nlo,$nhi,$m1
	$MULHD	$nhi,$nhi,$m1

	move	$tp,$sp
	li.d	$j,2*$BNSZ
.align	4
.L1st:
	$ADDU	$aj,$ap,$j
	$ADDU	$nj,$np,$j
	$LD	$aj,$aj,0
	$LD	$nj,$nj,0

	$ADDU	$lo0,$alo,$hi0
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo0,$hi0
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$hi1,$nhi,$t0
	$MULD	$alo,$aj,$bi
	$MULHD	$ahi,$aj,$bi

	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	addi.d	$j,$j,$BNSZ
	$ST	$lo1,$tp,0
	sltu	$t0,$j,$num
	$MULD	$nlo,$nj,$m1
	$MULHD	$nhi,$nj,$m1

	$PTR_ADD	$tp,$tp,$BNSZ
	bnez	$t0,.L1st

	$ADDU	$lo0,$alo,$hi0
	sltu	$t8,$lo0,$hi0
	$ADDU	$hi0,$ahi,$t8

	$ADDU	$lo1,$nlo,$hi1
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi1,$nhi,$t0
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8

	$ST	$lo1,$tp,0

	$ADDU	$hi1,$hi1,$hi0
	sltu	$t8,$hi1,$hi0
	$ST	$hi1,$tp,$BNSZ
	$ST	$t8,$tp,2*$BNSZ

	li.d	$i,$BNSZ
.align	4
.Louter:
	$ADDU	$bi,$bp,$i
	$LD	$bi,$bi,0
	$LD	$aj,$ap,0
	$LD	$ahi,$ap,$BNSZ
	$LD	$tj,$sp,0

	$LD	$nj,$np,0
	$LD	$nhi,$np,$BNSZ
	$MULD	$lo0,$aj,$bi
	$MULHD	$hi0,$aj,$bi
	$ADDU	$lo0,$lo0,$tj
	sltu	$t8,$lo0,$tj
	$ADDU	$hi0,$hi0,$t8
	$MULD	$m1,$lo0,$n0

	$MULD	$alo,$ahi,$bi
	$MULHD	$ahi,$ahi,$bi

	$MULD	$lo1,$nj,$m1
	$MULHD	$hi1,$nj,$m1

	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	$MULD	$nlo,$nhi,$m1
	$MULHD	$nhi,$nhi,$m1

	move	$tp,$sp
	li.d	$j,2*$BNSZ
	$LD	$tj,$tp,$BNSZ
.align	4
.Linner:
	$ADDU	$aj,$ap,$j
	$ADDU	$nj,$np,$j
	$LD	$aj,$aj,0
	$LD	$nj,$nj,0

	$ADDU	$lo0,$alo,$hi0
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo0,$hi0
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$hi1,$nhi,$t0
	$MULD	$alo,$aj,$bi
	$MULHD	$ahi,$aj,$bi

	$ADDU	$lo0,$lo0,$tj
	addi.d	$j,$j,$BNSZ
	sltu	$t8,$lo0,$tj
	$ADDU	$lo1,$lo1,$lo0
	$ADDU	$hi0,$hi0,$t8
	sltu	$t0,$lo1,$lo0
	$LD	$tj,$tp,2*$BNSZ
	$ADDU	$hi1,$hi1,$t0
	sltu	$t8,$j,$num
	$MULD	$nlo,$nj,$m1
	$MULHD	$nhi,$nj,$m1
	$ST	$lo1,$tp,0
	$PTR_ADD	$tp,$tp,$BNSZ
	bnez	$t8,.Linner

	$ADDU	$lo0,$alo,$hi0
	sltu	$t8,$lo0,$hi0
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$lo0,$lo0,$tj
	sltu	$t0,$lo0,$tj
	$ADDU	$hi0,$hi0,$t0

	$LD	$tj,$tp,2*$BNSZ
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo1,$hi1
	$ADDU	$hi1,$nhi,$t8
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t0,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t0
	$ST	$lo1,$tp,0

	$ADDU	$lo1,$hi1,$hi0
	sltu	$hi1,$lo1,$hi0
	$ADDU	$lo1,$lo1,$tj
	sltu	$t8,$lo1,$tj
	$ADDU	$hi1,$hi1,$t8
	$ST	$lo1,$tp,$BNSZ
	$ST	$hi1,$tp,2*$BNSZ

	$PTR_ADD	$i,$i,$BNSZ
	sltu	$t0,$i,$num
	bnez	$t0,.Louter

	$ADDU	$tj,$sp,$num	# &tp[num]
	move	$tp,$sp
	move	$ap,$sp
	li.d	$hi0,0	# clear borrow bit

.align	4
.Lsub:
	$LD	$lo0,$tp,0
	$LD	$lo1,$np,0
	$PTR_ADD	$tp,$tp,$BNSZ
	$PTR_ADD	$np,$np,$BNSZ
	$SUBU	$lo1,$lo0,$lo1	# tp[i]-np[i]
	sltu	$t8,$lo0,$lo1
	$SUBU	$lo0,$lo1,$hi0
	sltu	$hi0,$lo1,$lo0
	$ST	$lo0,$rp,0
	or	$hi0,$hi0,$t8
	sltu	$t8,$tp,$tj
	$PTR_ADD	$rp,$rp,$BNSZ
	bnez	$t8,.Lsub
	$SUBU	$hi0,$hi1,$hi0	# handle upmost overflow bit
	move	$tp,$sp
	$SUBU	$rp,$rp,$num	# restore rp
	nor	$hi1,$hi0,$zero
.Lcopy:
	$LD	$nj,$tp,0	# conditional move
	$LD	$aj,$rp,0
	$ST	$zero,$tp,0
	$PTR_ADD	$tp,$tp,$BNSZ
	and	$nj,$nj,$hi0
	and	$aj,$aj,$hi1
	or	$aj,$aj,$nj
	sltu	$t8,$tp,$tj
	$ST	$aj,$rp,0
	$PTR_ADD	$rp,$rp,$BNSZ
	bnez	$t8,.Lcopy
	li.d	$a0,1
	li.d	$t0,1
	move	$sp,$fp
___
$code.=<<___;
	$REG_L	$fp,$sp,$SZREG*0
	$REG_L	$s0,$sp,$SZREG*1
	$REG_L	$s1,$sp,$SZREG*2
	$REG_L	$s2,$sp,$SZREG*3
	$REG_L	$s3,$sp,$SZREG*4
	$REG_L	$s4,$sp,$SZREG*5
	$REG_L	$s5,$sp,$SZREG*6
	$REG_L	$s6,$sp,$SZREG*7
	$PTR_ADD	$sp,$sp,64;
	jr	$ra
___

$zero="\$r0";	#zero
$ra="\$r1";	#ra
$tp="\$r2";	#tp
$sp="\$r3";	#sp
$rp="\$r4";	#a0

$ap="\$r5";	#a1
$t0="\$r5";

$bp="\$r6";	#a2

$np="\$r7";	#a3
$t1="\$r7";

$n0="\$r8";	#a4

$num="\$r9";	#a5
$bp_end="\$r9";

$bi="\$r10";	#a6
$mi="\$r10";	#a6

$t2="\$r11";	#a7

$d0="\$r12";	#t0
$d1="\$r13";	#t1
$d2="\$r14";	#t2
$d3="\$r15";	#t3
$m0="\$r16";	#t4;
$m1="\$r17";	#t5;
$m2="\$r18";	#t6
$m3="\$r19";	#t7;
$carry="\$r20";	#t8;
#r21; platform-reserved

$fp="\$r22";	#s9/fp


$acc0="\$r23";	#s0;
$acc1="\$r24";	#s1;
$acc2="\$r25";	#s2;
$acc3="\$r26";	#s3;

$t4="\$r27";	#s4;
$t5="\$r28";	#s5;
$t6="\$r29";	#s6;
$t7="\$r30";	#s7;
$t3="\$r31";    #s8

$code.=<<___;
.type __bn256_mul_mont,%function

__bn256_mul_mont:
.align 4
	$PTR_ADD	$sp,$sp,-160
	alsl.d	$bp_end,$num,$bp,3
	$LD	$n0,$n0,0
	$LD	$bi,$bp,8*0

	$LD	$d0,$ap,8*0
	$LD	$d1,$ap,8*1
	$REG_S	$s8,$sp,144
	move	$carry,$zero

	$LD	$d2,$ap,8*2
	$LD	$d3,$ap,8*3
	//$PTR_ADD	$fp,$sp,160

	$LD	$m0,$np,8*0
	$LD	$m1,$np,8*1
	$REG_S	$s0,$sp,136
	$REG_S	$s1,$sp,128


	move	$acc0, $zero
	move	$acc1, $zero
	$LD	$m2,$np,8*2
	$LD	$m3,$np,8*3

	$REG_S	$s2,$sp,120
	$REG_S	$s3,$sp,112
	move	$acc2, $zero
	move	$acc3, $zero

	$REG_S	$s4,$sp,104
	$REG_S	$s5,$sp,96
	$REG_S	$s6,$sp,88
	$REG_S	$s7,$sp,80

.Loop_mul4x_1st_reduction:
	$MULD	$t0,$d0,$bi		//@4
	$MULD	$t1,$d1,$bi
	$MULD	$t2,$d2,$bi
	$MULD	$t3,$d3,$bi

	$MULHD	$t4,$d0,$bi
	$MULHD	$t5,$d1,$bi
	$ADDU	$acc0,$acc0,$t0		//0 adds	$acc0,$acc0,LO($d0*$bi)
	$ADDU	$acc1,$acc1,$t1		//1 adcs	$acc1,$acc1,LO($d1*$bi)

	$PTR_ADD	$bp,$bp,8
	$MULD	$t6,$n0,$acc0		//$mi alias with $t6
	sltu	$t0,$acc0,$t0		//done 0
	sltu	$t1,$acc1,$t1

	$ADDU	$acc1,$acc1,$t0
	sltu	$t7,$zero,$acc0		//10 subs	$zero,$acc0,1
	$ADDU	$acc2,$acc2,$t2		//2 adcs	$acc2,$acc2,LO($d2*$bi)
	$ADDU	$acc3,$acc3,$t3		//3 adcs	$acc3,$acc3,LO($d3*$bi)


	sltu	$t0,$acc1,$t0
	$ADDU	$acc1,$acc1,$t4		//11 adds	$acc1,$acc1,HI($d0*$bi)
	sltu	$t2,$acc2,$t2
	sltu	$t3,$acc3,$t3

	or	$t0,$t0,$t1		//done 1
	sltu	$t4,$acc1,$t4		//done 11
	$ADDU	$acc0,$acc1,$t7		//20 adcs	$acc0,$acc1,LO($m1*$mi)
	$MULHD	$t1,$d2,$bi

	$MULD	$t7,$m1,$t6
	$ADDU	$t4,$t4,$t5
	sltu	$acc1,$acc0,$acc1
	$ADDU	$acc2,$acc2,$t0

	$MULHD	$t5,$d3,$bi
	$MULD	$bi,$m2,$t6
	sltu	$t0,$acc2,$t0
	$ADDU	$acc2,$acc2,$t4		//12 adcs	$acc2,$acc2,HI($d1*$bi)


	or	$t0,$t0,$t2		//done 2
	sltu	$t4,$acc2,$t4		//done 12
	$MULD	$t2,$m3,$t6
	$ADDU	$acc0,$acc0,$t7

	$ADDU	$t4,$t4,$t1
	$ADDU	$acc3,$acc3,$t0
	sltu	$t7,$acc0,$t7
	$MULHD	$t1,$m0,$t6

	sltu	$t0,$acc3,$t0
	$ADDU	$acc3,$acc3,$t4		//13 adcs	$acc3,$acc3,HI($d2*$bi)
	or	$t7,$acc1,$t7		//done 20
	$ADDU	$acc1,$acc2,$bi		//21 adcs	$acc1,$acc2,LO($m2*$mi)

	or	$t0,$t0,$t3		//done 3,	adc $acc4,$zero,$zero
	sltu	$t4,$acc3,$t4		//done 13
	sltu	$acc2,$acc1,$acc2
	$MULHD	$t3,$m1,$t6

	$ADDU	$t4,$t4,$t5
	$ADDU	$acc1,$acc1,$t7
	$ADDU	$acc3,$acc3,$t2		//22 adcs	$acc2,$acc3,LO($m3*$mi)
	$MULHD	$t5,$m2,$t6


	$ADDU	$t0,$t0,$t4		//14 addc	$acc4,$acc4,HI($d3*$bi)
	sltu	$t7,$acc1,$t7
	sltu	$t2,$acc3,$t2
	$ADDU	$acc0,$acc0,$t1		//30 adcs	$acc0,$acc0,HI($m0*$mi)

	or	$t7,$acc2,$t7		//done 21
	sltu	$t1,$acc0,$t1
	$LD	$bi,$bp,0
	$ADDU	$t0,$t0,$carry  	//23 adcs	$acc3,$acc4,$carry

	$ADDU	$acc2,$acc3,$t7
	$ADDU	$t1,$t3,$t1		//done 30
	$MULHD	$t6,$m3,$t6
	sltu	$carry,$t0,$carry


	sltu	$t7,$acc2,$acc3
	$ADDU	$acc1,$acc1,$t1		//31 adcs	$acc1,$acc1,HI($m1*$mi)

	or	$t7,$t2,$t7		//done 22
	sltu	$t1,$acc1,$t1		//done 31

	$ADDU	$acc3,$t0,$t7
	$ADDU	$t1,$t1,$t5

	sltu	$t7,$acc3,$t7
	$ADDU	$acc2,$acc2,$t1		//32 adcs	$acc2,$acc2,HI($m2*$mi)

	or	$carry,$carry,$t7	//done 23, adc	$carry,$zero,$zero
	sltu	$t1,$acc2,$t1		//done 32

	$ADDU	$t1,$t1,$t6

	$ADDU	$acc3,$acc3,$t1		//33 adcs	$acc3,$acc3,HI($m3*$mi)
	sltu	$t1,$acc3,$t1		//done 33

	$ADDU	$carry,$carry,$t1	//adc $carry,$carry,$zero

	bne	$bp,$bp_end,.Loop_mul4x_1st_reduction

	sltu	$n0,$acc0,$m0		//subs	$t0,$acc0,$m0
	$SUBU	$t0,$acc0,$m0
	sltu	$bp_end,$acc1,$m1	//sbcs	$t1,$acc1,$m1
	$SUBU	$t1,$acc1,$m1

	sltu	$m1,$t1,$n0
	$SUBU	$t1,$t1,$n0
	sltu	$bp,$acc2,$m2		//sbcs	$t2,$acc2,$m2
	$SUBU	$t2,$acc2,$m2

	or	$n0,$bp_end,$m1
	sltu	$bp_end,$acc3,$m3	//sbcs	$t3,$acc3,$m3
	$SUBU	$t3,$acc3,$m3

	sltu	$m2,$t2,$n0
	$SUBU	$t2,$t2,$n0
	$REG_L	$s7,$sp,80
	$REG_L	$s6,$sp,88

	or	$n0,$bp,$m2
	$REG_L	$s5,$sp,96
	$REG_L	$s4,$sp,104

	sltu	$m3,$t3,$n0
	$SUBU	$t3,$t3,$n0

	or	$n0,$bp_end,$m3

	sltu	$n0,$carry,$n0		//sbcs	$zero,$carry,$zero

	maskeqz	$m3,$acc3,$n0
	masknez	$d3,$t3,$n0
	$REG_L	$s8,$sp,144
	$REG_L	$s3,$sp,112

	maskeqz	$m2,$acc2,$n0
	masknez	$d2,$t2,$n0
	$REG_L	$s2,$sp,120
	or	$m3,$m3,$d3

	maskeqz	$m1,$acc1,$n0
	masknez	$d1,$t1,$n0
	or	$m2,$m2,$d2
	$REG_L	$s1,$sp,128

	maskeqz	$m0,$acc0,$n0
	masknez	$d0,$t0,$n0
	or	$m1,$m1,$d1
	$REG_L	$s0,$sp,136


	or	$m0,$m0,$d0
	$ST	$m3,$rp,8*3
	$ST	$m2,$rp,8*2
	$PTR_ADD	$sp,$sp,160

	$ST	$m1,$rp,8*1
	$ST	$m0,$rp,8*0
	li.d	$a0,1
	jirl	$zero,$ra,0

___
$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;
close STDOUT;
