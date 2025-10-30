/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Copyright 2011-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

.text

.globl	felem_shrink
.type	felem_shrink,%function
felem_shrink:
	ld.d	$t6, $a1, 48 # in[3] low
	ld.d	$t4, $a1, 32
	ld.d	$t5, $a1, 40
	ld.d	$t7, $a1, 56 # in[3] high

	ld.d	$t2, $a1, 16
	ld.d	$t0, $a1, 0
	li.d	$a6, -1
	li.d	$t8, -1 # 0xffffffff ffffffff zerop[0] zerop[2]

	ld.d	$t3, $a1, 24
	ld.d	$t1, $a1, 8
	lu32i.d	$a6, -2  # 0xfffffffe ffffffff zerop[3]
	slli.d	$a7, $t8, 32 # 0xffffffff 00000000 zerop[1]

	add.d	$t6, $t6, $a6 # tmp[3]_1 = zerop[3] + in[3]_low
	add.d	$t4, $t4, $t8 # tmp[2] = zerop[2] + (u64)in[2]
	sltu	$a2, $t6, $a6 #
	add.d	$t6, $t6, $t5 # tmp[3]_2 = tmp[3]_1 + in[2]_high

	add.d	$t7, $t7, $a2
	sltu	$a2, $t6, $t5
	add.d	$t0, $t0, $t8 # tmp[0] = zerop[0] + in[0]
	add.d	$t2, $t2, $a7 # tmp[1] = zerop[1] + in[1]

	add.d	$t7, $t7, $a2
	sltu	$a4, $t0, $t8
	slli.d	$a2, $t7, 32  #((limb) a) << 32
	srli.d	$a3, $t7, 32

	add.d	$t6, $t6, $a2
	add.d	$t1, $t1, $a4 # tmp[0]_high += carry
	sltu	$a4, $t6, $a2
	sltu	$a5, $t2, $a7

	add.d	$a2, $a3, $a4 # tmp[3] = {$a2, $t6}
	sltu	$t5, $t4, $t8
	slli.d	$a3, $a2, 32
	add.d	$a4, $t7, $a2 # b += a

	add.d	$t3, $t3, $a5 # tmp[1]_high += carry
	srli.d	$a2, $a2, 32
	add.d	$t6, $t6, $a3
	slli.d	$a5, $a4, 32

	srli.d	$t8, $a4, 32
	add.d	$t0, $t0, $a4 # tmp[0] += b
	sltu 	$t7, $t6, $a3
	add.d	$t2, $t2, $a5 # tmp[1]_low  += ((limb)b << 32)_low

	add.d	$t3, $t3, $t8 # tmp[1]_high += ((limb)b << 32)_high
	sltu	$t8, $t6, $a6
	sltu 	$a3, $t0, $a4
	add.d	$t7, $a2, $t7 # tmp[3]_high

	sltu	$a5, $t2, $a5
	sub.d	$a2, $zero, $t8
	add.d	$t1, $t1, $a3 # tmp[0]_high + carry
	sub.d	$a3, $zero, $t7 # high = 0 - high

	sltu	$t8, $t2, $a4
	add.d	$t3, $t3, $a5 # tmp[1]_high + carry
	sub.d	$t2, $t2, $a4
	orn	$a2, $a3, $a2 #

	sub.d	$t3, $t3, $t8 # tmp[1]_high - carry
	and	$a4, $a7, $a2 #
	sltu	$a3, $t0, $a2 #
	sub.d	$t0, $t0, $a2 #

	sltu	$a7, $t2, $a4 #
	sub.d	$t2, $t2, $a4 #
	sub.d	$t1, $t1, $a3 # - tmp[0]_high - carry
	and	$a5, $a6, $a2 #

	sltu	$a3, $t4, $a2 #
	sub.d	$t3, $t3, $a7 # - tmp[1]_high - carry
	add.d	$t2, $t2, $t1 # tmp[1]_low += tmp[1]_high
	sub.d	$t4, $t4, $a2 #

	st.d	$t0, $a0, 0   #
	sub.d	$t5, $t5, $a3 # - tmp[2]_high - carry
	sltu	$a6, $t2, $t1 #
	sub.d	$t6, $t6, $a5 #

	st.d	$t2, $a0, 8   #
	add.d	$t3, $t3, $a6 # + tmp[1]_high += carry
	add.d	$t6, $t6, $t5 # tmp[3]_low += tmp[2]_high
	add.d	$t4, $t4, $t3 # tmp[2] += tmp[1]_high

	sltu	$a6, $t4, $t3 #
	st.d	$t4, $a0, 16  #
	add.d	$t6, $t6, $a6 # tmp[3]_low += carry
	st.d	$t6, $a0, 24  #

	jr	$ra

.size	felem_shrink,.-felem_shrink

.globl	smallfelem_square
.type	smallfelem_square,%function
smallfelem_square:
	vld	$vr0, $a1, 0
	vld	$vr1, $a1, 16
	vmul.d	$vr4, $vr0, $vr0	# lo a1*a1 | a0*a0
	vmuh.du	$vr16, $vr1, $vr1	# hi a3*a3 | a2*a2

	vmul.d	$vr17, $vr1, $vr1	# lo a3*a3 | a2*a2
	vmuh.du	$vr5, $vr0, $vr0	# hi a1*a1 | a0*a0
	vshuf4i.d	$vr2, $vr1, 11
	vshuf4i.d	$vr3, $vr0, 11

	vmul.d	$vr8, $vr0, $vr2	# lo a1*a2 | a0*a3
	vmuh.du	$vr9, $vr0, $vr2	# hi a1*a2 | a0*a3
	vshuf4i.d	$vr2, $vr0, 2
	vshuf4i.d	$vr3, $vr1, 8

	vmul.d	$vr10, $vr0, $vr1	# lo a3*a1 | a2*a0
	vmuh.du	$vr11, $vr0, $vr1	# hi a3*a1 | a2*a0
	vmul.d	$vr12, $vr2, $vr3	# lo $a2*a3 | a0*a1
	vmuh.du	$vr13, $vr2, $vr3	# hi $a2*a3 | a0*a1

	vextl.qu.du	$vr0, $vr4	# out[0] lo a0*a0
	vexth.qu.du	$vr7, $vr16	# out[7] hi a3*a3
	vhaddw.qu.du	$vr8, $vr8, $vr8	# out[3] lo(a0*a3)+lo(a1*a2)
	vhaddw.qu.du	$vr9, $vr9, $vr9	# out[4] hi(a0*a3)+hi(a0*a3)

	vexth.qu.du	$vr4, $vr4	# out[2] lo(a1*a1)
	vextl.qu.du	$vr16, $vr16	# out[5] hi(a2*a2)
	vaddwev.q.du	$vr20, $vr10, $vr10	# out[2] lo(a0*a2)
	vaddwod.q.du	$vr21, $vr11, $vr11	# out[5] hi(a1*a3)

	vaddwev.q.du	$vr11, $vr11, $vr11	# out[3] hi(a0*a2)
	vaddwod.q.du	$vr10, $vr10, $vr10	# out[4] lo(a1*a3)
	vextl.qu.du	$vr19, $vr17	# out[4] lo(a2*a2)
	vexth.qu.du	$vr17, $vr17	# out[6] lo(a3*a3)

	vadd.q	$vr8, $vr8, $vr8	# out[3]
	vadd.q	$vr9, $vr9, $vr9	# out[4]
	vexth.qu.du	$vr18, $vr5	# out[3] hi(a1*a1)
	vextl.qu.du	$vr5, $vr5	# out[1] hi(a0*a0)

	vadd.q	$vr20, $vr20, $vr4	# out[2] lo(a1*a1)+lo(a0*a2)*2
	vadd.q	$vr21, $vr21, $vr16	# out[5] hi(a2*a2)+hi(a1*a3)
	vaddwev.q.du	$vr1, $vr12, $vr12	# out[1] lo(a0*a1)*2
	vaddwod.q.du	$vr6, $vr13, $vr13	# out[6] hi(a2*a3)*2

	vaddwod.q.du	$vr12, $vr12, $vr12	# out[5] lo(a2*a3)*2
	vaddwev.q.du	$vr13, $vr13, $vr13	# out[2] hi(a0*a1)*2
	vadd.q	$vr11, $vr11, $vr18	# out[3]
	vadd.q	$vr10, $vr10, $vr19	# out[4]

	vst	$vr0, $a0, 0
	vst	$vr7, $a0, 112
	vadd.q	$vr1, $vr1, $vr5	# out[1]
	vadd.q	$vr6, $vr6, $vr17	# out[6]

	vst	$vr1, $a0, 16
	vst	$vr6, $a0, 96
	vadd.q	$vr2, $vr20, $vr13	# out[2]
	vadd.q	$vr5, $vr21, $vr12	# out[5]

	vadd.q	$vr3, $vr8, $vr11	# out[3]
	vadd.q	$vr4, $vr9, $vr10	# out[4]

	vst	$vr3, $a0, 48
	vst	$vr4, $a0, 64
	vst	$vr2, $a0, 32
	vst	$vr5, $a0, 80

	jr	$ra
.size	smallfelem_square,.-smallfelem_square

.globl	smallfelem_mul
.type	smallfelem_mul,%function
smallfelem_mul:
	vld	$vr0, $a1, 0
	vld	$vr2, $a2, 0
	vld	$vr1, $a1, 16
	vld	$vr3, $a2, 16

	vshuf4i.d	$vr4, $vr0, 11
	vshuf4i.d	$vr5, $vr1, 11
	vmul.d	$vr8, $vr0, $vr2	# b1*a1|b0*a0
	vmuh.du	$vr15, $vr1, $vr3

	vmul.d	$vr10, $vr3, $vr4	# b3*a0|b2*a1
	vmuh.du	$vr11, $vr3, $vr4
	vmul.d	$vr12, $vr2, $vr5	# b1*a2|b0*a3
	vmuh.du	$vr13, $vr2, $vr5

	vmuh.du	$vr21, $vr2, $vr4	# out[2]
	vmul.d	$vr22, $vr3, $vr5	# out[5] b3*a2|b2*a3
	vmul.d	$vr20, $vr2, $vr4	# out[1] b1*a0|b0*a1
	vmuh.du	$vr23, $vr3, $vr5	# out[6]

	vmul.d	$vr16, $vr1, $vr2	# b1*a3|b0*a2
	vmul.d	$vr18, $vr0, $vr3	# b3*a1|b2*a0
	vmuh.du	$vr17, $vr1, $vr2
	vmuh.du	$vr19, $vr0, $vr3

	vmul.d	$vr14, $vr1, $vr3	# b3*a3|b2*a2
	vmuh.du	$vr9, $vr0, $vr2
	vextl.qu.du	$vr0, $vr8
	vexth.qu.du	$vr7, $vr15

	vhaddw.qu.du	$vr10, $vr10, $vr10	# out[3]
	vhaddw.qu.du	$vr11, $vr11, $vr11	# out[4]
	vexth.qu.du	$vr2, $vr8	# out[2] lo(b1*a1)
	vextl.qu.du	$vr5, $vr15	# out[5] hi(b2*a2)

	vhaddw.qu.du	$vr12, $vr12, $vr12	# out[3]
	vhaddw.qu.du	$vr13, $vr13, $vr13	# out[4]
	vhaddw.qu.du	$vr21, $vr21, $vr21	# out[2]
	vhaddw.qu.du	$vr22, $vr22, $vr22	# out[5]

	vhaddw.qu.du	$vr20, $vr20, $vr20	# out[1]
	vhaddw.qu.du	$vr23, $vr23, $vr23	# out[6]
	vaddwev.q.du	$vr8, $vr16, $vr18	# out[2]
	vaddwod.q.du	$vr4, $vr16, $vr18	# out[4]

	vaddwev.q.du	$vr3, $vr17, $vr19	# out[3]
	vaddwod.q.du	$vr15, $vr17, $vr19	# out[5]
	vextl.qu.du	$vr1, $vr9	# out[1] hi(b0*a0)
	vexth.qu.du	$vr6, $vr14	# out[6] lo(b3*a3)

	vadd.q	$vr10, $vr10, $vr12	# out[3]
	vadd.q	$vr11, $vr11, $vr13	# out[4]
	vexth.qu.du	$vr9, $vr9	# out[3] hi(b1*a1)
	vextl.qu.du	$vr14, $vr14	# out[4] lo(b2*a2)

	vst	$vr0, $a0, 0
	vst	$vr7, $a0, 112
	vadd.q	$vr1, $vr1, $vr20	# out[1]
	vadd.q	$vr6, $vr6, $vr23	# out[6]

	vadd.q	$vr3, $vr3, $vr9	# out[3]
	vadd.q	$vr4, $vr4, $vr14	# out[4]

	vadd.q	$vr2, $vr2, $vr21	# out[2]
	vadd.q	$vr5, $vr5, $vr22	# out[5]

	vst	$vr1, $a0, 16
	vst	$vr6, $a0, 96

	vadd.q	$vr2, $vr2, $vr8	# out[2]
	vadd.q	$vr5, $vr5, $vr15	# out[5]

	vadd.q	$vr3, $vr3, $vr10	# out[3]
	vadd.q	$vr4, $vr4, $vr11	# out[4]
	vst	$vr2, $a0, 32
	vst	$vr5, $a0, 80
	vst	$vr3, $a0, 48
	vst	$vr4, $a0, 64

	jr	$ra

.size	smallfelem_mul,.-smallfelem_mul

.globl	smallfelem_mul_reduced
.type	smallfelem_mul_reduced,%function
smallfelem_mul_reduced:
	vld	$vr0, $a1, 0
	vld	$vr2, $a2, 0
	vld	$vr1, $a1, 16
	vld	$vr3, $a2, 16

	vshuf4i.d	$vr4, $vr0, 11
	vshuf4i.d	$vr5, $vr1, 11
	vmul.d	$vr8, $vr0, $vr2	# b1*a1|b0*a0
	vmuh.du	$vr15, $vr1, $vr3

	vmul.d	$vr10, $vr3, $vr4	# b3*a0|b2*a1
	vmuh.du	$vr11, $vr3, $vr4
	vmul.d	$vr12, $vr2, $vr5	# b1*a2|b0*a3
	vmuh.du	$vr13, $vr2, $vr5

	vmuh.du	$vr21, $vr2, $vr4	# out[2]
	vmul.d	$vr22, $vr3, $vr5	# out[5] b3*a2|b2*a3
	vmul.d	$vr20, $vr2, $vr4	# out[1] b1*a0|b0*a1
	vmuh.du	$vr23, $vr3, $vr5	# out[6]

	vmul.d	$vr16, $vr1, $vr2	# b1*a3|b0*a2
	vmul.d	$vr18, $vr0, $vr3	# b3*a1|b2*a0
	vmuh.du	$vr17, $vr1, $vr2
	vmuh.du	$vr19, $vr0, $vr3

	vmul.d	$vr14, $vr1, $vr3	# b3*a3|b2*a2
	vmuh.du	$vr9, $vr0, $vr2
	vextl.qu.du	$vr0, $vr8
	vexth.qu.du	$vr7, $vr15

	vhaddw.qu.du	$vr10, $vr10, $vr10	# out[3]
	vhaddw.qu.du	$vr11, $vr11, $vr11	# out[4]
	vexth.qu.du	$vr2, $vr8	# out[2] lo(b1*a1)
	vextl.qu.du	$vr5, $vr15	# out[5] hi(b2*a2)

	vhaddw.qu.du	$vr12, $vr12, $vr12	# out[3]
	vhaddw.qu.du	$vr13, $vr13, $vr13	# out[4]
	vhaddw.qu.du	$vr21, $vr21, $vr21	# out[2]
	vhaddw.qu.du	$vr22, $vr22, $vr22	# out[5]

	vhaddw.qu.du	$vr20, $vr20, $vr20	# out[1]
	vhaddw.qu.du	$vr23, $vr23, $vr23	# out[6]
	vaddwev.q.du	$vr3, $vr17, $vr19	# out[3]
	vaddwod.q.du	$vr4, $vr16, $vr18	# out[4]

	vaddwev.q.du	$vr8, $vr16, $vr18	# out[2]
	vaddwod.q.du	$vr15, $vr17, $vr19	# out[5]
	vextl.qu.du	$vr1, $vr9	# out[1] hi(b0*a0)
	vexth.qu.du	$vr6, $vr14	# out[6] lo(b3*a3)

	vadd.q	$vr10, $vr10, $vr12	# out[3]
	vadd.q	$vr11, $vr11, $vr13	# out[4]
	vexth.qu.du	$vr9, $vr9	# out[3] hi(b1*a1)
	vextl.qu.du	$vr14, $vr14	# out[4] lo(b2*a2)

	vadd.q	$vr1, $vr1, $vr20	# out[1]
	vadd.q	$vr6, $vr6, $vr23	# out[6]

	vadd.q	$vr3, $vr3, $vr9	# out[3]
	vadd.q	$vr4, $vr4, $vr14	# out[4]

	vadd.q	$vr2, $vr2, $vr21	# out[2]
	vadd.q	$vr5, $vr5, $vr22	# out[5]

	vadd.q	$vr2, $vr2, $vr8	# out[2]
	vadd.q	$vr5, $vr5, $vr15	# out[5]

	vadd.q	$vr3, $vr3, $vr10	# out[3]
	vadd.q	$vr4, $vr4, $vr11	# out[4]

	vadd.q	$vr8, $vr6, $vr7	# a
	vadd.q	$vr9, $vr5, $vr7	# b

	vadd.q	$vr5, $vr4, $vr5	# in[4] + in[5] out[3]
	vadd.q	$vr3, $vr3, $vr7	# in[3] + in[7] out[3]

	vadd.q	$vr10, $vr4, $vr7	# c
	vadd.q	$vr0, $vr0, $vr4	# in[0] + in[4] out[0]

	vadd.q	$vr14, $vr8, $vr8	# a*2
	vadd.q	$vr13, $vr8, $vr9	# d

	vbsll.v	$vr11, $vr9, 4	# b << 32
	vadd.q	$vr12, $vr10, $vr6	# in[6] + c out[1]

	vsub.q	$vr1, $vr1, $vr10	# in[1] - c out[1]
	vadd.q	$vr2, $vr2, $vr7	# in[2] + in[7] out[2]

	vadd.q	$vr5, $vr5, $vr14	# in[4] + in[5] + a*2 out[3]
	vadd.q	$vr11, $vr11, $vr8	# b << 32 + a out[2]

	vbsll.v	$vr4, $vr13, 4	# d << 32 out[0]
	vbsll.v	$vr12, $vr12, 4	# (c + in[6]) << 32 out[1]

	vadd.q	$vr13, $vr13, $vr4	# d << 32 + d out[0]
	vadd.q	$vr1, $vr1, $vr12	# out[1]

	vbsll.v	$vr5, $vr5, 4	# out[3]
	vadd.q	$vr2, $vr2, $vr11	# out[2]

	vadd.q	$vr3, $vr3, $vr5	# out[3]
	vadd.q	$vr0, $vr13, $vr0	# out[0]

	vst	$vr2, $a0, 32
	vst	$vr1, $a0, 16

	vst	$vr3, $a0, 48
	vst	$vr0, $a0, 0

	jr	$ra
.size	smallfelem_mul_reduced,.-smallfelem_mul_reduced

.globl	smallfelem_square_reduced
.type	smallfelem_square_reduced,%function
smallfelem_square_reduced:

	vld	$vr0, $a1, 0
	vld	$vr1, $a1, 16

	vmul.d	$vr16, $vr1, $vr1	# lo a3*a3 | a2*a2
	vmuh.du	$vr17, $vr1, $vr1	# hi a3*a3 | a2*a2
	vshuf4i.d	$vr2, $vr1, 11
	vshuf4i.d	$vr3, $vr0, 11

	vmul.d	$vr18, $vr0, $vr2	# lo a1*a2 | a0*a3
	vmuh.du	$vr19, $vr0, $vr2	# hi a1*a2 | a0*a3
	vshuf4i.d	$vr2, $vr0, 2
	vshuf4i.d	$vr3, $vr1, 8

	vmuh.du	$vr23, $vr2, $vr3	# hi $a2*a3 | a0*a1
	vmul.d	$vr22, $vr2, $vr3	# lo $a2*a3 | a0*a1
	vmuh.du	$vr21, $vr0, $vr1	# hi a3*a1 | a2*a0
	vmul.d	$vr20, $vr0, $vr1	# lo a3*a1 | a2*a0

	vaddwod.q.du	$vr8, $vr16, $vr17	# lo(a3*a3)+hi(a3*a3)
	vhaddw.qu.du	$vr9, $vr17, $vr17	# hi(a3*a3)+hi(a2*a2)
	vmul.d	$vr12, $vr0, $vr0		# lo a1*a1|a0*a0
	vmuh.du	$vr13, $vr0, $vr0		# hi a1*a1|a0*a0

	vhaddw.qu.du	$vr18, $vr18, $vr18	# out[3] lo(a1*a2)+lo(a0*a3)
	vhaddw.qu.du	$vr19, $vr19, $vr19	# out[4] hi(a1*a2)+hi(a0*a3)
	vaddwod.q.du	$vr10, $vr23, $vr23	# hi(a2*a3)*2
	vaddwod.q.du	$vr11, $vr22, $vr21	# hi(a1*a3)+lo(a2*a3)

	vextl.qu.du	$vr3, $vr21
	vexth.qu.du	$vr4, $vr20
	vadd.q	$vr3, $vr3, $vr18	# out[3] lo(a1*a2)+lo(a0*a3)+hi(a0*a2)
	vadd.q	$vr4, $vr4, $vr19	# out[4] hi(a1*a2)+hi(a0*a3)+lo(a1*a3)

	vadd.q	$vr11, $vr11, $vr11	# out[5] (hi(a1*a3)+lo(a2*a3))*2
	vaddwev.q.du	$vr5, $vr16, $vr17	# hi(a2*a2)+lo(a2*a2)	in[4]+in[5]

	vaddwod.q.du	$vr7, $vr13, $vr17	# hi(a3*a3)+hi(a1*a1)	in[3]+in[7]
	vhaddw.qu.du	$vr18, $vr17, $vr16	# hi(a3*a3)+lo(a2*a2)	in[4]+in[7]
	vadd.q	$vr3, $vr3, $vr3	# out[3] lo(a1*a2)+lo(a0*a3)+hi(a0*a2)
	vadd.q	$vr4, $vr4, $vr4	# out[4] hi(a1*a2)+hi(a0*a3)+lo(a1*a3)

	vadd.q	$vr9, $vr9, $vr11	# b
	vadd.q	$vr8, $vr8, $vr10	# a
	vaddwod.q.du	$vr2, $vr12, $vr17	# hi(a3*a3)+lo(a1*a1)	in[2]+in[7]
	vaddwev.q.du	$vr22, $vr22, $vr22	# out[1]	lo(a0*a1)*2

	vextl.qu.du	$vr1, $vr13	# out[1]
	vexth.qu.du	$vr6, $vr16	# out[6] lo(a3*a3)
	vadd.q	$vr5, $vr5, $vr11	# in[4]+int[5] out[3]
	vaddwev.q.du	$vr23, $vr23, $vr20	# out[2] hi(a0*a1)+lo(a0*a2)

	vadd.q	$vr6, $vr6, $vr10	# out[6]
	vaddwev.q.du	$vr0, $vr12, $vr16	# in[0]+in[4]
	vadd.q	$vr3, $vr3, $vr7	# in[3]+in[7] out[3]
	vadd.q	$vr1, $vr1, $vr22	# out[1]

	vadd.q	$vr10, $vr4, $vr18	# c in[4]+in[7]
	vadd.q	$vr13, $vr8, $vr9	# d
	vbsll.v	$vr11, $vr9, 4	# b << 32

	vadd.q	$vr14, $vr8, $vr8	# a*2
	vadd.q	$vr23, $vr23, $vr23	# out[2] (hi(a0*a1)+lo(a0*a2))*2

	vadd.q	$vr0, $vr0, $vr4	# in[0]+in[4]
	vadd.q	$vr5, $vr5, $vr4	# in[4]+in[5] out[3]
	vadd.q	$vr12, $vr10, $vr6	# in[6] + c out[1]
	vsub.q	$vr1, $vr1, $vr10	# in[1] - c out[1]
	vadd.q	$vr2, $vr2, $vr23	# in[2]+in[7] out[2]

	vadd.q	$vr5, $vr5, $vr14	# in[4] + in[5] + a*2 out[3]
	vadd.q	$vr11, $vr11, $vr8	# b << 32 + a out[2]

	vbsll.v	$vr4, $vr13, 4	# d << 32 out[0]
	vbsll.v	$vr12, $vr12, 4	# (c + in[6]) << 32 out[1]

	vadd.q	$vr13, $vr13, $vr4	# d << 32 + d out[0]
	vadd.q	$vr1, $vr1, $vr12	# out[1]

	vbsll.v	$vr5, $vr5, 4	# out[3]
	vadd.q	$vr2, $vr2, $vr11	# out[2]

	vadd.q	$vr3, $vr3, $vr5	# out[3]
	vadd.q	$vr0, $vr13, $vr0	# out[0]

	vst	$vr2, $a0, 32
	vst	$vr1, $a0, 16

	vst	$vr3, $a0, 48
	vst	$vr0, $a0, 0
	jr	$ra

.size smallfelem_square_reduced,.-smallfelem_square_reduced

.globl	felem_reduce
.type	felem_reduce,%function
felem_reduce:
	vld	$vr7, $a1, 112	# in[7]
	vld	$vr6, $a1, 96	# in[6]
	vld	$vr5, $a1, 80	# in[5]
	vld	$vr4, $a1, 64	# in[4]
	vld	$vr3, $a1, 48	# in[3]
	vld	$vr2, $a1, 32	# in[2]
	vld	$vr0, $a1, 0	# in[0]
	vld	$vr1, $a1, 16	# in[1]

	vadd.q	$vr8, $vr6, $vr7	# a
	vadd.q	$vr9, $vr5, $vr7	# b

	vadd.q	$vr5, $vr4, $vr5	# in[4] + in[5] out[3]
	vadd.q	$vr3, $vr3, $vr7	# in[3] + in[7] out[3]

	vadd.q	$vr10, $vr4, $vr7	# c
	vadd.q	$vr0, $vr0, $vr4	# in[0] + in[4] out[0]

	vadd.q	$vr14, $vr8, $vr8	# a*2
	vadd.q	$vr13, $vr8, $vr9	# d

	vbsll.v	$vr11, $vr9, 4	# b << 32
	vadd.q	$vr12, $vr10, $vr6	# in[6] + c out[1]

	vsub.q	$vr1, $vr1, $vr10	# in[1] - c out[1]
	vadd.q	$vr2, $vr2, $vr7	# in[2] + in[7] out[2]

	vadd.q	$vr5, $vr5, $vr14	# in[4] + in[5] + a*2 out[3]
	vadd.q	$vr11, $vr11, $vr8	# b << 32 + a out[2]


	vbsll.v	$vr4, $vr13, 4	# d << 32 out[0]
	vbsll.v	$vr12, $vr12, 4	# (c + in[6]) << 32 out[1]

	vadd.q	$vr13, $vr13, $vr4	# d << 32 + d out[0]
	vadd.q	$vr1, $vr1, $vr12	# out[1]


	vbsll.v	$vr5, $vr5, 4	# out[3]
	vadd.q	$vr2, $vr2, $vr11	# out[2]

	vadd.q	$vr3, $vr3, $vr5	# out[3]
	vadd.q	$vr0, $vr13, $vr0	# out[0]

	vst	$vr2, $a0, 32
	vst	$vr1, $a0, 16

	vst	$vr3, $a0, 48
	vst	$vr0, $a0, 0
	jr	$ra

.size felem_reduce,.-felem_reduce
