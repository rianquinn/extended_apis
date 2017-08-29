//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <vmcs/vmcs_intel_x64_vmm_state_eapis.h>

using namespace x64;
using namespace intel_x64;

// -----------------------------------------------------------------------------
// Interrupt Service Routines
// -----------------------------------------------------------------------------

// The following ISRs are used to populate the IDT. These ISRs are defined
// in assembly, and call the generic ISR handler.

/// @cond

extern "C" void _isr0(void) noexcept;
extern "C" void _isr1(void) noexcept;
extern "C" void _isr2(void) noexcept;
extern "C" void _isr3(void) noexcept;
extern "C" void _isr4(void) noexcept;
extern "C" void _isr5(void) noexcept;
extern "C" void _isr6(void) noexcept;
extern "C" void _isr7(void) noexcept;
extern "C" void _isr8(void) noexcept;
extern "C" void _isr9(void) noexcept;
extern "C" void _isr10(void) noexcept;
extern "C" void _isr11(void) noexcept;
extern "C" void _isr12(void) noexcept;
extern "C" void _isr13(void) noexcept;
extern "C" void _isr14(void) noexcept;
extern "C" void _isr15(void) noexcept;
extern "C" void _isr16(void) noexcept;
extern "C" void _isr17(void) noexcept;
extern "C" void _isr18(void) noexcept;
extern "C" void _isr19(void) noexcept;
extern "C" void _isr20(void) noexcept;
extern "C" void _isr21(void) noexcept;
extern "C" void _isr22(void) noexcept;
extern "C" void _isr23(void) noexcept;
extern "C" void _isr24(void) noexcept;
extern "C" void _isr25(void) noexcept;
extern "C" void _isr26(void) noexcept;
extern "C" void _isr27(void) noexcept;
extern "C" void _isr28(void) noexcept;
extern "C" void _isr29(void) noexcept;
extern "C" void _isr30(void) noexcept;
extern "C" void _isr31(void) noexcept;
extern "C" void _isr32(void) noexcept;
extern "C" void _isr33(void) noexcept;
extern "C" void _isr34(void) noexcept;
extern "C" void _isr35(void) noexcept;
extern "C" void _isr36(void) noexcept;
extern "C" void _isr37(void) noexcept;
extern "C" void _isr38(void) noexcept;
extern "C" void _isr39(void) noexcept;
extern "C" void _isr40(void) noexcept;
extern "C" void _isr41(void) noexcept;
extern "C" void _isr42(void) noexcept;
extern "C" void _isr43(void) noexcept;
extern "C" void _isr44(void) noexcept;
extern "C" void _isr45(void) noexcept;
extern "C" void _isr46(void) noexcept;
extern "C" void _isr47(void) noexcept;
extern "C" void _isr48(void) noexcept;
extern "C" void _isr49(void) noexcept;
extern "C" void _isr50(void) noexcept;
extern "C" void _isr51(void) noexcept;
extern "C" void _isr52(void) noexcept;
extern "C" void _isr53(void) noexcept;
extern "C" void _isr54(void) noexcept;
extern "C" void _isr55(void) noexcept;
extern "C" void _isr56(void) noexcept;
extern "C" void _isr57(void) noexcept;
extern "C" void _isr58(void) noexcept;
extern "C" void _isr59(void) noexcept;
extern "C" void _isr60(void) noexcept;
extern "C" void _isr61(void) noexcept;
extern "C" void _isr62(void) noexcept;
extern "C" void _isr63(void) noexcept;
extern "C" void _isr64(void) noexcept;
extern "C" void _isr65(void) noexcept;
extern "C" void _isr66(void) noexcept;
extern "C" void _isr67(void) noexcept;
extern "C" void _isr68(void) noexcept;
extern "C" void _isr69(void) noexcept;
extern "C" void _isr70(void) noexcept;
extern "C" void _isr71(void) noexcept;
extern "C" void _isr72(void) noexcept;
extern "C" void _isr73(void) noexcept;
extern "C" void _isr74(void) noexcept;
extern "C" void _isr75(void) noexcept;
extern "C" void _isr76(void) noexcept;
extern "C" void _isr77(void) noexcept;
extern "C" void _isr78(void) noexcept;
extern "C" void _isr79(void) noexcept;
extern "C" void _isr80(void) noexcept;
extern "C" void _isr81(void) noexcept;
extern "C" void _isr82(void) noexcept;
extern "C" void _isr83(void) noexcept;
extern "C" void _isr84(void) noexcept;
extern "C" void _isr85(void) noexcept;
extern "C" void _isr86(void) noexcept;
extern "C" void _isr87(void) noexcept;
extern "C" void _isr88(void) noexcept;
extern "C" void _isr89(void) noexcept;
extern "C" void _isr90(void) noexcept;
extern "C" void _isr91(void) noexcept;
extern "C" void _isr92(void) noexcept;
extern "C" void _isr93(void) noexcept;
extern "C" void _isr94(void) noexcept;
extern "C" void _isr95(void) noexcept;
extern "C" void _isr96(void) noexcept;
extern "C" void _isr97(void) noexcept;
extern "C" void _isr98(void) noexcept;
extern "C" void _isr99(void) noexcept;
extern "C" void _isr100(void) noexcept;
extern "C" void _isr101(void) noexcept;
extern "C" void _isr102(void) noexcept;
extern "C" void _isr103(void) noexcept;
extern "C" void _isr104(void) noexcept;
extern "C" void _isr105(void) noexcept;
extern "C" void _isr106(void) noexcept;
extern "C" void _isr107(void) noexcept;
extern "C" void _isr108(void) noexcept;
extern "C" void _isr109(void) noexcept;
extern "C" void _isr110(void) noexcept;
extern "C" void _isr111(void) noexcept;
extern "C" void _isr112(void) noexcept;
extern "C" void _isr113(void) noexcept;
extern "C" void _isr114(void) noexcept;
extern "C" void _isr115(void) noexcept;
extern "C" void _isr116(void) noexcept;
extern "C" void _isr117(void) noexcept;
extern "C" void _isr118(void) noexcept;
extern "C" void _isr119(void) noexcept;
extern "C" void _isr120(void) noexcept;
extern "C" void _isr121(void) noexcept;
extern "C" void _isr122(void) noexcept;
extern "C" void _isr123(void) noexcept;
extern "C" void _isr124(void) noexcept;
extern "C" void _isr125(void) noexcept;
extern "C" void _isr126(void) noexcept;
extern "C" void _isr127(void) noexcept;
extern "C" void _isr128(void) noexcept;
extern "C" void _isr129(void) noexcept;
extern "C" void _isr130(void) noexcept;
extern "C" void _isr131(void) noexcept;
extern "C" void _isr132(void) noexcept;
extern "C" void _isr133(void) noexcept;
extern "C" void _isr134(void) noexcept;
extern "C" void _isr135(void) noexcept;
extern "C" void _isr136(void) noexcept;
extern "C" void _isr137(void) noexcept;
extern "C" void _isr138(void) noexcept;
extern "C" void _isr139(void) noexcept;
extern "C" void _isr140(void) noexcept;
extern "C" void _isr141(void) noexcept;
extern "C" void _isr142(void) noexcept;
extern "C" void _isr143(void) noexcept;
extern "C" void _isr144(void) noexcept;
extern "C" void _isr145(void) noexcept;
extern "C" void _isr146(void) noexcept;
extern "C" void _isr147(void) noexcept;
extern "C" void _isr148(void) noexcept;
extern "C" void _isr149(void) noexcept;
extern "C" void _isr150(void) noexcept;
extern "C" void _isr151(void) noexcept;
extern "C" void _isr152(void) noexcept;
extern "C" void _isr153(void) noexcept;
extern "C" void _isr154(void) noexcept;
extern "C" void _isr155(void) noexcept;
extern "C" void _isr156(void) noexcept;
extern "C" void _isr157(void) noexcept;
extern "C" void _isr158(void) noexcept;
extern "C" void _isr159(void) noexcept;
extern "C" void _isr160(void) noexcept;
extern "C" void _isr161(void) noexcept;
extern "C" void _isr162(void) noexcept;
extern "C" void _isr163(void) noexcept;
extern "C" void _isr164(void) noexcept;
extern "C" void _isr165(void) noexcept;
extern "C" void _isr166(void) noexcept;
extern "C" void _isr167(void) noexcept;
extern "C" void _isr168(void) noexcept;
extern "C" void _isr169(void) noexcept;
extern "C" void _isr170(void) noexcept;
extern "C" void _isr171(void) noexcept;
extern "C" void _isr172(void) noexcept;
extern "C" void _isr173(void) noexcept;
extern "C" void _isr174(void) noexcept;
extern "C" void _isr175(void) noexcept;
extern "C" void _isr176(void) noexcept;
extern "C" void _isr177(void) noexcept;
extern "C" void _isr178(void) noexcept;
extern "C" void _isr179(void) noexcept;
extern "C" void _isr180(void) noexcept;
extern "C" void _isr181(void) noexcept;
extern "C" void _isr182(void) noexcept;
extern "C" void _isr183(void) noexcept;
extern "C" void _isr184(void) noexcept;
extern "C" void _isr185(void) noexcept;
extern "C" void _isr186(void) noexcept;
extern "C" void _isr187(void) noexcept;
extern "C" void _isr188(void) noexcept;
extern "C" void _isr189(void) noexcept;
extern "C" void _isr190(void) noexcept;
extern "C" void _isr191(void) noexcept;
extern "C" void _isr192(void) noexcept;
extern "C" void _isr193(void) noexcept;
extern "C" void _isr194(void) noexcept;
extern "C" void _isr195(void) noexcept;
extern "C" void _isr196(void) noexcept;
extern "C" void _isr197(void) noexcept;
extern "C" void _isr198(void) noexcept;
extern "C" void _isr199(void) noexcept;
extern "C" void _isr200(void) noexcept;
extern "C" void _isr201(void) noexcept;
extern "C" void _isr202(void) noexcept;
extern "C" void _isr203(void) noexcept;
extern "C" void _isr204(void) noexcept;
extern "C" void _isr205(void) noexcept;
extern "C" void _isr206(void) noexcept;
extern "C" void _isr207(void) noexcept;
extern "C" void _isr208(void) noexcept;
extern "C" void _isr209(void) noexcept;
extern "C" void _isr210(void) noexcept;
extern "C" void _isr211(void) noexcept;
extern "C" void _isr212(void) noexcept;
extern "C" void _isr213(void) noexcept;
extern "C" void _isr214(void) noexcept;
extern "C" void _isr215(void) noexcept;
extern "C" void _isr216(void) noexcept;
extern "C" void _isr217(void) noexcept;
extern "C" void _isr218(void) noexcept;
extern "C" void _isr219(void) noexcept;
extern "C" void _isr220(void) noexcept;
extern "C" void _isr221(void) noexcept;
extern "C" void _isr222(void) noexcept;
extern "C" void _isr223(void) noexcept;
extern "C" void _isr224(void) noexcept;
extern "C" void _isr225(void) noexcept;
extern "C" void _isr226(void) noexcept;
extern "C" void _isr227(void) noexcept;
extern "C" void _isr228(void) noexcept;
extern "C" void _isr229(void) noexcept;
extern "C" void _isr230(void) noexcept;
extern "C" void _isr231(void) noexcept;
extern "C" void _isr232(void) noexcept;
extern "C" void _isr233(void) noexcept;
extern "C" void _isr234(void) noexcept;
extern "C" void _isr235(void) noexcept;
extern "C" void _isr236(void) noexcept;
extern "C" void _isr237(void) noexcept;
extern "C" void _isr238(void) noexcept;
extern "C" void _isr239(void) noexcept;
extern "C" void _isr240(void) noexcept;
extern "C" void _isr241(void) noexcept;
extern "C" void _isr242(void) noexcept;
extern "C" void _isr243(void) noexcept;
extern "C" void _isr244(void) noexcept;
extern "C" void _isr245(void) noexcept;
extern "C" void _isr246(void) noexcept;
extern "C" void _isr247(void) noexcept;
extern "C" void _isr248(void) noexcept;
extern "C" void _isr249(void) noexcept;
extern "C" void _isr250(void) noexcept;
extern "C" void _isr251(void) noexcept;
extern "C" void _isr252(void) noexcept;
extern "C" void _isr253(void) noexcept;
extern "C" void _isr254(void) noexcept;
extern "C" void _isr255(void) noexcept;

/// @endcond

// -----------------------------------------------------------------------------
// VMM State Implementation
// -----------------------------------------------------------------------------

vmcs_intel_x64_vmm_state_eapis::vmcs_intel_x64_vmm_state_eapis()
{
    m_idt.set(0, _isr0, 0x8);
    m_idt.set(1, _isr1, 0x8);
    m_idt.set(2, _isr2, 0x8);
    m_idt.set(3, _isr3, 0x8);
    m_idt.set(4, _isr4, 0x8);
    m_idt.set(5, _isr5, 0x8);
    m_idt.set(6, _isr6, 0x8);
    m_idt.set(7, _isr7, 0x8);
    m_idt.set(8, _isr8, 0x8);
    m_idt.set(9, _isr9, 0x8);
    m_idt.set(10, _isr10, 0x8);
    m_idt.set(11, _isr11, 0x8);
    m_idt.set(12, _isr12, 0x8);
    m_idt.set(13, _isr13, 0x8);
    m_idt.set(14, _isr14, 0x8);
    m_idt.set(15, _isr15, 0x8);
    m_idt.set(16, _isr16, 0x8);
    m_idt.set(17, _isr17, 0x8);
    m_idt.set(18, _isr18, 0x8);
    m_idt.set(19, _isr19, 0x8);
    m_idt.set(20, _isr20, 0x8);
    m_idt.set(21, _isr21, 0x8);
    m_idt.set(22, _isr22, 0x8);
    m_idt.set(23, _isr23, 0x8);
    m_idt.set(24, _isr24, 0x8);
    m_idt.set(25, _isr25, 0x8);
    m_idt.set(26, _isr26, 0x8);
    m_idt.set(27, _isr27, 0x8);
    m_idt.set(28, _isr28, 0x8);
    m_idt.set(29, _isr29, 0x8);
    m_idt.set(30, _isr30, 0x8);
    m_idt.set(31, _isr31, 0x8);
    m_idt.set(32, _isr32, 0x8);
    m_idt.set(33, _isr33, 0x8);
    m_idt.set(34, _isr34, 0x8);
    m_idt.set(35, _isr35, 0x8);
    m_idt.set(36, _isr36, 0x8);
    m_idt.set(37, _isr37, 0x8);
    m_idt.set(38, _isr38, 0x8);
    m_idt.set(39, _isr39, 0x8);
    m_idt.set(40, _isr40, 0x8);
    m_idt.set(41, _isr41, 0x8);
    m_idt.set(42, _isr42, 0x8);
    m_idt.set(43, _isr43, 0x8);
    m_idt.set(44, _isr44, 0x8);
    m_idt.set(45, _isr45, 0x8);
    m_idt.set(46, _isr46, 0x8);
    m_idt.set(47, _isr47, 0x8);
    m_idt.set(48, _isr48, 0x8);
    m_idt.set(49, _isr49, 0x8);
    m_idt.set(50, _isr50, 0x8);
    m_idt.set(51, _isr51, 0x8);
    m_idt.set(52, _isr52, 0x8);
    m_idt.set(53, _isr53, 0x8);
    m_idt.set(54, _isr54, 0x8);
    m_idt.set(55, _isr55, 0x8);
    m_idt.set(56, _isr56, 0x8);
    m_idt.set(57, _isr57, 0x8);
    m_idt.set(58, _isr58, 0x8);
    m_idt.set(59, _isr59, 0x8);
    m_idt.set(60, _isr60, 0x8);
    m_idt.set(61, _isr61, 0x8);
    m_idt.set(62, _isr62, 0x8);
    m_idt.set(63, _isr63, 0x8);
    m_idt.set(64, _isr64, 0x8);
    m_idt.set(65, _isr65, 0x8);
    m_idt.set(66, _isr66, 0x8);
    m_idt.set(67, _isr67, 0x8);
    m_idt.set(68, _isr68, 0x8);
    m_idt.set(69, _isr69, 0x8);
    m_idt.set(70, _isr70, 0x8);
    m_idt.set(71, _isr71, 0x8);
    m_idt.set(72, _isr72, 0x8);
    m_idt.set(73, _isr73, 0x8);
    m_idt.set(74, _isr74, 0x8);
    m_idt.set(75, _isr75, 0x8);
    m_idt.set(76, _isr76, 0x8);
    m_idt.set(77, _isr77, 0x8);
    m_idt.set(78, _isr78, 0x8);
    m_idt.set(79, _isr79, 0x8);
    m_idt.set(80, _isr80, 0x8);
    m_idt.set(81, _isr81, 0x8);
    m_idt.set(82, _isr82, 0x8);
    m_idt.set(83, _isr83, 0x8);
    m_idt.set(84, _isr84, 0x8);
    m_idt.set(85, _isr85, 0x8);
    m_idt.set(86, _isr86, 0x8);
    m_idt.set(87, _isr87, 0x8);
    m_idt.set(88, _isr88, 0x8);
    m_idt.set(89, _isr89, 0x8);
    m_idt.set(90, _isr90, 0x8);
    m_idt.set(91, _isr91, 0x8);
    m_idt.set(92, _isr92, 0x8);
    m_idt.set(93, _isr93, 0x8);
    m_idt.set(94, _isr94, 0x8);
    m_idt.set(95, _isr95, 0x8);
    m_idt.set(96, _isr96, 0x8);
    m_idt.set(97, _isr97, 0x8);
    m_idt.set(98, _isr98, 0x8);
    m_idt.set(99, _isr99, 0x8);
    m_idt.set(100, _isr100, 0x8);
    m_idt.set(101, _isr101, 0x8);
    m_idt.set(102, _isr102, 0x8);
    m_idt.set(103, _isr103, 0x8);
    m_idt.set(104, _isr104, 0x8);
    m_idt.set(105, _isr105, 0x8);
    m_idt.set(106, _isr106, 0x8);
    m_idt.set(107, _isr107, 0x8);
    m_idt.set(108, _isr108, 0x8);
    m_idt.set(109, _isr109, 0x8);
    m_idt.set(110, _isr110, 0x8);
    m_idt.set(111, _isr111, 0x8);
    m_idt.set(112, _isr112, 0x8);
    m_idt.set(113, _isr113, 0x8);
    m_idt.set(114, _isr114, 0x8);
    m_idt.set(115, _isr115, 0x8);
    m_idt.set(116, _isr116, 0x8);
    m_idt.set(117, _isr117, 0x8);
    m_idt.set(118, _isr118, 0x8);
    m_idt.set(119, _isr119, 0x8);
    m_idt.set(120, _isr120, 0x8);
    m_idt.set(121, _isr121, 0x8);
    m_idt.set(122, _isr122, 0x8);
    m_idt.set(123, _isr123, 0x8);
    m_idt.set(124, _isr124, 0x8);
    m_idt.set(125, _isr125, 0x8);
    m_idt.set(126, _isr126, 0x8);
    m_idt.set(127, _isr127, 0x8);
    m_idt.set(128, _isr128, 0x8);
    m_idt.set(129, _isr129, 0x8);
    m_idt.set(130, _isr130, 0x8);
    m_idt.set(131, _isr131, 0x8);
    m_idt.set(132, _isr132, 0x8);
    m_idt.set(133, _isr133, 0x8);
    m_idt.set(134, _isr134, 0x8);
    m_idt.set(135, _isr135, 0x8);
    m_idt.set(136, _isr136, 0x8);
    m_idt.set(137, _isr137, 0x8);
    m_idt.set(138, _isr138, 0x8);
    m_idt.set(139, _isr139, 0x8);
    m_idt.set(140, _isr140, 0x8);
    m_idt.set(141, _isr141, 0x8);
    m_idt.set(142, _isr142, 0x8);
    m_idt.set(143, _isr143, 0x8);
    m_idt.set(144, _isr144, 0x8);
    m_idt.set(145, _isr145, 0x8);
    m_idt.set(146, _isr146, 0x8);
    m_idt.set(147, _isr147, 0x8);
    m_idt.set(148, _isr148, 0x8);
    m_idt.set(149, _isr149, 0x8);
    m_idt.set(150, _isr150, 0x8);
    m_idt.set(151, _isr151, 0x8);
    m_idt.set(152, _isr152, 0x8);
    m_idt.set(153, _isr153, 0x8);
    m_idt.set(154, _isr154, 0x8);
    m_idt.set(155, _isr155, 0x8);
    m_idt.set(156, _isr156, 0x8);
    m_idt.set(157, _isr157, 0x8);
    m_idt.set(158, _isr158, 0x8);
    m_idt.set(159, _isr159, 0x8);
    m_idt.set(160, _isr160, 0x8);
    m_idt.set(161, _isr161, 0x8);
    m_idt.set(162, _isr162, 0x8);
    m_idt.set(163, _isr163, 0x8);
    m_idt.set(164, _isr164, 0x8);
    m_idt.set(165, _isr165, 0x8);
    m_idt.set(166, _isr166, 0x8);
    m_idt.set(167, _isr167, 0x8);
    m_idt.set(168, _isr168, 0x8);
    m_idt.set(169, _isr169, 0x8);
    m_idt.set(170, _isr170, 0x8);
    m_idt.set(171, _isr171, 0x8);
    m_idt.set(172, _isr172, 0x8);
    m_idt.set(173, _isr173, 0x8);
    m_idt.set(174, _isr174, 0x8);
    m_idt.set(175, _isr175, 0x8);
    m_idt.set(176, _isr176, 0x8);
    m_idt.set(177, _isr177, 0x8);
    m_idt.set(178, _isr178, 0x8);
    m_idt.set(179, _isr179, 0x8);
    m_idt.set(180, _isr180, 0x8);
    m_idt.set(181, _isr181, 0x8);
    m_idt.set(182, _isr182, 0x8);
    m_idt.set(183, _isr183, 0x8);
    m_idt.set(184, _isr184, 0x8);
    m_idt.set(185, _isr185, 0x8);
    m_idt.set(186, _isr186, 0x8);
    m_idt.set(187, _isr187, 0x8);
    m_idt.set(188, _isr188, 0x8);
    m_idt.set(189, _isr189, 0x8);
    m_idt.set(190, _isr190, 0x8);
    m_idt.set(191, _isr191, 0x8);
    m_idt.set(192, _isr192, 0x8);
    m_idt.set(193, _isr193, 0x8);
    m_idt.set(194, _isr194, 0x8);
    m_idt.set(195, _isr195, 0x8);
    m_idt.set(196, _isr196, 0x8);
    m_idt.set(197, _isr197, 0x8);
    m_idt.set(198, _isr198, 0x8);
    m_idt.set(199, _isr199, 0x8);
    m_idt.set(200, _isr200, 0x8);
    m_idt.set(201, _isr201, 0x8);
    m_idt.set(202, _isr202, 0x8);
    m_idt.set(203, _isr203, 0x8);
    m_idt.set(204, _isr204, 0x8);
    m_idt.set(205, _isr205, 0x8);
    m_idt.set(206, _isr206, 0x8);
    m_idt.set(207, _isr207, 0x8);
    m_idt.set(208, _isr208, 0x8);
    m_idt.set(209, _isr209, 0x8);
    m_idt.set(210, _isr210, 0x8);
    m_idt.set(211, _isr211, 0x8);
    m_idt.set(212, _isr212, 0x8);
    m_idt.set(213, _isr213, 0x8);
    m_idt.set(214, _isr214, 0x8);
    m_idt.set(215, _isr215, 0x8);
    m_idt.set(216, _isr216, 0x8);
    m_idt.set(217, _isr217, 0x8);
    m_idt.set(218, _isr218, 0x8);
    m_idt.set(219, _isr219, 0x8);
    m_idt.set(220, _isr220, 0x8);
    m_idt.set(221, _isr221, 0x8);
    m_idt.set(222, _isr222, 0x8);
    m_idt.set(223, _isr223, 0x8);
    m_idt.set(224, _isr224, 0x8);
    m_idt.set(225, _isr225, 0x8);
    m_idt.set(226, _isr226, 0x8);
    m_idt.set(227, _isr227, 0x8);
    m_idt.set(228, _isr228, 0x8);
    m_idt.set(229, _isr229, 0x8);
    m_idt.set(230, _isr230, 0x8);
    m_idt.set(231, _isr231, 0x8);
    m_idt.set(232, _isr232, 0x8);
    m_idt.set(233, _isr233, 0x8);
    m_idt.set(234, _isr234, 0x8);
    m_idt.set(235, _isr235, 0x8);
    m_idt.set(236, _isr236, 0x8);
    m_idt.set(237, _isr237, 0x8);
    m_idt.set(238, _isr238, 0x8);
    m_idt.set(239, _isr239, 0x8);
    m_idt.set(240, _isr240, 0x8);
    m_idt.set(241, _isr241, 0x8);
    m_idt.set(242, _isr242, 0x8);
    m_idt.set(243, _isr243, 0x8);
    m_idt.set(244, _isr244, 0x8);
    m_idt.set(245, _isr245, 0x8);
    m_idt.set(246, _isr246, 0x8);
    m_idt.set(247, _isr247, 0x8);
    m_idt.set(248, _isr248, 0x8);
    m_idt.set(249, _isr249, 0x8);
    m_idt.set(250, _isr250, 0x8);
    m_idt.set(251, _isr251, 0x8);
    m_idt.set(252, _isr252, 0x8);
    m_idt.set(253, _isr253, 0x8);
    m_idt.set(254, _isr254, 0x8);
    m_idt.set(255, _isr255, 0x8);

    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE * 2);
    m_tss.ist1 = setup_stack(m_ist1.get());
}
