//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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


#include <vcpu/arch/intel_x64/vcpu.h>

namespace eapis
{
namespace intel_x64
{

vcpu::vcpu(vcpuid::type id) :
    bfvmm::intel_x64::vcpu{id}
{ }

gsl::not_null<control_register *>
vcpu::control_register()
{ return m_control_register.get(); }

void
vcpu::enable_wrcr0_exiting(
   vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    init_control_register();
    m_control_register->enable_wrcr0_exiting(mask, shadow);
}

void
vcpu::enable_wrcr4_exiting(
   vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    init_control_register();
    m_control_register->enable_wrcr4_exiting(mask, shadow);
}

void
vcpu::add_wrcr0_handler(control_register::handler_delegate_t &&d)
{
    init_control_register();
    m_control_register->add_wrcr0_handler(std::move(d));
}

void
vcpu::add_rdcr3_handler(control_register::handler_delegate_t &&d)
{
    check_rdcr3();
    m_control_register->add_rdcr3_handler(std::move(d));
}

void
vcpu::add_wrcr3_handler(control_register::handler_delegate_t &&d)
{
    check_wrcr3();
    m_control_register->add_wrcr3_handler(std::move(d));
}

void
vcpu::add_wrcr4_handler(control_register::handler_delegate_t &&d)
{
    init_control_register();
    m_control_register->add_wrcr4_handler(std::move(d));
}

void
vcpu::add_rdcr8_handler(control_register::handler_delegate_t &&d)
{
    check_rdcr8();
    m_control_register->add_rdcr8_handler(std::move(d));
}

void
vcpu::add_wrcr8_handler(control_register::handler_delegate_t &&d)
{
    check_wrcr8();
    m_control_register->add_wrcr8_handler(std::move(d));
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

gsl::not_null<cpuid *>
vcpu::cpuid()
{ return m_cpuid.get(); }

void
vcpu::add_cpuid_handler(
    cpuid::leaf_t leaf, cpuid::subleaf_t subleaf, cpuid::handler_delegate_t &&d)
{
    init_cpuid();
    m_cpuid->add_handler(leaf, subleaf, std::move(d));
}

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

gsl::not_null<monitor_trap *>
vcpu::monitor_trap()
{ return m_monitor_trap.get(); }

void
vcpu::add_monitor_trap_handler(monitor_trap::handler_delegate_t &&d)
{
    init_monitor_trap();
    m_monitor_trap->add_handler(std::move(d));
}

void
vcpu::enable_monitor_trap_flag()
{
    init_monitor_trap();
    m_monitor_trap->enable();
}

//--------------------------------------------------------------------------
// Move DR
//--------------------------------------------------------------------------

gsl::not_null<mov_dr *>
vcpu::mov_dr()
{ return m_mov_dr.get(); }

void
vcpu::add_mov_dr_handler(mov_dr::handler_delegate_t &&d)
{
    init_mov_dr();
    m_mov_dr->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

gsl::not_null<rdmsr *>
vcpu::rdmsr()
{ return m_rdmsr.get(); }

void
vcpu::pass_through_all_rdmsr_accesses()
{ init_rdmsr(); }

void
vcpu::add_rdmsr_handler(
   vmcs_n::value_type msr, rdmsr::handler_delegate_t &&d)
{
    init_rdmsr();
    m_rdmsr->add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

gsl::not_null<vpid *>
vcpu::vpid()
{ return m_vpid.get(); }

void
vcpu::enable_vpid()
{
    init_vpid();
    m_vpid->enable();
}

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

gsl::not_null<wrmsr *>
vcpu::wrmsr()
{ return m_wrmsr.get(); }

void
vcpu::pass_through_all_wrmsr_accesses()
{ init_wrmsr(); }

void
vcpu::add_wrmsr_handler(
   vmcs_n::value_type msr, wrmsr::handler_delegate_t &&d)
{
    init_wrmsr();
    m_wrmsr->add_handler(msr, std::move(d));
}

void
vcpu::init_control_register()
{
    if (!m_control_register) {
        m_control_register = std::make_unique<eapis::intel_x64::control_register>(this);
    }
}

void
vcpu::check_rdcr3()
{
    init_control_register();

    if (!m_is_rdcr3_enabled) {
        m_is_rdcr3_enabled = true;
        m_control_register->enable_rdcr3_exiting();
    }
}

void
vcpu::check_wrcr3()
{
    init_control_register();

    if (!m_is_wrcr3_enabled) {
        m_is_wrcr3_enabled = true;
        m_control_register->enable_wrcr3_exiting();
    }
}

void
vcpu::check_rdcr8()
{
    init_control_register();

    if (!m_is_rdcr8_enabled) {
        m_is_rdcr8_enabled = true;
        m_control_register->enable_rdcr8_exiting();
    }
}

void
vcpu::check_wrcr8()
{
    init_control_register();

    if (!m_is_wrcr8_enabled) {
        m_is_wrcr8_enabled = true;
        m_control_register->enable_wrcr8_exiting();
    }
}

void
vcpu::init_cpuid()
{
    if (!m_cpuid) {
        m_cpuid = std::make_unique<eapis::intel_x64::cpuid>(this);
    }
}

void
vcpu::init_monitor_trap()
{
    m_monitor_trap = std::make_unique<eapis::intel_x64::monitor_trap>(this);
}

void
vcpu::init_mov_dr()
{
    if (!m_mov_dr) {
        m_mov_dr = std::make_unique<eapis::intel_x64::mov_dr>(this);
    }
}

void
vcpu::check_msr_bitmap()
{
    using namespace vmcs_n;

    if (!m_msr_bitmap) {
        m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::page_size);

        address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
        primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    }
}

void
vcpu::init_rdmsr()
{
    check_msr_bitmap();

    if (!m_rdmsr) {
        m_rdmsr = std::make_unique<eapis::intel_x64::rdmsr>(this);
    }
}

void
vcpu::init_wrmsr()
{
    check_msr_bitmap();

    if (!m_wrmsr) {
        m_wrmsr = std::make_unique<eapis::intel_x64::wrmsr>(this);
    }
}

void
vcpu::init_vpid()
{
    if (!m_vpid) {
        m_vpid = std::make_unique<eapis::intel_x64::vpid>();
    }
}

gsl::span<uint8_t>
vcpu::msr_bitmap()
{ return gsl::make_span<uint8_t>(m_msr_bitmap.get(), ::x64::page_size); }

}
}
