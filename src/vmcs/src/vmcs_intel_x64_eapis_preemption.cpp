//
// Bareflank Extended APIs
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

#include <intrinsics/msrs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_preemption_timer()
{
    pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();
    vm_exit_controls::save_vmx_preemption_timer_value::enable();

    auto &&bit = intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();
    m_preemption_multiplier = (1UL << bit);

    clear_preemption_timer();
}

void
vmcs_intel_x64_eapis::disable_preemption_timer()
{
    pin_based_vm_execution_controls::activate_vmx_preemption_timer::disable();
    vm_exit_controls::save_vmx_preemption_timer_value::disable();

    clear_preemption_timer();
}

void
vmcs_intel_x64_eapis::set_preemption_timer(preemption_value_type val)
{
    if (m_preemption_multiplier == 0)
        throw std::runtime_error("set_preemption_timer failed: either enable_preemption_timer has not been run, or the preemption timer is not allowed");

    vmx_preemption_timer_value::set(val / m_preemption_multiplier);
}

vmcs_intel_x64_eapis::preemption_value_type
vmcs_intel_x64_eapis::get_preemption_timer() const
{
    if (m_preemption_multiplier == 0)
        throw std::runtime_error("set_preemption_timer failed: either enable_preemption_timer has not been run, or the preemption timer is not allowed");

    return m_preemption_multiplier * vmx_preemption_timer_value::get();
}

void
vmcs_intel_x64_eapis::clear_preemption_timer()
{
    if (m_preemption_multiplier == 0)
        return;

    vmx_preemption_timer_value::set(0UL);
}
