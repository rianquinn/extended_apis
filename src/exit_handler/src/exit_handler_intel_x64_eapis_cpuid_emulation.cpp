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

#include <exit_handler/exit_handler_intel_x64_eapis.h>

void
exit_handler_intel_x64_eapis::log_cpuid_access(bool enable)
{ m_cpuid_access_log_enabled = enable; }

void
exit_handler_intel_x64_eapis::clear_cpuid_access_log()
{ m_cpuid_access_log.clear(); }

void
exit_handler_intel_x64_eapis::handle_exit__cpuid()
{
    cpuid_key_type leaf = m_state_save->rax;
    cpuid_key_type subleaf = m_state_save->rcx;
    cpuid_key_type key = create_key(leaf, subleaf);

    if (m_cpuid_access_log_enabled) {
        m_cpuid_access_log[key]++;
    }

    auto i = m_cpuid_emu_map.find(key);
    if (i != m_cpuid_emu_map.end()) {
        auto regs = i->second;
        m_state_save->rax = regs.rax;
        m_state_save->rbx = regs.rbx;
        m_state_save->rcx = regs.rcx;
        m_state_save->rdx = regs.rdx;

        advance_rip();
    }
    else {
        this->handle_cpuid();
    }

    this->resume();
}
