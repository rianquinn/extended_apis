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

#include <test_support.h>
#include <catch/catch.hpp>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(ehlr->m_io_access_log[42] == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: log io access enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    g_vmcs[primary_processor_based_vm_execution_controls::addr] = 0xFFFFFFFFFFFFFFFF;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 1);
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled());

    g_vmcs[vmcs::exit_reason::addr] = exit_reason::basic_exit_reason::monitor_trap_flag;
    ehlr->dispatch();
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: log io access disabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(false);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    g_vmcs[primary_processor_based_vm_execution_controls::addr] = 0xFFFFFFFFFFFFFFFF;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 0);
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled());

    g_vmcs[vmcs::exit_reason::addr] = exit_reason::basic_exit_reason::monitor_trap_flag;
    ehlr->dispatch();
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: clear io access log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 1);
    ehlr->clear_io_access_log();
    CHECK(ehlr->m_io_access_log[42] == 0);
}

#endif