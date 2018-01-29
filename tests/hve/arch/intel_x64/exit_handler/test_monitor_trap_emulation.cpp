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

TEST_CASE("exit_handler_intel_x64_eapis_monitor_trap_emulation: exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->register_monitor_trap(&exit_handler_ut::monitor_trap_callback);
    CHECK_NOTHROW(ehlr->dispatch());
}

TEST_CASE("exit_handler_intel_x64_eapis_monitor_trap_emulation: register trap")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->register_monitor_trap(&exit_handler_ut::monitor_trap_callback);
    ehlr->dispatch();
    ehlr->clear_monitor_trap();

    CHECK(g_monitor_trap_callback_called);
    CHECK_THROWS(ehlr->dispatch());
}

TEST_CASE("exit_handler_intel_x64_eapis_monitor_trap_emulation: clear trap")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_THROWS(ehlr->dispatch());
}

#endif