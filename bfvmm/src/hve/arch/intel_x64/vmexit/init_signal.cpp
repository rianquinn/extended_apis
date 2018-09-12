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

#include <bfdebug.h>
#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

init_signal_handler::init_signal_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::init_signal,
        ::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle>(this)
    );

    apis->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_x2apic_icr::addr,
        wrmsr_handler::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle_icr_write>(this)
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool g_handled = false;

static void
wait_until_handled() noexcept
{
    while (!g_handled) {
        ::intel_x64::pause();
    }
}

bool
init_signal_handler::handle_icr_write(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
{
    bfignored(vmcs);

    switch (::intel_x64::lapic::icr::delivery_mode::get(info.val)) {
        case ::intel_x64::lapic::icr::delivery_mode::init:
            if (::intel_x64::lapic::icr::level::is_disabled(info.val)) {
                break;
            }

            ::intel_x64::msrs::set(::intel_x64::msrs::ia32_x2apic_icr::addr, info.val);
            wait_until_handled();

            // We set this to false so that the next AP(s) will boot too
            // This code assumes that APs are brought up sequentially
            g_handled = false;
            info.ignore_write = true;
            break;

        default:
            break;
    }

    return true;
}

bool
init_signal_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::wait_for_sipi
    );

    g_handled = true;
    return true;
}

}
}
