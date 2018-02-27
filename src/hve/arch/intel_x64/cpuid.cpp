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
#include <hve/arch/intel_x64/cpuid.h>

namespace eapis
{
namespace intel_x64
{

cpuid::cpuid(
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler)
:
    m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid,
        handler_delegate_t::create<cpuid, &cpuid::handle_cpuid>(this)
    );
}

cpuid::~cpuid()
{
    if(!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// CR0
// -----------------------------------------------------------------------------

void cpuid::add_cpuid_handler(
    leaf_t leaf, subleaf_t subleaf, cpuid_handler_delegate_t &&d)
{ m_cpuid_handlers[{leaf, subleaf}].push_front(std::move(d)); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

#ifndef NDEBUG

void
cpuid::enable_log()
{ m_log_enabled = true; }

void
cpuid::disable_log()
{ m_log_enabled = false; }

void
cpuid::dump_log()
{
    // bfdebug_transaction(0, [&](std::string * msg) {
    //     bfdebug_lnbr(0, msg);
    //     bfdebug_info(0, "cpuid log", msg);
    //     bfdebug_brk2(0, msg);

    //     bfdebug_info(0, "wrcr0 log", msg);
    //     for(const auto &val : m_wrcr0_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_info(0, "rdcr3 log", msg);
    //     for(const auto &val : m_rdcr3_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_info(0, "wrcr3 log", msg);
    //     for(const auto &val : m_wrcr3_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_info(0, "wrcr4 log", msg);
    //     for(const auto &val : m_wrcr4_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_info(0, "rdcr8 log", msg);
    //     for(const auto &val : m_rdcr8_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_info(0, "wrcr8 log", msg);
    //     for(const auto &val : m_wrcr8_log) {
    //         bfdebug_subnhex(0, "value", val, msg);
    //     }

    //     bfdebug_lnbr(0, msg);
    // });
}

#endif

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid::handle_cpuid(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    const auto &hdlrs = m_cpuid_handlers.find(
        {vmcs->save_state()->rax, vmcs->save_state()->rcx}
    );

    if (GSL_LIKELY(hdlrs != m_cpuid_handlers.end())) {

        auto ret = ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
        );

        struct info_t info = {
            ret.rax,
            ret.rbx,
            ret.rcx,
            ret.rdx,
            false,
            false
        };

        if (!ndebug && m_log_enabled) {
            m_log.push_back({
                info.rax,
                info.rbx,
                info.rcx,
                info.rdx,
                false
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    set_bits(vmcs->save_state()->rax, 0x00000000FFFFFFFF, info.rax);
                    set_bits(vmcs->save_state()->rbx, 0x00000000FFFFFFFF, info.rbx);
                    set_bits(vmcs->save_state()->rcx, 0x00000000FFFFFFFF, info.rcx);
                    set_bits(vmcs->save_state()->rdx, 0x00000000FFFFFFFF, info.rdx);

                    if (!ndebug && m_log_enabled) {
                        m_log.push_back({
                            info.rax,
                            info.rbx,
                            info.rcx,
                            info.rdx,
                            true
                        });
                    }
                }

                if(!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

    return false;
}

}
}
