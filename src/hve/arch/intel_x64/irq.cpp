//
// Bareflank Extended APIs
//
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

#include <utility>
#include <hve/arch/intel_x64/irq.h>

namespace eapis
{
namespace intel_x64
{

/// ---------------------------------------------------------------------------
/// Namespace aliases
/// ---------------------------------------------------------------------------

namespace exit_irq_info = ::intel_x64::vmcs::vm_exit_interruption_information;
namespace exit_ctl = ::intel_x64::vmcs::vm_exit_controls;
namespace pin_ctl = ::intel_x64::vmcs::pin_based_vm_execution_controls;
namespace ack_on_exit = exit_ctl::acknowledge_interrupt_on_exit;
namespace irq_exiting = pin_ctl::external_interrupt_exiting;

/// ---------------------------------------------------------------------------
/// Helpers
/// ---------------------------------------------------------------------------

static irq::info_t
parse_info(gsl::not_null<irq::vmcs_t *> vmcs)
{
    return { exit_irq_info::vector::get() };
}

/// ---------------------------------------------------------------------------
/// Implementation
/// ---------------------------------------------------------------------------

irq::irq(gsl::not_null<exit_handler_t *> exit_handler)
:
    m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        reason::external_interrupt,
        handler_delegate_t::create<irq_t, &irq_t::handle>(this)
    );
}

void
irq::add_handler(vector_t vector, handler_t &&d)
{
    m_handlers[vector].push_front(std::move(d));
}

void
irq::trap()
{
    ack_on_exit::enable();
    irq_exiting::enable();
}

void
irq::pass_through()
{
    ack_on_exit::disable();
    irq_exiting::disable();
}

bool
irq::handle(gsl::not_null<vmcs_t *> vmcs)
{
    auto info = parse_info(vmcs);
    for (const auto &d : m_handlers[info.vec]) {
        if (d(vmcs, info)) {
            return true;
        }
    }

    return false;
}

} // namespace intel_x64
} // namespace eapis
