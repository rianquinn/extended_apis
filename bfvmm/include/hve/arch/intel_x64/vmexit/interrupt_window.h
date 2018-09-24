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

#ifndef INTERRUPT_WINDOW_INTEL_X64_EAPIS_H
#define INTERRUPT_WINDOW_INTEL_X64_EAPIS_H

#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>

#include "../interrupt_queue.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis::intel_x64
{

class vcpu;

/// Interrupt window
///
/// Provides an interface for registering handlers of the interrupt-window exit.
///
class EXPORT_EAPIS_HVE interrupt_window_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this interrupt window handler
    ///
    interrupt_window_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_window_handler() = default;

public:

    /// Queue External Interrupt
    ///
    /// Queue an external interrupt at the given vector on the
    /// next upcoming open interrupt window.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    ///
    void queue_external_interrupt(uint64_t vector);

    /// Inject General Protection Fault
    ///
    /// Queues a general protection fault (ec = 0). The injection of a GPF can
    /// occur at any time, and so no window is needed.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void inject_gpf();

public:

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    void enable_exiting();
    void disable_exiting();

    bool is_open();

    void inject_exception(uint64_t vector);
    void inject_external_interrupt(uint64_t vector);

private:

    vcpu *m_vcpu;
    interrupt_queue m_interrupt_queue;

public:

    /// @cond

    interrupt_window_handler(interrupt_window_handler &&) = default;
    interrupt_window_handler &operator=(interrupt_window_handler &&) = default;

    interrupt_window_handler(const interrupt_window_handler &) = delete;
    interrupt_window_handler &operator=(const interrupt_window_handler &) = delete;

    /// @endcond
};

}

#endif