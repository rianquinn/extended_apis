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

#ifndef INIT_SIGNAL_INTEL_X64_EAPIS_H
#define INIT_SIGNAL_INTEL_X64_EAPIS_H

#include "../base.h"
#include "wrmsr.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;

/// INIT signal
///
/// Provides an interface for registering handlers of the INIT signal exit.
///
class EXPORT_EAPIS_HVE init_signal_handler : public base
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this INIT signal handler
    ///
    init_signal_handler(gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~init_signal_handler() final = default;

public:

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final
    { }

public:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);
    bool handle_icr_write(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);

    /// @endcond

public:

    /// @cond

    init_signal_handler(init_signal_handler &&) = default;
    init_signal_handler &operator=(init_signal_handler &&) = default;

    init_signal_handler(const init_signal_handler &) = delete;
    init_signal_handler &operator=(const init_signal_handler &) = delete;

    /// @endcond
};

}
}

#endif
