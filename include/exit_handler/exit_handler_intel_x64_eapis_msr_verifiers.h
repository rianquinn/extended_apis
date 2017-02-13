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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_MSR_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_MSR_VERIFIERS_H

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

class default_verifier__enable_msr_bitmap : public vmcall_verifier
{
public:
    default_verifier__enable_msr_bitmap() = default;
    ~default_verifier__enable_msr_bitmap() override = default;

    verifier_result verify(bool enabled)
    { (void) enabled; return default_verify(); }
};

#endif