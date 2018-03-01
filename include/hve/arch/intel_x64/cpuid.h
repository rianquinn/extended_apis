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

#ifndef CPUID_INTEL_X64_EAPIS_H
#define CPUID_INTEL_X64_EAPIS_H

#include <bfgsl.h>

#include <list>
#include <utility>
#include <unordered_map>

#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>

#ifndef CPUID_LOG_MAX
#define CPUID_LOG_MAX 10
#endif

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

struct pair_hash {
    template <typename T1, typename T2>
    std::size_t operator () (const std::pair<T1,T2> &p) const {
        return ((std::hash<T1>{}(p.first) & 0x00000000FFFFFFFF) > 0) |
               ((std::hash<T2>{}(p.second) & 0xFFFFFFFF00000000) > 32);
    }
};

class EXPORT_EAPIS_HVE cpuid
{
public:

    using leaf_t = uint64_t;
    using subleaf_t = uint64_t;

    struct info_t {
        uint64_t rax;           // In / Out
        uint64_t rbx;           // In / Out
        uint64_t rcx;           // In / Out
        uint64_t rdx;           // In / Out
        bool ignore_write;      // Out
        bool ignore_advance;    // Out
    };

    using cpuid_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    cpuid(
        gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid();

public:

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_cpuid_handler(
        leaf_t leaf, subleaf_t subleaf, cpuid_handler_delegate_t &&d);

#ifndef NDEBUG
public:

    /// Enable Log
    ///
    /// Example:
    /// @code
    /// this->enable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_log();

    /// Disable Log
    ///
    /// Example:
    /// @code
    /// this->disable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_log();

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
    void dump_log();
#endif

public:

    /// @cond

    bool handle_cpuid(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

    /// @endcond

private:

    bfvmm::intel_x64::exit_handler *m_exit_handler;
    std::unordered_map<std::pair<leaf_t, subleaf_t>, std::list<cpuid_handler_delegate_t>, pair_hash> m_cpuid_handlers;

private:

    struct cpuid_record_t {
        uint64_t leaf;
        uint64_t subleaf;
        uint64_t rax;
        uint64_t rbx;
        uint64_t rcx;
        uint64_t rdx;
        bool out;
    };

    bool m_log_enabled{false};
    std::list<cpuid_record_t> m_log;

    void add_record(const cpuid_record_t &record)
    {
        if (m_log.size() < CPUID_LOG_MAX) {
            m_log.push_back(record);
        }
    }

public:

    /// @cond

    cpuid(cpuid &&) = default;
    cpuid &operator=(cpuid &&) = default;

    cpuid(const cpuid &) = delete;
    cpuid &operator=(const cpuid &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
