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

#include <algorithm>
#include <iterator>

#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/vcpu/arch/intel_x64/vcpu.h>

#include "../../../hve/arch/intel_x64/control_register.h"
#include "../../../hve/arch/intel_x64/cpuid.h"
#include "../../../hve/arch/intel_x64/monitor_trap.h"
#include "../../../hve/arch/intel_x64/mov_dr.h"
#include "../../../hve/arch/intel_x64/rdmsr.h"
#include "../../../hve/arch/intel_x64/vpid.h"
#include "../../../hve/arch/intel_x64/wrmsr.h"

namespace eapis
{
namespace intel_x64
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:

    using handler_list_t = std::unordered_map<vmcs_n::value_type, base *>;
    const static std::list<vmcs_n::value_type> s_available_handlers;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id},
        m_used_handlers{&s_available_handlers}
    {
        init_handlers();
    }

    /// Constructor with specified handlers
    ///
    /// @expects
    /// @ensures
    ///
    vcpu(vcpuid::type id, std::list<vmcs_n::value_type> *needed_handlers) :
        bfvmm::intel_x64::vcpu{id},
        m_used_handlers{needed_handlers}
    {
        init_handlers();
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

public:

    /// Handlers
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the list of handlers this vcpu is using
    ///
    gsl::not_null<handler_list_t *> handlers()
    { return &m_handlers; }

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Get Control Register Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CR object stored in the vCPU if CR trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<control_register *> control_register()
    { return m_control_register.get(); }

    /// Enable Write CR0 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr0_exiting(
       vmcs_n::value_type mask, vmcs_n::value_type shadow)
    {
        init_control_register();
        m_control_register->enable_wrcr0_exiting(mask, shadow);
    }

    /// Enable Write CR4 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr4_exiting(
       vmcs_n::value_type mask, vmcs_n::value_type shadow)
    {
        init_control_register();
        m_control_register->enable_wrcr4_exiting(mask, shadow);
    }

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_wrcr0_handler(control_register::handler_delegate_t &&d)
    {
        init_control_register();
        m_control_register->add_wrcr0_handler(std::move(d));
    }

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_rdcr3_handler(control_register::handler_delegate_t &&d)
    {
        check_rdcr3();
        m_control_register->add_rdcr3_handler(std::move(d));
    }

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_wrcr3_handler(control_register::handler_delegate_t &&d)
    {
        check_wrcr3();
        m_control_register->add_wrcr3_handler(std::move(d));
    }

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_wrcr4_handler(control_register::handler_delegate_t &&d)
    {
        init_control_register();
        m_control_register->add_wrcr4_handler(std::move(d));
    }

    /// Add Read CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_rdcr8_handler(control_register::handler_delegate_t &&d)
    {
        check_rdcr8();
        m_control_register->add_rdcr8_handler(std::move(d));
    }

    /// Add Write CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_wrcr8_handler(control_register::handler_delegate_t &&d)
    {
        check_wrcr8();
        m_control_register->add_wrcr8_handler(std::move(d));
    }

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID object stored in the vCPU if CPUID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<cpuid *> cpuid()
    { return m_cpuid.get(); }

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_cpuid_handler(
        cpuid::leaf_t leaf, cpuid::subleaf_t subleaf, cpuid::handler_delegate_t &&d)
    {
        init_cpuid();
        m_cpuid->add_handler(leaf, subleaf, std::move(d));
    }

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Get Monitor Trap Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Monitor Trap object stored in the vCPU if Monitor
    ///     Trap is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<monitor_trap *> monitor_trap()
    { return m_monitor_trap.get(); }

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_monitor_trap_handler(monitor_trap::handler_delegate_t &&d)
    {
        init_monitor_trap();
        m_monitor_trap->add_handler(std::move(d));
    }

    /// Enable Monitor Trap Flag
    ///
    /// @expects
    /// @ensures
    ///
    void enable_monitor_trap_flag()
    {
        init_monitor_trap();
        m_monitor_trap->enable();
    }

    //--------------------------------------------------------------------------
    // Move DR
    //--------------------------------------------------------------------------

    /// Get Move DR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Move DR object stored in the vCPU if Move DR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<mov_dr *> mov_dr()
    { return m_mov_dr.get(); }

    /// Add Move DR Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_mov_dr_handler(mov_dr::handler_delegate_t &&d)
    {
        init_mov_dr();
        m_mov_dr->add_handler(std::move(d));
    }

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Get Read MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Read MSR object stored in the vCPU if Read MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<rdmsr *> rdmsr()
    { return m_rdmsr.get(); }

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_accesses()
    { init_rdmsr(); }

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_rdmsr_handler(
       vmcs_n::value_type msr, rdmsr::handler_delegate_t &&d)
    {
        init_rdmsr();
        m_rdmsr->add_handler(msr, std::move(d));
    }

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Get VPID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID object stored in the vCPU if VPID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<vpid *> vpid()
    { return m_vpid.get(); }

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    void enable_vpid()
    {
        init_vpid();
        m_vpid->enable();
    }

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Get Write MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Write MSR object stored in the vCPU if Write MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<wrmsr *> wrmsr()
    { return m_wrmsr.get(); }

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_accesses()
    { init_wrmsr(); }

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    void add_wrmsr_handler(
       vmcs_n::value_type msr, wrmsr::handler_delegate_t &&d)
    {
        init_wrmsr();
        m_wrmsr->add_handler(msr, std::move(d));
    }

private:

    void init_control_register()
    {
        if (!m_control_register) {
            m_control_register = std::make_unique<eapis::intel_x64::control_register>(this->exit_handler());
            m_handlers[vmcs_n::exit_reason::basic_exit_reason::control_register_accesses] = m_control_register.get();
        }
    }

    void check_rdcr3()
    {
        init_control_register();

        if (!m_is_rdcr3_enabled) {
            m_is_rdcr3_enabled = true;
            m_control_register->enable_rdcr3_exiting();
        }
    }

    void check_wrcr3()
    {
        init_control_register();

        if (!m_is_wrcr3_enabled) {
            m_is_wrcr3_enabled = true;
            m_control_register->enable_wrcr3_exiting();
        }
    }

    void check_rdcr8()
    {
        init_control_register();

        if (!m_is_rdcr8_enabled) {
            m_is_rdcr8_enabled = true;
            m_control_register->enable_rdcr8_exiting();
        }
    }

    void check_wrcr8()
    {
        init_control_register();

        if (!m_is_wrcr8_enabled) {
            m_is_wrcr8_enabled = true;
            m_control_register->enable_wrcr8_exiting();
        }
    }

    void init_cpuid()
    {
        if (!m_cpuid) {
            m_cpuid = std::make_unique<eapis::intel_x64::cpuid>(this->exit_handler());
            m_handlers[vmcs_n::exit_reason::basic_exit_reason::cpuid] = m_cpuid.get();
        }
    }

    void init_monitor_trap()
    {
        m_monitor_trap = std::make_unique<eapis::intel_x64::monitor_trap>(this->exit_handler());
        m_handlers[vmcs_n::exit_reason::basic_exit_reason::monitor_trap_flag] = m_monitor_trap.get();
    }

    void init_mov_dr()
    {
        if (!m_mov_dr) {
            m_mov_dr = std::make_unique<eapis::intel_x64::mov_dr>(this->exit_handler());
            m_handlers[vmcs_n::exit_reason::basic_exit_reason::mov_dr] = m_mov_dr.get();
        }
    }

    void check_msr_bitmap()
    {
        using namespace vmcs_n;

        if (!m_msr_bitmap) {
            m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::page_size);

            address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
            primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
        }
    }

    void init_rdmsr()
    {
        check_msr_bitmap();

        if (!m_rdmsr) {
            m_rdmsr = std::make_unique<eapis::intel_x64::rdmsr>(
                m_msr_bitmap.get(), this->exit_handler()
            );
            m_handlers[vmcs_n::exit_reason::basic_exit_reason::rdmsr] = m_rdmsr.get();
        }
    }

    void init_wrmsr()
    {
        check_msr_bitmap();

        if (!m_wrmsr) {
            m_wrmsr = std::make_unique<eapis::intel_x64::wrmsr>(
                m_msr_bitmap.get(), this->exit_handler()
            );
            m_handlers[vmcs_n::exit_reason::basic_exit_reason::wrmsr] = m_wrmsr.get();
        }
    }

    void init_vpid()
    {
        if (!m_vpid) {
            m_vpid = std::make_unique<eapis::intel_x64::vpid>();
        }
    }

private:

    void init_handlers();
    void init_exit_handler(vmcs_n::value_type reason);

    bool m_is_rdcr3_enabled{false};
    bool m_is_wrcr3_enabled{false};
    bool m_is_rdcr8_enabled{false};
    bool m_is_wrcr8_enabled{false};

    std::unique_ptr<eapis::intel_x64::vpid> m_vpid;
    std::unique_ptr<uint8_t[]> m_msr_bitmap;

    std::unique_ptr<eapis::intel_x64::control_register> m_control_register;
    std::unique_ptr<eapis::intel_x64::cpuid> m_cpuid;
    std::unique_ptr<eapis::intel_x64::monitor_trap> m_monitor_trap;
    std::unique_ptr<eapis::intel_x64::mov_dr> m_mov_dr;
    std::unique_ptr<eapis::intel_x64::rdmsr> m_rdmsr;
    std::unique_ptr<eapis::intel_x64::wrmsr> m_wrmsr;

    handler_list_t m_handlers;
    const std::list<vmcs_n::value_type> *m_used_handlers;
};

const std::list<vmcs_n::value_type>
vcpu::s_available_handlers{
    vmcs_n::exit_reason::basic_exit_reason::control_register_accesses,
    vmcs_n::exit_reason::basic_exit_reason::cpuid,
    vmcs_n::exit_reason::basic_exit_reason::monitor_trap_flag,
    vmcs_n::exit_reason::basic_exit_reason::mov_dr,
    vmcs_n::exit_reason::basic_exit_reason::rdmsr,
    vmcs_n::exit_reason::basic_exit_reason::wrmsr
};

void
vcpu::init_exit_handler(vmcs_n::value_type reason)
{
    using namespace vmcs_n::exit_reason;

    switch (reason) {
        case basic_exit_reason::control_register_accesses:
            init_control_register();
            break;

        case basic_exit_reason::cpuid:
            init_cpuid();
            break;

        case basic_exit_reason::monitor_trap_flag:
            init_monitor_trap();
            break;

        case basic_exit_reason::mov_dr:
            init_mov_dr();
            break;

        case basic_exit_reason::rdmsr:
            init_rdmsr();
            break;

        case basic_exit_reason::wrmsr:
            init_wrmsr();
            break;

        default:
            bferror_info(0, "Attempt to use unavailable exit handler");
            bferror_subnhex(0, "reason", reason);
            throw std::runtime_error("init_exit_handler: handler unavailable");
    }
}

void
vcpu::init_handlers()
{
    for (const auto &handler : *m_used_handlers) {
        init_exit_handler(handler);
    }
}

}
}
