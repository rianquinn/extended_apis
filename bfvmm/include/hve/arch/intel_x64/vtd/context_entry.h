//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VTD_CONTEXT_ENTRY_H
#define VTD_CONTEXT_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace context_entry
{
	constexpr const auto name = "context_entry";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &context_entry) noexcept
		{ return is_bit_set(context_entry.data[index], from); }

		inline auto is_disabled(const value_type &context_entry) noexcept
		{ return !is_bit_set(context_entry.data[index], from); }

		inline void enable(value_type &context_entry) noexcept
		{ context_entry.data[index] = set_bit(context_entry.data[index], from); }

		inline void disable(value_type &context_entry) noexcept
		{ context_entry.data[index] = clear_bit(context_entry.data[index], from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(context_entry), msg); }
	}

	namespace fpd
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "fault_processing_disable";

		inline auto is_enabled(const value_type &context_entry) noexcept
		{ return is_bit_set(context_entry.data[index], from); }

		inline auto is_disabled(const value_type &context_entry) noexcept
		{ return !is_bit_set(context_entry.data[index], from); }

		inline void enable(value_type &context_entry) noexcept
		{ context_entry.data[index] = set_bit(context_entry.data[index], from); }

		inline void disable(value_type &context_entry) noexcept
		{ context_entry.data[index] = clear_bit(context_entry.data[index], from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(context_entry), msg); }
	}

	namespace t
	{
		constexpr const auto mask = 0xCULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "translation_type";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace slptptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "second_level_page_translation_pointer";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace aw
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "address_width";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace did
	{
		constexpr const auto mask = 0xFFFF00ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "domain_identifier";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "context_entry[63:0]", context_entry.data[0], msg);
		bfdebug_nhex(level, "context_entry[127:64]", context_entry.data[1], msg);

		p::dump(level, context_entry, msg);
		fpd::dump(level, context_entry, msg);
		t::dump(level, context_entry, msg);
		slptptr::dump(level, context_entry, msg);
		aw::dump(level, context_entry, msg);
		did::dump(level, context_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
