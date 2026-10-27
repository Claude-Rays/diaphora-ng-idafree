// Diaphora, a diffing plugin for IDA
// Copyright (c) 2015-2026 Joxean Koret
// Copyright (c) 2026 ClaudeMonkey (C++ port, Claude-Rays/diaphora-ng-idafree)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// The Local Function Affinity code is a port of codecut/lfa.py:
//   Copyright 2018 The Johns Hopkins University Applied Physics Laboratory LLC
//   All rights reserved.
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this
//   software and associated documentation files (the "Software"), to deal in the Software
//   without restriction, including without limitation the rights to use, copy, modify,
//   merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
//   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
//   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//   LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
//   OR OTHER DEALINGS IN THE SOFTWARE.
// The source file names detection is a port of jkutils/IDAMagicStrings.py:
//   Copyright (c) 2018-2019, 2026, Joxean Koret
//   Licensed under the GNU GPL v3.

// Diaphora-ng - compilation units detection
// Port of codecut/lfa.py (Local Function Affinity), the parts of
// jkutils/IDAMagicStrings.py used by Diaphora (get_source_strings) and
// CIDABinDiff.get_modules_using_lfa / save_compilation_units.
#pragma once
#include "bindiff_impl.hpp"

namespace dph
{

struct cu_module_t
{
  std::string name;
  ea_t start = 0;
  ea_t end = 0;
  int64 total = 0;
  bignum_t primes{ 1 };
  bignum_t pseudo_primes{ 1 };
};

std::vector<cu_module_t> get_modules_using_lfa(const std::vector<func_cache_t> &funcs_cache);
void save_compilation_units(bindiff_t &bd, const std::vector<func_cache_t> &funcs_cache);

} // namespace dph
