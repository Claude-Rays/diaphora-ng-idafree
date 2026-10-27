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

// Diaphora-ng - built-in port of scripts/patch_diff_vulns.py
//
// The python version loads this script as "project specific hooks" when a
// patch diffing session is detected. IDA Free has no python, so the script is
// compiled in and installed the same way (config::RUN_DEFAULT_SCRIPTS).
#pragma once
#include "bindiff.hpp"

namespace dph
{

class vuln_hooks_t
{
  bindiff_t &bd;
  std::mutex lock;
  std::set<std::string> dones;

public:
  vuln_hooks_t(bindiff_t &_bd);
  // returns (should_add, ratio) like the python on_match hook
  std::pair<bool, double> on_match(const func_cmp_t &func1, const func_cmp_t &func2,
                                   const std::string &description, double ratio);
};

} // namespace dph
