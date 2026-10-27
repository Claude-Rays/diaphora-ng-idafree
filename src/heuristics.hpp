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

// Diaphora-ng - SQL heuristics (diaphora_heuristics.py)
//
// The heuristics table is generated from the original python file by
// tools/gen_heuristics.py into heuristics_data.inc.
#pragma once
#include "common.hpp"

namespace dph
{

// Use only for heuristics generating 1.0 ratios, results without false positives
const int HEUR_TYPE_NO_FPS = 0;
// 1.0 ratios to the best chooser, 0.5..<1.0 to the partial chooser and <0.5 to
// the unreliable chooser (if specified)
const int HEUR_TYPE_RATIO = 1;
// Similar as before, but partial results are only assigned for matches with a
// min specified ratio
const int HEUR_TYPE_RATIO_MAX = 2;
// Similar as before, but 'unreliable' results go to the 'partial' tab instead
const int HEUR_TYPE_RATIO_MAX_TRUSTED = 3;

const int HEUR_FLAG_NONE       = 0;
const int HEUR_FLAG_UNRELIABLE = 1;
const int HEUR_FLAG_SLOW       = 2;
// The heuristic should only be launched when diffing the same architecture
const int HEUR_FLAG_SAME_CPU   = 3;

struct heuristic_t
{
  const char *name;
  const char *category;
  int ratio;
  double min;
  uint32 flags;     // bitmask of (1 << HEUR_FLAG_*)
  const char *sql;

  bool has_flag(int flag) const { return (flags & (1u << flag)) != 0; }
};

const heuristic_t *get_heuristics(size_t *count);

// python repr() of a string
std::string py_repr(const std::string &s);
// diaphora_heuristics.get_query_fields()
std::string get_query_fields(const std::string &heur, bool quote = true);

} // namespace dph
