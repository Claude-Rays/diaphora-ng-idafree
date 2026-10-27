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

// Diaphora-ng - "Claude diff pseudo-code"
//
// Not in the Python version. Claude-Rays Decompiler (clauderays-decompiler.dll)
// gets the other version from its SQLite and the assembly diff, and returns both
// decompilations aligned, with the changes and their assessment.
#pragma once
#include "bindiff.hpp"

namespace dph
{

struct claude_line_t
{
  std::string text;               // shaped code, without address annotations
  std::string address;            // "0x..." or ""
};

struct claude_side_t
{
  std::string summary;
  std::string prototype;
  std::vector<claude_line_t> lines;
  std::vector<std::pair<std::string, std::string>> uncertain;   // address, reason
};

struct claude_change_t
{
  std::string kind;               // added, removed, modified, compiler
  std::vector<std::string> old_addresses;
  std::vector<std::string> new_addresses;
  std::string description;
};

struct claude_diff_t
{
  claude_side_t old_side;
  claude_side_t new_side;
  std::vector<claude_change_t> changes;
  std::string security_relevant;  // likely, possible, unlikely
  std::string fix_class;
  std::string reasoning;
  std::string confidence;
  std::vector<std::string> follow_up;
  std::vector<std::string> warnings;    // validator, "old:" / "new:" prefixes
  std::vector<std::string> notes;       // about the data Diaphora could send
  std::string model;
  std::string model_id;
  std::string effort;
  std::string date;
  int64 input_tokens = 0;
  int64 output_tokens = 0;
  double cost_usd = 0;
  bool cached = false;
};

// Claude-Rays Decompiler is loaded and has a compatible API; otherwise *why says what
// is missing. Loads the plugin if needed.
bool claude_diff_available(std::string *why);

// Run the query (Claude-Rays Decompiler shows its wait box) or take it from its cache.
// 'a_is_new': the open database is the new version. false and *err on
// failure or when cancelled.
bool claude_diff(bindiff_t &bd, const chooser_item_t &item, bool a_is_new, bool force,
                 claude_diff_t *out, std::string *err);

} // namespace dph
