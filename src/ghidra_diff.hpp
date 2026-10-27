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

// Diaphora-ng - "GhidraDec diff pseudo-code"
//
// Not in the Python version. GhidraDec (ghidradec.dll) decompiles both versions
// live, the other one from its binary (the SQLite has no bytes), and returns the
// aligned diff; Diaphora-ng only paints it.
#pragma once
#include "bindiff.hpp"
#include "difflib.hpp"

namespace dph
{

struct ghidra_side_t
{
  std::string name;
  std::string address;
  std::string prototype;
  std::string source;             // where the code comes from
  std::vector<std::string> lines;
};

struct ghidra_change_t
{
  std::string kind;               // added, removed, modified
  int old_first = 0, old_last = 0;  // 1-based lines, 0 if none
  int new_first = 0, new_last = 0;
  std::string description;
};

struct ghidra_diff_t
{
  ghidra_side_t old_side;
  ghidra_side_t new_side;
  std::vector<sbs_row_t> rows;    // aligned by GhidraDec
  std::vector<ghidra_change_t> changes;
  std::vector<std::string> calls_added, calls_removed;
  std::vector<std::string> constants_added, constants_removed;
  int normalized_rows = 0;
  bool identical = false;
  // what GhidraDec applied (see ghidra_diff_settings_t)
  bool canonical_names = true;
  bool rename_locals = true;
  std::vector<std::string> warnings;
  std::string ghidra;             // the Ghidra installation
  std::string version;            // of GhidraDec
  int64 seconds = 0;
};

// The two phases that make the diff of two builds readable, both optional
// (Diaphora-ng, saved in the registry, on by default):
// - canonical_names ("level 1"): GhidraDec names the locals v1, v2... on both
//   sides, in the order of first use, as Hex-Rays does, instead of Ghidra's
//   uVar3, local_28... that depend on registers and stack offsets.
// - rename_locals ("level 2"): the locals of NEW are renamed after those of
//   OLD, matched by where they are used in the aligned lines.
// Off, the diff shows what Ghidra's decompiler gives, as Diaphora would.
struct ghidra_diff_settings_t
{
  bool canonical_names = true;
  bool rename_locals = true;
};
ghidra_diff_settings_t ghidra_diff_settings();
// asks for them (menu Diaphora-ng > GhidraDec diff settings...)
void cmd_ghidra_diff_settings();

// GhidraDec is loaded and has a compatible API; otherwise *why says what is
// missing. Loads the plugin if needed.
bool ghidra_diff_available(std::string *why);

// 'a_is_new': the open database is the new version. false and *err on failure.
bool ghidra_diff(bindiff_t &bd, const chooser_item_t &item, bool a_is_new, ghidra_diff_t *out, std::string *err);

} // namespace dph
