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

// Diaphora-ng - configuration options
// Port of diaphora_config.py. The python file was a script that users could
// edit; here the values are compile time defaults. The most useful ones can be
// overridden at runtime with DIAPHORA_* environment variables (see README).
#pragma once
#include "common.hpp"

namespace dph
{
namespace config
{

//------------------------------------------------------------------------------
// Colors (0xBBGGRR for IDA, "#RRGGBB" for html)
//------------------------------------------------------------------------------
const bgcolor_t CALLGRAPH_COLOR_TARGET = 0xEEFF00;
const bgcolor_t CALLGRAPH_COLOR_CALLER = 0xFFFFFF;
const bgcolor_t CALLGRAPH_COLOR_CALLEE = 0xFFFFFF;

const bgcolor_t DIFF_COLOR_ADDED      = 0xaaffaa;   // "#aaffaa"
const bgcolor_t DIFF_COLOR_CHANGED    = 0x77ffff;   // "#ffff77"
const bgcolor_t DIFF_COLOR_SUBTRACTED = 0xaaaaff;   // "#ffaaaa"
const bgcolor_t DIFF_COLOR_LINE_NO    = 0xe0e0e0;

const bgcolor_t HIGHLIGHT_FUNCTION_BEST       = 0xffff99;
const bgcolor_t HIGHLIGHT_FUNCTION_PARTIAL    = 0x99ff99;
const bgcolor_t HIGHLIGHT_FUNCTION_UNRELIABLE = 0x9999ff;

const bgcolor_t GRAPH_BBLOCK_MATCH_PARTIAL = 0xCCFFFF;
const bgcolor_t GRAPH_BBLOCK_MATCH_PERFECT = 0xFFFFFF;
const bgcolor_t GRAPH_BBLOCK_MATCH_NONE    = 0xCCCCFF;

const bgcolor_t LITTLE_ORANGE = 0x026AFD;

//------------------------------------------------------------------------------
// Default export & diffing options
//------------------------------------------------------------------------------
const bool DIFFING_ENABLE_UNRELIABLE = false;
const bool DIFFING_ENABLE_RELAXED_RATIO = false;
const bool DIFFING_ENABLE_EXPERIMENTAL = true;
const bool DIFFING_ENABLE_SLOW_HEURISTICS = true;
const bool DIFFING_IGNORE_SUB_FUNCTION_NAMES = true;
const bool DIFFING_IGNORE_ALL_FUNCTION_NAMES = false;
const bool DIFFING_IGNORE_SMALL_FUNCTIONS = false;

const bool EXPORTING_USE_DECOMPILER = true;
const bool EXPORTING_EXCLUDE_LIBRARY_THUNK = true;
const bool EXPORTING_ONLY_NON_IDA_SUBS = true;
const bool EXPORTING_FUNCTION_SUMMARIES_ONLY = false;
const bool EXPORTING_USE_MICROCODE = true;

// Number of rows that must be inserted to commit the transaction
const int EXPORTING_FUNCTIONS_TO_COMMIT = 5000;
const bool COMMIT_AFTER_EACH_GUI_UPDATE = true;

const int MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001;
const int MIN_FUNCTIONS_TO_CONSIDER_MEDIUM = 8001;
const int MIN_FUNCTIONS_TO_CONSIDER_HUGE = 100000;

// Block size to use to generate fuzzy hashes for pseudo-codes
const int FUZZY_HASHING_BLOCK_SIZE = 512;

const bool EXPORTING_COMPILATION_UNITS = true;

//------------------------------------------------------------------------------
// SQL and SQLite
//------------------------------------------------------------------------------
const int64 SQL_MAX_PROCESSED_ROWS = 1000000;
const int64 SQL_TIMEOUT_LIMIT = 60 * 5;
const char *const SQLITE_JOURNAL_MODE = "WAL";
const char *const SQLITE_PRAGMA_SYNCHRONOUS = "1";

//------------------------------------------------------------------------------
// Heuristics
//------------------------------------------------------------------------------
const double MATCHES_BONUS_RATIO = 0.01;
const int MAX_FUNCTIONS_PER_GAP = 100;
const char *const SQL_DEFAULT_POSTFIX = " and f.instructions > 5 and df.instructions > 5 ";
const double MINIMUM_RARE_MD_INDEX = 10.0;
const double DEFAULT_PARTIAL_RATIO = 0.5;
const double DEFAULT_TRUSTED_PARTIAL_RATIO = 0.3;
const double INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU = 0.006;
const double INCREASE_RATIO_PER_CONSTANT_MATCH = 0.008;

static const char *const CLEANING_CMP_REPS[] =
{
  "loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_",
};
static const char *const CLEANING_CMP_REMS[] =
{
  "dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr",
};

const double SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT = 99.0;
const double SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT = 90.0;
const double SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO = 0.6;
const int DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT = 25;
const int DIFFING_MATCHES_MIN_BBLOCKS = 3;

// Run default scripts? In this port the default patch diffing script
// (scripts/patch_diff_vulns.py) is built in (see vulns.cpp).
const bool RUN_DEFAULT_SCRIPTS = true;

const double RELATED_MATCHES_MIN_RATIO = 0.8;

// Seconds between checks of the heuristic threads
const double THREADS_WAIT_TIME = 1;

// Workarounds for IDA bugs
const bool DIAPHORA_WORKAROUND_MAX_TINFO_T = false;

} // namespace config
} // namespace dph
