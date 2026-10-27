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

// Diaphora-ng - internal state of bindiff_t shared by the
// implementation files. Not part of the public interface.
#pragma once
#include "bindiff.hpp"

namespace dph
{

struct func_cache_t
{
  ea_t ea = BADADDR;
  int64 func_id = 0;
  sql_value_t primes_value;
  sql_value_t pseudocode_primes;
};

struct bindiff_t::impl_t
{
  //----------------------------------------------------------------------------
  // databases: the main thread uses main_db, every worker thread gets its own
  // connection (the python version did the same with dbs_dict)
  std::unique_ptr<sql_db_t> main_db;
  std::mutex dbs_lock;
  std::unordered_map<std::thread::id, std::unique_ptr<sql_db_t>> dbs;

  //----------------------------------------------------------------------------
  // export state
  bool export_state_ready = false;
  std::vector<uint32> primes;        // primesbelow(2048 * 2048)
  std::vector<uint32> ast_primes;    // primesbelow(4096), used by CAstVisitor
  std::unordered_map<ea_t, std::string> names;  // dict(Names())
  std::vector<func_cache_t> funcs_cache;        // _funcs_cache
  std::unordered_map<ea_t, size_t> funcs_cache_idx;
  bool decompiler_available = config::EXPORTING_USE_DECOMPILER;
  std::vector<std::string> microcode_ins_list;
  std::unordered_map<std::string, size_t> microcode_ins_idx;
  std::vector<std::string> cpu_ins_list;
  std::unordered_map<std::string, size_t> cpu_ins_idx;

  // per function decompiler output (pseudo, pseudo_hash, pseudo_comments and
  // microcode in the python version)
  struct decomp_t
  {
    bool ok = false;
    std::vector<std::string> pseudo;
    bignum_t pseudo_hash;
    std::map<int64, std::pair<std::string, int>> pseudo_comments;
    bool have_microcode = false;
    std::vector<std::string> microcode;
    std::vector<microcode_block_t> microcode_bblocks;
    std::map<int, std::vector<int>> microcode_bbrelations;
  };
  std::map<ea_t, decomp_t> decomp;

  void add_func_cache(ea_t ea, int64 func_id, const sql_value_t &primes_value, const sql_value_t &pseudo_primes)
  {
    auto p = funcs_cache_idx.find(ea);
    if ( p != funcs_cache_idx.end() )
    {
      func_cache_t &fc = funcs_cache[p->second];
      fc.func_id = func_id;
      fc.primes_value = primes_value;
      fc.pseudocode_primes = pseudo_primes;
      return;
    }
    funcs_cache_idx[ea] = funcs_cache.size();
    funcs_cache.push_back({ ea, func_id, primes_value, pseudo_primes });
  }
};

// is the diffing being cancelled / timing out in this thread?
bool heuristic_should_stop();

// initialize the Hex-Rays decompiler API (true if available)
bool hexrays_ready();
void hexrays_term();

// lazily build the state needed to read functions (primes, names...)
void ensure_export_state(bindiff_t::impl_t &impl);

} // namespace dph
