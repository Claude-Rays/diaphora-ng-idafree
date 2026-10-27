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
#include "compunits.hpp"

#include <cmath>
#include <regex>
#include <strlist.hpp>

namespace dph
{

//------------------------------------------------------------------------------
// codecut/lfa.py
//------------------------------------------------------------------------------
namespace
{
// Threshold above which a function call is considered "external"
const int64 MAX_CALL = 0x1000;

struct func_info_t
{
  ea_t loc;
  double score1;
  double score2;
  double total_score;
  int lfa_skip;
  int edge;
};

struct lfa_module_t
{
  ea_t start;
  ea_t end;
  std::string name;
};

// FuncXrefsFrom(): functions called from f
std::set<ea_t> func_xrefs_from(ea_t f)
{
  std::set<ea_t> out;
  func_t *pfn = get_func(f);
  if ( pfn == nullptr )
    return out;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
  {
    ea_t item = fii.current();
    for ( ea_t x = get_first_fcref_from(item); x != BADADDR; x = get_next_fcref_from(item, x) )
    {
      func_t *xf = get_func(x);
      ea_t s = xf != nullptr ? xf->start_ea : BADADDR;
      if ( x == s )
        out.insert(x);
    }
  }
  return out;
}

double lfa_weight(ea_t f, const std::vector<ea_t> &xrefs)
{
  int64 fc = 0;
  double fs = 0;
  for ( ea_t xref : xrefs )
  {
    int64 delta = int64(xref) - int64(f);
    int64 dist = delta < 0 ? -delta : delta;
    if ( dist > MAX_CALL )
      continue;
    double logdist = dist != 0 ? std::log(double(dist)) : 0;
    fs += delta < 0 ? -logdist : logdist;
    fc += 1;
  }
  return fc == 0 ? 0 : fs / double(fc);
}

// func_callers_weight(): the "calls from" score
double func_callers_weight(ea_t f)
{
  std::set<ea_t> s = func_xrefs_from(f);
  std::vector<ea_t> xrefs(s.begin(), s.end());
  return lfa_weight(f, xrefs);
}

// func_callee_weight(): the "calls to" score
double func_callee_weight(ea_t f)
{
  std::vector<ea_t> xrefs;
  for ( ea_t x = get_first_fcref_to(f); x != BADADDR; x = get_next_fcref_to(f, x) )
    xrefs.push_back(x);
  return lfa_weight(f, xrefs);
}

void func_call_weight(std::vector<func_info_t> &function_list)
{
  ea_t f = get_next_func(0) != nullptr ? get_next_func(0)->start_ea : BADADDR;
  double prevscore_1 = 0, prevscore_2 = 0;
  double z1 = 0, z2 = 0;
  while ( f != BADADDR )
  {
    double score_1 = func_callers_weight(f);
    double score_2 = func_callee_weight(f);

    func_t *next = get_next_func(f);
    ea_t next_f = next != nullptr ? next->start_ea : BADADDR;

    // no references for the function or all refs are above the threshold
    if ( score_1 == 0 && score_2 == 0 )
    {
      prevscore_1 = 0;
      prevscore_2 = 0;
      z1 = 1;
      z2 = 1;
      function_list.push_back({ f, 0, 0, 0, 1, 0 });
      f = next_f;
      continue;
    }

    // interpolate using the previous score and an assumed negative slope
    if ( score_1 == 0 )
    {
      score_1 = prevscore_1 - z1 * .4;
      z1 += 1;
    }
    else
    {
      prevscore_1 = score_1;
      z1 = 1;
    }
    if ( score_2 == 0 )
    {
      score_2 = prevscore_2 - z2 * .4;
      z2 += 1;
    }
    else
    {
      prevscore_2 = score_2;
      z2 = 1;
    }

    function_list.push_back({ f, score_1, score_2, score_1 + score_2, 0, 0 });
    f = next_f;
  }
}

bool get_last_three(const std::vector<func_info_t> &fl, size_t index, const func_info_t **p)
{
  int c = 0;
  int64 i = int64(index) - 1;
  while ( c < 3 && i > 0 )
  {
    if ( fl[size_t(i)].lfa_skip == 0 )
      p[c++] = &fl[size_t(i)];
    --i;
  }
  return c == 3;
}

size_t get_lfa_start(const std::vector<func_info_t> &fl)
{
  int c = 0;
  size_t i = 0;
  while ( c < 4 && i < fl.size() )
  {
    if ( fl[i].lfa_skip == 0 )
      ++c;
    ++i;
  }
  return i;
}

// Determine boundaries between object files
std::vector<lfa_module_t> edge_detect(std::vector<func_info_t> &fl)
{
  std::vector<lfa_module_t> modules;
  const double EDGE_THRESHOLD = 2;
  for ( size_t c = get_lfa_start(fl); c < fl.size(); ++c )
  {
    if ( fl[c].lfa_skip != 0 )
      continue;
    const func_info_t *p[3];
    if ( !get_last_three(fl, c, p) )
      continue;
    double p_1 = p[0]->total_score, p_2 = p[1]->total_score, p_3 = p[2]->total_score;
    double s = fl[c].total_score;
    if ( p[0]->edge != 1 && s > 0 && (s - p_1) > EDGE_THRESHOLD )
    {
      double m[3] = { p_1, p_2, p_3 };
      std::sort(m, m + 3);
      if ( m[1] < 0 )
        fl[c].edge = 1;
    }
  }
  if ( fl.empty() )
    return modules;
  ea_t mod_start = fl[0].loc;
  for ( const auto &f : fl )
  {
    if ( f.edge == 1 )
    {
      modules.push_back({ mod_start, f.loc - 1, "" });
      mod_start = f.loc;
    }
  }
  return modules;
}

//------------------------------------------------------------------------------
// IDAMagicStrings.get_source_strings()
//------------------------------------------------------------------------------
struct source_ref_t
{
  ea_t ref;
  std::string func_name;
  std::string mod_name;
};

const char *get_lang(const std::string &full_path)
{
  std::string ext;
  size_t dot = full_path.find_last_of('.');
  if ( dot != std::string::npos )
    ext = to_lower(full_path.substr(dot + 1));
  if ( ext == "c" || ext == "cc" || ext == "cxx" || ext == "cpp" || ext == "h" || ext == "hpp" )
    return "C/C++";
  if ( ext == "m" )
    return "Obj-C";
  if ( ext == "rs" )
    return "Rust";
  if ( ext == "go" )
    return "Golang";
  if ( ext == "ml" )
    return "OCaml";
  return nullptr;
}

std::string func_name_at(ea_t ea)
{
  qstring n;
  get_func_name(&n, ea);
  return n.c_str();
}

void get_source_strings(size_t min_len,
                        std::vector<std::pair<std::string, std::vector<source_ref_t>>> &d)
{
  std::unordered_map<std::string, size_t> d_idx;
  std::map<std::string, int> src_langs;
  int total_files = 0;

  auto add_source_file = [&](const std::string &full_path, ea_t ref, const std::string &s)
  {
    auto p = d_idx.find(full_path);
    if ( p == d_idx.end() )
    {
      d_idx[full_path] = d.size();
      d.emplace_back(full_path, std::vector<source_ref_t>());
      p = d_idx.find(full_path);
    }
    d[p->second].second.push_back({ ref, func_name_at(ref), s });
  };

  // find_source_files_in_strings(): strtypes [0, 1], like idautils.Strings
  strwinsetup_t *opts = const_cast<strwinsetup_t *>(get_strlist_options());
  strwinsetup_t saved = *opts;
  opts->strtypes.clear();
  opts->strtypes.push_back(STRTYPE_C);
  opts->strtypes.push_back(STRTYPE_C_16);
  opts->minlen = 5;
  opts->only_7bit = 1;
  opts->display_only_existing_strings = 0;
  opts->ignore_heads = 0;
  clear_strlist();
  build_strlist();

  static const std::regex source_re(
        R"(([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| ))",
        std::regex::icase | std::regex::optimize);
  size_t qty = get_strlist_qty();
  for ( size_t n = 0; n < qty; ++n )
  {
    string_info_t si;
    if ( !get_strlist_item(&si, n) || si.length <= (int)min_len )
      continue;
    qstring q;
    if ( get_strlit_contents(&q, si.ea, si.length, si.type) <= 0 )
      continue;
    std::string s = q.c_str();
    std::smatch m;
    if ( !std::regex_search(s, m, source_re) )
      continue;
    std::vector<ea_t> refs;
    for ( ea_t x = get_first_dref_to(si.ea); x != BADADDR; x = get_next_dref_to(si.ea, x) )
      refs.push_back(x);
    if ( refs.empty() )
      continue;
    total_files += 1;
    std::string full_path = m[1].str();
    const char *lang = get_lang(full_path);
    if ( lang != nullptr )
      src_langs[lang] += 1;
    for ( ea_t ref : refs )
      add_source_file(full_path, ref, s);
  }

  // restore the user's string list options
  *opts = saved;
  clear_strlist();
  build_strlist();

  // find_source_files_in_debug_info()
  for ( size_t fi = 0; fi < get_func_qty(); ++fi )
  {
    func_t *func = getn_func(fi);
    if ( func == nullptr )
      continue;
    qflow_chart_t fc("", func, BADADDR, BADADDR, FC_NOPREDS);
    for ( int b = 0; b < fc.size(); ++b )
    {
      ea_t ea = fc.blocks[b].start_ea;
      ea_t end = fc.blocks[b].end_ea;
      if ( !is_head(get_flags(ea)) )
        ea = next_head(ea, end);
      while ( ea < end && ea != BADADDR )
      {
        qstring path;
        if ( get_sourcefile_by_ea(&path, ea) )
        {
          total_files += 1;
          std::string full_path = path.c_str();
          const char *lang = get_lang(full_path);
          if ( lang != nullptr )
            src_langs[lang] += 1;
          add_source_file(full_path, ea, "Symbol: " + full_path);
        }
        ea = next_head(ea, end);
      }
    }
  }

  if ( !d.empty() && total_files > 0 )
  {
    msg("Programming languages found:\n\n");
    for ( const auto &kv : src_langs )
      msg("    %-10s %f%%\n", kv.first.c_str(), kv.second * 100. / total_files);
    msg("\n\n");
  }
}
} // namespace

//------------------------------------------------------------------------------
std::vector<cu_module_t> get_modules_using_lfa(const std::vector<func_cache_t> &funcs_cache)
{
  // First, try to guess modules areas
  std::vector<func_info_t> function_list;
  func_call_weight(function_list);
  std::vector<lfa_module_t> lfa_modules = edge_detect(function_list);

  // Next, using IDAMagicStrings, try to guess file names
  std::vector<std::pair<std::string, std::vector<source_ref_t>>> d;
  get_source_strings(4, d);

  // put the names found with IDAMagicStrings to anonymous modules found with LFA
  std::unordered_set<ea_t> func_modules;
  for ( const auto &kv : d )
  {
    for ( const auto &item : kv.second )
    {
      ea_t func_ea = get_name_ea(BADADDR, item.func_name.c_str());
      if ( func_modules.find(func_ea) != func_modules.end() )
        continue;
      func_modules.insert(func_ea);
      for ( auto &module : lfa_modules )
      {
        if ( func_ea >= module.start && func_ea <= module.end )
        {
          if ( module.name.empty() )
          {
            module.name = item.mod_name;
            break;
          }
        }
      }
    }
  }

  // find the limits of modules with the same name that appear multiple times
  std::vector<cu_module_t> new_modules;
  std::vector<std::pair<std::string, std::pair<ea_t, ea_t>>> named_modules;
  std::unordered_map<std::string, size_t> named_idx;
  for ( const auto &module : lfa_modules )
  {
    if ( module.name.empty() )
      continue;
    auto p = named_idx.find(module.name);
    if ( p == named_idx.end() )
    {
      named_idx[module.name] = named_modules.size();
      named_modules.push_back({ module.name, { module.start, module.end } });
    }
    else
    {
      named_modules[p->second].second.second = module.end;
    }
  }

  std::vector<std::pair<ea_t, ea_t>> areas;
  for ( const auto &nm : named_modules )
  {
    cu_module_t m;
    m.name = nm.first;
    m.start = nm.second.first;
    m.end = nm.second.second;
    new_modules.push_back(m);
    areas.push_back(nm.second);
  }

  // discard anonymous modules that fall in the area of named modules
  for ( const auto &module : lfa_modules )
  {
    if ( !module.name.empty() )
      continue;
    bool found = false;
    for ( const auto &a : areas )
    {
      if ( module.start >= a.first && module.end <= a.second )
      {
        found = true;
        break;
      }
    }
    if ( !found )
    {
      cu_module_t m;
      m.start = module.start;
      m.end = module.end;
      new_modules.push_back(m);
    }
  }

  // modules weights
  size_t iterations = 1;
  for ( const auto &item : funcs_cache )
  {
    if ( iterations++ % 1000 == 0 )
      log_refresh("Calculating modules weights...");
    for ( auto &module : new_modules )
    {
      if ( module.start <= item.ea && item.ea <= module.end )
      {
        module.total += 1;
        if ( !item.primes_value.is_null() )
          module.primes.mul(bignum_t::from_string(item.primes_value.str()));
        if ( !item.pseudocode_primes.is_null() )
          module.pseudo_primes.mul(bignum_t::from_string(item.pseudocode_primes.str()));
        break;
      }
    }
  }
  return new_modules;
}

//------------------------------------------------------------------------------
void save_compilation_units(bindiff_t &bd, const std::vector<func_cache_t> &funcs_cache)
{
  log_refresh("Finding compilation units...");
  std::vector<cu_module_t> lfa_modules = get_modules_using_lfa(funcs_cache);
  log_refresh("Saving compilation units...");

  // functions sorted by address, to find the ones inside every module quickly
  std::vector<std::pair<ea_t, size_t>> sorted;
  for ( size_t i = 0; i < funcs_cache.size(); ++i )
    sorted.emplace_back(funcs_cache[i].ea, i);
  std::sort(sorted.begin(), sorted.end());

  sql_db_t &db = bd.get_db();
  sql_stmt_t sql1(db, "insert or ignore into compilation_units (name, start_ea, end_ea) values (?, ?, ?)");
  sql_stmt_t sql2(db, "insert or ignore into compilation_unit_functions(cu_id, func_id) values (?, ?)");
  sql_stmt_t sql3(db, R"SQL( update compilation_units
          set primes_value = ?,
            pseudocode_primes = ?,
            functions = ?
        where id = ? )SQL");
  sql_stmt_t sql4(db, " update functions set source_file = ? where id = ? ");

  std::unordered_set<int64> dones;
  size_t total = lfa_modules.size();
  size_t checkpoint = total / 100;
  for ( size_t i = 0; i < total; ++i )
  {
    const cu_module_t &module = lfa_modules[i];
    if ( i > 0 && checkpoint > 0 && i % checkpoint == 0 )
      log_refresh(strfmt("Processing compilation unit %u out of %u...", unsigned(i), unsigned(total)));

    sql_value_t module_name;
    if ( !module.name.empty() )
      module_name = sql_value_t(module.name);

    sql1.run({ module.name, std::to_string(module.start), std::to_string(module.end) });
    if ( db.changes() == 0 )
    {
      debug_log("Duplicated compilation unit at 0x%llx ignored", (unsigned long long)module.start);
      continue;
    }
    int64 cu_id = db.last_insert_rowid();

    auto p = std::lower_bound(sorted.begin(), sorted.end(), std::make_pair(module.start, size_t(0)));
    for ( ; p != sorted.end() && p->first <= module.end; ++p )
    {
      int64 func_id = funcs_cache[p->second].func_id;
      if ( dones.insert(func_id).second )
      {
        sql2.run({ cu_id, func_id });
        sql4.run({ module_name, func_id });
      }
    }

    sql3.run({ module.primes.str(), module.pseudo_primes.str(), std::to_string(module.total), cu_id });
  }
}

} // namespace dph
