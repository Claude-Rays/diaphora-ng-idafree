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
// Find patches that could be fixing vulnerabilities by simply doing pattern
// matching between pseudo-codes and assembly of partial matches.
#include "vulns.hpp"
#include "difflib.hpp"
#include "heuristics.hpp"

namespace dph
{

static const char *const PATTERNS[] =
{
  // Generic C 'unsafe' functions
  "cpy", "printf", "strcat", "strncat", "gets", "mem", "system",
  "scanf", "alloc", "free", "strto",
  // Windows 'unsafe' APIs
  "ShellExecute", "WinExec", "LoadLibrary", "CreateProcess",
  // Functions that may be interesting for Windows kernel drivers
  "ProbeForWrite", "ProbeForRead",
  // UNC paths related pattern
  "UNC",
};

static const char *const COMPARISONS[] = { " < ", " > ", " <= ", " >= " };

struct vuln_result_t
{
  bool found = false;
  std::string description;
  std::string line;
};

static const char *signed_unsigned(const std::string &mnem)
{
  static const char *const pairs[][2] =
  {
    { "jl", "jb" }, { "jle", "jbe" }, { "jg", "ja" }, { "jge", "jae" },
    { "jb", "jl" }, { "jbe", "jle" }, { "ja", "jg" }, { "jae", "jge" },
  };
  for ( const auto &p : pairs )
    if ( mnem == p[0] )
      return p[1];
  return nullptr;
}

// Find potential vulnerabilities by simply doing pattern matching
static vuln_result_t search_pseudo_patterns(const std::string &src_line)
{
  vuln_result_t ret;
  for ( const char *pattern : PATTERNS )
  {
    if ( src_line.find(pattern) != std::string::npos )
    {
      ret.found = true;
      ret.description = std::string("Pattern ") + py_repr(pattern);
      ret.line = src_line;
      break;
    }
  }
  return ret;
}

// Try to guess if it looks like a newly added size check
static vuln_result_t search_for_added_size_check(const std::string &src_line)
{
  vuln_result_t ret;
  if ( starts_with(src_line, "if ") )
  {
    for ( const char *pattern : COMPARISONS )
    {
      if ( src_line.find(pattern) != std::string::npos )
      {
        // Ignore comparisons with 0
        if ( src_line.find(std::string(pattern) + "0 ") == std::string::npos )
        {
          ret.description = "Potential size check added";
          ret.found = true;
          ret.line = src_line;
          break;
        }
      }
    }
  }
  return ret;
}

// Try to search for signedness fixed issues
static vuln_result_t find_vulns_using_assembly(const func_cmp_t &func1, const func_cmp_t &func2)
{
  vuln_result_t results;
  if ( func1.asm_text == nullptr || func1.asm_text->is_null() || func2.asm_text == nullptr || func2.asm_text->is_null() )
    return results;

  std::vector<std::string> lines = unified_diff(split(func1.asm_text->str(), '\n'), split(func2.asm_text->str(), '\n'));
  bool have_added = false, have_removed = false;
  std::string added, removed;
  bool found = false;
  for ( const auto &line : lines )
  {
    if ( line.empty() )
      continue;
    char c = line[0];
    // Only consider removed/added lines (which also means modified lines)
    if ( c != '-' && c != '+' )
      continue;
    if ( c == '+' )
    {
      added = line.substr(1);
      have_added = true;
    }
    else
    {
      if ( ends_with(line.substr(1), ":") )
        continue;
      removed = line.substr(1);
      have_removed = true;
    }

    if ( have_added && have_removed )
    {
      // Check the list of known signed <-> unsigned instructions
      std::string mnem1 = to_lower(split(added, ' ')[0]);
      std::string mnem2 = to_lower(split(removed, ' ')[0]);
      const char *other = signed_unsigned(mnem1);
      if ( other != nullptr )
      {
        if ( mnem2 == other )
        {
          found = true;
          break;
        }
      }
      else if ( !mnem1.empty() && !mnem2.empty() && mnem1[0] == 'b' && mnem2[0] == 'b' )
      {
        // Check for branch instructions where only one is signed
        char last_c1 = mnem1.back();
        char last_c2 = mnem2.back();
        if ( (last_c1 == 's' || last_c2 == 's') && last_c1 != last_c2 )
        {
          found = true;
          break;
        }
      }
    }
  }

  if ( found )
  {
    results.description = "Signed/Unsigned check changed";
    results.found = true;
    results.line = "Added: " + py_repr(added) + "\tRemoved: " + py_repr(removed);
  }
  return results;
}

static vuln_result_t find_vulns_using_pseudocode(const func_cmp_t &func1, const func_cmp_t &func2)
{
  vuln_result_t results;
  if ( func1.pseudo == nullptr || func1.pseudo->is_null() || func2.pseudo == nullptr || func2.pseudo->is_null() )
    return results;

  std::vector<std::string> lines = unified_diff(split(func1.pseudo->str(), '\n'), split(func2.pseudo->str(), '\n'));
  for ( const auto &line : lines )
  {
    if ( line.empty() )
      continue;
    char c = line[0];
    if ( c == '-' || c == '+' )
    {
      std::string src_line = strip(line.size() > 2 ? line.substr(2) : std::string(), " ");
      results = search_pseudo_patterns(src_line);
      // Search for potentially newly added checks
      if ( !results.found && c == '+' )
        results = search_for_added_size_check(src_line);
    }
    if ( results.found )
      break;
  }
  return results;
}

vuln_hooks_t::vuln_hooks_t(bindiff_t &_bd) : bd(_bd)
{
  bd.interesting_matches.clear();
}

std::pair<bool, double> vuln_hooks_t::on_match(
        const func_cmp_t &func1,
        const func_cmp_t &func2,
        const std::string &description,
        double ratio)
{
  qnotused(description);
  // Ignore matches with ratio 1.0, as they contain no changes
  if ( ratio >= 1.0 )
    return { true, ratio };

  std::string name1 = func1.name->str();
  std::string name2 = func2.name->str();
  {
    // We might receive 2 times a match in some cases, avoid analysing it twice
    std::lock_guard<std::mutex> g(lock);
    if ( !dones.insert(name1 + "\x01" + name2).second )
      return { true, ratio };
  }

  vuln_result_t results = find_vulns_using_assembly(func1, func2);
  if ( !results.found )
    results = find_vulns_using_pseudocode(func1, func2);

  if ( results.found )
  {
    log_refresh(strfmt("Potentially interesting patch found (pattern '%s'): %s - %s",
                       results.description.c_str(), name1.c_str(), name2.c_str()));
    log("> %s", results.line.c_str());

    match_item_t item;
    item.ea1 = (uint64)func1.ea->to_int();
    item.name1 = name1;
    item.ea2 = (uint64)func2.ea->to_int();
    item.name2 = name2;
    item.desc = results.description;
    item.ratio = ratio;
    item.nodes1 = func1.nodes->to_int();
    item.nodes2 = func2.nodes->to_int();
    std::lock_guard<std::mutex> g(lock);
    bd.interesting_matches.add_item(item);
  }
  return { true, ratio };
}

} // namespace dph
