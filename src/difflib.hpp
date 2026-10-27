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
// Port of parts of Python's difflib module:
//   Copyright (c) 2001 Python Software Foundation; All Rights Reserved
//   Licensed under the Python Software Foundation License Version 2.
//   Changes: only SequenceMatcher, unified_diff and a side by side diff similar
//   to _mdiff were ported, to C++.

// Diaphora-ng - port of the parts of python's difflib that Diaphora
// uses: SequenceMatcher (quick_ratio, real_quick_ratio, opcodes), unified_diff
// and a side by side diff similar to difflib._mdiff.
#pragma once
#include "common.hpp"

namespace dph
{

struct match_block_t
{
  int a, b, size;
};

struct opcode_t
{
  char tag;   // 'r'eplace, 'd'elete, 'i'nsert, 'e'qual
  int i1, i2, j1, j2;
};

//------------------------------------------------------------------------------
// difflib.SequenceMatcher (isjunk=None, autojunk=True)
template <typename Seq>
class sequence_matcher_t
{
  using elem_t = typename Seq::value_type;
  const Seq &a;
  const Seq &b;
  std::unordered_map<elem_t, std::vector<int>> b2j;
  std::vector<match_block_t> blocks;
  bool have_blocks = false;

public:
  sequence_matcher_t(const Seq &_a, const Seq &_b, bool autojunk = true) : a(_a), b(_b)
  {
    int n = int(b.size());
    for ( int i = 0; i < n; ++i )
      b2j[b[i]].push_back(i);
    // purge popular elements that are not junk
    if ( autojunk && n >= 200 )
    {
      size_t ntest = size_t(n / 100 + 1);
      for ( auto p = b2j.begin(); p != b2j.end(); )
      {
        if ( p->second.size() > ntest )
          p = b2j.erase(p);
        else
          ++p;
      }
    }
  }

  match_block_t find_longest_match(int alo, int ahi, int blo, int bhi) const
  {
    int besti = alo, bestj = blo, bestsize = 0;
    std::unordered_map<int, int> j2len, newj2len;
    for ( int i = alo; i < ahi; ++i )
    {
      newj2len.clear();
      auto p = b2j.find(a[i]);
      if ( p != b2j.end() )
      {
        for ( int j : p->second )
        {
          if ( j < blo )
            continue;
          if ( j >= bhi )
            break;
          auto q = j2len.find(j - 1);
          int k = (q != j2len.end() ? q->second : 0) + 1;
          newj2len[j] = k;
          if ( k > bestsize )
          {
            besti = i - k + 1;
            bestj = j - k + 1;
            bestsize = k;
          }
        }
      }
      j2len.swap(newj2len);
    }
    // there is no junk, but popular elements were purged from b2j: extend the
    // match with equal elements on both sides
    while ( besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] )
    {
      --besti;
      --bestj;
      ++bestsize;
    }
    while ( besti + bestsize < ahi && bestj + bestsize < bhi && a[besti + bestsize] == b[bestj + bestsize] )
      ++bestsize;
    return { besti, bestj, bestsize };
  }

  const std::vector<match_block_t> &get_matching_blocks()
  {
    if ( have_blocks )
      return blocks;
    int la = int(a.size()), lb = int(b.size());
    struct range_t { int alo, ahi, blo, bhi; };
    std::vector<range_t> queue{ { 0, la, 0, lb } };
    std::vector<match_block_t> mb;
    while ( !queue.empty() )
    {
      range_t r = queue.back();
      queue.pop_back();
      match_block_t x = find_longest_match(r.alo, r.ahi, r.blo, r.bhi);
      if ( x.size != 0 )
      {
        mb.push_back(x);
        if ( r.alo < x.a && r.blo < x.b )
          queue.push_back({ r.alo, x.a, r.blo, x.b });
        if ( x.a + x.size < r.ahi && x.b + x.size < r.bhi )
          queue.push_back({ x.a + x.size, r.ahi, x.b + x.size, r.bhi });
      }
    }
    std::sort(mb.begin(), mb.end(), [](const match_block_t &x, const match_block_t &y)
    {
      if ( x.a != y.a ) return x.a < y.a;
      if ( x.b != y.b ) return x.b < y.b;
      return x.size < y.size;
    });
    int i1 = 0, j1 = 0, k1 = 0;
    for ( const auto &m : mb )
    {
      if ( i1 + k1 == m.a && j1 + k1 == m.b )
      {
        k1 += m.size;
      }
      else
      {
        if ( k1 != 0 )
          blocks.push_back({ i1, j1, k1 });
        i1 = m.a;
        j1 = m.b;
        k1 = m.size;
      }
    }
    if ( k1 != 0 )
      blocks.push_back({ i1, j1, k1 });
    blocks.push_back({ la, lb, 0 });
    have_blocks = true;
    return blocks;
  }

  std::vector<opcode_t> get_opcodes()
  {
    std::vector<opcode_t> answer;
    int i = 0, j = 0;
    for ( const auto &m : get_matching_blocks() )
    {
      char tag = 0;
      if ( i < m.a && j < m.b )
        tag = 'r';
      else if ( i < m.a )
        tag = 'd';
      else if ( j < m.b )
        tag = 'i';
      if ( tag != 0 )
        answer.push_back({ tag, i, m.a, j, m.b });
      i = m.a + m.size;
      j = m.b + m.size;
      if ( m.size != 0 )
        answer.push_back({ 'e', m.a, i, m.b, j });
    }
    return answer;
  }

  std::vector<std::vector<opcode_t>> get_grouped_opcodes(int n = 3)
  {
    std::vector<std::vector<opcode_t>> groups;
    std::vector<opcode_t> codes = get_opcodes();
    if ( codes.empty() )
      codes.push_back({ 'e', 0, 1, 0, 1 });
    if ( codes.front().tag == 'e' )
    {
      opcode_t &c = codes.front();
      c.i1 = std::max(c.i1, c.i2 - n);
      c.j1 = std::max(c.j1, c.j2 - n);
    }
    if ( codes.back().tag == 'e' )
    {
      opcode_t &c = codes.back();
      c.i2 = std::min(c.i2, c.i1 + n);
      c.j2 = std::min(c.j2, c.j1 + n);
    }
    int nn = n + n;
    std::vector<opcode_t> group;
    for ( opcode_t c : codes )
    {
      if ( c.tag == 'e' && c.i2 - c.i1 > nn )
      {
        group.push_back({ 'e', c.i1, std::min(c.i2, c.i1 + n), c.j1, std::min(c.j2, c.j1 + n) });
        groups.push_back(group);
        group.clear();
        c.i1 = std::max(c.i1, c.i2 - n);
        c.j1 = std::max(c.j1, c.j2 - n);
      }
      group.push_back(c);
    }
    if ( !group.empty() && !(group.size() == 1 && group[0].tag == 'e') )
      groups.push_back(group);
    return groups;
  }

  double ratio()
  {
    int matches = 0;
    for ( const auto &m : get_matching_blocks() )
      matches += m.size;
    size_t length = a.size() + b.size();
    return length != 0 ? 2.0 * matches / double(length) : 1.0;
  }
};

//------------------------------------------------------------------------------
// diaphora.quick_ratio / real_quick_ratio: nullptr stands for python's None
double quick_ratio(const std::string *buf1, const std::string *buf2);
double real_quick_ratio(const std::string *buf1, const std::string *buf2);

// difflib.unified_diff(a, b, lineterm=lineterm), returns all the yielded lines
std::vector<std::string> unified_diff(
        const std::vector<std::string> &a,
        const std::vector<std::string> &b,
        const char *lineterm = "\n");

//------------------------------------------------------------------------------
// side by side diff rows (similar to difflib._mdiff)
struct sbs_span_t
{
  int start, end;     // byte offsets of a changed span
  // as difflib._mdiff marks it: '+' added, '-' deleted, '^' changed
  char kind = '^';
};

struct sbs_row_t
{
  int lno = 0;        // 1-based line number in a (0: no line)
  int rno = 0;        // 1-based line number in b (0: no line)
  std::string ltxt;
  std::string rtxt;
  bool changed = false;
  // whole line removed on the left and/or added on the right (no close match)
  bool full_change = false;
  std::vector<sbs_span_t> lspans;
  std::vector<sbs_span_t> rspans;
};

std::vector<sbs_row_t> side_by_side_diff(
        const std::vector<std::string> &a,
        const std::vector<std::string> &b);

} // namespace dph
