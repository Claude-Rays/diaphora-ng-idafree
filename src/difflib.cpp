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

// Diaphora-ng - difflib port
#include "difflib.hpp"

namespace dph
{

//------------------------------------------------------------------------------
static bool check_bufs(const std::string *buf1, const std::string *buf2)
{
  if ( buf1 == nullptr || buf2 == nullptr )
    return false;
  if ( buf1->empty() || buf2->empty() )
    return false;
  return true;
}

double quick_ratio(const std::string *buf1, const std::string *buf2)
{
  if ( !check_bufs(buf1, buf2) )
    return 0;
  std::vector<std::string> a = split(*buf1, '\n');
  std::vector<std::string> b = split(*buf2, '\n');
  std::unordered_map<std::string, int> fullbcount;
  for ( const auto &x : b )
    fullbcount[x]++;
  std::unordered_map<std::string, int> avail;
  int matches = 0;
  for ( const auto &elt : a )
  {
    int numb;
    auto p = avail.find(elt);
    if ( p != avail.end() )
    {
      numb = p->second;
    }
    else
    {
      auto q = fullbcount.find(elt);
      numb = q != fullbcount.end() ? q->second : 0;
    }
    avail[elt] = numb - 1;
    if ( numb > 0 )
      ++matches;
  }
  size_t length = a.size() + b.size();
  return length != 0 ? 2.0 * matches / double(length) : 1.0;
}

double real_quick_ratio(const std::string *buf1, const std::string *buf2)
{
  if ( !check_bufs(buf1, buf2) )
    return 0;
  size_t la = std::count(buf1->begin(), buf1->end(), '\n') + 1;
  size_t lb = std::count(buf2->begin(), buf2->end(), '\n') + 1;
  size_t length = la + lb;
  return length != 0 ? 2.0 * std::min(la, lb) / double(length) : 1.0;
}

//------------------------------------------------------------------------------
static std::string format_range_unified(int start, int stop)
{
  int beginning = start + 1;
  int length = stop - start;
  if ( length == 1 )
    return std::to_string(beginning);
  if ( length == 0 )
    --beginning;
  return std::to_string(beginning) + "," + std::to_string(length);
}

std::vector<std::string> unified_diff(
        const std::vector<std::string> &a,
        const std::vector<std::string> &b,
        const char *lineterm)
{
  std::vector<std::string> out;
  sequence_matcher_t<std::vector<std::string>> sm(a, b);
  bool started = false;
  for ( const auto &group : sm.get_grouped_opcodes(3) )
  {
    if ( !started )
    {
      started = true;
      out.push_back(std::string("--- ") + lineterm);
      out.push_back(std::string("+++ ") + lineterm);
    }
    const opcode_t &first = group.front();
    const opcode_t &last = group.back();
    out.push_back("@@ -" + format_range_unified(first.i1, last.i2)
                + " +" + format_range_unified(first.j1, last.j2) + " @@" + lineterm);
    for ( const auto &c : group )
    {
      if ( c.tag == 'e' )
      {
        for ( int i = c.i1; i < c.i2; ++i )
          out.push_back(" " + a[i]);
        continue;
      }
      if ( c.tag == 'r' || c.tag == 'd' )
        for ( int i = c.i1; i < c.i2; ++i )
          out.push_back("-" + a[i]);
      if ( c.tag == 'r' || c.tag == 'i' )
        for ( int j = c.j1; j < c.j2; ++j )
          out.push_back("+" + b[j]);
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// side by side
//------------------------------------------------------------------------------
namespace
{
struct sbs_builder_t
{
  const std::vector<std::string> &a;
  const std::vector<std::string> &b;
  std::vector<sbs_row_t> rows;

  sbs_builder_t(const std::vector<std::string> &_a, const std::vector<std::string> &_b) : a(_a), b(_b) {}

  void equal_row(int i, int j)
  {
    sbs_row_t r;
    r.lno = i + 1;
    r.rno = j + 1;
    r.ltxt = a[i];
    r.rtxt = b[j];
    rows.push_back(std::move(r));
  }

  // lines without a close match: deletions on the left, additions on the right
  void plain_replace(int i1, int i2, int j1, int j2)
  {
    int n = std::max(i2 - i1, j2 - j1);
    for ( int k = 0; k < n; ++k )
    {
      sbs_row_t r;
      r.changed = true;
      r.full_change = true;
      if ( i1 + k < i2 )
      {
        r.lno = i1 + k + 1;
        r.ltxt = a[i1 + k];
        r.lspans.push_back({ 0, int(r.ltxt.size()), '-' });
      }
      if ( j1 + k < j2 )
      {
        r.rno = j1 + k + 1;
        r.rtxt = b[j1 + k];
        r.rspans.push_back({ 0, int(r.rtxt.size()), '+' });
      }
      rows.push_back(std::move(r));
    }
  }

  void intraline_row(int i, int j)
  {
    sbs_row_t r;
    r.lno = i + 1;
    r.rno = j + 1;
    r.ltxt = a[i];
    r.rtxt = b[j];
    r.changed = true;
    sequence_matcher_t<std::string> sm(r.ltxt, r.rtxt, false);
    for ( const auto &op : sm.get_opcodes() )
    {
      if ( op.tag == 'e' )
        continue;
      if ( op.i2 > op.i1 )
        r.lspans.push_back({ op.i1, op.i2, op.tag == 'r' ? '^' : '-' });
      if ( op.j2 > op.j1 )
        r.rspans.push_back({ op.j1, op.j2, op.tag == 'r' ? '^' : '+' });
    }
    rows.push_back(std::move(r));
  }

  static double char_quick_ratio(const std::string &x, const std::string &y)
  {
    int cnt[256] = { 0 };
    for ( unsigned char c : y )
      cnt[c]++;
    int matches = 0;
    for ( unsigned char c : x )
    {
      if ( cnt[c] > 0 )
      {
        --cnt[c];
        ++matches;
      }
    }
    size_t length = x.size() + y.size();
    return length != 0 ? 2.0 * matches / double(length) : 1.0;
  }

  void helper(int i1, int i2, int j1, int j2)
  {
    if ( i1 < i2 && j1 < j2 )
      fancy_replace(i1, i2, j1, j2);
    else if ( i1 < i2 )
      plain_replace(i1, i2, j2, j2);
    else if ( j1 < j2 )
      plain_replace(i2, i2, j1, j2);
  }

  // simplified difflib.Differ._fancy_replace
  void fancy_replace(int i1, int i2, int j1, int j2)
  {
    if ( int64(i2 - i1) * int64(j2 - j1) > 2500 )
    {
      plain_replace(i1, i2, j1, j2);
      return;
    }
    const double cutoff = 0.75;
    double best_ratio = 0.74;
    int best_i = -1, best_j = -1;
    int eqi = -1, eqj = -1;
    for ( int j = j1; j < j2; ++j )
    {
      for ( int i = i1; i < i2; ++i )
      {
        if ( a[i] == b[j] )
        {
          if ( eqi < 0 )
          {
            eqi = i;
            eqj = j;
          }
          continue;
        }
        size_t la = a[i].size(), lb = b[j].size();
        double rq = (la + lb) != 0 ? 2.0 * std::min(la, lb) / double(la + lb) : 1.0;
        if ( rq <= best_ratio || char_quick_ratio(a[i], b[j]) <= best_ratio )
          continue;
        sequence_matcher_t<std::string> sm(a[i], b[j], false);
        double r = sm.ratio();
        if ( r > best_ratio )
        {
          best_ratio = r;
          best_i = i;
          best_j = j;
        }
      }
    }
    bool identical = false;
    if ( best_ratio < cutoff )
    {
      if ( eqi < 0 )
      {
        plain_replace(i1, i2, j1, j2);
        return;
      }
      best_i = eqi;
      best_j = eqj;
      identical = true;
    }
    helper(i1, best_i, j1, best_j);
    if ( identical )
      equal_row(best_i, best_j);
    else
      intraline_row(best_i, best_j);
    helper(best_i + 1, i2, best_j + 1, j2);
  }
};
} // namespace

std::vector<sbs_row_t> side_by_side_diff(
        const std::vector<std::string> &a,
        const std::vector<std::string> &b)
{
  sbs_builder_t sb(a, b);
  sequence_matcher_t<std::vector<std::string>> sm(a, b);
  for ( const auto &op : sm.get_opcodes() )
  {
    switch ( op.tag )
    {
      case 'e':
        for ( int k = 0; k < op.i2 - op.i1; ++k )
          sb.equal_row(op.i1 + k, op.j1 + k);
        break;
      case 'r':
        sb.fancy_replace(op.i1, op.i2, op.j1, op.j2);
        break;
      case 'd':
        sb.plain_replace(op.i1, op.i2, op.j2, op.j2);
        break;
      case 'i':
        sb.plain_replace(op.i2, op.i2, op.j1, op.j2);
        break;
    }
  }
  return std::move(sb.rows);
}

} // namespace dph
