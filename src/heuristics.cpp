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

// Diaphora-ng - SQL heuristics
#include "heuristics.hpp"

namespace dph
{

#include "heuristics_data.inc"

const heuristic_t *get_heuristics(size_t *count)
{
  *count = qnumber(HEURISTICS_DATA);
  return HEURISTICS_DATA;
}

std::string py_repr(const std::string &s)
{
  char quote = '\'';
  if ( s.find('\'') != std::string::npos && s.find('"') == std::string::npos )
    quote = '"';
  std::string out;
  out += quote;
  for ( unsigned char c : s )
  {
    if ( c == quote || c == '\\' )
    {
      out += '\\';
      out += (char)c;
    }
    else if ( c == '\n' )
    {
      out += "\\n";
    }
    else if ( c == '\r' )
    {
      out += "\\r";
    }
    else if ( c == '\t' )
    {
      out += "\\t";
    }
    else if ( c < 0x20 || c == 0x7f )
    {
      out += strfmt("\\x%02x", c);
    }
    else
    {
      out += (char)c;
    }
  }
  out += quote;
  return out;
}

std::string get_query_fields(const std::string &heur, bool quote)
{
  std::string val = quote ? py_repr(heur) : heur;
  return replace_all(SELECT_FIELDS_TEMPLATE, "{heur}", val);
}

} // namespace dph
