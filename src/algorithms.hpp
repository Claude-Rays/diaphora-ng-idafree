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
// The kfuzzy hash is a port of jkutils/kfuzzy.py:
//   Fuzzy hashing algorithms
//   Copyright (C) 2009-2023, Joxean Koret
//   Licensed under the GNU Lesser General Public License, version 2.1 or later.
// The Tarjan and topological sort code is a port of others/tarjan_sort.py:
//   Tarjan's algorithm and topological sorting implementation in Python
//   by Paul Harrison (http://www.logarithmic.net/pfh-files/blog/01208083168/)

// Diaphora-ng - algorithms without IDA dependencies
//   - others/tarjan_sort.py      (strongly connected components, topo sort)
//   - jkutils/kfuzzy.py          (CKoretFuzzyHashing.hash_bytes)
//   - CBinDiff.get_cmp_asm / get_cmp_pseudo_lines / prettify_asm
#pragma once
#include "common.hpp"

namespace dph
{

//------------------------------------------------------------------------------
// a graph as a python dict of lists: keys keep their insertion order
using gnode_t = int64;
struct ograph_t
{
  std::vector<gnode_t> order;
  std::unordered_map<gnode_t, std::vector<gnode_t>> adj;

  bool has(gnode_t k) const { return adj.find(k) != adj.end(); }
  std::vector<gnode_t> &at(gnode_t k)
  {
    auto p = adj.find(k);
    if ( p == adj.end() )
    {
      order.push_back(k);
      p = adj.emplace(k, std::vector<gnode_t>()).first;
    }
    return p->second;
  }
  const std::vector<gnode_t> *find(gnode_t k) const
  {
    auto p = adj.find(k);
    return p == adj.end() ? nullptr : &p->second;
  }
  size_t size() const { return order.size(); }
};

using component_t = std::vector<gnode_t>;

// Tarjan's algorithm, same output order as the (recursive) python version
std::vector<component_t> strongly_connected_components(const ograph_t &graph);
// identify strongly connected components, then topologically sort them
std::vector<component_t> robust_topological_sort(const ograph_t &graph);
// json.dumps(list of tuples)
std::string components_to_json(const std::vector<component_t> &comps);

//------------------------------------------------------------------------------
// CKoretFuzzyHashing with bsize = config.FUZZY_HASHING_BLOCK_SIZE
// returns "hash1;hash2;hash3"
std::string kfuzzy_hash_bytes(const std::string &bytes, int bsize);

//------------------------------------------------------------------------------
// text clean up used to compare assembly / pseudo-code / microcode
std::string get_cmp_asm(const std::string &asm_line);
std::string get_cmp_asm_lines(const std::string &asm_text);
std::string get_cmp_pseudo_lines(const std::string &pseudo);
std::string prettify_asm(const std::string &asm_source);
bool is_auto_generated(const std::string &name);
// CBinDiff.get_valid_definition
std::string get_valid_definition(const std::string &defs);

} // namespace dph
