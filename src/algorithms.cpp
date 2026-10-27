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
#include "algorithms.hpp"
#include "config.hpp"

namespace dph
{

//------------------------------------------------------------------------------
// tarjan_sort.py
//------------------------------------------------------------------------------
std::vector<component_t> strongly_connected_components(const ograph_t &graph)
{
  std::vector<component_t> result;
  std::unordered_map<gnode_t, int64> index, lowlinks;
  std::unordered_set<gnode_t> on_stack;
  std::vector<gnode_t> stack;
  int64 counter = 0;

  struct frame_t
  {
    gnode_t node;
    const std::vector<gnode_t> *succs;
    size_t pos;
    gnode_t child;
    bool has_child;
  };
  std::vector<frame_t> frames;
  static const std::vector<gnode_t> empty;

  auto start = [&](gnode_t node)
  {
    index[node] = counter;
    lowlinks[node] = counter;
    ++counter;
    stack.push_back(node);
    on_stack.insert(node);
    const std::vector<gnode_t> *succs = graph.find(node);
    frames.push_back({ node, succs != nullptr ? succs : &empty, 0, 0, false });
  };

  for ( gnode_t root : graph.order )
  {
    if ( lowlinks.find(root) != lowlinks.end() )
      continue;
    start(root);
    while ( !frames.empty() )
    {
      size_t fi = frames.size() - 1;
      gnode_t node = frames[fi].node;
      if ( frames[fi].has_child )
      {
        frames[fi].has_child = false;
        lowlinks[node] = std::min(lowlinks[node], lowlinks[frames[fi].child]);
      }
      if ( frames[fi].pos < frames[fi].succs->size() )
      {
        gnode_t succ = (*frames[fi].succs)[frames[fi].pos++];
        if ( lowlinks.find(succ) == lowlinks.end() )
        {
          frames[fi].child = succ;
          frames[fi].has_child = true;
          start(succ);
        }
        else if ( on_stack.find(succ) != on_stack.end() )
        {
          lowlinks[node] = std::min(lowlinks[node], index[succ]);
        }
        continue;
      }
      if ( lowlinks[node] == index[node] )
      {
        component_t comp;
        while ( true )
        {
          gnode_t s = stack.back();
          stack.pop_back();
          on_stack.erase(s);
          comp.push_back(s);
          if ( s == node )
            break;
        }
        result.push_back(std::move(comp));
      }
      frames.pop_back();
    }
  }
  return result;
}

std::vector<component_t> robust_topological_sort(const ograph_t &graph)
{
  std::vector<component_t> components = strongly_connected_components(graph);

  std::unordered_map<gnode_t, size_t> node_component;
  for ( size_t c = 0; c < components.size(); ++c )
    for ( gnode_t n : components[c] )
      node_component[n] = c;

  std::vector<std::vector<size_t>> component_graph(components.size());
  for ( gnode_t node : graph.order )
  {
    auto pc = node_component.find(node);
    if ( pc == node_component.end() )
      continue;
    for ( gnode_t succ : graph.adj.at(node) )
    {
      auto ps = node_component.find(succ);
      if ( ps == node_component.end() )
        continue;
      if ( pc->second != ps->second )
        component_graph[pc->second].push_back(ps->second);
    }
  }

  // topological_sort()
  std::vector<int64> count(components.size(), 0);
  for ( size_t n = 0; n < component_graph.size(); ++n )
    for ( size_t s : component_graph[n] )
      count[s]++;
  std::vector<size_t> ready;
  for ( size_t n = 0; n < component_graph.size(); ++n )
    if ( count[n] == 0 )
      ready.push_back(n);
  std::vector<component_t> result;
  while ( !ready.empty() )
  {
    size_t node = ready.back();
    ready.pop_back();
    result.push_back(components[node]);
    for ( size_t s : component_graph[node] )
    {
      count[s]--;
      if ( count[s] == 0 )
        ready.push_back(s);
    }
  }
  return result;
}

std::string components_to_json(const std::vector<component_t> &comps)
{
  std::string out = "[";
  for ( size_t i = 0; i < comps.size(); ++i )
  {
    if ( i > 0 )
      out += ", ";
    out += "[";
    for ( size_t j = 0; j < comps[i].size(); ++j )
    {
      if ( j > 0 )
        out += ", ";
      out += std::to_string(comps[i][j]);
    }
    out += "]";
  }
  return out + "]";
}

//------------------------------------------------------------------------------
// kfuzzy.py
//------------------------------------------------------------------------------
static void utf8_append(std::string &out, int cp)
{
  if ( cp < 0x80 )
  {
    out += (char)cp;
  }
  else
  {
    out += (char)(0xC0 | (cp >> 6));
    out += (char)(0x80 | (cp & 0x3F));
  }
}

// CKoretFuzzyHashing._hash(strbytes, aggresive=False)
static std::string kfuzzy_hash(const std::string &bytes, int bsize)
{
  const int output_size = 32;
  std::vector<int> ret;
  size_t total_size = bytes.size();
  size_t idx = 0;
  while ( true )
  {
    size_t chunk_size = idx * bsize;
    uint64 sum = 0;
    for ( size_t k = chunk_size; k < chunk_size + bsize && k < total_size; ++k )
      sum += (uchar)bytes[k];
    int c = int(sum % 255);
    // reduce_errors
    if ( c != 255 && c != 0 )
      ret.push_back(c);
    ++idx;
    if ( chunk_size + bsize > total_size )
      break;
  }

  size_t size = std::min<size_t>(ret.size() / output_size, 1);
  std::vector<int> buf;
  for ( size_t c = 0; c < (size_t)output_size; ++c )
  {
    // ret[c:c+size+1][1:2] and the 'ignore_range' loop both append ret[c+1]
    size_t sl_end = std::min(ret.size(), c + size + 1);
    size_t sl_len = sl_end > c ? sl_end - c : 0;
    if ( sl_len >= 2 )
    {
      buf.push_back(ret[c + 1]);
      buf.push_back(ret[c + 1]);
    }
  }
  std::string encoded;
  for ( int cp : buf )
    utf8_append(encoded, cp);
  std::string b64 = base64_encode(encoded);
  while ( !b64.empty() && b64.back() == '=' )
    b64.pop_back();
  if ( b64.size() > (size_t)output_size )
    b64.resize(output_size);
  return b64;
}

static std::string kfuzzy_mix_blocks(const std::string &bytes, int bsize)
{
  std::string ret;
  size_t idx = 0;
  while ( true )
  {
    size_t s1 = idx * bsize;
    std::string tmp = s1 < bytes.size() ? bytes.substr(s1, bsize) : std::string();
    ret += tmp;
    ret += tmp;
    ++idx;
    if ( tmp.size() < (size_t)bsize )
      break;
  }
  return ret;
}

std::string kfuzzy_hash_bytes(const std::string &bytes, int bsize)
{
  std::string mix = kfuzzy_mix_blocks(bytes, bsize);
  std::string rev(bytes.rbegin(), bytes.rend());
  return kfuzzy_hash(mix, bsize) + ";" + kfuzzy_hash(bytes, bsize) + ";" + kfuzzy_hash(rev, bsize);
}

//------------------------------------------------------------------------------
// text clean up (re.sub with re.IGNORECASE, hand coded for speed)
//------------------------------------------------------------------------------
static inline bool is_hex(char c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline bool is_alpha(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline bool is_digit(char c)
{
  return c >= '0' && c <= '9';
}

static inline bool is_alnum(char c)
{
  return is_alpha(c) || is_digit(c);
}

// re.sub(prefix + "[a-f0-9A-F]+", repl, s, flags=re.IGNORECASE)
static std::string sub_prefix_hex(const std::string &s, const char *prefix, const char *repl)
{
  size_t plen = strlen(prefix);
  if ( s.size() <= plen )
    return s;
  std::string out;
  size_t i = 0, n = s.size();
  bool changed = false;
  while ( i < n )
  {
    if ( i + plen < n && strnicmp(s.c_str() + i, prefix, plen) == 0 && is_hex(s[i + plen]) )
    {
      size_t j = i + plen;
      while ( j < n && is_hex(s[j]) )
        ++j;
      out += repl;
      i = j;
      changed = true;
      continue;
    }
    out += s[i++];
  }
  return changed ? out : s;
}

// re.sub(letter + "[0-9]+", repl, s, flags=re.IGNORECASE) where the prefix is
// a literal string
static std::string sub_prefix_digits(const std::string &s, const char *prefix, const char *repl)
{
  size_t plen = strlen(prefix);
  std::string out;
  size_t i = 0, n = s.size();
  while ( i < n )
  {
    if ( i + plen < n && strnicmp(s.c_str() + i, prefix, plen) == 0 && is_digit(s[i + plen]) )
    {
      size_t j = i + plen;
      while ( j < n && is_digit(s[j]) )
        ++j;
      out += repl;
      i = j;
      continue;
    }
    out += s[i++];
  }
  return out;
}

std::string get_cmp_asm(const std::string &asm_line)
{
  // Ignore the comments in the assembly dump
  std::string tmp = asm_line.substr(0, asm_line.find(';'));
  size_t pos = tmp.find(" # ");
  if ( pos != std::string::npos )
    tmp.resize(pos);

  // Now, replace sub_, byte_, word_, dword_, loc_, etc...
  for ( const char *rep : config::CLEANING_CMP_REPS )
    tmp = sub_prefix_hex(tmp, rep, "XXXX");

  // Remove dword ptr, byte ptr, etc...
  for ( const char *rep : config::CLEANING_CMP_REMS )
    tmp = sub_prefix_hex(tmp, rep, "");

  // \+[a-f0-9A-F]+h\+  ->  +XXXX+
  {
    std::string out;
    size_t i = 0, n = tmp.size();
    while ( i < n )
    {
      if ( tmp[i] == '+' && i + 1 < n && is_hex(tmp[i + 1]) )
      {
        size_t j = i + 1;
        while ( j < n && is_hex(tmp[j]) )
          ++j;
        if ( j + 1 < n && (tmp[j] == 'h' || tmp[j] == 'H') && tmp[j + 1] == '+' )
        {
          out += "+XXXX+";
          i = j + 2;
          continue;
        }
      }
      out += tmp[i++];
    }
    tmp.swap(out);
  }

  // \.\.[a-f0-9A-F]{8}  ->  XXX
  {
    std::string out;
    size_t i = 0, n = tmp.size();
    while ( i < n )
    {
      if ( i + 10 <= n && tmp[i] == '.' && tmp[i + 1] == '.' )
      {
        bool ok = true;
        for ( size_t k = 2; k < 10; ++k )
          ok = ok && is_hex(tmp[i + k]);
        if ( ok )
        {
          out += "XXX";
          i += 10;
          continue;
        }
      }
      out += tmp[i++];
    }
    tmp.swap(out);
  }

  // Strip any possible remaining white-space character at the end
  tmp = rstrip(tmp, " \t\n");

  // a[A-Z]+[a-z0-9]+_[0-9]+  ->  aXXX
  {
    std::string out;
    size_t i = 0, n = tmp.size();
    while ( i < n )
    {
      if ( tmp[i] == 'a' || tmp[i] == 'A' )
      {
        size_t j = i + 1;
        if ( j < n && is_alpha(tmp[j]) )
        {
          size_t k = j;
          while ( k < n && is_alnum(tmp[k]) )
            ++k;
          if ( k - j >= 2 && k + 1 < n && tmp[k] == '_' && is_digit(tmp[k + 1]) )
          {
            size_t e = k + 1;
            while ( e < n && is_digit(tmp[e]) )
              ++e;
            out += "aXXX";
            i = e;
            continue;
          }
        }
      }
      out += tmp[i++];
    }
    tmp.swap(out);
  }

  // \#0x[A-Z0-9]+  ->  0xXXX
  {
    std::string out;
    size_t i = 0, n = tmp.size();
    while ( i < n )
    {
      if ( tmp[i] == '#' && i + 3 < n && tmp[i + 1] == '0' && (tmp[i + 2] == 'x' || tmp[i + 2] == 'X') && is_alnum(tmp[i + 3]) )
      {
        size_t j = i + 3;
        while ( j < n && is_alnum(tmp[j]) )
          ++j;
        out += "0xXXX";
        i = j;
        continue;
      }
      out += tmp[i++];
    }
    tmp.swap(out);
  }
  return tmp;
}

std::string get_cmp_asm_lines(const std::string &asm_text)
{
  std::vector<std::string> lines = split(asm_text, '\n');
  if ( !lines.empty() && lines.back().empty() )
    lines.pop_back();
  for ( auto &l : lines )
    l = get_cmp_asm(l);
  return join(lines, "\n");
}

std::string get_cmp_pseudo_lines(const std::string &pseudo)
{
  // Remove all the comments: " // .*"
  std::string tmp;
  {
    size_t i = 0, n = pseudo.size();
    tmp.reserve(n);
    while ( i < n )
    {
      if ( pseudo.compare(i, 4, " // ") == 0 )
      {
        size_t e = pseudo.find('\n', i);
        if ( e == std::string::npos )
          break;
        i = e;
        continue;
      }
      tmp += pseudo[i++];
    }
  }

  // Now, replace sub_, byte_, word_, dword_, loc_, etc...
  for ( const char *rep : config::CLEANING_CMP_REPS )
    tmp = sub_prefix_hex(tmp, rep, (std::string(rep) + "XXXX").c_str());
  tmp = sub_prefix_digits(tmp, "v", "vXXX");
  tmp = sub_prefix_digits(tmp, "a", "aXXX");
  tmp = sub_prefix_digits(tmp, "arg_", "aXXX");
  return tmp;
}

std::string prettify_asm(const std::string &asm_source)
{
  std::vector<std::string> lines = split(asm_source, '\n');
  for ( auto &l : lines )
    if ( !starts_with(l, "loc_") )
      l = "\t" + l;
  return join(lines, "\n");
}

bool is_auto_generated(const std::string &name)
{
  for ( const char *rep : config::CLEANING_CMP_REPS )
    if ( starts_with(name, rep) )
      return true;
  return false;
}

std::string get_valid_definition(const std::string &defs)
{
  std::string ret = defs;
  for ( auto &c : ret )
    if ( c == '?' || c == '@' || c == '$' )
      c = '_';
  return ret;
}

} // namespace dph
