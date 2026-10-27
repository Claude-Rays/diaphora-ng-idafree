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

// Diaphora-ng - "Claude diff pseudo-code": the request to
// Claude-Rays Decompiler and its response
#include "claude_diff.hpp"
#include "clauderays_link.hpp"
#include "difflib.hpp"

namespace dph
{

static const int CLAUDERAYS_API_VERSION = 1;

//------------------------------------------------------------------------------
bool claude_diff_available(std::string *why)
{
  int v = clauderays_link_version();
  if ( v < 0 )
  {
    // not loaded yet (or not installed)
    load_plugin("clauderays-decompiler");
    v = clauderays_link_version();
  }
  if ( v < 0 )
  {
    *why = "Claude-Rays Decompiler for IDA Free/Pro (clauderays-decompiler.dll) is not installed: copy it to the IDA plugins folder.";
    return false;
  }
  if ( v != CLAUDERAYS_API_VERSION )
  {
    *why = v == 0
         ? "the installed Claude-Rays Decompiler for IDA Free/Pro is too old: it has no API for Diaphora-ng. Install a newer clauderays-decompiler.dll."
         : strfmt("the installed Claude-Rays Decompiler for IDA Free/Pro has the API version %d, Diaphora-ng needs %d.", v, CLAUDERAYS_API_VERSION);
    return false;
  }
  return true;
}

static std::string hex_str(uint64 v)
{
  return strfmt("0x%llx", (unsigned long long)v);
}

//------------------------------------------------------------------------------
// the request: version B from the diff database
//------------------------------------------------------------------------------
static std::string demangled_short(const std::string &name)
{
  qstring dn;
  if ( name.empty() || demangle_name(&dn, name.c_str(), inf_get_short_demnames()) <= 0 || dn.empty() )
    return std::string();
  std::string s = dn.c_str();
  size_t p = s.find('(');
  if ( p != std::string::npos )
    s.resize(p);
  return s;
}

// [{address, succs, lines: [{address, text, comment}]}] from the exported
// basic blocks; from the plain assembly if the blocks were not exported
static std::string side_b_blocks(bindiff_t &bd, const sql_row_t &row, uint64 base, bool *no_blocks)
{
  sql_db_t &db = bd.get_db();
  uint64 ea2 = uint64(row.to_int("address"));

  // the instruction comments
  std::map<int64, std::string> comments;
  for ( const auto &r : db.query(R"SQL(select address, comment1, comment2
                                         from diff.instructions
                                        where func_id = (select id from diff.functions where address = ?)
                                          and asm_type = 'native')SQL",
                                 { std::to_string(ea2) }) )
  {
    std::string c = r.is_null("comment1") ? std::string() : r.str("comment1");
    std::string c2 = r.is_null("comment2") ? std::string() : r.str("comment2");
    if ( !c2.empty() && c2 != c )
      c += (c.empty() ? "" : " / ") + c2;
    if ( !c.empty() )
      comments[r.to_int("address")] = c;
  }

  auto line_json = [&](int64 rva, const std::string &text)
  {
    auto p = comments.find(rva);
    return "{\"address\":" + json_quote(hex_str(base + uint64(rva)))
         + ",\"text\":" + json_quote(text)
         + ",\"comment\":" + json_quote(p != comments.end() ? p->second : std::string()) + "}";
  };

  bb_graph_t g;
  bd.get_graph(ea2, false, "native", &g);
  std::string out = "[";
  if ( !g.blocks.empty() )
  {
    *no_blocks = false;
    bool first_block = true;
    for ( const auto &bb : g.order )
    {
      std::string succs;
      auto pr = g.relations.find(bb);
      if ( pr != g.relations.end() )
        for ( const auto &s : pr->second )
          succs += (succs.empty() ? "" : ",") + json_quote(hex_str(base + uint64(std::stoll(s))));
      std::vector<bb_graph_t::ins_t> insns = g.blocks[bb];
      std::sort(insns.begin(), insns.end(), [](const bb_graph_t::ins_t &a, const bb_graph_t::ins_t &b)
                { return std::stoll(a[0]) < std::stoll(b[0]); });
      std::string lines;
      for ( const auto &ins : insns )
        lines += (lines.empty() ? "" : ",") + line_json(std::stoll(ins[0]), ins[2]);
      out += std::string(first_block ? "" : ",")
           + "{\"address\":" + json_quote(hex_str(base + uint64(std::stoll(bb))))
           + ",\"succs\":[" + succs + "],\"lines\":[" + lines + "]}";
      first_block = false;
    }
    return out + "]";
  }

  // function_summaries_only: one pseudo block with the assembly in order
  *no_blocks = true;
  std::vector<std::string> asm_lines = split(row.str("assembly"), '\n');
  json_t addrs;
  std::vector<int64> rvas;
  if ( json_parse(row.str("assembly_addrs"), &addrs) && addrs.type == json_t::JARRAY )
    for ( const auto &a : addrs.arr )
      rvas.push_back(a.type == json_t::JINT ? a.i : atoll(jtext(&a).c_str()));
  std::string lines;
  for ( size_t i = 0; i < asm_lines.size() && i < rvas.size(); i++ )
    lines += (lines.empty() ? "" : ",") + line_json(rvas[i], asm_lines[i]);
  uint64 start = rvas.empty() ? ea2 : base + uint64(rvas[0]);
  return "[{\"address\":" + json_quote(hex_str(start)) + ",\"succs\":[],\"lines\":[" + lines + "]}]";
}

static std::string side_b_calls(bindiff_t &bd, uint64 ea2)
{
  std::string out = "[";
  bool first = true;
  for ( const auto &r : bd.get_db().query(R"SQL(select f.address address, f.name name, f.prototype prototype
                                                  from diff.callgraph c, diff.functions f
                                                 where c.func_id = (select id from diff.functions where address = ?)
                                                   and c.type = 'callee'
                                                   and cast(f.address as integer) = cast(c.address as integer)
                                                 order by c.id)SQL",
                                          { std::to_string(ea2) }) )
  {
    out += std::string(first ? "" : ",")
         + "{\"address\":" + json_quote(hex_str(uint64(r.to_int("address"))))
         + ",\"name\":" + json_quote(r.str("name"))
         + ",\"prototype\":" + json_quote(r.is_null("prototype") ? std::string() : r.str("prototype")) + "}";
    first = false;
  }
  return out + "]";
}

// the hunks of the diff of the cleaned assembly (no addresses), OLD -> NEW
static std::string asm_diff_json(const std::string &old_asm, const std::string &new_asm)
{
  std::vector<std::string> lines = unified_diff(split(old_asm, '\n'), split(new_asm, '\n'), "");
  std::string out = "[";
  bool first = true;
  // the first two lines are the file headers
  for ( size_t i = 2; i < lines.size(); i++ )
  {
    out += std::string(first ? "" : ",") + json_quote(strip(lines[i], "\n"));
    first = false;
  }
  return out + "]";
}

static bool build_request(bindiff_t &bd, const chooser_item_t &item, bool a_is_new, bool force,
                          std::string *req, std::vector<std::string> *notes, std::string *err)
{
  sql_db_t &db = bd.get_db();
  sql_row_t row2;
  if ( !db.query_one(R"SQL(select name, address, rva, prototype, comment, mangled_function, bytes_hash,
                                  assembly, assembly_addrs, clean_assembly, constants
                             from diff.functions where address = ?)SQL",
                     { std::to_string(item.ea2) }, &row2) )
  {
    *err = "the function " + hex_ea(item.ea2) + " is not in the diff database.";
    return false;
  }
  sql_row_t row1;
  std::string clean1;
  if ( db.query_one("select clean_assembly from main.functions where address = ?",
                    { std::to_string(item.ea1) }, &row1) && !row1.is_null("clean_assembly") )
    clean1 = row1.str("clean_assembly");
  std::string clean2 = row2.is_null("clean_assembly") ? std::string() : row2.str("clean_assembly");
  if ( clean1.empty() || clean2.empty() )
    notes->push_back("no cleaned assembly for one of the versions: the model got no assembly diff.");

  uint64 address = uint64(row2.to_int("address"));
  uint64 base = row2.is_null("rva") ? 0 : address - uint64(row2.to_int("rva"));
  bool no_blocks = false;
  std::string blocks = side_b_blocks(bd, row2, base, &no_blocks);
  if ( no_blocks )
    notes->push_back("the other database has no basic blocks (exported with 'function summaries only'): "
                     "its version was sent as plain assembly.");

  std::string name = row2.str("name");
  std::string mangled = row2.is_null("mangled_function") ? std::string() : row2.str("mangled_function");
  std::string demangled = demangled_short(mangled.empty() ? name : mangled);
  std::string consts = "[";
  json_t jc;
  if ( !row2.is_null("constants") && json_parse(row2.str("constants"), &jc) && jc.type == json_t::JARRAY )
    for ( size_t i = 0; i < jc.arr.size(); i++ )
      consts += std::string(i == 0 ? "" : ",") + json_quote(jtext(&jc.arr[i]));
  consts += "]";

  std::string old_asm = a_is_new ? clean2 : clean1;
  std::string new_asm = a_is_new ? clean1 : clean2;
  std::string src = "diaphora-ng:" + basename_any(bd.last_diff_db);
  *req = "{\"a\":{\"ea\":" + json_quote(hex_str(item.ea1)) + "},"
         "\"b\":{"
           "\"name\":" + json_quote(mangled.empty() ? name : mangled) + ","
           "\"demangled\":" + json_quote(demangled.empty() ? name : demangled) + ","
           "\"prototype\":" + json_quote(row2.is_null("prototype") ? std::string() : row2.str("prototype")) + ","
           "\"address\":" + json_quote(hex_str(address)) + ","
           "\"image_base\":" + json_quote(hex_str(base)) + ","
           "\"bytes_hash\":" + json_quote(row2.is_null("bytes_hash") ? std::string() : row2.str("bytes_hash")) + ","
           "\"comment\":" + json_quote(row2.is_null("comment") ? std::string() : row2.str("comment")) + ","
           "\"no_blocks\":" + (no_blocks ? "true" : "false") + ","
           "\"blocks\":" + blocks + ","
           "\"calls\":" + side_b_calls(bd, address) + ","
           "\"constants\":" + consts + ","
           "\"source\":" + json_quote(src) +
         "},"
         "\"a_is_new\":" + (a_is_new ? "true" : "false") + ","
         "\"asm_diff\":" + asm_diff_json(old_asm, new_asm) + ","
         "\"force\":" + (force ? "true" : "false") + "}";
  return true;
}

//------------------------------------------------------------------------------
// the response
//------------------------------------------------------------------------------
static void decode_side(const json_t *j, claude_side_t *out)
{
  out->summary = jstr(j, "summary");
  out->prototype = jstr(j, "prototype");
  const json_t *lines = jget(j, "lines");
  if ( lines != nullptr && lines->type == json_t::JARRAY )
    for ( const auto &l : lines->arr )
      out->lines.push_back({ jstr(&l, "text"), jstr(&l, "address") });
  const json_t *u = jget(j, "uncertain");
  if ( u != nullptr && u->type == json_t::JARRAY )
    for ( const auto &x : u->arr )
      out->uncertain.push_back({ jstr(&x, "address"), jstr(&x, "reason") });
}

bool claude_diff(bindiff_t &bd, const chooser_item_t &item, bool a_is_new, bool force,
                 claude_diff_t *out, std::string *err)
{
  if ( !claude_diff_available(err) )
    return false;
  std::string req;
  *out = claude_diff_t();
  if ( !build_request(bd, item, a_is_new, force, &req, &out->notes, err) )
    return false;
  debug_log("Claude diff request: %s", req.c_str());
  std::string resp;
  if ( !clauderays_link_diff(req, &resp) )
  {
    *err = "the call to Claude-Rays Decompiler failed.";
    return false;
  }
  json_t j;
  if ( !json_parse(resp, &j) || j.type != json_t::JOBJECT )
  {
    *err = "the response of Claude-Rays Decompiler is not valid JSON.";
    return false;
  }
  if ( !jbool(&j, "ok") )
  {
    *err = jstr(&j, "error");
    if ( err->empty() )
      *err = "Claude-Rays Decompiler gave no answer.";
    return false;
  }
  decode_side(jget(&j, "old"), &out->old_side);
  decode_side(jget(&j, "new"), &out->new_side);
  const json_t *ch = jget(&j, "changes");
  if ( ch != nullptr && ch->type == json_t::JARRAY )
  {
    for ( const auto &c : ch->arr )
    {
      claude_change_t cc;
      cc.kind = jstr(&c, "kind");
      cc.old_addresses = jlist(&c, "old_addresses");
      cc.new_addresses = jlist(&c, "new_addresses");
      cc.description = jstr(&c, "description");
      out->changes.push_back(cc);
    }
  }
  const json_t *as = jget(&j, "assessment");
  out->security_relevant = jstr(as, "security_relevant");
  out->fix_class = jstr(as, "class");
  out->reasoning = jstr(as, "reasoning");
  out->confidence = jstr(as, "confidence");
  out->follow_up = jlist(as, "follow_up");
  out->warnings = jlist(&j, "warnings");
  out->model = jstr(&j, "model");
  out->model_id = jstr(&j, "model_id");
  out->effort = jstr(&j, "effort");
  out->date = jstr(&j, "date");
  const json_t *u = jget(&j, "usage");
  out->input_tokens = int64(jnum(u, "input_tokens"));
  out->output_tokens = int64(jnum(u, "output_tokens"));
  out->cost_usd = jnum(u, "cost_usd");
  out->cached = jbool(&j, "cached");
  return true;
}

} // namespace dph
