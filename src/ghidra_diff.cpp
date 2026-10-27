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

// Diaphora-ng - "GhidraDec diff pseudo-code": the binary of the other
// version, the request to GhidraDec and its response
#include "ghidra_diff.hpp"
#include "ghidradec_link.hpp"
#include <registry.hpp>

namespace dph
{

// 3: both versions decompiled live, the other one from its binary (1 and 2
// also took pseudo-code stored at export time)
static const int GHIDRADEC_API_VERSION = 3;

//------------------------------------------------------------------------------
bool ghidra_diff_available(std::string *why)
{
  int v = ghidradec_link_version();
  if ( v < 0 )
  {
    // not loaded yet (or not installed)
    load_plugin("ghidradec");
    v = ghidradec_link_version();
  }
  if ( v < 0 )
  {
    *why = "GhidraDec (ghidradec.dll) is not installed: copy it to the IDA plugins folder.";
    return false;
  }
  if ( v != GHIDRADEC_API_VERSION )
  {
    *why = strfmt("the installed GhidraDec has the API version %d and this Diaphora-ng needs %d: install the "
                  "ghidradec.dll built with it.", v, GHIDRADEC_API_VERSION);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// settings
//------------------------------------------------------------------------------
ghidra_diff_settings_t ghidra_diff_settings()
{
  ghidra_diff_settings_t s;
  s.canonical_names = reg_read_bool("diaphora_ghidradec_canonical_names", true);
  s.rename_locals = reg_read_bool("diaphora_ghidradec_rename_locals", true);
  return s;
}

void cmd_ghidra_diff_settings()
{
  static const char form[] =
    "GhidraDec diff settings\n"
    "\n"
    "How GhidraDec diff pseudo-code and GhidraDec pseudo-code patch show the two versions.\n"
    "Both off: what Ghidra's decompiler gives, as the original Diaphora would show it.\n"
    "\n"
    "<##Local variables##"
    "#Name the locals v1, v2... in the order of first use, as Hex-Rays does, instead of Ghidra's uVar3, local_28...#"
    "Canonical names (level 1):C>\n"
    "<#Rename the locals of NEW after those of OLD, matched by where they are used in the aligned lines#"
    "Rename NEW after OLD (level 2):C>>\n";
  ghidra_diff_settings_t s = ghidra_diff_settings();
  ushort bits = 0;
  if ( s.canonical_names ) bits |= 1 << 0;
  if ( s.rename_locals )   bits |= 1 << 1;
  if ( ask_form(form, &bits) <= 0 )
    return;
  reg_write_bool("diaphora_ghidradec_canonical_names", (bits & (1 << 0)) != 0);
  reg_write_bool("diaphora_ghidradec_rename_locals", (bits & (1 << 1)) != 0);
  msg("Diaphora-ng: GhidraDec diff with canonical local names %s, NEW renamed after OLD %s.\n",
      (bits & (1 << 0)) != 0 ? "on" : "off", (bits & (1 << 1)) != 0 ? "on" : "off");
}

static std::string hex_str(uint64 v)
{
  return strfmt("0x%llx", (unsigned long long)v);
}

//------------------------------------------------------------------------------
// the binary of the other version
//------------------------------------------------------------------------------
// the binaries chosen in this session, by diff database
static std::map<std::string, std::string> g_other_binary;

static bool same_md5(const std::string &path, const std::string &md5)
{
  std::string got;
  return md5.empty() || (file_md5_hex(path, &got) && got == md5);
}

// the binary the other database was exported from: its path in the export
// (program_data 'input_file') if the file is still there, otherwise asked to
// the user. The MD5 of the export (program.md5sum) is checked.
static bool other_binary(bindiff_t &bd, std::string *path, std::string *err)
{
  auto cached = g_other_binary.find(bd.last_diff_db);
  if ( cached != g_other_binary.end() && file_exists(cached->second) )
  {
    *path = cached->second;
    return true;
  }
  sql_db_t &db = bd.get_db();
  std::string other = basename_any(bd.last_diff_db);
  sql_row_t row;
  std::string md5;
  if ( db.query_one("select md5sum from diff.program", {}, &row) && !row.is_null("md5sum") )
    md5 = row.str("md5sum");
  std::string stored;
  if ( db.query_one("select value from diff.program_data where type = 'input_file' and name = 'path' order by id desc",
                    {}, &row)
    && !row.is_null("value") )
    stored = row.str("value");
  if ( !stored.empty() && file_exists(stored) && same_md5(stored, md5) )
  {
    g_other_binary[bd.last_diff_db] = stored;
    *path = stored;
    return true;
  }

  std::string title = "Select the binary of " + other
                    + (stored.empty() ? std::string() : " (it was " + stored + ")")
                    + (md5.empty() ? std::string() : ", MD5 " + md5);
  const char *picked = ask_file(false, stored.empty() ? "*" : basename_any(stored).c_str(), "%s", title.c_str());
  if ( picked == nullptr )
  {
    *err = "the binary of the other database (" + other + ") was not found"
           + (stored.empty() ? std::string() : " (" + stored + ")") + ": select it to decompile the other version.";
    return false;
  }
  std::string chosen = picked;
  if ( !same_md5(chosen, md5)
    && ask_yn(ASKBTN_NO, "HIDECANCEL\nThe MD5 of %s is not the one of the binary %s was exported from.\n"
                         "Decompile it anyway?", basename_any(chosen).c_str(), other.c_str()) != ASKBTN_YES )
  {
    *err = basename_any(chosen) + " is not the binary of " + other + " (its MD5 differs).";
    return false;
  }
  g_other_binary[bd.last_diff_db] = chosen;
  // remembered in the other database for the next sessions
  if ( chosen != stored )
  {
    try
    {
      db.execute("delete from diff.program_data where type = 'input_file' and name = 'path'");
      db.execute("insert into diff.program_data (name, type, value) values ('path', 'input_file', ?)", { chosen });
    }
    catch ( const std::exception &e )
    {
      log("The path of the binary of %s was not saved in it: %s", other.c_str(), e.what());
    }
  }
  *path = chosen;
  return true;
}

static std::string other_prototype(const sql_row_t &r)
{
  // the type set in IDA, else its guess
  if ( !r.is_null("prototype2") && !r.str("prototype2").empty() )
    return r.str("prototype2");
  return r.is_null("prototype") ? std::string() : r.str("prototype");
}

// the side 'b' of the request: the binary, and the names and
// prototypes of the function and of its callees (the binary may have no
// symbols)
static bool side_b_json(bindiff_t &bd, uint64 address, uint64 base, std::string *side, std::string *err)
{
  std::string path;
  if ( !other_binary(bd, &path, err) )
    return false;
  sql_db_t &db = bd.get_db();
  sql_row_t f;
  db.query_one("select name, prototype, prototype2 from diff.functions where address = ?", { std::to_string(address) }, &f);
  std::string funcs = "[";
  bool first = true;
  for ( const auto &r : db.query(R"SQL(select f.address address, f.name name, f.prototype prototype, f.prototype2 prototype2
                                         from diff.callgraph c, diff.functions f
                                        where c.func_id = (select id from diff.functions where address = ?)
                                          and c.type = 'callee'
                                          and cast(f.address as integer) = cast(c.address as integer))SQL",
                                 { std::to_string(address) }) )
  {
    funcs += std::string(first ? "" : ",")
           + "{\"address\":" + json_quote(hex_str(uint64(r.to_int("address"))))
           + ",\"name\":" + json_quote(r.str("name"))
           + ",\"prototype\":" + json_quote(other_prototype(r)) + "}";
    first = false;
  }
  funcs += "]";
  *side = "{\"file\":" + json_quote(path) + ","
          "\"name\":" + json_quote(f.str("name")) + ","
          "\"address\":" + json_quote(hex_str(address)) + ","
          "\"image_base\":" + json_quote(hex_str(base)) + ","
          "\"prototype\":" + json_quote(other_prototype(f)) + ","
          "\"functions\":" + funcs + "}";
  return true;
}

//------------------------------------------------------------------------------
// the diff
//------------------------------------------------------------------------------
static void decode_side(const json_t *j, ghidra_side_t *out)
{
  out->name = jstr(j, "name");
  out->address = jstr(j, "address");
  out->prototype = jstr(j, "prototype");
  out->source = jstr(j, "source");
  out->lines = jlist(j, "lines");
}

static void decode_spans(const json_t *j, std::vector<sbs_span_t> *out)
{
  if ( j == nullptr || j->type != json_t::JARRAY )
    return;
  for ( const auto &s : j->arr )
  {
    if ( s.type != json_t::JARRAY || s.arr.size() != 3 )
      continue;
    sbs_span_t sp;
    sp.start = int(s.arr[0].i);
    sp.end = int(s.arr[1].i);
    sp.kind = s.arr[2].s.empty() ? '^' : s.arr[2].s[0];
    out->push_back(sp);
  }
}

bool ghidra_diff(bindiff_t &bd, const chooser_item_t &item, bool a_is_new, ghidra_diff_t *out, std::string *err)
{
  if ( !ghidra_diff_available(err) )
    return false;
  *out = ghidra_diff_t();
  sql_db_t &db = bd.get_db();
  sql_row_t row2;
  if ( !db.query_one("select address, rva from diff.functions where address = ?", { std::to_string(item.ea2) }, &row2) )
  {
    *err = "the function " + hex_ea(item.ea2) + " is not in the diff database.";
    return false;
  }
  uint64 address = uint64(row2.to_int("address"));
  uint64 base = row2.is_null("rva") ? 0 : address - uint64(row2.to_int("rva"));
  // GhidraDec decompiles the other version now, from its binary
  std::string side_b;
  if ( !side_b_json(bd, address, base, &side_b, err) )
    return false;

  ghidra_diff_settings_t s = ghidra_diff_settings();
  std::string req = "{\"a\":{\"ea\":" + json_quote(hex_str(item.ea1)) + "},"
                    "\"b\":" + side_b + ","
                    "\"a_is_new\":" + (a_is_new ? "true" : "false") + ","
                    "\"canonical_names\":" + (s.canonical_names ? "true" : "false") + ","
                    "\"rename_locals\":" + (s.rename_locals ? "true" : "false") + "}";
  debug_log("GhidraDec diff request: %s", req.c_str());
  std::string resp;
  if ( !ghidradec_link_diff(req, &resp) )
  {
    *err = "the call to GhidraDec failed.";
    return false;
  }
  json_t j;
  if ( !json_parse(resp, &j) || j.type != json_t::JOBJECT )
  {
    *err = "the response of GhidraDec is not valid JSON.";
    return false;
  }
  if ( !jbool(&j, "ok") )
  {
    *err = jstr(&j, "error");
    if ( err->empty() )
      *err = "GhidraDec gave no answer.";
    return false;
  }
  decode_side(jget(&j, "old"), &out->old_side);
  decode_side(jget(&j, "new"), &out->new_side);
  const std::vector<std::string> &ol = out->old_side.lines;
  const std::vector<std::string> &nl = out->new_side.lines;
  const json_t *rows = jget(&j, "rows");
  if ( rows != nullptr && rows->type == json_t::JARRAY )
  {
    for ( const auto &r : rows->arr )
    {
      sbs_row_t row;
      row.lno = int(jnum(&r, "l"));
      row.rno = int(jnum(&r, "r"));
      row.changed = jbool(&r, "c");
      if ( row.lno > 0 && size_t(row.lno) <= ol.size() )
        row.ltxt = ol[row.lno - 1];
      if ( row.rno > 0 && size_t(row.rno) <= nl.size() )
        row.rtxt = nl[row.rno - 1];
      decode_spans(jget(&r, "ls"), &row.lspans);
      decode_spans(jget(&r, "rs"), &row.rspans);
      out->rows.push_back(std::move(row));
    }
  }
  const json_t *ch = jget(&j, "changes");
  if ( ch != nullptr && ch->type == json_t::JARRAY )
  {
    for ( const auto &c : ch->arr )
    {
      ghidra_change_t gc;
      gc.kind = jstr(&c, "kind");
      const json_t *o = jget(&c, "old_lines");
      const json_t *n = jget(&c, "new_lines");
      if ( o != nullptr && o->type == json_t::JARRAY && o->arr.size() == 2 )
      {
        gc.old_first = int(o->arr[0].i);
        gc.old_last = int(o->arr[1].i);
      }
      if ( n != nullptr && n->type == json_t::JARRAY && n->arr.size() == 2 )
      {
        gc.new_first = int(n->arr[0].i);
        gc.new_last = int(n->arr[1].i);
      }
      gc.description = jstr(&c, "description");
      out->changes.push_back(gc);
    }
  }
  out->calls_added = jlist(&j, "calls_added");
  out->calls_removed = jlist(&j, "calls_removed");
  out->constants_added = jlist(&j, "constants_added");
  out->constants_removed = jlist(&j, "constants_removed");
  out->normalized_rows = int(jnum(&j, "normalized_rows"));
  out->identical = jbool(&j, "identical");
  // a GhidraDec older than the settings always applied both
  out->canonical_names = jget(&j, "canonical_names") == nullptr || jbool(&j, "canonical_names");
  out->rename_locals = jget(&j, "rename_locals") == nullptr || jbool(&j, "rename_locals");
  out->warnings = jlist(&j, "warnings");
  out->ghidra = jstr(&j, "ghidra");
  out->version = jstr(&j, "version");
  out->seconds = int64(jnum(&j, "seconds"));
  return true;
}

} // namespace dph
