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

// Diaphora-ng - import names, comments, prototypes and types from
// the diffed (secondary) database into the current IDA database.
// Port of the import related parts of diaphora_ida.CIDABinDiff.
#include "bindiff_impl.hpp"
#include "difflib.hpp"
#include "ui.hpp"

#include <hexrays.hpp>

namespace dph
{

//------------------------------------------------------------------------------
static std::string qs(const qstring &q)
{
  return std::string(q.c_str(), q.length());
}

// idc.SetType(): parse the declaration and apply it
static bool set_type(ea_t ea, const std::string &decl)
{
  if ( decl.empty() )
    return false;
  tinfo_t tif;
  qstring name;
  std::string text = decl;
  if ( text.back() != ';' )
    text += ';';
  if ( !parse_decl(&tif, &name, nullptr, text.c_str(), PT_SIL) )
    return false;
  return apply_tinfo(ea, tif, TINFO_DEFINITE);
}

// idc.get_struc_id(): the tid of a structure/union type, BADADDR otherwise
static tid_t get_struc_id(const std::string &name)
{
  tid_t tid = get_named_type_tid(name.c_str());
  if ( tid == BADADDR )
    return BADADDR;
  tinfo_t tif;
  if ( tif.get_type_by_tid(tid) && tif.is_udt() )
    return tid;
  return BADADDR;
}

//------------------------------------------------------------------------------
// type libraries and definitions
//------------------------------------------------------------------------------
void bindiff_t::import_til()
{
  log("Importing type libraries...");
  for ( const auto &row : get_db().query("select name from diff.program_data where type = 'til'") )
  {
    std::string til = row.str("name");
    if ( add_til(til.c_str(), ADDTIL_DEFAULT) == ADDTIL_FAILED )
      log("Error loading TIL %s", til.c_str());
  }
  auto_wait();
}

void bindiff_t::import_definitions()
{
  struct def_t
  {
    std::string type, name, value;
  };
  std::vector<def_t> new_rows;
  sql_rows_t rows = get_db().query(
        "select type, name, value from diff.program_data where type in ('structure', 'struct', 'enum', 'union')");
  for ( const auto &row : rows )
  {
    if ( row.is_null("name") )
      continue;
    std::string name = row.str("name");
    std::string the_name = split(name, ' ')[0];
    if ( get_struc_id(the_name) != BADADDR )
      continue;
    std::string type_name = "struct";
    if ( row.str("type") == "enum" )
      type_name = "enum";
    else if ( row.str("type") == "union" )
      type_name = "union";
    new_rows.push_back({ row.str("type"), name, row.str("value") });
    std::string line = type_name + " " + name + ";";
    parse_decls(nullptr, line.c_str(), nullptr, HTI_DCL);
  }

  for ( int i = 0; i < 10; ++i )
  {
    for ( const auto &row : new_rows )
    {
      std::string the_name = split(row.name, ' ')[0];
      if ( get_struc_id(the_name) == BADADDR && get_struc_id(row.name) == BADADDR )
      {
        std::string definition = get_valid_definition(row.value);
        parse_decls(nullptr, definition.c_str(), nullptr, HTI_DCL);
      }
    }
  }
  auto_wait();
}

//------------------------------------------------------------------------------
// instruction level
//------------------------------------------------------------------------------
namespace
{
// [ea, cmt1, cmt2, operand_names, name, type, dis, cmt, itp]
struct ins_sym_t
{
  std::string ea;
  sql_value_t cmt1;
  sql_value_t cmt2;
  std::vector<std::pair<int, std::string>> operand_names;
  sql_value_t name;
  sql_value_t type;
  sql_value_t dis;
  sql_value_t cmt;
  sql_value_t itp;
};

using ins_syms_t = std::unordered_map<std::string, ins_sym_t>;

void load_syms(const sql_rows_t &rows, ins_syms_t *out)
{
  for ( const auto &row : rows )
  {
    ins_sym_t s;
    s.ea = row.str("ea");
    s.cmt1 = row["cmt1"];
    s.cmt2 = row["cmt2"];
    if ( !row.is_null("operand_names") )
    {
      json_t j;
      if ( json_parse(row.str("operand_names"), &j) && j.type == json_t::JARRAY )
      {
        for ( const auto &op : j.arr )
        {
          if ( op.type == json_t::JARRAY && op.arr.size() == 2 )
            s.operand_names.emplace_back(int(op.arr[0].i), op.arr[1].s);
        }
      }
    }
    s.name = row["name"];
    s.type = row["type"];
    s.dis = row["dis"];
    s.cmt = row["cmt"];
    s.itp = row["itp"];
    (*out)[s.ea] = std::move(s);
  }
}

// row_is_importable(): note that the python version checks the 7th field
// (the disassembly, never None) as the pseudo-code comment, so any row with
// some importable data in the secondary database is importable.
bool row_is_importable(const std::string &ea2, const ins_syms_t &import_syms)
{
  auto p = import_syms.find(ea2);
  if ( p == import_syms.end() )
    return false;
  const ins_sym_t &s = p->second;
  if ( !s.cmt1.is_null() || !s.cmt2.is_null() )
    return true;
  for ( const auto &op : s.operand_names )
    if ( !op.second.empty() )
      return true;
  if ( !s.name.is_null() )
    return true;
  return !s.dis.is_null() || !s.cmt.is_null();
}
} // namespace

static void import_instruction(bindiff_t::impl_t &impl, const ins_sym_t &ins_data1, const ins_sym_t &ins_data2)
{
  ea_t ea1 = get_imagebase() + ea_t(parse_uint64(ins_data1.ea, 10));

  // Set instruction level comments
  qstring tmp;
  if ( !ins_data2.cmt1.is_null() && get_cmt(&tmp, ea1, false) < 0 )
    set_cmt(ea1, ins_data2.cmt1.str().c_str(), false);
  if ( !ins_data2.cmt2.is_null() && get_cmt(&tmp, ea1, true) < 0 )
    set_cmt(ea1, ins_data2.cmt2.str().c_str(), true);

  for ( const auto &op : ins_data2.operand_names )
    if ( !op.second.empty() )
      set_forced_operand(ea1, op.first, op.second.c_str());

  // pseudo-code comments
  if ( !ins_data2.cmt.is_null() && hexrays_ready() )
  {
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_function(ea1, &hf, DECOMP_NO_WAIT);
    if ( cfunc != nullptr )
    {
      treeloc_t tl;
      tl.ea = ea1;
      // We might have a pseudo-code comment without item_preciser_t
      // information. Don't assign anything in that case (issue #269).
      if ( !ins_data2.itp.is_null() )
        tl.itp = item_preciser_t(ins_data2.itp.to_int());
      cfunc->set_user_cmt(tl, ins_data2.cmt.str().c_str());
      cfunc->del_orphan_cmts();
      cfunc->save_user_cmts();
    }
  }

  const sql_value_t &name = ins_data2.name;
  bool has_name = !name.is_null() && !name.str().empty();
  ea_t tmp_ea = BADADDR;
  bool the_type = false;

  std::vector<ea_t> data_refs;
  for ( ea_t x = get_first_dref_from(ea1); x != BADADDR; x = get_next_dref_from(ea1, x) )
    data_refs.push_back(x);
  if ( !data_refs.empty() )
  {
    // Global variables
    tmp_ea = data_refs[0];
    if ( impl.names.find(tmp_ea) != impl.names.end() )
    {
      qstring curr_name;
      get_ea_name(&curr_name, tmp_ea);
      if ( has_name && qs(curr_name) != name.str() && is_auto_generated(qs(curr_name)) )
        set_name(tmp_ea, name.str().c_str(), SN_CHECK);
      the_type = false;
    }
    else
    {
      // If it's an object, we don't want to rename the offset, we want to
      // rename the true global variable.
      if ( is_off(get_flags(tmp_ea), OPND_ALL) )
      {
        ea_t next = get_first_dref_from(tmp_ea);
        if ( next != BADADDR )
          tmp_ea = next;
      }
      if ( has_name )
        set_name(tmp_ea, name.str().c_str(), SN_CHECK);
      the_type = true;
    }
  }
  else
  {
    // Functions
    std::vector<ea_t> code_refs;
    for ( ea_t x = get_first_fcref_from(ea1); x != BADADDR; x = get_next_fcref_from(ea1, x) )
      code_refs.push_back(x);
    if ( code_refs.empty() )
      for ( ea_t x = get_first_cref_from(ea1); x != BADADDR; x = get_next_cref_from(ea1, x) )
        code_refs.push_back(x);

    if ( !code_refs.empty() )
    {
      qstring curr_name;
      get_ea_name(&curr_name, code_refs[0]);
      if ( has_name && qs(curr_name) != name.str() && is_auto_generated(qs(curr_name)) )
      {
        set_name(code_refs[0], name.str().c_str(), SN_CHECK);
        tmp_ea = code_refs[0];
        the_type = true;
      }
    }
  }

  if ( tmp_ea != BADADDR && the_type && !ins_data2.type.is_null() )
  {
    tinfo_t tif;
    qstring cur;
    std::string current;
    if ( get_tinfo(&tif, tmp_ea) && tif.print(&cur, nullptr, PRTYPE_1LINE) )
      current = qs(cur);
    if ( current != ins_data2.type.str() )
      set_type(tmp_ea, ins_data2.type.str());
  }
}

static void import_instruction_level(bindiff_t &bd, ea_t ea1, ea_t ea2)
{
  sql_db_t &db = bd.get_db();
  // Check first if we have any importable items
  sql_rows_t import_rows = db.query(R"SQL( select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.operand_names operand_names, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
          from diff.function_bblocks bb,
             diff.functions f,
             diff.bb_instructions bbi,
             diff.instructions ins
         where f.id = bb.function_id
           and bbi.basic_block_id = bb.basic_block_id
           and ins.id = bbi.instruction_id
           and f.address = ?
           and (ins.comment1 is not null
           or ins.comment2 is not null
           or ins.operand_names is not null
           or ins.name is not null
           or pseudocomment is not null) )SQL", { std::to_string(ea2) });
  if ( import_rows.empty() )
    return;
  ins_syms_t import_syms;
  load_syms(import_rows, &import_syms);

  // Check in the current database
  sql_rows_t match_rows = db.query(R"SQL( select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.operand_names operand_names, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
          from function_bblocks bb,
             functions f,
             bb_instructions bbi,
             instructions ins
           where f.id = bb.function_id
           and bbi.basic_block_id = bb.basic_block_id
           and ins.id = bbi.instruction_id
           and f.address = ?)SQL", { std::to_string(ea1) });
  if ( match_rows.empty() )
    return;
  ins_syms_t matched_syms;
  load_syms(match_rows, &matched_syms);

  // We have 'something' to import, let's diff the assembly...
  // (the python version orders by the second column by mistake)
  sql_rows_t diff_rows = db.query(R"SQL(select *
           from (
          select assembly, assembly_addrs, 1 side
           from functions
          where address = ?
            and assembly is not null
       union select assembly, assembly_addrs, 2 side
           from diff.functions
          where address = ?
            and assembly is not null)
          order by side asc)SQL", { std::to_string(ea1), std::to_string(ea2) });
  if ( diff_rows.size() != 2 )
    return;

  try
  {
    json_t addrs1, addrs2;
    json_parse(diff_rows[0].str("assembly_addrs"), &addrs1);
    json_parse(diff_rows[1].str("assembly_addrs"), &addrs2);
    std::vector<std::string> lines1 = splitlines(diff_rows[0].str("assembly"));
    std::vector<std::string> lines2 = splitlines(diff_rows[1].str("assembly"));
    for ( const auto &x : side_by_side_diff(lines1, lines2) )
    {
      if ( x.lno == 0 || x.rno == 0 )
        continue;
      if ( size_t(x.lno) > addrs1.arr.size() || size_t(x.rno) > addrs2.arr.size() )
        continue;

      // At this point, we know which line number matches with which another
      // line number in both databases.
      std::string s_ea1 = addrs1.arr[x.lno - 1].dump();
      std::string s_ea2 = addrs2.arr[x.rno - 1].dump();
      bool changed = x.full_change;
      bool is_importable = row_is_importable(s_ea2, import_syms);
      if ( changed || is_importable )
      {
        auto m1 = matched_syms.find(s_ea1);
        auto i2 = import_syms.find(s_ea2);
        if ( m1 != matched_syms.end() && i2 != import_syms.end() )
          import_instruction(*bd.impl, m1->second, i2->second);
        auto m2 = matched_syms.find(s_ea2);
        auto i1 = import_syms.find(s_ea1);
        if ( m2 != matched_syms.end() && i1 != import_syms.end() )
          import_instruction(*bd.impl, m2->second, i1->second);
      }
    }
  }
  catch ( const std::exception &e )
  {
    log("Error importing item: %s", e.what());
  }
}

//------------------------------------------------------------------------------
// function level
//------------------------------------------------------------------------------
static void do_import_one(bindiff_t &bd, ea_t ea1, ea_t ea2, bool force)
{
  sql_row_t row;
  if ( !bd.get_db().query_one("select prototype, comment, mangled_function, function_flags from diff.functions where address = ?",
                              { std::to_string(ea2) }, &row) )
  {
    return;
  }

  ensure_export_state(*bd.impl);
  std::string name = row.str("mangled_function");
  if ( !row.is_null("mangled_function") && (!starts_with(name, "sub_") || force) )
  {
    if ( !set_name(ea1, name.c_str(), SN_NOWARN | SN_NOCHECK) )
    {
      for ( int i = 0; i < 10; ++i )
        if ( set_name(ea1, strfmt("%s_%d", name.c_str(), i).c_str(), SN_NOWARN | SN_NOCHECK) )
          break;
    }
  }

  if ( !row.is_null("prototype") && row.str("prototype") != "int()" )
    set_type(ea1, row.str("prototype"));

  if ( !row.is_null("comment") && !row.str("comment").empty() )
  {
    if ( get_func(ea1) != nullptr )
      set_func_cmt_ea(ea1, row.str("comment").c_str(), true);
  }

  if ( !row.is_null("function_flags") )
  {
    func_t *func = get_func(ea1);
    if ( func != nullptr )
    {
      func->flags = (uint64)row.to_int("function_flags");
      update_func(func);
    }
  }

  import_instruction_level(bd, ea1, ea2);
}

static void refresh_function_row(bindiff_t &bd, ea_t ea)
{
  std::unique_ptr<func_props_t> new_func = bd.read_function(ea);
  bd.impl->decomp.clear();
  bd.delete_function(ea);
  if ( new_func )
    bd.save_function(*new_func);
  else
    log("WARNING: Trying to save a non resolved function?");
}

void bindiff_t::import_one(const chooser_item_t &item)
{
  int ret = ask_yn(ASKBTN_YES, "AUTOHIDE DATABASE\nDo you want to import all the type libraries, structs and enumerations?");
  if ( ret == ASKBTN_YES )
  {
    // Import all the type libraries and the struct and enum definitions
    import_til();
    import_definitions();
  }
  else if ( ret == ASKBTN_CANCEL )
  {
    return;
  }

  // Import just the selected item
  do_import_one(*this, ea_t(item.ea1), ea_t(item.ea2), true);
  refresh_function_row(*this, ea_t(item.ea1));
  commit();
  update_choosers();
}

void bindiff_t::import_selected(const std::vector<chooser_item_t> &items, const sizevec_t &selected, bool only_auto)
{
  // Import all the type libraries and the struct and enum definitions
  import_til();
  import_definitions();

  std::vector<chooser_item_t> new_items;
  for ( size_t index : selected )
  {
    if ( index >= items.size() )
      continue;
    const chooser_item_t &item = items[index];
    if ( !only_auto || starts_with(item.name1, "sub_") )
      new_items.push_back(item);
  }
  import_items(new_items);
}

void bindiff_t::import_items(const std::vector<chooser_item_t> &items)
{
  std::vector<ea_t> to_import;
  std::unordered_set<ea_t> seen;
  // Import all the function names and comments
  for ( const auto &item : items )
  {
    do_import_one(*this, ea_t(item.ea1), ea_t(item.ea2), false);
    if ( seen.insert(ea_t(item.ea1)).second )
      to_import.push_back(ea_t(item.ea1));
  }

  show_wait_box("Updating primary database...");
  try
  {
    commit_and_start_transaction();
    size_t total = 0;
    for ( ea_t ea : to_import )
    {
      if ( user_cancelled() )
        break;
      refresh_function_row(*this, ea);
      if ( ++total % 100 == 0 )
        replace_wait_box("Updating primary database... %u/%u", unsigned(total), unsigned(to_import.size()));
    }
    commit();
    get_db().try_exec("analyze");
    hide_wait_box();
  }
  catch ( ... )
  {
    hide_wait_box();
    try { commit(); } catch ( ... ) {}
    throw;
  }

  // Update the choosers after importing
  update_choosers();
}

void bindiff_t::update_choosers()
{
  for ( chooser_data_t *chooser : { &best_chooser, &partial_chooser, &unreliable_chooser, &multimatch_chooser } )
  {
    for ( auto &item : chooser->items )
    {
      qstring func_name;
      get_func_name(&func_name, ea_t(item.ea1));
      if ( !func_name.empty() && qs(func_name) != item.name1 )
        item.name1 = qs(func_name);
    }
  }
  refresh_all_choosers(*this);
}

void bindiff_t::do_import_all(const std::vector<chooser_item_t> &items, bool only_subs)
{
  try
  {
    import_til();
    import_definitions();
    std::vector<chooser_item_t> list;
    for ( const auto &item : items )
      if ( !only_subs || starts_with(item.name1, "sub_") )
        list.push_back(item);
    import_items(list);
  }
  catch ( const std::exception &e )
  {
    log("import_all(): %s", e.what());
  }
}

void bindiff_t::import_all(const std::vector<chooser_item_t> &items)
{
  do_import_all(items, false);
}

void bindiff_t::import_all_auto(const std::vector<chooser_item_t> &items)
{
  do_import_all(items, true);
}

} // namespace dph
