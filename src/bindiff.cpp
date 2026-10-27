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

// Diaphora-ng - bindiff_t construction, databases and chooser data
// Port of the database related parts of diaphora.CBinDiff and db_support.
#include "bindiff_impl.hpp"
#include "vulns.hpp"

namespace dph
{

//------------------------------------------------------------------------------
// db_support/schema.py
//------------------------------------------------------------------------------
static const char *const SCHEMA_INDICES[][2] =
{
  { "functions", "bytes_hash" },
  { "functions", "pseudocode" },
  { "functions", "name" },
  { "functions", "mangled_function" },
  { "functions", "assembly, pseudocode" },
  { "functions", "nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree" },
  { "functions", "instructions, mnemonics, names" },
  { "functions", "nodes, edges, cyclomatic_complexity" },
  { "functions", "cyclomatic_complexity" },
  { "functions", "pseudocode_lines, pseudocode_primes" },
  { "functions", "names, mnemonics" },
  { "functions", "pseudocode_hash2" },
  { "functions", "pseudocode_hash3" },
  { "functions", "pseudocode_hash1, pseudocode_hash2, pseudocode_hash3" },
  { "functions", "strongly_connected" },
  { "functions", "strongly_connected_spp" },
  { "functions", "loops" },
  { "functions", "rva" },
  { "functions", "tarjan_topological_sort" },
  { "functions", "mnemonics_spp" },
  { "functions", "clean_assembly" },
  { "functions", "clean_pseudo" },
  { "functions", "switches" },
  { "functions", "function_hash" },
  { "functions", "md_index" },
  { "functions", "kgh_hash" },
  { "functions", "constants_count, constants" },
  { "functions", "md_index, constants_count, constants" },
  { "functions", "address" },
  { "functions", "microcode_spp" },
  { "functions", "microcode" },
  { "instructions", "address" },
  { "bb_relations", "parent_id, child_id" },
  { "bb_instructions", "basic_block_id, instruction_id" },
  { "function_bblocks", "function_id, basic_block_id" },
  { "constants", "constant, func_id" },
  { "callgraph", "func_id" },
  { "compilation_units", "pseudocode_primes" },
  { "compilation_units", "name" },
  { "compilation_unit_functions", "func_id" },
  { "compilation_unit_functions", "cu_id" },
};

static const char *const SCHEMA_TABLES[] =
{
  R"SQL( create table if not exists functions (
                          id integer primary key,
                          name varchar(255),
                          address text unique,
                          nodes integer,
                          edges integer,
                          indegree integer,
                          outdegree integer,
                          size integer,
                          instructions integer,
                          mnemonics text,
                          names text,
                          prototype text,
                          cyclomatic_complexity integer,
                          primes_value text,
                          comment text,
                          mangled_function text,
                          bytes_hash text,
                          pseudocode text,
                          pseudocode_lines integer,
                          pseudocode_hash1 text,
                          pseudocode_primes text,
                          function_flags integer,
                          assembly text,
                          prototype2 text,
                          pseudocode_hash2 text,
                          pseudocode_hash3 text,
                          strongly_connected integer,
                          loops integer,
                          rva text unique,
                          tarjan_topological_sort text,
                          strongly_connected_spp text,
                          clean_assembly text,
                          clean_pseudo text,
                          mnemonics_spp text,
                          switches text,
                          function_hash text,
                          bytes_sum integer,
                          md_index text,
                          constants text,
                          constants_count integer,
                          segment_rva text,
                          assembly_addrs text,
                          kgh_hash text,
                          source_file text,
                          userdata text,
                          microcode text,
                          clean_microcode text,
                          microcode_spp text,
                          export_time real) )SQL",
  R"SQL( create table if not exists program (
                  id integer primary key,
                  callgraph_primes text,
                  callgraph_all_primes text,
                  processor text,
                  md5sum text
                ) )SQL",
  R"SQL( create table if not exists program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                ))SQL",
  R"SQL( create table if not exists version (value text) )SQL",
  R"SQL( create table if not exists instructions (
                  id integer primary key,
                  func_id integer not null,
                  address text,
                  disasm text,
                  mnemonic text,
                  comment1 text,
                  comment2 text,
                  operand_names text,
                  name text,
                  type text,
                  pseudocomment text,
                  pseudoitp integer,
                  asm_type text) )SQL",
  R"SQL( create table if not exists basic_blocks (
                  id integer primary key,
                  num integer,
                  address text,
                  asm_type text))SQL",
  R"SQL( create table if not exists bb_relations (
                  id integer primary key,
                  parent_id integer not null references basic_blocks(id) ON DELETE CASCADE,
                  child_id integer not null references basic_blocks(id) ON DELETE CASCADE))SQL",
  R"SQL( create table if not exists bb_instructions (
                  id integer primary key,
                  basic_block_id integer references basic_blocks(id) on delete cascade,
                  instruction_id integer references instructions(id) on delete cascade))SQL",
  R"SQL( create table if not exists function_bblocks (
                  id integer primary key,
                  function_id integer not null references functions(id) on delete cascade,
                  basic_block_id integer not null references basic_blocks(id) on delete cascade,
                  asm_type text))SQL",
  R"SQL(create table if not exists callgraph (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  address text not null,
                  type text not null))SQL",
  R"SQL(create table if not exists constants (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  constant text not null))SQL",
  R"SQL( create table if not exists compilation_units (
                  id integer primary key,
                  name text,
                  functions int,
                  primes_value text,
                  pseudocode_primes text,
                  start_ea text unique,
                  end_ea text))SQL",
  R"SQL( create table if not exists compilation_unit_functions (
                  id integer primary key,
                  cu_id integer not null references compilation_units(id) on delete cascade,
                  func_id integer not null references functions(id) on delete cascade))SQL",
};

//------------------------------------------------------------------------------
// small types
//------------------------------------------------------------------------------
const char *category_name(int cat)
{
  switch ( cat )
  {
    case CAT_BEST:       return "best";
    case CAT_PARTIAL:    return "partial";
    case CAT_UNRELIABLE: return "unreliable";
    default:             return "none";
  }
}

std::string match_item_t::key() const
{
  uint64 bits;
  memcpy(&bits, &ratio, sizeof(bits));
  return strfmt("%llx\x01%s\x01%llx\x01%s\x01%s\x01%llx\x01%lld\x01%lld",
                (unsigned long long)ea1, name1.c_str(), (unsigned long long)ea2, name2.c_str(),
                desc.c_str(), (unsigned long long)bits, (long long)nodes1, (long long)nodes2);
}

chooser_data_t::chooser_data_t(const char *_title, bool _show_commands)
  : title(_title), show_commands(_show_commands)
{
  primary = title != "Unmatched in secondary";
}

void chooser_data_t::add_item(const match_item_t &item)
{
  chooser_item_t ci;
  ci.line = strfmt("%05llu", (unsigned long long)n);
  ci.ea1 = item.ea1;
  ci.name1 = item.name1;
  ci.ea2 = item.ea2;
  ci.name2 = item.name2;
  ci.ratio = item.ratio;
  ci.nodes1 = item.nodes1;
  ci.nodes2 = item.nodes2;
  ci.desc = item.desc;
  items.push_back(std::move(ci));
  ++n;
}

void chooser_data_t::add_unmatched(uint64 ea, const std::string &name)
{
  chooser_item_t ci;
  ci.line = strfmt("%05llu", (unsigned long long)n);
  ci.ea1 = ea;
  ci.name1 = name;
  items.push_back(std::move(ci));
  ++n;
}

bgcolor_t chooser_data_t::get_color() const
{
  if ( starts_with(title, "Best") )
    return config::HIGHLIGHT_FUNCTION_BEST;
  if ( starts_with(title, "Partial") )
    return config::HIGHLIGHT_FUNCTION_PARTIAL;
  if ( starts_with(title, "Unreliable") )
    return config::HIGHLIGHT_FUNCTION_UNRELIABLE;
  return DEFCOLOR;
}

//------------------------------------------------------------------------------
// BinDiffOptions defaults
//------------------------------------------------------------------------------
void bindiff_options_t::set_defaults()
{
  size_t total_functions = get_func_qty();
  qstring idb = get_path(PATH_TYPE_IDB);
  file_out = path_without_extension(idb.c_str()) + ".sqlite";
  file_in.clear();
  use_decompiler = config::EXPORTING_USE_DECOMPILER;
  exclude_library_thunk = config::EXPORTING_EXCLUDE_LIBRARY_THUNK;
  relax = false;
  unreliable = config::DIFFING_ENABLE_UNRELIABLE;
  slow = total_functions <= (size_t)config::MIN_FUNCTIONS_TO_DISABLE_SLOW;
  experimental = config::DIFFING_ENABLE_EXPERIMENTAL;
  min_ea = inf_get_min_ea();
  max_ea = inf_get_max_ea();
  ida_subs = config::EXPORTING_ONLY_NON_IDA_SUBS;
  ignore_sub_names = config::DIFFING_IGNORE_SUB_FUNCTION_NAMES;
  ignore_all_names = config::DIFFING_IGNORE_ALL_FUNCTION_NAMES;
  ignore_small_functions = config::DIFFING_IGNORE_SMALL_FUNCTIONS;
  // Enable, by default, exporting only function summaries for huge dbs
  func_summaries_only = total_functions > (size_t)config::MIN_FUNCTIONS_TO_CONSIDER_HUGE;
  // Microcode slows down the export process: disable it for 'big' databases
  export_microcode = total_functions <= (size_t)config::MIN_FUNCTIONS_TO_CONSIDER_MEDIUM;
}

//------------------------------------------------------------------------------
// bindiff_t
//------------------------------------------------------------------------------
bindiff_t::bindiff_t(const std::string &_db_name)
  : db_name(_db_name),
    best_chooser("Best matches"),
    partial_chooser("Partial matches"),
    unreliable_chooser("Unreliable matches"),
    multimatch_chooser("Problematic matches"),
    unmatched_primary("Unmatched in primary", false),
    unmatched_second("Unmatched in secondary", false),
    interesting_matches("Interesting matches")
{
  impl = std::make_unique<impl_t>();

  unreliable = get_value_for("unreliable", config::DIFFING_ENABLE_UNRELIABLE);
  relaxed_ratio = get_value_for("relaxed_ratio", config::DIFFING_ENABLE_RELAXED_RATIO);
  experimental = get_value_for("experimental", config::DIFFING_ENABLE_EXPERIMENTAL);
  slow_heuristics = get_value_for("slow_heuristics", config::DIFFING_ENABLE_SLOW_HEURISTICS);
  exclude_library_thunk = get_value_for("exclude_library_thunk", config::EXPORTING_EXCLUDE_LIBRARY_THUNK);
  use_decompiler = get_value_for("use_decompiler", config::EXPORTING_USE_DECOMPILER);
  timeout = (double)get_value_for("SQL_TIMEOUT_LIMIT", config::SQL_TIMEOUT_LIMIT);
  sql_max_processed_rows = get_value_for("SQL_MAX_PROCESSED_ROWS", config::SQL_MAX_PROCESSED_ROWS);
  ignore_all_names = get_value_for("ignore_all_names", config::DIFFING_IGNORE_ALL_FUNCTION_NAMES);
  ignore_small_functions = get_value_for("ignore_small_functions", config::DIFFING_IGNORE_SMALL_FUNCTIONS);
  export_microcode = get_value_for("export_microcode", config::EXPORTING_USE_MICROCODE);

  int cpus = int(std::thread::hardware_concurrency()) - 1;
  if ( cpus < 1 )
    cpus = 1;
  cpu_count = (int)get_value_for("CPU_COUNT", (int64)cpus);
  if ( cpu_count < 1 )
    cpu_count = 1;

  min_ea = inf_get_min_ea();
  max_ea = inf_get_max_ea();

  // open the main database and create the schema
  impl->main_db = std::make_unique<sql_db_t>();
  impl->main_db->open(db_name);
  create_schema();
}

bindiff_t::~bindiff_t()
{
  db_close();
}

void bindiff_t::apply_options(const bindiff_options_t &opts, int64 total_functions)
{
  use_decompiler = opts.use_decompiler;
  exclude_library_thunk = opts.exclude_library_thunk;
  unreliable = opts.unreliable;
  slow_heuristics = opts.slow;
  relaxed_ratio = opts.relax;
  experimental = opts.experimental;
  min_ea = opts.min_ea;
  max_ea = opts.max_ea;
  ida_subs = opts.ida_subs;
  ignore_sub_names = opts.ignore_sub_names;
  ignore_all_names = opts.ignore_all_names;
  ignore_small_functions = opts.ignore_small_functions;
  function_summaries_only = opts.func_summaries_only;
  export_microcode = opts.export_microcode;
  sql_max_processed_rows = config::SQL_MAX_PROCESSED_ROWS;
  timeout = double(config::SQL_TIMEOUT_LIMIT) * std::max(double(total_functions) / 20000.0, 1.0);
}

//------------------------------------------------------------------------------
sql_db_t &bindiff_t::get_db()
{
  if ( is_main_thread() )
  {
    // the database is closed after exporting: reopen it (CBinDiff.get_db)
    if ( !impl->main_db )
      impl->main_db = std::make_unique<sql_db_t>();
    if ( !impl->main_db->is_open() )
    {
      impl->main_db->open(db_name);
      create_schema();
      if ( !last_diff_db.empty() )
        impl->main_db->try_exec("attach '" + replace_all(last_diff_db, "'", "''") + "' as diff");
    }
    return *impl->main_db;
  }

  std::thread::id tid = std::this_thread::get_id();
  {
    std::lock_guard<std::mutex> lock(impl->dbs_lock);
    auto p = impl->dbs.find(tid);
    if ( p != impl->dbs.end() )
      return *p->second;
  }
  auto db = std::make_unique<sql_db_t>();
  db->open(db_name);
  if ( !last_diff_db.empty() )
    db->execute("attach ? as diff", { last_diff_db });
  std::lock_guard<std::mutex> lock(impl->dbs_lock);
  sql_db_t &ref = *db;
  impl->dbs[tid] = std::move(db);
  return ref;
}

void bindiff_t::release_thread_db()
{
  std::unique_ptr<sql_db_t> db;
  {
    std::lock_guard<std::mutex> lock(impl->dbs_lock);
    auto p = impl->dbs.find(std::this_thread::get_id());
    if ( p == impl->dbs.end() )
      return;
    db = std::move(p->second);
    impl->dbs.erase(p);
  }
  db->close();
}

void bindiff_t::db_close()
{
  {
    std::lock_guard<std::mutex> lock(impl->dbs_lock);
    impl->dbs.clear();
  }
  if ( impl->main_db )
    impl->main_db->close();
}

void bindiff_t::create_schema()
{
  sql_db_t &db = get_db();
  db.exec("PRAGMA foreign_keys = ON");
  for ( const char *sql : SCHEMA_TABLES )
    db.exec(sql);
  sql_row_t row;
  if ( !db.query_one("select 1 from version", {}, &row) )
    db.execute("insert into main.version values (?)", { DIAPHORA_DB_VERSION });
  commit();
}

void bindiff_t::create_indices()
{
  sql_db_t &db = get_db();
  for ( size_t i = 0; i < qnumber(SCHEMA_INDICES); ++i )
  {
    std::string sql = strfmt("create index if not exists idx_%u on %s(%s)",
                             unsigned(i), SCHEMA_INDICES[i][0], SCHEMA_INDICES[i][1]);
    db.exec(sql);
  }
  db.exec("analyze");
}

void bindiff_t::attach_database(const std::string &diff_db)
{
  get_db().execute("attach ? as diff", { diff_db });
}

void bindiff_t::commit()
{
  sql_db_t &db = get_db();
  if ( db.in_transaction() )
    db.exec("commit");
}

void bindiff_t::commit_and_start_transaction()
{
  sql_db_t &db = get_db();
  // Ignore the "cannot commit - no transaction active" error
  commit();
  if ( config::SQLITE_PRAGMA_SYNCHRONOUS != nullptr )
    db.try_exec(strfmt("PRAGMA synchronous = %s", config::SQLITE_PRAGMA_SYNCHRONOUS));
  if ( config::SQLITE_JOURNAL_MODE != nullptr )
    db.try_exec(strfmt("PRAGMA journal_mode = %s", config::SQLITE_JOURNAL_MODE));
  db.exec("BEGIN transaction");
}

void bindiff_t::add_program_data(const std::string &type_name, const std::string &key, const sql_value_t &value)
{
  get_db().execute("insert into main.program_data (name, type, value) values (?, ?, ?)",
                   { key, type_name, value });
}

bool bindiff_t::get_function_row(const std::string &name, const char *dbn, sql_row_t *row)
{
  try
  {
    return get_db().query_one(strfmt("select * from %s.functions where name = ?", dbn), { name }, row);
  }
  catch ( const std::exception &e )
  {
    log("ERROR at get_function_row: %s", e.what());
  }
  return false;
}

bool bindiff_t::get_function_row_by_ea(uint64 ea, const char *dbn, sql_row_t *row)
{
  try
  {
    return get_db().query_one(strfmt("select * from %s.functions where address = ?", dbn),
                              { std::to_string(ea) }, row);
  }
  catch ( const std::exception &e )
  {
    log("ERROR at get_function_row_by_ea: %s", e.what());
  }
  return false;
}

void bindiff_t::delete_function(ea_t ea)
{
  get_db().execute("delete from functions where address = ?", { std::to_string(ea) });
}

std::vector<chooser_data_t *> bindiff_t::all_choosers()
{
  return
  {
    &best_chooser, &partial_chooser, &multimatch_chooser, &unreliable_chooser,
    &unmatched_primary, &unmatched_second, &interesting_matches,
  };
}

//------------------------------------------------------------------------------
// globals
//------------------------------------------------------------------------------
bool is_ida_file(const std::string &filename)
{
  std::string f = to_lower(filename);
  return ends_with(f, ".idb") || ends_with(f, ".i64") || ends_with(f, ".til")
      || ends_with(f, ".id0") || ends_with(f, ".id1") || ends_with(f, ".nam");
}

void remove_db_file(const std::string &filename)
{
  if ( remove_file_quiet(filename) )
    return;
  // Fix for Bug #5: if the file cannot be removed (still opened by somebody
  // else in Windows) just drop the database's tables
  try
  {
    sql_db_t db;
    db.open(filename);
    static const char *const tables[] =
    {
      "functions", "program", "program_data", "version", "instructions",
      "basic_blocks", "bb_relations", "bb_instructions", "function_bblocks",
      "compilation_units", "compilation_unit_functions",
      // GhidraDec pseudo-code of the exports of older Diaphora-ng versions
      "ghidradec_pseudocode",
    };
    for ( const char *t : tables )
      db.try_exec(strfmt("drop table if exists %s", t));
  }
  catch ( const std::exception &e )
  {
    log("Error removing database %s: %s", filename.c_str(), e.what());
  }
}

std::vector<std::string> get_cpu_instruction_list()
{
  std::vector<std::string> out;
  for ( int i = PH.instruc_start; i < PH.instruc_end; ++i )
  {
    const char *name = PH.instruc[i - PH.instruc_start].name;
    if ( name != nullptr && name[0] != '\0' )
      out.push_back(name);
  }
  std::sort(out.begin(), out.end());
  return out;
}

} // namespace dph
