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

// Diaphora-ng - the main binary diffing class
//
// Port of diaphora.CBinDiff (diaphora.py) and diaphora_ida.CIDABinDiff
// (diaphora_ida.py). The implementation is split in several files:
//   bindiff.cpp   - construction, databases, choosers data
//   exporter.cpp  - exporting the IDA database to SQLite
//   differ.cpp    - the diffing engine (heuristics, matches, multimatches)
//   results.cpp   - saving / loading diffing results
//   importer.cpp  - importing names, comments, prototypes and types
//   vulns.cpp     - built-in port of scripts/patch_diff_vulns.py
#pragma once
#include "common.hpp"
#include "config.hpp"
#include "db.hpp"
#include "algorithms.hpp"
#include <array>

namespace dph
{

//------------------------------------------------------------------------------
// match categories ("best", "partial", "unreliable")
enum category_t
{
  CAT_NONE = -1,
  CAT_BEST = 0,
  CAT_PARTIAL = 1,
  CAT_UNRELIABLE = 2,
  CAT_COUNT = 3,
};
const char *category_name(int cat);

// [ea1, name1, ea2, name2, description, ratio, nodes1, nodes2]
struct match_item_t
{
  uint64 ea1 = 0;
  std::string name1;
  uint64 ea2 = 0;
  std::string name2;
  std::string desc;
  double ratio = 0;
  int64 nodes1 = 0;
  int64 nodes2 = 0;

  std::string key() const;
};

struct matched_t
{
  std::string name;
  double ratio = 0;
};

//------------------------------------------------------------------------------
// CChooser: the data shown by the result choosers
struct chooser_item_t
{
  std::string line;       // "%05lu"
  uint64 ea1 = 0;
  std::string name1;
  uint64 ea2 = 0;
  std::string name2;
  double ratio = 0;
  int64 nodes1 = 0;
  int64 nodes2 = 0;
  std::string desc;
};

struct chooser_data_t
{
  std::string title;
  bool primary = true;        // jump to the main database address
  bool show_commands = true;  // false for the "Unmatched in" choosers
  std::vector<chooser_item_t> items;
  uint64 n = 0;

  chooser_data_t(const char *_title, bool _show_commands = true);
  bool is_unmatched() const { return !show_commands; }
  void add_item(const match_item_t &item);
  void add_unmatched(uint64 ea, const std::string &name);
  bgcolor_t get_color() const;
  void clear() { items.clear(); n = 0; }
};

//------------------------------------------------------------------------------
// export / diff options (BinDiffOptions)
struct bindiff_options_t
{
  std::string file_out;
  std::string file_in;
  bool use_decompiler = config::EXPORTING_USE_DECOMPILER;
  bool exclude_library_thunk = config::EXPORTING_EXCLUDE_LIBRARY_THUNK;
  bool relax = false;
  bool unreliable = config::DIFFING_ENABLE_UNRELIABLE;
  bool slow = true;
  bool experimental = config::DIFFING_ENABLE_EXPERIMENTAL;
  ea_t min_ea = 0;
  ea_t max_ea = 0;
  bool ida_subs = config::EXPORTING_ONLY_NON_IDA_SUBS;
  bool ignore_sub_names = config::DIFFING_IGNORE_SUB_FUNCTION_NAMES;
  bool ignore_all_names = config::DIFFING_IGNORE_ALL_FUNCTION_NAMES;
  bool ignore_small_functions = config::DIFFING_IGNORE_SMALL_FUNCTIONS;
  bool func_summaries_only = false;
  bool export_microcode = true;

  // fill the defaults that depend on the current IDA database
  void set_defaults();
};

//------------------------------------------------------------------------------
// exported data for one function (the 'props' tuple of the python version)
struct instruction_data_t
{
  int64 rva = 0;
  std::string mnem;
  std::string disasm;
  sql_value_t cmt1;
  sql_value_t cmt2;
  std::string operand_names;  // json
  sql_value_t name;
  sql_value_t type;
};

struct microcode_line_t
{
  sql_value_t address;
  std::string line;
  sql_value_t mnemonic;
  std::string color_line;
  sql_value_t comments;
};

struct microcode_block_t
{
  int serial = 0;
  ea_t start = 0;
  ea_t end = 0;
  std::vector<microcode_line_t> lines;
  int64 bblock_id = 0;
};

// a constant: either a number or a string
struct constant_t
{
  bool is_str = false;
  uint64 num = 0;
  std::string str;
  std::string json() const { return is_str ? json_quote(str) : std::to_string(num); }
};

struct func_props_t
{
  std::string name;
  int64 nodes = 0;
  int64 edges = 0;
  int64 indegree = 0;
  int64 outdegree = 0;
  int64 size = 0;
  int64 instructions = 0;
  std::vector<std::string> mnems;
  std::vector<std::string> names;
  sql_value_t proto;
  int64 cc = 0;
  sql_value_t prime;              // str(primes[cc]) or 0
  ea_t f = BADADDR;
  sql_value_t comment;
  std::string true_name;
  std::string bytes_hash;
  sql_value_t pseudo;
  int64 pseudo_lines = 0;
  sql_value_t pseudo_hash1;
  sql_value_t pseudocode_primes;
  uint64 function_flags = 0;
  std::string asm_text;
  sql_value_t proto2;
  sql_value_t pseudo_hash2;
  sql_value_t pseudo_hash3;
  int64 strongly_connected_size = 0;
  int64 loops = 0;
  int64 rva = 0;
  sql_value_t bb_topological;
  bignum_t strongly_connected_spp;
  std::string clean_assembly;
  sql_value_t clean_pseudo;
  bignum_t mnemonics_spp;
  std::string switches;           // json
  std::string function_hash;
  uint64 bytes_sum = 0;
  sql_value_t md_index;
  std::vector<constant_t> constants;
  int64 seg_rva = 0;
  std::vector<int64> assembly_addrs;
  std::string kgh_hash;
  sql_value_t microcode;
  sql_value_t clean_microcode;
  bignum_t microcode_spp;
  std::string export_time;
  std::vector<microcode_block_t> microcode_bblocks;
  std::map<int, std::vector<int>> microcode_bbrelations;
  std::vector<ea_t> callers;
  std::vector<ea_t> callees;
  std::vector<std::pair<int64, std::vector<instruction_data_t>>> basic_blocks_data;
  ograph_t bb_relations;
  // rva -> (comment, item preciser) of the user comments in the pseudo-code
  std::map<int64, std::pair<std::string, int>> pseudo_comments;
};

// fields of a function needed to compare two functions (main_d / diff_d).
// The pointers reference the values of a sql_row_t that must outlive this.
struct func_cmp_t
{
  const sql_value_t *ea = nullptr;
  const sql_value_t *name = nullptr;
  const sql_value_t *pseudo = nullptr;
  const sql_value_t *asm_text = nullptr;
  const sql_value_t *pseudocode_primes = nullptr;
  const sql_value_t *nodes = nullptr;
  const sql_value_t *md_index = nullptr;
  const sql_value_t *clean_assembly = nullptr;
  const sql_value_t *clean_pseudo = nullptr;
  const sql_value_t *clean_micro = nullptr;
  const sql_value_t *bytes_hash = nullptr;
};

// basic blocks of a function as returned by CBinDiff.get_graph()
struct bb_graph_t
{
  using ins_t = std::array<std::string, 3>;   // [address, mnemonic, disasm]
  std::vector<std::string> order;             // blocks in query order
  std::unordered_map<std::string, std::vector<ins_t>> blocks;
  std::vector<std::string> rel_order;
  std::unordered_map<std::string, std::set<std::string>> relations;
  bool empty() const { return blocks.empty() && relations.empty(); }
};
using bb_colours_t = std::unordered_map<std::string, bgcolor_t>;

class vuln_hooks_t;

//------------------------------------------------------------------------------
class bindiff_t
{
public:
  //----------------------------------------------------------------------------
  // options
  std::string db_name;
  bool unreliable;
  bool relaxed_ratio;
  bool experimental;
  bool slow_heuristics;
  bool exclude_library_thunk;
  bool use_decompiler;
  bool ida_subs = config::EXPORTING_ONLY_NON_IDA_SUBS;
  bool function_summaries_only = config::EXPORTING_FUNCTION_SUMMARIES_ONLY;
  bool ignore_sub_names = config::DIFFING_IGNORE_SUB_FUNCTION_NAMES;
  bool ignore_all_names;
  bool ignore_small_functions;
  bool export_microcode;
  ea_t min_ea = 0;
  ea_t max_ea = 0;
  int64 sql_max_processed_rows;
  double timeout;
  int cpu_count;

  //----------------------------------------------------------------------------
  // matching state
  std::mutex items_lock;
  std::array<std::vector<match_item_t>, CAT_COUNT> all_matches;
  std::array<std::unordered_set<std::string>, CAT_COUNT> all_matches_keys;
  std::unordered_map<std::string, matched_t> matched_primary;
  std::unordered_map<std::string, matched_t> matched_secondary;
  int64 total_functions1 = 0;
  int64 total_functions2 = 0;
  bool equal_callgraph = false;
  bool is_symbols_stripped = false;
  bool is_patch_diff = false;
  bool is_same_processor = false;
  bool do_continue = true;
  double percent = 0;

  std::mutex ratios_lock;
  std::unordered_map<std::string, double> ratios_cache;

  std::unique_ptr<vuln_hooks_t> hooks;

  //----------------------------------------------------------------------------
  // choosers
  chooser_data_t best_chooser;
  chooser_data_t partial_chooser;
  chooser_data_t unreliable_chooser;
  chooser_data_t multimatch_chooser;
  chooser_data_t unmatched_primary;
  chooser_data_t unmatched_second;
  chooser_data_t interesting_matches;

  std::string last_diff_db;

  //----------------------------------------------------------------------------
  bindiff_t(const std::string &db_name);
  ~bindiff_t();
  bindiff_t(const bindiff_t &) = delete;
  bindiff_t &operator=(const bindiff_t &) = delete;

  void apply_options(const bindiff_options_t &opts, int64 total_functions);

  //----------------------------------------------------------------------------
  // databases (bindiff.cpp)
  sql_db_t &get_db();
  // close the connection of a worker thread
  void release_thread_db();
  void db_close();
  void create_schema();
  void create_indices();
  void attach_database(const std::string &diff_db);
  void commit_and_start_transaction();
  void commit();
  void add_program_data(const std::string &type_name, const std::string &key, const sql_value_t &value);
  bool get_function_row(const std::string &name, const char *db_name, sql_row_t *row);
  bool get_function_row_by_ea(uint64 ea, const char *db_name, sql_row_t *row);
  void delete_function(ea_t ea);
  std::vector<chooser_data_t *> all_choosers();

  //----------------------------------------------------------------------------
  // export (exporter.cpp)
  void export_db();
  std::unique_ptr<func_props_t> read_function(ea_t ea);
  void save_function(func_props_t &props);
  // decompile a function, returns the prototype line (or false)
  bool decompile_and_get(ea_t ea, std::string *proto);

  //----------------------------------------------------------------------------
  // diff (differ.cpp)
  bool diff(const std::string &diff_db);
  double check_ratio(const func_cmp_t &main_d, const func_cmp_t &diff_d);
  double compare_function_rows(const sql_row_t &main_row, const sql_row_t &diff_row);
  bool has_better_match(const std::string &name1, const std::string &name2, double ratio);
  bool equal_db();
  // graphs for the 'Diff assembly in a graph' views
  void get_graph(uint64 ea, bool primary, const char *asm_type, bb_graph_t *g);
  void compare_graphs(const bb_graph_t &g1, const bb_graph_t &g2,
                      bb_colours_t *colours1, bb_colours_t *colours2);

  //----------------------------------------------------------------------------
  // results (results.cpp)
  void save_results(const std::string &filename);
  void populate_choosers(sql_db_t &results_db, double min_ratio, bool multimatch);

  //----------------------------------------------------------------------------
  // import (importer.cpp)
  void import_til();
  void import_definitions();
  void import_one(const chooser_item_t &item);
  void import_selected(const std::vector<chooser_item_t> &items, const sizevec_t &selected, bool only_auto);
  void import_all(const std::vector<chooser_item_t> &items);
  void import_all_auto(const std::vector<chooser_item_t> &items);
  void do_import_all(const std::vector<chooser_item_t> &items, bool only_subs);
  void import_items(const std::vector<chooser_item_t> &items);
  void update_choosers();

  //----------------------------------------------------------------------------
  // internal state shared by the implementation files
  struct impl_t;
  std::unique_ptr<impl_t> impl;

  // add a match to the internal lists (must always be used)
  void add_match(const std::string &name1, const std::string &name2, double ratio,
                 const match_item_t *item, int category);
  bool has_best_match_nolock(const std::string &name1, const std::string &name2);
  bool has_better_match_nolock(const std::string &name1, const std::string &name2, double ratio);
  bool all_functions_matched();
  void cleanup_matches();
};

//------------------------------------------------------------------------------
// global helpers
bool is_ida_file(const std::string &filename);
// remove a database file, or drop its tables if it cannot be removed
void remove_db_file(const std::string &filename);
// sorted list of the processor instruction names (GetInstructionList)
std::vector<std::string> get_cpu_instruction_list();

} // namespace dph
