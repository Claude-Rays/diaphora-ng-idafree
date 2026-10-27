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

// Diaphora-ng - top level commands and the export / diff dialog
// Port of _diff_or_export, CBinDiffExporterSetup, BinDiffOptions, main() and
// the menu handlers of diaphora_ida.py / diaphora_plugin.py.
#include "ui.hpp"
#include "results.hpp"

#include <chrono>

namespace dph
{

static const char MSG_RELAXED_RATIO_ENABLED[] =
  "AUTOHIDE DATABASE\n\n"
  "Relaxed ratio calculations can be enabled. It will ignore many small\n"
  "modifications to functions and will match more functions with higher ratios.\n"
  "Enable this option if you're only interested in the new functionality. Disable\n"
  "it for patch diffing if you're interested in small modifications (like buffer\n"
  "sizes).\n\n"
  "You can disable it by un-checking the 'Relaxed calculations of differences\n"
  "ratios' option.";

static const char MSG_FUNCTION_SUMMARIES_ONLY[] =
  "AUTOHIDE DATABASE\n\n"
  "Do not export basic blocks or instructions will be enabled. It will not export\n"
  "the information relative to basic blocks or instructions and 'Diff assembly in a\n"
  "graph' will not be available.\n\n"
  "This is automatically done for exporting huge databases with more than 100,000\n"
  "functions. You can disable it by un-checking the 'Do not export basic blocks or\n"
  "instructions' option.";

static double now_seconds()
{
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

static std::string format_duration(double secs)
{
  int64 s = (int64)secs;
  return strfmt("%d:%02d:%02d", int(s / 3600), int((s / 60) % 60), int(s % 60));
}

//------------------------------------------------------------------------------
// CBinDiffExporterSetup
//------------------------------------------------------------------------------
static bool show_export_dialog(bindiff_options_t *opts)
{
  static const char form[] =
    "STARTITEM 0\n"
    "Diaphora\n"
    "Please select the path to the SQLite database to save the current IDA database and the path of the SQLite database to diff against.\n"
    "If no SQLite diff database is selected, it will just export the current IDA database to SQLite format. "
    "Leave the 2nd field empty if you are exporting the first database.\n"
    "\n"
    "SQLite databases:\n"
    "<#Select a file to export the current IDA database to SQLite format#Export IDA database to SQLite  :f:1:64::>\n"
    "<#Select the SQLite database to diff against#SQLite database to diff against:f:0:64::>\n"
    "\n"
    "Export filter limits:\n"
    "<#Minimum address to find functions to export#From address:$::22::>\n"
    "<#Maximum address to find functions to export#To address  :$::22::>\n"
    "\n"
    "<##Export options##Use the decompiler if available:C>\n"
    "<#Use this option to enable or disable exporting microcode#Export microcode instructions and basic blocks:C>\n"
    "<Do not export library and thunk functions:C>\n"
    "<#Enable if you want neither sub_* functions nor library functions to be exported#Export only non-IDA generated functions:C>\n"
    "<#Export only function summaries, not all instructions. Showing differences in a graph between functions will not be available.#Do not export instructions and basic blocks:C>\n"
    "<#Enable this option to ignore thunk functions, nullsubs, etc....#Ignore small functions:C>>\n"
    "\n"
    "<##Diffing options##Use probably unreliable methods:C>\n"
    "<#Recommended to disable with databases with more than 5.000 functions#Use slow heuristics:C>\n"
    "<#Enable this option if you aren't interested in small changes#Relaxed calculations of differences ratios:C>\n"
    "<#Use tricks to speed ups some of the most common diffing tasks#Use speed ups:C>\n"
    "<#Enable this option to ignore sub_* names for the 'Same name' heuristic.#Ignore automatically generated names:C>\n"
    "<#Enable this option to ignore all function names for the 'Same name' heuristic.#Ignore all function names:C>>\n"
    "\n"
    "NOTE: Don't select IDA database files (.IDB, .I64) as only SQLite databases are considered.\n";

  char file_out[QMAXPATH];
  char file_in[QMAXPATH];
  qstrncpy(file_out, opts->file_out.c_str(), sizeof(file_out));
  qstrncpy(file_in, opts->file_in.c_str(), sizeof(file_in));
  ea_t min_ea = opts->min_ea;
  ea_t max_ea = opts->max_ea;

  ushort export_bits = 0;
  if ( opts->use_decompiler )        export_bits |= 1 << 0;
  if ( opts->export_microcode )      export_bits |= 1 << 1;
  if ( opts->exclude_library_thunk ) export_bits |= 1 << 2;
  if ( !opts->ida_subs )             export_bits |= 1 << 3;
  if ( opts->func_summaries_only )   export_bits |= 1 << 4;
  if ( opts->ignore_small_functions ) export_bits |= 1 << 5;

  ushort diff_bits = 0;
  if ( opts->unreliable )       diff_bits |= 1 << 0;
  if ( opts->slow )             diff_bits |= 1 << 1;
  if ( opts->relax )            diff_bits |= 1 << 2;
  if ( opts->experimental )     diff_bits |= 1 << 3;
  if ( opts->ignore_sub_names ) diff_bits |= 1 << 4;
  if ( opts->ignore_all_names ) diff_bits |= 1 << 5;

  if ( ask_form(form, file_out, file_in, &min_ea, &max_ea, &export_bits, &diff_bits) <= 0 )
    return false;

  opts->file_out = strip(file_out);
  opts->file_in = strip(file_in);
  opts->min_ea = min_ea;
  opts->max_ea = max_ea;
  opts->use_decompiler = (export_bits & (1 << 0)) != 0;
  opts->export_microcode = (export_bits & (1 << 1)) != 0;
  opts->exclude_library_thunk = (export_bits & (1 << 2)) != 0;
  opts->ida_subs = (export_bits & (1 << 3)) == 0;
  opts->func_summaries_only = (export_bits & (1 << 4)) != 0;
  opts->ignore_small_functions = (export_bits & (1 << 5)) != 0;
  opts->unreliable = (diff_bits & (1 << 0)) != 0;
  opts->slow = (diff_bits & (1 << 1)) != 0;
  opts->relax = (diff_bits & (1 << 2)) != 0;
  opts->experimental = (diff_bits & (1 << 3)) != 0;
  opts->ignore_sub_names = (diff_bits & (1 << 4)) != 0;
  opts->ignore_all_names = (diff_bits & (1 << 5)) != 0;
  if ( opts->relax )
    warning("%s", MSG_RELAXED_RATIO_ENABLED);
  return true;
}

//------------------------------------------------------------------------------
// _diff_or_export
//------------------------------------------------------------------------------
void diff_or_export(bool use_ui, const std::string &file_in)
{
  size_t total_functions = get_func_qty();
  qstring idb = get_path(PATH_TYPE_IDB);
  if ( idb.empty() || total_functions == 0 )
  {
    warning("No IDA database opened or no function in the database.\n"
            "Please open an IDA database and create some functions before running this script.");
    return;
  }

  bindiff_options_t opts;
  opts.set_defaults();
  opts.file_in = file_in;
  if ( opts.func_summaries_only )
    warning("%s", MSG_FUNCTION_SUMMARIES_ONLY);

  if ( use_ui && !show_export_dialog(&opts) )
    return;

  if ( opts.file_out == opts.file_in )
  {
    warning("Both databases are the same file!");
    return;
  }
  if ( opts.file_out.size() < 5 )
  {
    warning("No output database selected or invalid filename. Please select a database file.");
    return;
  }
  if ( is_ida_file(opts.file_in) || is_ida_file(opts.file_out) )
  {
    warning("One of the selected databases is an IDA file. Please select only database files.");
    return;
  }

  // the previous results reference the databases we may overwrite
  release_current_bindiff();

  bool do_export = true;
  if ( file_exists(opts.file_out) )
  {
    std::string crash_file = opts.file_out + "-crash";
    bool resume_crashed = false;
    bool crashed_before = false;
    if ( file_exists(crash_file) )
    {
      crashed_before = true;
      int ret = ask_yn(ASKBTN_YES, "The previous export session crashed. Do you want to resume the previous crashed session?");
      if ( ret == ASKBTN_CANCEL )
      {
        log("Cancelled");
        return;
      }
      resume_crashed = ret == ASKBTN_YES;
    }

    if ( !resume_crashed && !crashed_before )
    {
      int ret = ask_yn(ASKBTN_NO, "Export database already exists. Do you want to overwrite it?");
      if ( ret == ASKBTN_CANCEL )
      {
        log("Cancelled");
        return;
      }
      if ( ret == ASKBTN_NO )
        do_export = false;
    }

    if ( do_export && !resume_crashed )
    {
      remove_db_file(opts.file_out);
      log("Database '%s' removed", opts.file_out.c_str());
      remove_file_quiet(crash_file);
    }
  }

  double t0 = now_seconds();
  std::unique_ptr<bindiff_t> bd;
  try
  {
    bd = std::make_unique<bindiff_t>(opts.file_out);
    bd->apply_options(opts, (int64)total_functions);

    if ( do_export )
    {
      bd->export_db();
      log("Database exported, time taken: %s.", format_duration(now_seconds() - t0).c_str());
    }

    if ( !opts.file_in.empty() )
    {
      if ( !file_exists(opts.file_in) )
      {
        warning("The database to diff against does not exist:\n%s", opts.file_in.c_str());
        return;
      }
      if ( bd->diff(opts.file_in) )
      {
        bindiff_t *pbd = bd.get();
        set_current_bindiff(std::move(bd));
        // And, finally, show the list of best and partial matches
        show_choosers(*pbd);
        msg("Diaphora-ng: if you close one tab you can always re-open it by pressing F3 or selecting Diaphora-ng -> Show results\n");
      }
    }
  }
  catch ( const cancelled_error & )
  {
    hide_wait_box();
    log("Cancelled.");
  }
  catch ( const std::exception &e )
  {
    hide_wait_box();
    log("Error: %s", e.what());
    warning("Diaphora-ng error: %s", e.what());
  }
}

//------------------------------------------------------------------------------
// leave IDA after a batch mode operation. In the GUI (IDA Free has no batch
// mode) qexit() from a timer may hang, so ask the UI to quit instead.
static void batch_exit(int code)
{
  if ( batch )
    qexit(code);
  if ( !process_ui_action("QuitIDA") )
    qexit(code);
}

//------------------------------------------------------------------------------
// batch mode export: DIAPHORA_AUTO=1 DIAPHORA_EXPORT_FILE=path
//------------------------------------------------------------------------------
void auto_export_from_env()
{
  std::string file_out = env_str("DIAPHORA_EXPORT_FILE");
  if ( file_out.empty() )
  {
    log("No export file specified (DIAPHORA_EXPORT_FILE)!");
    batch_exit(1);
    return;
  }

  bool use_decompiler = env_exists("DIAPHORA_USE_DECOMPILER");
  auto_wait();

  if ( file_exists(file_out) )
  {
    release_current_bindiff();
    remove_db_file(file_out);
    log("Database '%s' removed", file_out.c_str());
  }

  try
  {
    bindiff_t bd(file_out);
    bd.use_decompiler = use_decompiler;
    bd.exclude_library_thunk = get_value_for("exclude_library_thunk", bd.exclude_library_thunk);
    bd.ida_subs = get_value_for("ida_subs", bd.ida_subs);
    bd.ignore_sub_names = get_value_for("ignore_sub_names", bd.ignore_sub_names);
    bd.function_summaries_only = get_value_for("function_summaries_only", bd.function_summaries_only);
    bd.min_ea = ea_t(parse_uint64(env_str("DIAPHORA_FROM_ADDRESS", "0"), 16));
    bd.export_microcode = get_value_for("export_microcode", bd.export_microcode);
    std::string to_ea = env_str("DIAPHORA_TO_ADDRESS");
    if ( !to_ea.empty() )
      bd.max_ea = ea_t(parse_uint64(to_ea, 16, bd.max_ea));
    bd.export_db();
  }
  catch ( const std::exception &e )
  {
    log("Error: %s", e.what());
  }
  batch_exit(0);
}

//------------------------------------------------------------------------------
// batch mode diff: DIAPHORA_AUTO_DIFF=1 DIAPHORA_DB1=a.sqlite
// DIAPHORA_DB2=b.sqlite DIAPHORA_DIFF_OUT=results.diaphora
// (the command line mode of diaphora.py)
//------------------------------------------------------------------------------
void auto_diff_from_env()
{
  std::string db1 = env_str("DIAPHORA_DB1");
  std::string db2 = env_str("DIAPHORA_DB2");
  std::string diff_out = env_str("DIAPHORA_DIFF_OUT");
  if ( db1.empty() || db2.empty() || diff_out.empty() )
  {
    log("DIAPHORA_DB1, DIAPHORA_DB2 and DIAPHORA_DIFF_OUT must be specified!");
    batch_exit(1);
    return;
  }

  int code = 0;
  try
  {
    bindiff_t bd(db1);
    bd.ignore_all_names = false;
    if ( bd.diff(db2) )
      bd.save_results(diff_out);
    else
      code = 1;
  }
  catch ( const std::exception &e )
  {
    log("Error: %s", e.what());
    code = 1;
  }
  batch_exit(code);
}

//------------------------------------------------------------------------------
// menu commands
//------------------------------------------------------------------------------
void cmd_diff_or_export()
{
  diff_or_export(true, "");
}

void cmd_show_results()
{
  bindiff_t *bd = current_bindiff();
  if ( bd != nullptr )
    show_choosers(*bd, false);
  else
    warning("No active diffing results to show.");
}

void cmd_save_results()
{
  bindiff_t *bd = current_bindiff();
  if ( bd == nullptr )
  {
    warning("No active diffing results to save.");
    return;
  }
  const char *filename = ask_file(true, "*.diaphora", "Select the file to store diffing results");
  if ( filename == nullptr )
    return;
  try
  {
    bd->save_results(filename);
  }
  catch ( const std::exception &e )
  {
    warning("Error saving results: %s", e.what());
  }
}

void cmd_load_results()
{
  const char *fn = ask_file(false, "*.diaphora", "Select the file to load diffing results");
  if ( fn == nullptr )
    return;
  std::string filename = fn;

  results_config_t cfg;
  if ( !read_results_config(filename, &cfg) )
  {
    warning("Malformed results database!");
    return;
  }
  if ( cfg.version != DIAPHORA_DB_VERSION )
    warning("The version of the diff results is %s and current version is %s, there can be some incompatibilities.",
            cfg.version.c_str(), DIAPHORA_DB_VERSION);

  std::string main_db = cfg.main_db;
  std::string diff_db = cfg.diff_db;
  if ( !file_exists(main_db) )
  {
    log("Primary database %s not found.", main_db.c_str());
    const char *p = ask_file(false, main_db.c_str(), "Select the primary database path");
    if ( p == nullptr )
      return;
    main_db = p;
  }
  if ( !file_exists(diff_db) )
  {
    const char *p = ask_file(false, diff_db.c_str(), "Select the secondary database path");
    if ( p == nullptr )
      return;
    diff_db = p;
  }

  try
  {
    release_current_bindiff();
    std::unique_ptr<bindiff_t> bd = open_results(filename, main_db, diff_db, -1, true);
    bindiff_t *pbd = bd.get();
    set_current_bindiff(std::move(bd));
    log("Showing diff results.");
    show_choosers(*pbd);
  }
  catch ( const std::exception &e )
  {
    warning("Error loading results: %s", e.what());
  }
}

void cmd_load_and_import_results()
{
  const char *fn = ask_file(false, "*.diaphora", "Select the diffing results to load and import");
  if ( fn == nullptr )
    return;
  std::string filename = fn;

  results_config_t cfg;
  if ( !read_results_config(filename, &cfg) )
  {
    warning("Malformed results database!");
    return;
  }
  if ( cfg.version != DIAPHORA_DB_VERSION )
    warning("The version of the diff results is %s and current version is %s, there can be some incompatibilities.",
            cfg.version.c_str(), DIAPHORA_DB_VERSION);

  try
  {
    release_current_bindiff();
    double min_ratio = get_value_for("MINIMUM_IMPORT_RATIO", 0.5);
    log("Minimum import threshold %f", min_ratio);
    std::unique_ptr<bindiff_t> bd = open_results(filename, cfg.main_db, cfg.diff_db, min_ratio, false);
    bd->import_all_auto(bd->best_chooser.items);
    bd->import_all_auto(bd->partial_chooser.items);
    set_current_bindiff(std::move(bd));
  }
  catch ( const cancelled_error & )
  {
    hide_wait_box();
    log("Cancelled.");
  }
  catch ( const std::exception &e )
  {
    hide_wait_box();
    warning("Error importing results: %s", e.what());
  }
}

void cmd_import_definitions()
{
  const char *fn = ask_file(false, "*.sqlite", "Select the file to import structures, unions and enumerations from");
  if ( fn == nullptr )
    return;
  std::string filename = fn;
  if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nDo you really want to import all structures, unions and enumerations?") != ASKBTN_YES )
    return;
  try
  {
    bindiff_t tmp(":memory:");
    tmp.attach_database(filename);
    tmp.last_diff_db = filename;
    tmp.import_til();
    tmp.import_definitions();
  }
  catch ( const std::exception &e )
  {
    warning("Error importing definitions: %s", e.what());
  }
}

} // namespace dph
