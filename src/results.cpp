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

// Diaphora-ng - save / load diffing results (*.diaphora files)
// Port of CBinDiff.save_results and CIDABinDiff.load_results /
// load_and_import_all_results / populate_choosers.
#include "bindiff_impl.hpp"
#include "results.hpp"

#include <ctime>

namespace dph
{

static std::string asctime_now()
{
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_s(&tmv, &t);
  char buf[64];
  strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &tmv);
  return buf;
}

//------------------------------------------------------------------------------
void bindiff_t::save_results(const std::string &filename)
{
  if ( file_exists(filename) )
  {
    remove_file_quiet(filename);
    log("Previous diff results '%s' removed.", filename.c_str());
  }

  sql_db_t results_db;
  results_db.open(filename);
  results_db.exec("create table config (main_db text, diff_db text, version text, date text)");
  results_db.execute("insert into config values (?, ?, ?, ?)",
                     { db_name, last_diff_db, DIAPHORA_DB_VERSION, asctime_now() });
  results_db.exec(R"SQL(create table results (type, line, address, name, address2, name2,
                   ratio, nodes1, nodes2, description))SQL");
  results_db.exec("create unique index uq_results on results(address, address2)");
  results_db.exec("create table unmatched (type, line, address, name)");

  results_db.exec("BEGIN transaction");
  {
    sql_stmt_t results_sql(results_db, "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    sql_stmt_t unmatched_sql(results_db, "insert into unmatched values (?, ?, ?, ?)");

    struct cat_t { const char *name; chooser_data_t *chooser; bool unmatched; };
    // NOTE: the python version stores the functions unmatched in the secondary
    // database with the 'primary' type (and vice versa). Keep it compatible.
    const cat_t cats[] =
    {
      { "best",       &best_chooser,       false },
      { "partial",    &partial_chooser,    false },
      { "unreliable", &unreliable_chooser, false },
      { "multimatch", &multimatch_chooser, false },
      { "primary",    &unmatched_second,   true },
      { "secondary",  &unmatched_primary,  true },
    };
    for ( const auto &c : cats )
    {
      for ( const auto &item : c.chooser->items )
      {
        if ( c.unmatched )
        {
          unmatched_sql.run({ c.name, item.line, hex_ea(item.ea1), item.name1 });
        }
        else
        {
          results_sql.run({ c.name, item.line, hex_ea(item.ea1), item.name1, hex_ea(item.ea2),
                            item.name2, format_ratio(item.ratio), std::to_string(item.nodes1),
                            std::to_string(item.nodes2), item.desc });
        }
      }
    }
  }
  results_db.exec("commit");
  results_db.close();
  log("Diffing results saved in file '%s'.", filename.c_str());
}

//------------------------------------------------------------------------------
void bindiff_t::populate_choosers(sql_db_t &results_db, double min_ratio, bool multimatch)
{
  for ( const auto &row : results_db.query("select * from results") )
  {
    std::string rtype = row.str("type");
    chooser_data_t *choose;
    if ( rtype == "best" )
      choose = &best_chooser;
    else if ( rtype == "partial" )
      choose = &partial_chooser;
    else if ( rtype == "multimatch" && multimatch )
      choose = &multimatch_chooser;
    else
      choose = &unreliable_chooser;

    double ratio = row.to_double("ratio");
    if ( min_ratio >= 0 && ratio < min_ratio )
    {
      log("Match %s-%s is excluded", row.str("name").c_str(), row.str("name2").c_str());
      continue;
    }

    match_item_t item;
    item.ea1 = parse_uint64(row.str("address"), 16);
    item.name1 = row.str("name");
    item.ea2 = parse_uint64(row.str("address2"), 16);
    item.name2 = row.str("name2");
    item.desc = row.str("description");
    item.ratio = ratio;
    item.nodes1 = row.to_int("nodes1");
    item.nodes2 = row.to_int("nodes2");
    choose->add_item(item);
  }

  for ( const auto &row : results_db.query("select * from unmatched") )
  {
    chooser_data_t *choose = row.str("type") == "primary" ? &unmatched_second : &unmatched_primary;
    choose->add_unmatched(parse_uint64(row.str("address"), 16), row.str("name"));
  }
}

//------------------------------------------------------------------------------
bool read_results_config(const std::string &filename, results_config_t *out)
{
  try
  {
    sql_db_t results_db;
    results_db.open(filename);
    sql_rows_t rows = results_db.query("select main_db, diff_db, version from config");
    if ( rows.size() != 1 )
      return false;
    out->main_db = rows[0].str("main_db");
    out->diff_db = rows[0].str("diff_db");
    out->version = rows[0].str("version");
    return true;
  }
  catch ( const std::exception &e )
  {
    log("Error reading results file %s: %s", filename.c_str(), e.what());
  }
  return false;
}

std::unique_ptr<bindiff_t> open_results(const std::string &filename,
                                        const std::string &main_db,
                                        const std::string &diff_db,
                                        double min_ratio,
                                        bool multimatch)
{
  log("Main database '%s'.", main_db.c_str());
  log("Diff database '%s'.", diff_db.c_str());
  auto bd = std::make_unique<bindiff_t>(main_db);
  bd->attach_database(diff_db);
  bd->last_diff_db = diff_db;

  sql_db_t results_db;
  results_db.open(filename);
  bd->populate_choosers(results_db, min_ratio, multimatch);
  return bd;
}

} // namespace dph
