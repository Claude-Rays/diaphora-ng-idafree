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

// Diaphora-ng - thin SQLite wrapper
//
// The python version uses the sqlite3 module with sqlite3.Row rows. This is a
// minimal equivalent: dynamically typed values, rows addressable by column
// name, cursors and transactions.
//
// SQLite comes either from the amalgamation in third_party/sqlite (if present)
// or from the system winsqlite3.dll shipped with Windows 10/11.
#pragma once
#include "common.hpp"

struct sqlite3;
struct sqlite3_stmt;

namespace dph
{

//------------------------------------------------------------------------------
struct sql_value_t
{
  enum type_t { NUL, INT, REAL, TEXT };
  type_t type = NUL;
  int64 i = 0;
  double d = 0;
  std::string s;

  sql_value_t() {}
  sql_value_t(std::nullptr_t) {}
  sql_value_t(int v) : type(INT), i(v) {}
  sql_value_t(int64 v) : type(INT), i(v) {}
  sql_value_t(uint64 v)
  {
    if ( v > (uint64)INT64_MAX )
    {
      type = TEXT;
      s = std::to_string(v);
    }
    else
    {
      type = INT;
      i = (int64)v;
    }
  }
  sql_value_t(double v) : type(REAL), d(v) {}
  sql_value_t(const char *v) { if ( v != nullptr ) { type = TEXT; s = v; } }
  sql_value_t(const std::string &v) : type(TEXT), s(v) {}
  sql_value_t(std::string &&v) : type(TEXT), s(std::move(v)) {}

  // optional strings: nullptr -> NULL
  static sql_value_t opt(const std::string *v) { return v == nullptr ? sql_value_t() : sql_value_t(*v); }

  bool is_null() const { return type == NUL; }
  bool is_number() const { return type == INT || type == REAL; }
  // python str()
  std::string str() const;
  // python int() / float()
  int64 to_int() const;
  double to_double() const;
  // python == between the values sqlite3 returns
  bool operator==(const sql_value_t &o) const;
  bool operator!=(const sql_value_t &o) const { return !(*this == o); }
};
using sql_params_t = std::vector<sql_value_t>;

//------------------------------------------------------------------------------
struct sql_row_t
{
  std::shared_ptr<std::vector<std::string>> names;
  std::vector<sql_value_t> values;

  bool empty() const { return values.empty(); }
  int index_of(const char *name) const;
  bool has(const char *name) const { return index_of(name) >= 0; }
  const sql_value_t &operator[](const char *name) const;
  const sql_value_t &operator[](size_t idx) const { return values.at(idx); }
  std::string str(const char *name) const { return (*this)[name].str(); }
  int64 to_int(const char *name) const { return (*this)[name].to_int(); }
  double to_double(const char *name) const { return (*this)[name].to_double(); }
  bool is_null(const char *name) const { return (*this)[name].is_null(); }
};
using sql_rows_t = std::vector<sql_row_t>;

//------------------------------------------------------------------------------
class sql_db_t
{
  sqlite3 *db = nullptr;
  std::function<bool()> abort_cb;

public:
  std::string path;

  sql_db_t() {}
  ~sql_db_t() { close(); }
  sql_db_t(const sql_db_t &) = delete;
  sql_db_t &operator=(const sql_db_t &) = delete;

  void open(const std::string &db_path);
  void close();
  bool is_open() const { return db != nullptr; }
  sqlite3 *handle() const { return db; }

  // execute one or more statements without parameters
  void exec(const std::string &sql);
  // execute one statement, ignoring the results
  void execute(const std::string &sql, const sql_params_t &params = {});
  // execute ignoring errors, returns success
  bool try_exec(const std::string &sql);
  sql_rows_t query(const std::string &sql, const sql_params_t &params = {});
  bool query_one(const std::string &sql, const sql_params_t &params, sql_row_t *out);

  int64 last_insert_rowid() const;
  int changes() const;
  bool in_transaction() const;

  // cb() returning true aborts the running statement (SQLITE_INTERRUPT)
  void set_abort_callback(std::function<bool()> cb);

  std::string errmsg() const;
};

//------------------------------------------------------------------------------
// a prepared statement, used like a python cursor
class sql_stmt_t
{
  sql_db_t &db;
  sqlite3_stmt *st = nullptr;
  std::shared_ptr<std::vector<std::string>> names;
  bool finished = false;

public:
  sql_stmt_t(sql_db_t &_db, const std::string &sql);
  ~sql_stmt_t();
  sql_stmt_t(const sql_stmt_t &) = delete;
  sql_stmt_t &operator=(const sql_stmt_t &) = delete;

  // reset the statement and bind new parameters
  void bind(const sql_params_t &params);
  // fetch the next row, false at the end
  bool fetch(sql_row_t *row);
  // run to completion (insert/update/delete)
  void run(const sql_params_t &params);
};

} // namespace dph
