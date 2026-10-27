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
#include "db.hpp"

#ifdef DIAPHORA_USE_WINSQLITE
#  include <winsqlite/winsqlite3.h>
#else
#  include "sqlite3.h"
#endif

#ifndef SQLITE_CALLBACK
#  define SQLITE_CALLBACK
#endif

namespace dph
{

//------------------------------------------------------------------------------
// sql_value_t
//------------------------------------------------------------------------------
std::string sql_value_t::str() const
{
  switch ( type )
  {
    case INT:  return std::to_string(i);
    case REAL: return float_repr(d);
    case TEXT: return s;
    default:   return "None";
  }
}

int64 sql_value_t::to_int() const
{
  switch ( type )
  {
    case INT:  return i;
    case REAL: return (int64)d;
    case TEXT:
      {
        int64 v;
        if ( parse_int64(s, 10, &v) )
          return v;
        return (int64)strtod(s.c_str(), nullptr);
      }
    default:
      return 0;
  }
}

double sql_value_t::to_double() const
{
  switch ( type )
  {
    case INT:  return double(i);
    case REAL: return d;
    case TEXT: return strtod(s.c_str(), nullptr);
    default:   return 0;
  }
}

bool sql_value_t::operator==(const sql_value_t &o) const
{
  if ( type == NUL || o.type == NUL )
    return type == o.type;
  if ( is_number() && o.is_number() )
  {
    if ( type == INT && o.type == INT )
      return i == o.i;
    return to_double() == o.to_double();
  }
  if ( type == TEXT && o.type == TEXT )
    return s == o.s;
  return false;
}

//------------------------------------------------------------------------------
// sql_row_t
//------------------------------------------------------------------------------
int sql_row_t::index_of(const char *name) const
{
  if ( !names )
    return -1;
  for ( size_t k = 0; k < names->size(); ++k )
    if ( stricmp((*names)[k].c_str(), name) == 0 )
      return int(k);
  return -1;
}

const sql_value_t &sql_row_t::operator[](const char *name) const
{
  int idx = index_of(name);
  if ( idx < 0 )
    throw std::runtime_error(std::string("No such column: ") + name);
  return values[idx];
}

//------------------------------------------------------------------------------
// sql_db_t
//------------------------------------------------------------------------------
void sql_db_t::open(const std::string &db_path)
{
  close();
  path = db_path;
  int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
  int rc = sqlite3_open_v2(db_path.c_str(), &db, flags, nullptr);
  if ( rc != SQLITE_OK )
  {
    std::string err = db != nullptr ? sqlite3_errmsg(db) : "out of memory";
    if ( db != nullptr )
      sqlite3_close(db);
    db = nullptr;
    throw std::runtime_error("Cannot open database '" + db_path + "': " + err);
  }
  sqlite3_busy_timeout(db, 60000);
}

void sql_db_t::close()
{
  if ( db != nullptr )
  {
    sqlite3_progress_handler(db, 0, nullptr, nullptr);
    sqlite3_close_v2(db);
    db = nullptr;
  }
}

std::string sql_db_t::errmsg() const
{
  return db != nullptr ? sqlite3_errmsg(db) : "database not opened";
}

void sql_db_t::exec(const std::string &sql)
{
  char *err = nullptr;
  int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
  if ( rc != SQLITE_OK )
  {
    std::string e = err != nullptr ? err : errmsg();
    sqlite3_free(err);
    throw std::runtime_error(e);
  }
}

bool sql_db_t::try_exec(const std::string &sql)
{
  char *err = nullptr;
  int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
  sqlite3_free(err);
  return rc == SQLITE_OK;
}

void sql_db_t::execute(const std::string &sql, const sql_params_t &params)
{
  sql_stmt_t st(*this, sql);
  st.run(params);
}

sql_rows_t sql_db_t::query(const std::string &sql, const sql_params_t &params)
{
  sql_rows_t rows;
  sql_stmt_t st(*this, sql);
  st.bind(params);
  sql_row_t row;
  while ( st.fetch(&row) )
    rows.push_back(std::move(row));
  return rows;
}

bool sql_db_t::query_one(const std::string &sql, const sql_params_t &params, sql_row_t *out)
{
  sql_stmt_t st(*this, sql);
  st.bind(params);
  return st.fetch(out);
}

int64 sql_db_t::last_insert_rowid() const
{
  return sqlite3_last_insert_rowid(db);
}

int sql_db_t::changes() const
{
  return sqlite3_changes(db);
}

bool sql_db_t::in_transaction() const
{
  return db != nullptr && sqlite3_get_autocommit(db) == 0;
}

static int SQLITE_CALLBACK progress_cb(void *ud)
{
  auto *cb = (std::function<bool()> *)ud;
  return (*cb)() ? 1 : 0;
}

void sql_db_t::set_abort_callback(std::function<bool()> cb)
{
  abort_cb = std::move(cb);
  if ( abort_cb )
    sqlite3_progress_handler(db, 10000, progress_cb, &abort_cb);
  else
    sqlite3_progress_handler(db, 0, nullptr, nullptr);
}

//------------------------------------------------------------------------------
// sql_stmt_t
//------------------------------------------------------------------------------
sql_stmt_t::sql_stmt_t(sql_db_t &_db, const std::string &sql) : db(_db)
{
  if ( !db.is_open() )
    throw std::runtime_error("Database not opened");
  int rc = sqlite3_prepare_v2(db.handle(), sql.c_str(), int(sql.size()), &st, nullptr);
  if ( rc != SQLITE_OK )
    throw std::runtime_error(db.errmsg());
  names = std::make_shared<std::vector<std::string>>();
  int n = sqlite3_column_count(st);
  for ( int k = 0; k < n; ++k )
  {
    const char *name = sqlite3_column_name(st, k);
    names->push_back(name != nullptr ? name : "");
  }
}

sql_stmt_t::~sql_stmt_t()
{
  if ( st != nullptr )
    sqlite3_finalize(st);
}

void sql_stmt_t::bind(const sql_params_t &params)
{
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
  finished = false;
  for ( size_t k = 0; k < params.size(); ++k )
  {
    const sql_value_t &v = params[k];
    int idx = int(k) + 1;
    int rc;
    switch ( v.type )
    {
      case sql_value_t::INT:  rc = sqlite3_bind_int64(st, idx, v.i); break;
      case sql_value_t::REAL: rc = sqlite3_bind_double(st, idx, v.d); break;
      case sql_value_t::TEXT: rc = sqlite3_bind_text(st, idx, v.s.c_str(), int(v.s.size()), SQLITE_TRANSIENT); break;
      default:                rc = sqlite3_bind_null(st, idx); break;
    }
    if ( rc != SQLITE_OK )
      throw std::runtime_error(db.errmsg());
  }
}

bool sql_stmt_t::fetch(sql_row_t *row)
{
  if ( finished )
    return false;
  int rc = sqlite3_step(st);
  if ( rc == SQLITE_DONE )
  {
    finished = true;
    return false;
  }
  if ( rc != SQLITE_ROW )
  {
    finished = true;
    throw std::runtime_error(db.errmsg());
  }
  int n = sqlite3_column_count(st);
  row->names = names;
  row->values.resize(n);
  for ( int k = 0; k < n; ++k )
  {
    sql_value_t &v = row->values[k];
    v.s.clear();
    switch ( sqlite3_column_type(st, k) )
    {
      case SQLITE_INTEGER:
        v.type = sql_value_t::INT;
        v.i = sqlite3_column_int64(st, k);
        break;
      case SQLITE_FLOAT:
        v.type = sql_value_t::REAL;
        v.d = sqlite3_column_double(st, k);
        break;
      case SQLITE_NULL:
        v.type = sql_value_t::NUL;
        break;
      default:
        {
          v.type = sql_value_t::TEXT;
          const unsigned char *txt = sqlite3_column_text(st, k);
          int len = sqlite3_column_bytes(st, k);
          if ( txt != nullptr )
            v.s.assign((const char *)txt, len);
        }
        break;
    }
  }
  return true;
}

void sql_stmt_t::run(const sql_params_t &params)
{
  bind(params);
  while ( true )
  {
    int rc = sqlite3_step(st);
    if ( rc == SQLITE_DONE )
      break;
    if ( rc != SQLITE_ROW )
      throw std::runtime_error(db.errmsg());
  }
  finished = true;
}

} // namespace dph
