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

// Diaphora-ng - shared definitions
//
// Port of joxeankoret/diaphora (IDAPython) to the IDA C++ SDK (IDA Free/Pro
// 9.4+), plus pseudo-code diffs made by Claude-Rays Decompiler and GhidraDec.
#pragma once

// allow the C runtime file/string helpers we use
#define USE_STANDARD_FILE_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <lines.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <demangle.hpp>

// VERSION_VALUE of the Python version: databases and results are compatible
#define DIAPHORA_DB_VERSION     "3.4"
// version of the original Diaphora this port is based on
#define DIAPHORA_BASE_VERSION   "3.4.1"
// Diaphora-ng: Diaphora plus the Claude and GhidraDec pseudo-code diffs
#define DIAPHORA_NG_VERSION     "0.1.0-beta"

namespace dph
{

//------------------------------------------------------------------------------
// errors
//------------------------------------------------------------------------------
// thrown when the user presses 'Cancel' in a wait box
struct cancelled_error : public std::runtime_error
{
  cancelled_error() : std::runtime_error("Cancelled") {}
};

//------------------------------------------------------------------------------
// logging (diaphora.log / log_refresh / debug_refresh)
//------------------------------------------------------------------------------
void log(const char *format, ...);
void debug_log(const char *format, ...);
bool is_debug_enabled();
// replace the wait box text (main thread only) and throw if cancelled
void log_refresh(const std::string &message, bool show = false, bool do_log = true);
void check_cancelled();

//------------------------------------------------------------------------------
// string helpers (python-like semantics)
//------------------------------------------------------------------------------
std::string strfmt(const char *format, ...);
bool starts_with(const std::string &s, const char *prefix);
bool ends_with(const std::string &s, const char *suffix);
bool istarts_with(const std::string &s, const char *prefix);
// str.split(sep) with an explicit separator
std::vector<std::string> split(const std::string &s, char sep);
// str.splitlines() (keepends=False)
std::vector<std::string> splitlines(const std::string &s);
std::string join(const std::vector<std::string> &v, const std::string &sep);
std::string strip(const std::string &s, const char *chars = " \t\r\n\v\f");
std::string lstrip(const std::string &s, const char *chars = " \t\r\n\v\f");
std::string rstrip(const std::string &s, const char *chars = " \t\r\n\v\f");
std::string to_lower(std::string s);
std::string replace_all(std::string s, const std::string &from, const std::string &to);
// str.isdigit()
bool is_digits(const std::string &s);
// "%08x"
std::string hex_ea(uint64 ea);
// int(s, base) without exceptions
bool parse_int64(const std::string &s, int base, int64 *out);
uint64 parse_uint64(const std::string &s, int base, uint64 def = 0);
// python float formatting helpers
std::string float_repr(double d);              // repr(float)
std::string format_ratio(double d);            // "%.7f" (config.DECIMAL_VALUES)

//------------------------------------------------------------------------------
// environment / DIAPHORA_* overrides (CBinDiff.get_value_for)
//------------------------------------------------------------------------------
bool env_exists(const char *name);
std::string env_str(const char *name, const std::string &def = "");
bool get_value_for(const char *value_name, bool def);
int64 get_value_for(const char *value_name, int64 def);
double get_value_for(const char *value_name, double def);

//------------------------------------------------------------------------------
// files
//------------------------------------------------------------------------------
bool file_exists(const std::string &path);
bool remove_file_quiet(const std::string &path);
bool write_text_file(const std::string &path, const std::string &data);
std::string path_without_extension(const std::string &path);
std::string basename_any(const std::string &path);

//------------------------------------------------------------------------------
// hashing / encoding
//------------------------------------------------------------------------------
std::string md5_hex(const void *data, size_t len);
std::string base64_encode(const std::string &data);

//------------------------------------------------------------------------------
// minimal JSON (python json.dumps / json.loads compatible for our needs)
//------------------------------------------------------------------------------
std::string json_quote(const std::string &s);     // ensure_ascii=False

struct json_t
{
  // JBIGINT: integer that does not fit in int64, its digits are kept in 's'
  enum type_t { JNULL, JBOOL, JINT, JBIGINT, JREAL, JSTR, JARRAY, JOBJECT };
  type_t type = JNULL;
  bool b = false;
  int64 i = 0;
  double d = 0;
  std::string s;
  std::vector<json_t> arr;
  std::vector<std::pair<std::string, json_t>> obj;

  // canonical key used to emulate python set() membership of mixed values
  std::string set_key() const;
  std::string dump() const;
};
bool json_parse(const std::string &text, json_t *out);
// member of an object (nullptr if missing), its value as text, number, bool
// or list of texts
const json_t *jget(const json_t *j, const char *key);
std::string jtext(const json_t *j);
std::string jstr(const json_t *j, const char *key);
double jnum(const json_t *j, const char *key);
bool jbool(const json_t *j, const char *key);
std::vector<std::string> jlist(const json_t *j, const char *key);

//------------------------------------------------------------------------------
// arbitrary precision unsigned integers (python int products of primes)
//------------------------------------------------------------------------------
class bignum_t
{
  std::vector<uint32> limbs;   // base 1e9, little endian
public:
  bignum_t(uint64 v = 0);
  static bignum_t from_string(const std::string &s);
  void mul(uint64 m);           // m < 2^32
  void mul(const bignum_t &o);
  bool is_zero() const { return limbs.empty(); }
  // the value fits in [-0xFFFFFFFF, 0xFFFFFFFF] (CBinDiff.get_valid_prop)
  bool fits_valid_prop(int64 *out) const;
  std::string str() const;
};

// decimal.Decimal multiplication with the default context (28 digits,
// ROUND_HALF_EVEN), used for the program call graph primes signature
class decimal28_t
{
  std::string coeff = "1";
  int64 exp = 0;
public:
  void mul(const std::string &integer_string);
  std::string str() const;
};

//------------------------------------------------------------------------------
// primes (jkutils.factor)
//------------------------------------------------------------------------------
// primesbelow(N)
std::vector<uint32> primes_below(uint32 n);
// python list indexing (negative indexes wrap around)
uint32 prime_at(const std::vector<uint32> &primes, int64 index, bool *ok = nullptr);
// difference_ratio() for numbers that fit in 64 bits
double difference_ratio(uint64 num1, uint64 num2);

} // namespace dph
