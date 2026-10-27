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

// Diaphora-ng - generic helpers
// Port of bits of diaphora.py, jkutils/factor.py and python's stdlib that the
// original code relies on (json, hashlib, base64, decimal).
#include "common.hpp"

#include <cmath>
#include <ctime>
#include <cstdarg>
#include <intrin.h>
#include <md5.h>

namespace dph
{

//------------------------------------------------------------------------------
// logging
//------------------------------------------------------------------------------
static std::string asctime_now()
{
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_s(&tmv, &t);
  char buf[64];
  // time.asctime(): 'Wed Oct 15 12:34:56 2026'
  strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &tmv);
  return buf;
}

static void vlog(const char *format, va_list va)
{
  qstring text;
  text.vsprnt(format, va);
  msg("[Diaphora-ng: %s] %s\n", asctime_now().c_str(), text.c_str());
}

void log(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vlog(format, va);
  va_end(va);
}

bool is_debug_enabled()
{
  return env_exists("DIAPHORA_DEBUG");
}

void debug_log(const char *format, ...)
{
  if ( !is_debug_enabled() )
    return;
  va_list va;
  va_start(va, format);
  vlog(format, va);
  va_end(va);
}

void check_cancelled()
{
  if ( is_main_thread() && user_cancelled() )
    throw cancelled_error();
}

void log_refresh(const std::string &message, bool show, bool do_log)
{
  // Do not call UI messages handling except from within IDA's main thread
  if ( !is_main_thread() )
  {
    if ( do_log )
      log("%s", message.c_str());
    return;
  }

  if ( show )
    show_wait_box("%s", message.c_str());
  else
    replace_wait_box("%s", message.c_str());

  if ( user_cancelled() )
    throw cancelled_error();

  if ( do_log )
    log("%s", message.c_str());
}

//------------------------------------------------------------------------------
// strings
//------------------------------------------------------------------------------
std::string strfmt(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  qstring out;
  out.vsprnt(format, va);
  va_end(va);
  return out.c_str();
}

bool starts_with(const std::string &s, const char *prefix)
{
  size_t n = strlen(prefix);
  return s.size() >= n && memcmp(s.data(), prefix, n) == 0;
}

bool istarts_with(const std::string &s, const char *prefix)
{
  size_t n = strlen(prefix);
  return s.size() >= n && strnicmp(s.data(), prefix, n) == 0;
}

bool ends_with(const std::string &s, const char *suffix)
{
  size_t n = strlen(suffix);
  return s.size() >= n && memcmp(s.data() + s.size() - n, suffix, n) == 0;
}

std::vector<std::string> split(const std::string &s, char sep)
{
  std::vector<std::string> out;
  size_t start = 0;
  while ( true )
  {
    size_t pos = s.find(sep, start);
    if ( pos == std::string::npos )
    {
      out.push_back(s.substr(start));
      break;
    }
    out.push_back(s.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

std::vector<std::string> splitlines(const std::string &s)
{
  std::vector<std::string> out;
  size_t i = 0, start = 0, n = s.size();
  while ( i < n )
  {
    char c = s[i];
    if ( c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == '\x1c' || c == '\x1d' || c == '\x1e' )
    {
      out.push_back(s.substr(start, i - start));
      if ( c == '\r' && i + 1 < n && s[i + 1] == '\n' )
        ++i;
      start = i + 1;
    }
    ++i;
  }
  if ( start < n )
    out.push_back(s.substr(start));
  return out;
}

std::string join(const std::vector<std::string> &v, const std::string &sep)
{
  std::string out;
  size_t total = 0;
  for ( const auto &x : v )
    total += x.size() + sep.size();
  out.reserve(total);
  for ( size_t i = 0; i < v.size(); ++i )
  {
    if ( i > 0 )
      out += sep;
    out += v[i];
  }
  return out;
}

std::string lstrip(const std::string &s, const char *chars)
{
  size_t b = s.find_first_not_of(chars);
  return b == std::string::npos ? std::string() : s.substr(b);
}

std::string rstrip(const std::string &s, const char *chars)
{
  size_t e = s.find_last_not_of(chars);
  return e == std::string::npos ? std::string() : s.substr(0, e + 1);
}

std::string strip(const std::string &s, const char *chars)
{
  return lstrip(rstrip(s, chars), chars);
}

std::string to_lower(std::string s)
{
  for ( auto &c : s )
    c = (char)qtolower((uchar)c);
  return s;
}

std::string replace_all(std::string s, const std::string &from, const std::string &to)
{
  if ( from.empty() )
    return s;
  size_t pos = 0;
  while ( (pos = s.find(from, pos)) != std::string::npos )
  {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
  return s;
}

bool is_digits(const std::string &s)
{
  if ( s.empty() )
    return false;
  for ( char c : s )
    if ( c < '0' || c > '9' )
      return false;
  return true;
}

std::string hex_ea(uint64 ea)
{
  char buf[32];
  qsnprintf(buf, sizeof(buf), "%08llx", (unsigned long long)ea);
  return buf;
}

bool parse_int64(const std::string &str, int base, int64 *out)
{
  std::string s = strip(str);
  if ( s.empty() )
    return false;
  bool neg = false;
  size_t i = 0;
  if ( s[0] == '-' || s[0] == '+' )
  {
    neg = s[0] == '-';
    i = 1;
  }
  if ( base == 16 && s.size() > i + 1 && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X') )
    i += 2;
  if ( i >= s.size() )
    return false;
  uint64 v = 0;
  for ( ; i < s.size(); ++i )
  {
    char c = s[i];
    int d;
    if ( c >= '0' && c <= '9' )
      d = c - '0';
    else if ( c >= 'a' && c <= 'f' )
      d = c - 'a' + 10;
    else if ( c >= 'A' && c <= 'F' )
      d = c - 'A' + 10;
    else if ( c == '_' )
      continue;
    else
      return false;
    if ( d >= base )
      return false;
    v = v * base + d;
  }
  *out = neg ? -(int64)v : (int64)v;
  return true;
}

uint64 parse_uint64(const std::string &s, int base, uint64 def)
{
  int64 v;
  if ( !parse_int64(s, base, &v) )
    return def;
  return (uint64)v;
}

std::string float_repr(double d)
{
  if ( std::isnan(d) )
    return "nan";
  if ( std::isinf(d) )
    return d > 0 ? "inf" : "-inf";
  char buf[64];
  for ( int prec = 1; prec <= 17; ++prec )
  {
    qsnprintf(buf, sizeof(buf), "%.*g", prec, d);
    if ( strtod(buf, nullptr) == d )
      break;
  }
  std::string s = buf;
  if ( s.find_first_of(".eEn") == std::string::npos )
    s += ".0";
  return s;
}

std::string format_ratio(double d)
{
  char buf[64];
  qsnprintf(buf, sizeof(buf), "%.7f", d);
  return buf;
}

//------------------------------------------------------------------------------
// environment
//------------------------------------------------------------------------------
bool env_exists(const char *name)
{
  return qgetenv(name, nullptr);
}

std::string env_str(const char *name, const std::string &def)
{
  qstring buf;
  if ( !qgetenv(name, &buf) )
    return def;
  return buf.c_str();
}

static bool env_for(const char *value_name, std::string *out)
{
  std::string var = "DIAPHORA_";
  for ( const char *p = value_name; *p != '\0'; ++p )
    var += (char)qtoupper((uchar)*p);
  qstring buf;
  if ( !qgetenv(var.c_str(), &buf) )
    return false;
  *out = buf.c_str();
  return true;
}

bool get_value_for(const char *value_name, bool def)
{
  std::string v;
  if ( !env_for(value_name, &v) )
    return def;
  std::string l = to_lower(strip(v));
  return !(l.empty() || l == "0" || l == "false" || l == "no" || l == "off");
}

int64 get_value_for(const char *value_name, int64 def)
{
  std::string v;
  int64 out;
  if ( !env_for(value_name, &v) || !parse_int64(v, 10, &out) )
    return def;
  return out;
}

double get_value_for(const char *value_name, double def)
{
  std::string v;
  if ( !env_for(value_name, &v) )
    return def;
  char *end = nullptr;
  double d = strtod(v.c_str(), &end);
  return end != v.c_str() ? d : def;
}

//------------------------------------------------------------------------------
// files
//------------------------------------------------------------------------------
bool file_exists(const std::string &path)
{
  return !path.empty() && qfileexist(path.c_str());
}

bool remove_file_quiet(const std::string &path)
{
  return qunlink(path.c_str()) == 0;
}

bool write_text_file(const std::string &path, const std::string &data)
{
  FILE *fp = qfopen(path.c_str(), "wb");
  if ( fp == nullptr )
    return false;
  bool ok = qfwrite(fp, data.data(), data.size()) == data.size();
  qfclose(fp);
  return ok;
}

std::string path_without_extension(const std::string &path)
{
  size_t slash = path.find_last_of("/\\");
  size_t dot = path.find_last_of('.');
  if ( dot == std::string::npos || (slash != std::string::npos && dot < slash) )
    return path;
  return path.substr(0, dot);
}

std::string basename_any(const std::string &path)
{
  size_t slash = path.find_last_of("/\\");
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

//------------------------------------------------------------------------------
// hashing / encoding
//------------------------------------------------------------------------------
std::string md5_hex(const void *data, size_t len)
{
  MD5Context ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, data, len);
  uchar digest[16];
  MD5Final(digest, &ctx);
  static const char hexd[] = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for ( int i = 0; i < 16; ++i )
  {
    out += hexd[digest[i] >> 4];
    out += hexd[digest[i] & 15];
  }
  return out;
}

std::string base64_encode(const std::string &data)
{
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  size_t i = 0;
  const uchar *p = (const uchar *)data.data();
  size_t n = data.size();
  while ( i + 2 < n )
  {
    uint32 v = (p[i] << 16) | (p[i + 1] << 8) | p[i + 2];
    out += tbl[(v >> 18) & 63];
    out += tbl[(v >> 12) & 63];
    out += tbl[(v >> 6) & 63];
    out += tbl[v & 63];
    i += 3;
  }
  if ( i + 1 == n )
  {
    uint32 v = p[i] << 16;
    out += tbl[(v >> 18) & 63];
    out += tbl[(v >> 12) & 63];
    out += "==";
  }
  else if ( i + 2 == n )
  {
    uint32 v = (p[i] << 16) | (p[i + 1] << 8);
    out += tbl[(v >> 18) & 63];
    out += tbl[(v >> 12) & 63];
    out += tbl[(v >> 6) & 63];
    out += '=';
  }
  return out;
}

//------------------------------------------------------------------------------
// json
//------------------------------------------------------------------------------
std::string json_quote(const std::string &s)
{
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for ( unsigned char c : s )
  {
    switch ( c )
    {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if ( c < 0x20 )
        {
          char buf[8];
          qsnprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        }
        else
        {
          out += (char)c;
        }
        break;
    }
  }
  out += '"';
  return out;
}

std::string json_t::set_key() const
{
  switch ( type )
  {
    case JINT:  return "i" + std::to_string(i);
    case JBIGINT: return "i" + s;
    case JREAL:
      if ( std::floor(d) == d && std::fabs(d) < 9e18 )
        return "i" + std::to_string((int64)d);
      return "f" + float_repr(d);
    case JSTR:  return "s" + s;
    case JBOOL: return b ? "i1" : "i0";
    default:    return "x" + dump();
  }
}

std::string json_t::dump() const
{
  switch ( type )
  {
    case JNULL: return "null";
    case JBOOL: return b ? "true" : "false";
    case JINT:  return std::to_string(i);
    case JBIGINT: return s;
    case JREAL: return float_repr(d);
    case JSTR:  return json_quote(s);
    case JARRAY:
      {
        std::string out = "[";
        for ( size_t k = 0; k < arr.size(); ++k )
        {
          if ( k > 0 )
            out += ", ";
          out += arr[k].dump();
        }
        return out + "]";
      }
    case JOBJECT:
      {
        std::string out = "{";
        for ( size_t k = 0; k < obj.size(); ++k )
        {
          if ( k > 0 )
            out += ", ";
          out += json_quote(obj[k].first);
          out += ": ";
          out += obj[k].second.dump();
        }
        return out + "}";
      }
  }
  return "null";
}

namespace
{
struct json_parser_t
{
  const char *p;
  const char *end;

  void ws()
  {
    while ( p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') )
      ++p;
  }

  static void put_utf8(std::string &out, uint32 cp)
  {
    if ( cp < 0x80 )
    {
      out += (char)cp;
    }
    else if ( cp < 0x800 )
    {
      out += (char)(0xC0 | (cp >> 6));
      out += (char)(0x80 | (cp & 0x3F));
    }
    else if ( cp < 0x10000 )
    {
      out += (char)(0xE0 | (cp >> 12));
      out += (char)(0x80 | ((cp >> 6) & 0x3F));
      out += (char)(0x80 | (cp & 0x3F));
    }
    else
    {
      out += (char)(0xF0 | (cp >> 18));
      out += (char)(0x80 | ((cp >> 12) & 0x3F));
      out += (char)(0x80 | ((cp >> 6) & 0x3F));
      out += (char)(0x80 | (cp & 0x3F));
    }
  }

  bool hex4(uint32 *out)
  {
    if ( end - p < 4 )
      return false;
    uint32 v = 0;
    for ( int k = 0; k < 4; ++k )
    {
      char c = *p++;
      v <<= 4;
      if ( c >= '0' && c <= '9' ) v |= c - '0';
      else if ( c >= 'a' && c <= 'f' ) v |= c - 'a' + 10;
      else if ( c >= 'A' && c <= 'F' ) v |= c - 'A' + 10;
      else return false;
    }
    *out = v;
    return true;
  }

  bool string(std::string *out)
  {
    if ( p >= end || *p != '"' )
      return false;
    ++p;
    while ( p < end && *p != '"' )
    {
      char c = *p++;
      if ( c != '\\' )
      {
        *out += c;
        continue;
      }
      if ( p >= end )
        return false;
      char e = *p++;
      switch ( e )
      {
        case '"': *out += '"'; break;
        case '\\': *out += '\\'; break;
        case '/': *out += '/'; break;
        case 'b': *out += '\b'; break;
        case 'f': *out += '\f'; break;
        case 'n': *out += '\n'; break;
        case 'r': *out += '\r'; break;
        case 't': *out += '\t'; break;
        case 'u':
          {
            uint32 cp;
            if ( !hex4(&cp) )
              return false;
            if ( cp >= 0xD800 && cp <= 0xDBFF && end - p >= 6 && p[0] == '\\' && p[1] == 'u' )
            {
              const char *save = p;
              p += 2;
              uint32 lo;
              if ( hex4(&lo) && lo >= 0xDC00 && lo <= 0xDFFF )
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              else
                p = save;
            }
            put_utf8(*out, cp);
          }
          break;
        default:
          return false;
      }
    }
    if ( p >= end )
      return false;
    ++p;
    return true;
  }

  bool value(json_t *out, int depth)
  {
    if ( depth > 256 )
      return false;
    ws();
    if ( p >= end )
      return false;
    char c = *p;
    if ( c == '"' )
    {
      out->type = json_t::JSTR;
      return string(&out->s);
    }
    if ( c == '[' )
    {
      ++p;
      out->type = json_t::JARRAY;
      ws();
      if ( p < end && *p == ']' )
      {
        ++p;
        return true;
      }
      while ( true )
      {
        json_t v;
        if ( !value(&v, depth + 1) )
          return false;
        out->arr.push_back(std::move(v));
        ws();
        if ( p < end && *p == ',' )
        {
          ++p;
          continue;
        }
        if ( p < end && *p == ']' )
        {
          ++p;
          return true;
        }
        return false;
      }
    }
    if ( c == '{' )
    {
      ++p;
      out->type = json_t::JOBJECT;
      ws();
      if ( p < end && *p == '}' )
      {
        ++p;
        return true;
      }
      while ( true )
      {
        ws();
        std::string key;
        if ( !string(&key) )
          return false;
        ws();
        if ( p >= end || *p != ':' )
          return false;
        ++p;
        json_t v;
        if ( !value(&v, depth + 1) )
          return false;
        out->obj.emplace_back(std::move(key), std::move(v));
        ws();
        if ( p < end && *p == ',' )
        {
          ++p;
          continue;
        }
        if ( p < end && *p == '}' )
        {
          ++p;
          return true;
        }
        return false;
      }
    }
    if ( end - p >= 4 && strncmp(p, "null", 4) == 0 )
    {
      p += 4;
      out->type = json_t::JNULL;
      return true;
    }
    if ( end - p >= 4 && strncmp(p, "true", 4) == 0 )
    {
      p += 4;
      out->type = json_t::JBOOL;
      out->b = true;
      return true;
    }
    if ( end - p >= 5 && strncmp(p, "false", 5) == 0 )
    {
      p += 5;
      out->type = json_t::JBOOL;
      out->b = false;
      return true;
    }
    // number
    const char *start = p;
    bool real = false;
    if ( p < end && (*p == '-' || *p == '+') )
      ++p;
    while ( p < end && ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' || *p == 'E' || *p == '-' || *p == '+') )
    {
      if ( *p == '.' || *p == 'e' || *p == 'E' )
        real = true;
      ++p;
    }
    if ( p == start )
      return false;
    std::string num(start, p);
    if ( !real )
    {
      int64 v;
      if ( parse_int64(num, 10, &v) && num.size() < 19 )
      {
        out->type = json_t::JINT;
        out->i = v;
        return true;
      }
      // python ints are unbounded: keep huge values as their digits
      if ( !num.empty() && num[0] == '+' )
        num.erase(0, 1);
      out->type = json_t::JBIGINT;
      out->s = num;
      return true;
    }
    out->type = json_t::JREAL;
    out->d = strtod(num.c_str(), nullptr);
    return true;
  }
};
} // namespace

bool json_parse(const std::string &text, json_t *out)
{
  json_parser_t jp{ text.data(), text.data() + text.size() };
  *out = json_t();
  if ( !jp.value(out, 0) )
    return false;
  jp.ws();
  return jp.p == jp.end;
}

//------------------------------------------------------------------------------
// JSON accessors (the responses of Claude-Rays Decompiler and GhidraDec)
//------------------------------------------------------------------------------
const json_t *jget(const json_t *j, const char *key)
{
  if ( j == nullptr || j->type != json_t::JOBJECT )
    return nullptr;
  for ( const auto &kv : j->obj )
    if ( kv.first == key )
      return &kv.second;
  return nullptr;
}

std::string jtext(const json_t *j)
{
  if ( j == nullptr )
    return std::string();
  switch ( j->type )
  {
    case json_t::JSTR:    return j->s;
    case json_t::JINT:    return std::to_string(j->i);
    case json_t::JBIGINT: return j->s;
    case json_t::JREAL:   return strfmt("%.6f", j->d);
    case json_t::JBOOL:   return j->b ? "true" : "false";
    case json_t::JNULL:   return std::string();
    default:              return j->dump();
  }
}

std::string jstr(const json_t *j, const char *key)
{
  return jtext(jget(j, key));
}

double jnum(const json_t *j, const char *key)
{
  const json_t *v = jget(j, key);
  if ( v == nullptr )
    return 0;
  if ( v->type == json_t::JINT )
    return double(v->i);
  if ( v->type == json_t::JREAL )
    return v->d;
  return atof(jtext(v).c_str());
}

bool jbool(const json_t *j, const char *key)
{
  const json_t *v = jget(j, key);
  return v != nullptr && v->type == json_t::JBOOL && v->b;
}

std::vector<std::string> jlist(const json_t *j, const char *key)
{
  std::vector<std::string> out;
  const json_t *v = jget(j, key);
  if ( v != nullptr && v->type == json_t::JARRAY )
    for ( const auto &x : v->arr )
      out.push_back(jtext(&x));
  return out;
}

//------------------------------------------------------------------------------
// bignum
//------------------------------------------------------------------------------
static const uint32 BIG_BASE = 1000000000u;

bignum_t::bignum_t(uint64 v)
{
  while ( v != 0 )
  {
    limbs.push_back(uint32(v % BIG_BASE));
    v /= BIG_BASE;
  }
}

bignum_t bignum_t::from_string(const std::string &str)
{
  bignum_t r;
  std::string s;
  for ( char c : str )
  {
    if ( c >= '0' && c <= '9' )
      s += c;
    else if ( c == '.' || c == 'e' || c == 'E' )
      break;
  }
  size_t first = s.find_first_not_of('0');
  if ( first == std::string::npos )
    return r;
  s = s.substr(first);
  for ( int64 end = (int64)s.size(); end > 0; end -= 9 )
  {
    int64 start = std::max<int64>(0, end - 9);
    r.limbs.push_back((uint32)strtoul(s.substr(start, end - start).c_str(), nullptr, 10));
  }
  return r;
}

void bignum_t::mul(uint64 m)
{
  if ( m == 0 )
  {
    limbs.clear();
    return;
  }
  if ( m >= 0x100000000ull )
  {
    mul(bignum_t(m));
    return;
  }
  uint64 carry = 0;
  for ( auto &l : limbs )
  {
    uint64 cur = uint64(l) * m + carry;
    l = uint32(cur % BIG_BASE);
    carry = cur / BIG_BASE;
  }
  while ( carry != 0 )
  {
    limbs.push_back(uint32(carry % BIG_BASE));
    carry /= BIG_BASE;
  }
}

void bignum_t::mul(const bignum_t &o)
{
  if ( is_zero() || o.is_zero() )
  {
    limbs.clear();
    return;
  }
  if ( o.limbs.size() == 1 )
  {
    mul(uint64(o.limbs[0]));
    return;
  }
  std::vector<uint64> res(limbs.size() + o.limbs.size() + 1, 0);
  for ( size_t i = 0; i < limbs.size(); ++i )
  {
    uint64 carry = 0;
    uint64 a = limbs[i];
    for ( size_t j = 0; j < o.limbs.size(); ++j )
    {
      uint64 cur = res[i + j] + a * o.limbs[j] + carry;
      res[i + j] = cur % BIG_BASE;
      carry = cur / BIG_BASE;
    }
    size_t k = i + o.limbs.size();
    while ( carry != 0 )
    {
      uint64 cur = res[k] + carry;
      res[k] = cur % BIG_BASE;
      carry = cur / BIG_BASE;
      ++k;
    }
  }
  while ( !res.empty() && res.back() == 0 )
    res.pop_back();
  limbs.assign(res.begin(), res.end());
}

bool bignum_t::fits_valid_prop(int64 *out) const
{
  if ( limbs.size() > 2 )
    return false;
  uint64 v = 0;
  for ( size_t i = limbs.size(); i > 0; --i )
    v = v * BIG_BASE + limbs[i - 1];
  if ( v > 0xFFFFFFFFull )
    return false;
  *out = (int64)v;
  return true;
}

std::string bignum_t::str() const
{
  if ( limbs.empty() )
    return "0";
  std::string out = std::to_string(limbs.back());
  char buf[16];
  for ( size_t i = limbs.size() - 1; i > 0; --i )
  {
    qsnprintf(buf, sizeof(buf), "%09u", limbs[i - 1]);
    out += buf;
  }
  return out;
}

//------------------------------------------------------------------------------
// decimal (28 digits, ROUND_HALF_EVEN)
//------------------------------------------------------------------------------
void decimal28_t::mul(const std::string &integer_string)
{
  bignum_t a = bignum_t::from_string(coeff);
  a.mul(bignum_t::from_string(integer_string));
  std::string digits = a.str();
  if ( digits == "0" )
  {
    coeff = "0";
    return;
  }
  const size_t PREC = 28;
  while ( digits.size() > PREC )
  {
    size_t drop = digits.size() - PREC;
    std::string keep = digits.substr(0, PREC);
    std::string rest = digits.substr(PREC);
    // compare the dropped part against one half
    int cmp;
    if ( rest[0] > '5' )
      cmp = 1;
    else if ( rest[0] < '5' )
      cmp = -1;
    else
      cmp = rest.find_first_not_of('0', 1) == std::string::npos ? 0 : 1;
    bool round_up = cmp > 0 || (cmp == 0 && ((keep.back() - '0') & 1) != 0);
    exp += drop;
    if ( round_up )
    {
      // keep + 1
      std::string ks = keep;
      int i = int(ks.size()) - 1;
      while ( i >= 0 )
      {
        if ( ks[i] == '9' )
        {
          ks[i] = '0';
          --i;
          continue;
        }
        ++ks[i];
        break;
      }
      if ( i < 0 )
        ks.insert(ks.begin(), '1');
      digits = ks;
    }
    else
    {
      digits = keep;
    }
  }
  coeff = digits;
}

std::string decimal28_t::str() const
{
  if ( exp == 0 )
    return coeff;
  // decimal.Decimal.__str__ in scientific notation
  int64 leftdigits = exp + (int64)coeff.size();
  std::string out;
  out += coeff[0];
  if ( coeff.size() > 1 )
  {
    out += '.';
    out += coeff.substr(1);
  }
  out += strfmt("E%+lld", (long long)(leftdigits - 1));
  return out;
}

//------------------------------------------------------------------------------
// primes / factorization
//------------------------------------------------------------------------------
std::vector<uint32> primes_below(uint32 n)
{
  std::vector<uint32> out;
  if ( n < 3 )
    return out;
  std::vector<bool> sieve(n, true);
  sieve[0] = sieve[1] = false;
  for ( uint32 i = 2; uint64(i) * i < n; ++i )
    if ( sieve[i] )
      for ( uint64 j = uint64(i) * i; j < n; j += i )
        sieve[(size_t)j] = false;
  for ( uint32 i = 2; i < n; ++i )
    if ( sieve[i] )
      out.push_back(i);
  return out;
}

uint32 prime_at(const std::vector<uint32> &primes, int64 index, bool *ok)
{
  int64 n = (int64)primes.size();
  if ( index < 0 )
    index += n;
  if ( index < 0 || index >= n )
  {
    if ( ok != nullptr )
      *ok = false;
    return 0;
  }
  if ( ok != nullptr )
    *ok = true;
  return primes[(size_t)index];
}

static uint64 mulmod(uint64 a, uint64 b, uint64 m)
{
  uint64 hi;
  uint64 lo = _umul128(a, b, &hi);
  uint64 rem;
  _udiv128(hi % m, lo, m, &rem);
  return rem;
}

static uint64 powmod(uint64 a, uint64 e, uint64 m)
{
  uint64 r = 1;
  a %= m;
  while ( e != 0 )
  {
    if ( e & 1 )
      r = mulmod(r, a, m);
    a = mulmod(a, a, m);
    e >>= 1;
  }
  return r;
}

static bool is_prime_u64(uint64 n)
{
  if ( n < 2 )
    return false;
  static const uint64 small[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
  for ( uint64 p : small )
  {
    if ( n % p == 0 )
      return n == p;
  }
  uint64 d = n - 1;
  int s = 0;
  while ( (d & 1) == 0 )
  {
    d >>= 1;
    ++s;
  }
  for ( uint64 a : small )
  {
    uint64 x = powmod(a, d, n);
    if ( x == 1 || x == n - 1 )
      continue;
    bool composite = true;
    for ( int r = 1; r < s; ++r )
    {
      x = mulmod(x, x, n);
      if ( x == n - 1 )
      {
        composite = false;
        break;
      }
    }
    if ( composite )
      return false;
  }
  return true;
}

static uint64 gcd_u64(uint64 a, uint64 b)
{
  while ( b != 0 )
  {
    uint64 t = a % b;
    a = b;
    b = t;
  }
  return a;
}

static uint64 pollard_brent(uint64 n)
{
  if ( n % 2 == 0 )
    return 2;
  if ( n % 3 == 0 )
    return 3;
  for ( uint64 c = 1; c < 100; ++c )
  {
    uint64 y = 2, m = 128, g = 1, r = 1, q = 1, x = 0, ys = 0;
    while ( g == 1 )
    {
      x = y;
      for ( uint64 i = 0; i < r; ++i )
        y = (mulmod(y, y, n) + c) % n;
      uint64 k = 0;
      while ( k < r && g == 1 )
      {
        ys = y;
        for ( uint64 i = 0; i < std::min(m, r - k); ++i )
        {
          y = (mulmod(y, y, n) + c) % n;
          q = mulmod(q, x > y ? x - y : y - x, n);
        }
        g = gcd_u64(q, n);
        k += m;
      }
      r *= 2;
    }
    if ( g == n )
    {
      do
      {
        ys = (mulmod(ys, ys, n) + c) % n;
        g = gcd_u64(x > ys ? x - ys : ys - x, n);
      } while ( g == 1 );
    }
    if ( g != n )
      return g;
  }
  return n;
}

static void prime_factors(uint64 n, std::map<uint64, int> &out)
{
  static const std::vector<uint32> small = primes_below(10000);
  for ( uint32 p : small )
  {
    if ( uint64(p) * p > n )
      break;
    while ( n % p == 0 )
    {
      out[p]++;
      n /= p;
    }
  }
  if ( n < 2 )
    return;
  std::vector<uint64> stack{ n };
  while ( !stack.empty() )
  {
    uint64 v = stack.back();
    stack.pop_back();
    if ( v < 2 )
      continue;
    if ( is_prime_u64(v) )
    {
      out[v]++;
      continue;
    }
    uint64 f = pollard_brent(v);
    if ( f == v || f <= 1 )
    {
      out[v]++;  // give up, treat it as a prime
      continue;
    }
    stack.push_back(f);
    stack.push_back(v / f);
  }
}

double difference_ratio(uint64 num1, uint64 num2)
{
  std::map<uint64, int> f1, f2;
  prime_factors(num1, f1);
  prime_factors(num2, f2);
  int64 diffs = 0;
  for ( const auto &kv : f1 )
  {
    auto p = f2.find(kv.first);
    if ( p == f2.end() )
      diffs += kv.second;
    else
      diffs += std::abs(kv.second - p->second);
  }
  for ( const auto &kv : f2 )
    if ( f1.find(kv.first) == f1.end() )
      diffs += kv.second;
  int64 s1 = 0, s2 = 0;
  for ( const auto &kv : f1 )
    s1 += kv.second;
  for ( const auto &kv : f2 )
    s2 += kv.second;
  int64 total = std::max(s1, s2);
  if ( total == 0 )
    return 0;
  return 1.0 - double(diffs) / double(total);
}

} // namespace dph
