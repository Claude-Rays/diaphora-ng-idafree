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

// Diaphora-ng - link to the C API of GhidraDec (ghidradec.dll)
#include "ghidradec_link.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#include <vector>

namespace dph
{

typedef int (*api_version_fn_t)(void);
typedef char *(*json_fn_t)(const char *request_json);
typedef void (*free_fn_t)(char *p);

static HMODULE ghidradec_module()
{
  return GetModuleHandleW(L"ghidradec.dll");
}

int ghidradec_link_version()
{
  HMODULE h = ghidradec_module();
  if ( h == nullptr )
    return -1;
  api_version_fn_t f = (api_version_fn_t)GetProcAddress(h, "ghidradec_api_version");
  return f != nullptr ? f() : 0;
}

static bool call_json(const char *fn_name, const std::string &request_json, std::string *response_json)
{
  HMODULE h = ghidradec_module();
  if ( h == nullptr )
    return false;
  json_fn_t fn = (json_fn_t)GetProcAddress(h, fn_name);
  free_fn_t release = (free_fn_t)GetProcAddress(h, "ghidradec_free");
  if ( fn == nullptr || release == nullptr )
    return false;
  char *p = fn(request_json.c_str());
  if ( p == nullptr )
    return false;
  *response_json = p;
  release(p);
  return true;
}

bool ghidradec_link_diff(const std::string &request_json, std::string *response_json)
{
  return call_json("ghidradec_diff_functions", request_json, response_json);
}

bool file_md5_hex(const std::string &path, std::string *md5)
{
  int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
  if ( n <= 0 )
    return false;
  std::vector<wchar_t> wpath(n);
  MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), n);
  HANDLE f = CreateFileW(wpath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if ( f == INVALID_HANDLE_VALUE )
    return false;
  bool ok = false;
  HCRYPTPROV prov = 0;
  HCRYPTHASH hash = 0;
  if ( CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
    && CryptCreateHash(prov, CALG_MD5, 0, 0, &hash) )
  {
    std::vector<BYTE> buf(1 << 20);
    DWORD got = 0;
    ok = true;
    while ( ok && ReadFile(f, buf.data(), DWORD(buf.size()), &got, nullptr) && got != 0 )
      ok = CryptHashData(hash, buf.data(), got, 0) != FALSE;
    BYTE digest[16];
    DWORD len = sizeof(digest);
    if ( ok && CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0) && len == 16 )
    {
      static const char hexd[] = "0123456789abcdef";
      md5->clear();
      for ( BYTE b : digest )
      {
        *md5 += hexd[b >> 4];
        *md5 += hexd[b & 15];
      }
    }
    else
    {
      ok = false;
    }
  }
  if ( hash != 0 )
    CryptDestroyHash(hash);
  if ( prov != 0 )
    CryptReleaseContext(prov, 0);
  CloseHandle(f);
  return ok;
}

} // namespace dph
