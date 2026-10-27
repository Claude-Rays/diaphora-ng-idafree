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

// Diaphora-ng - link to the C API of Claude-Rays Decompiler (clauderays-decompiler.dll)
#include "clauderays_link.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dph
{

typedef int (*api_version_fn_t)(void);
typedef char *(*diff_functions_fn_t)(const char *request_json);
typedef void (*free_fn_t)(char *p);

int clauderays_link_version()
{
  HMODULE h = GetModuleHandleW(L"clauderays-decompiler.dll");
  if ( h == nullptr )
    return -1;
  api_version_fn_t f = (api_version_fn_t)GetProcAddress(h, "clauderays_api_version");
  return f != nullptr ? f() : 0;
}

bool clauderays_link_diff(const std::string &request_json, std::string *response_json)
{
  HMODULE h = GetModuleHandleW(L"clauderays-decompiler.dll");
  if ( h == nullptr )
    return false;
  diff_functions_fn_t diff = (diff_functions_fn_t)GetProcAddress(h, "clauderays_diff_functions");
  free_fn_t release = (free_fn_t)GetProcAddress(h, "clauderays_free");
  if ( diff == nullptr || release == nullptr )
    return false;
  char *p = diff(request_json.c_str());
  if ( p == nullptr )
    return false;
  *response_json = p;
  release(p);
  return true;
}

} // namespace dph
