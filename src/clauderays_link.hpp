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
//
// The API is found at run time with GetProcAddress, so there is no link time
// dependency. Kept free of IDA headers so <windows.h> never meets the SDK in
// the same translation unit.
#pragma once
#include <string>

namespace dph
{

// the API version of the loaded clauderays-decompiler.dll: -1 if it is not loaded, 0 if
// it has no API (an older Claude-Rays Decompiler)
int clauderays_link_version();

// clauderays_diff_functions(): false if the API is missing
bool clauderays_link_diff(const std::string &request_json, std::string *response_json);

} // namespace dph
