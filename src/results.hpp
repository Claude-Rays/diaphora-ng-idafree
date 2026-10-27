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

// Diaphora-ng - diffing results files
#pragma once
#include "bindiff.hpp"

namespace dph
{

struct results_config_t
{
  std::string main_db;
  std::string diff_db;
  std::string version;
};

// read the 'config' table of a results file
bool read_results_config(const std::string &filename, results_config_t *out);

// CIDABinDiff.reinit + populate_choosers: a new bindiff_t for the given
// databases with the results of the file loaded in its choosers.
// min_ratio < 0 means no minimum ratio.
std::unique_ptr<bindiff_t> open_results(const std::string &filename,
                                        const std::string &main_db,
                                        const std::string &diff_db,
                                        double min_ratio,
                                        bool multimatch);

} // namespace dph
