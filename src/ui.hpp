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

// Diaphora-ng - user interface
//
// The python version mixes IDA choosers/forms with Qt widgets (QTextBrowser
// for the html diffs). The C++ SDK for IDA Free has no Qt headers, so:
//   - result choosers (CIDAChooser)       -> chooser_multi_t + popup actions
//   - html diff viewer (CHtmlViewer)      -> custom viewers with colored lines
//   - graph diffs (CDiffGraphViewer)      -> graph viewers (create_graph_viewer)
//   - export dialog (CBinDiffExporterSetup) -> ask_form
#pragma once
#include "bindiff.hpp"

namespace dph
{

//------------------------------------------------------------------------------
// the active diffing results (g_bindiff)
bindiff_t *current_bindiff();
void set_current_bindiff(std::unique_ptr<bindiff_t> bd);
// close the choosers and destroy the current results
void release_current_bindiff();

//------------------------------------------------------------------------------
// choosers
void show_choosers(bindiff_t &bd, bool force = false);
void close_choosers();
void refresh_all_choosers(bindiff_t &bd);
bool is_diaphora_chooser(TWidget *widget);

// actions used in the choosers popup menu
void register_chooser_actions(plugmod_t *owner);
void unregister_chooser_actions();
void attach_chooser_popup(TWidget *widget, TPopupMenu *popup);

// ui_get_lines_rendering_info: the backgrounds of the changed spans in the
// diff viewers, behind those characters only
void text_view_rendering_info(lines_rendering_output_t *out, const TWidget *widget,
                              const lines_rendering_input_t *info);

// a widget was closed (graph viewers cleanup)
void on_widget_closed(TWidget *widget);
// close every viewer created by the plugin (before unloading it)
void close_all_views();

// light / dark colors for the diff viewers
bool dark_mode();
void toggle_dark_mode();

//------------------------------------------------------------------------------
// top level commands (menu entries)
void cmd_diff_or_export();
void cmd_show_results();
void cmd_save_results();
void cmd_load_results();
void cmd_load_and_import_results();
void cmd_import_definitions();
void cmd_local_diff();

// _diff_or_export(): show the export dialog (if use_ui) and export / diff
void diff_or_export(bool use_ui, const std::string &file_in);

// batch mode export (DIAPHORA_AUTO environment variable)
void auto_export_from_env();
// batch mode diff (DIAPHORA_AUTO_DIFF environment variable)
void auto_diff_from_env();

} // namespace dph
