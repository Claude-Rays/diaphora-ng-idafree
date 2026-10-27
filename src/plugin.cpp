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

// Diaphora-ng - IDA plugin entry point
// Port of diaphora_plugin.py: a top level "Diaphora-ng" menu with the commands.
#include "ui.hpp"
#include "ghidra_diff.hpp"
#include "bindiff_impl.hpp"

namespace dph
{

static const char MENU_ID[] = "diaphora_ng_menu";
static const char MENU_PATH[] = "Diaphora-ng/";

struct plugin_ctx_t;

//------------------------------------------------------------------------------
struct menu_action_t : public action_handler_t
{
  void (*fn)();
  explicit menu_action_t(void (*f)()) : fn(f) {}

  int idaapi activate(action_activation_ctx_t *) override
  {
    try
    {
      fn();
    }
    catch ( const cancelled_error & )
    {
      hide_wait_box();
      log("Cancelled.");
    }
    catch ( const std::exception &e )
    {
      hide_wait_box();
      log("Error: %s", e.what());
      warning("Diaphora-ng error: %s", e.what());
    }
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

struct menu_item_t
{
  const char *name;
  const char *label;
  void (*fn)();
  const char *hotkey;
};

static const menu_item_t MENU_ITEMS[] =
{
  { "diaphora-ng:export",      "Diff or export",            cmd_diff_or_export,          nullptr },
  { "diaphora-ng:show",        "Show results",              cmd_show_results,            "F3" },
  { "diaphora-ng:load",        "Load results",              cmd_load_results,            nullptr },
  { "diaphora-ng:save",        "Save results",              cmd_save_results,            nullptr },
  { "diaphora-ng:load_import", "Load and import results",   cmd_load_and_import_results, nullptr },
  { "diaphora-ng:imp_defs",    "Import definitions",        cmd_import_definitions,      nullptr },
  { "diaphora-ng:local_diff",  "Local diff",                cmd_local_diff,              nullptr },
  { "diaphora-ng:dark_mode",   "Toggle dark mode colors",   toggle_dark_mode,            nullptr },
  { "diaphora-ng:ghidra_set",  "GhidraDec diff settings...", cmd_ghidra_diff_settings,   nullptr },
};

//------------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  std::vector<std::unique_ptr<menu_action_t>> handlers;
  std::vector<std::string> registered;
  bool auto_mode = false;

  plugin_ctx_t()
  {
    install_ui();
    register_chooser_actions(this);
    hook_event_listener(HT_UI, this);

    msg("Diaphora-ng for IDA Free/Pro %s by ClaudeMonkey (Claude-Rays/diaphora-ng-idafree)\n"
        "C++ port of Diaphora %s by Joxean Koret (joxeankoret/diaphora), "
        "plus the Claude-Rays Decompiler and GhidraDec pseudo-code diffs.\n",
        DIAPHORA_NG_VERSION, DIAPHORA_BASE_VERSION);

    // batch modes: export (DIAPHORA_AUTO) and diff (DIAPHORA_AUTO_DIFF), run
    // once the database is loaded and the UI is ready
    auto_mode = env_exists("DIAPHORA_AUTO") || env_exists("DIAPHORA_AUTO_DIFF");
    if ( auto_mode )
      register_timer(500, auto_timer, this);
  }

  static int idaapi auto_timer(void *ud)
  {
    plugin_ctx_t *ctx = (plugin_ctx_t *)ud;
    if ( !ctx->auto_mode )
      return -1;
    ctx->auto_mode = false;
    if ( env_exists("DIAPHORA_AUTO_DIFF") )
      auto_diff_from_env();
    else
      auto_export_from_env();
    return -1;
  }

  ~plugin_ctx_t() override
  {
    ::unhook_event_listener(HT_UI, this);
    release_current_bindiff();
    close_all_views();
    hexrays_term();
    unregister_chooser_actions();
    uninstall_ui();
  }

  void install_ui()
  {
    create_menu(MENU_ID, "Diaphora-ng", "Options");
    for ( const auto &item : MENU_ITEMS )
    {
      auto h = std::make_unique<menu_action_t>(item.fn);
      action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(item.name, item.label, h.get(), this, item.hotkey, item.label, -1);
      if ( register_action(desc) )
      {
        registered.push_back(item.name);
        attach_action_to_menu(MENU_PATH, item.name, SETMENU_APP);
      }
      handlers.push_back(std::move(h));
    }
  }

  void uninstall_ui()
  {
    for ( const auto &name : registered )
    {
      detach_action_from_menu(MENU_PATH, name.c_str());
      unregister_action(name.c_str());
    }
    registered.clear();
    delete_menu(MENU_ID);
  }

  bool idaapi run(size_t) override
  {
    try
    {
      cmd_diff_or_export();
    }
    catch ( const std::exception &e )
    {
      hide_wait_box();
      warning("Diaphora-ng error: %s", e.what());
    }
    return true;
  }

  ssize_t idaapi on_event(ssize_t code, va_list va) override
  {
    switch ( code )
    {
      case ui_finish_populating_widget_popup:
        {
          TWidget *widget = va_arg(va, TWidget *);
          TPopupMenu *popup = va_arg(va, TPopupMenu *);
          if ( get_widget_type(widget) == BWN_CHOOSER )
            attach_chooser_popup(widget, popup);
        }
        break;
      case ui_get_lines_rendering_info:
        {
          lines_rendering_output_t *out = va_arg(va, lines_rendering_output_t *);
          const TWidget *widget = va_arg(va, const TWidget *);
          const lines_rendering_input_t *info = va_arg(va, const lines_rendering_input_t *);
          text_view_rendering_info(out, widget, info);
        }
        break;
      case ui_widget_invisible:
        {
          TWidget *widget = va_arg(va, TWidget *);
          on_widget_closed(widget);
        }
        break;
    }
    return 0;
  }
};

//------------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t();
}

} // namespace dph

//------------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,                                   // plugin flags
  dph::init,                                      // initialize
  nullptr,                                        // terminate (PLUGIN_MULTI)
  nullptr,                                        // invoke (PLUGIN_MULTI)
  "Diaphora-ng for IDA Free/Pro: C++ port of Diaphora by Joxean Koret + Claude-Rays Decompiler + GhidraDec",  // comment
  "Export, diff, and import results between binaries; Claude diff pseudo-code with Claude-Rays Decompiler; GhidraDec diff pseudo-code",  // help
  "Diaphora-ng",                                  // the preferred short name
  "",                                             // the preferred hotkey
};
