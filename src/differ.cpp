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

// Diaphora-ng - the diffing engine
// Port of the diffing parts of diaphora.CBinDiff (diaphora.py) and of
// jkutils/threads.py.
#include "bindiff_impl.hpp"
#include "difflib.hpp"
#include "heuristics.hpp"
#include "vulns.hpp"

#include <chrono>
#include <list>
#include <set>

namespace dph
{

//------------------------------------------------------------------------------
// threads, timeouts and cancellation
//------------------------------------------------------------------------------
namespace
{
struct heur_thread_ctx_t
{
  std::string name;
  std::atomic<bool> timeout{ false };
  std::atomic<bool> done{ false };
  double start = 0;
};

thread_local heur_thread_ctx_t *t_ctx = nullptr;
std::atomic<bool> g_abort{ false };

// raised to stop a heuristic (SystemExit in the python version)
struct stop_heuristic_t {};

double monotonic()
{
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

double round_digits(double v, int digits)
{
  char buf[64];
  qsnprintf(buf, sizeof(buf), "%.*f", digits, v);
  return strtod(buf, nullptr);
}

const sql_value_t NULL_VALUE;

// optional string view of a value (nullptr for python's None)
struct opt_text_t
{
  std::string tmp;
  const std::string *p = nullptr;
  opt_text_t(const sql_value_t *v)
  {
    if ( v == nullptr || v->is_null() )
      return;
    if ( v->type == sql_value_t::TEXT )
    {
      p = &v->s;
    }
    else
    {
      tmp = v->str();
      p = &tmp;
    }
  }
};

// row columns of the heuristics queries (SELECT_FIELDS)
struct heur_cols_t
{
  std::shared_ptr<std::vector<std::string>> names;
  int ea, name1, ea2, name2, description, pseudo1, pseudo2, asm1, asm2;
  int pseudo_primes1, pseudo_primes2, nodes1, nodes2, md1, md2;
  int clean_assembly1, clean_assembly2, clean_pseudo1, clean_pseudo2;
  int mangled1, mangled2, clean_micro1, clean_micro2, bytes_hash1, bytes_hash2;

  void init(const sql_row_t &row)
  {
    if ( names == row.names )
      return;
    names = row.names;
    ea = row.index_of("ea");
    name1 = row.index_of("name1");
    ea2 = row.index_of("ea2");
    name2 = row.index_of("name2");
    description = row.index_of("description");
    pseudo1 = row.index_of("pseudo1");
    pseudo2 = row.index_of("pseudo2");
    asm1 = row.index_of("asm1");
    asm2 = row.index_of("asm2");
    pseudo_primes1 = row.index_of("pseudo_primes1");
    pseudo_primes2 = row.index_of("pseudo_primes2");
    nodes1 = row.index_of("nodes1");
    nodes2 = row.index_of("nodes2");
    md1 = row.index_of("md1");
    md2 = row.index_of("md2");
    clean_assembly1 = row.index_of("clean_assembly1");
    clean_assembly2 = row.index_of("clean_assembly2");
    clean_pseudo1 = row.index_of("clean_pseudo1");
    clean_pseudo2 = row.index_of("clean_pseudo2");
    mangled1 = row.index_of("mangled1");
    mangled2 = row.index_of("mangled2");
    clean_micro1 = row.index_of("clean_micro1");
    clean_micro2 = row.index_of("clean_micro2");
    bytes_hash1 = row.index_of("bytes_hash1");
    bytes_hash2 = row.index_of("bytes_hash2");
  }

  static const sql_value_t *get(const sql_row_t &row, int idx)
  {
    return idx >= 0 ? &row.values[idx] : &NULL_VALUE;
  }

  void build(const sql_row_t &row, func_cmp_t *main_d, func_cmp_t *diff_d) const
  {
    main_d->ea = get(row, ea);
    main_d->name = get(row, name1);
    main_d->pseudo = get(row, pseudo1);
    main_d->asm_text = get(row, asm1);
    main_d->pseudocode_primes = get(row, pseudo_primes1);
    main_d->nodes = get(row, nodes1);
    main_d->md_index = get(row, md1);
    main_d->clean_assembly = get(row, clean_assembly1);
    main_d->clean_pseudo = get(row, clean_pseudo1);
    main_d->clean_micro = get(row, clean_micro1);
    main_d->bytes_hash = get(row, bytes_hash1);

    diff_d->ea = get(row, ea2);
    diff_d->name = get(row, name2);
    diff_d->pseudo = get(row, pseudo2);
    diff_d->asm_text = get(row, asm2);
    diff_d->pseudocode_primes = get(row, pseudo_primes2);
    diff_d->nodes = get(row, nodes2);
    diff_d->md_index = get(row, md2);
    diff_d->clean_assembly = get(row, clean_assembly2);
    diff_d->clean_pseudo = get(row, clean_pseudo2);
    diff_d->clean_micro = get(row, clean_micro2);
    diff_d->bytes_hash = get(row, bytes_hash2);
  }
};

// a function table row -> func_cmp_t (compare_function_rows)
void function_row_cmp(const sql_row_t &row, func_cmp_t *d)
{
  auto get = [&](const char *name) -> const sql_value_t *
  {
    int idx = row.index_of(name);
    return idx >= 0 ? &row.values[idx] : &NULL_VALUE;
  };
  d->ea = get("address");
  d->name = get("name");
  d->pseudo = get("pseudocode");
  d->asm_text = get("assembly");
  d->pseudocode_primes = get("pseudocode_primes");
  d->nodes = get("nodes");
  d->md_index = get("md_index");
  d->clean_assembly = get("clean_assembly");
  d->clean_pseudo = get("clean_pseudo");
  d->clean_micro = get("clean_microcode");
  d->bytes_hash = get("bytes_hash");
}

// re.findall(CPP_NAMES_RE, text, re.IGNORECASE) with
// CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"
std::vector<std::string> find_cpp_names(const std::string &text)
{
  auto is_word = [](char c) { return qisalnum((uchar)c) || c == '_'; };
  auto is_first = [](char c) { return qisalpha((uchar)c) || c == '_'; };
  std::vector<std::string> out;
  size_t i = 0, n = text.size();
  while ( i < n )
  {
    char c = text[i];
    if ( (uchar)c < 0x80 && is_first(c) )
    {
      size_t j = i;
      while ( j < n && (uchar)text[j] < 0x80 && is_word(text[j]) )
        ++j;
      if ( j - i >= 4 )
      {
        // ((::){0,1}[a-zA-Z0-9_]+)*
        while ( j + 2 < n && text[j] == ':' && text[j + 1] == ':' && (uchar)text[j + 2] < 0x80 && is_word(text[j + 2]) )
        {
          j += 2;
          while ( j < n && (uchar)text[j] < 0x80 && is_word(text[j]) )
            ++j;
        }
        out.push_back(text.substr(i, j - i));
        i = j;
        continue;
      }
    }
    ++i;
  }
  return out;
}

std::string py_set_key_list(const std::string &json_text, std::set<std::string> *out)
{
  json_t j;
  if ( json_parse(json_text, &j) && j.type == json_t::JARRAY )
    for ( const auto &v : j.arr )
      out->insert(v.set_key());
  return std::string();
}
} // namespace

bool heuristic_should_stop()
{
  return g_abort.load() || (t_ctx != nullptr && t_ctx->timeout.load());
}

//------------------------------------------------------------------------------
// matches bookkeeping
//------------------------------------------------------------------------------
bool bindiff_t::has_best_match_nolock(const std::string &name1, const std::string &name2)
{
  auto p = matched_primary.find(name1);
  if ( p != matched_primary.end() && p->second.ratio == 1.0 )
    return true;
  auto q = matched_secondary.find(name2);
  if ( q != matched_secondary.end() && q->second.ratio == 1.0 )
    return true;
  return false;
}

bool bindiff_t::has_better_match_nolock(const std::string &name1, const std::string &name2, double ratio)
{
  // If we have a match by name, that's the best match
  if ( !starts_with(name1, "sub_") && !starts_with(name2, "sub_") )
  {
    auto p = matched_primary.find(name1);
    if ( p != matched_primary.end() )
      return p->second.name == name1;
  }
  auto p = matched_primary.find(name1);
  if ( p != matched_primary.end() && p->second.ratio > ratio )
    return true;
  auto q = matched_secondary.find(name2);
  if ( q != matched_secondary.end() && q->second.ratio > ratio )
    return true;
  return false;
}

bool bindiff_t::has_better_match(const std::string &name1, const std::string &name2, double ratio)
{
  std::lock_guard<std::mutex> g(items_lock);
  return has_better_match_nolock(name1, name2, ratio);
}

bool bindiff_t::all_functions_matched()
{
  std::lock_guard<std::mutex> g(items_lock);
  return (int64)matched_primary.size() == total_functions1
      || (int64)matched_secondary.size() == total_functions2;
}

void bindiff_t::add_match(const std::string &name1, const std::string &name2, double ratio,
                          const match_item_t *item, int category)
{
  std::lock_guard<std::mutex> g(items_lock);
  // If the function names are the same, it's a best match, regardless of the
  // ratio we got for the match, so fake the ratio as if it was 1.0.
  if ( name1 == name2 )
    ratio = 1.0;

  if ( ratio != 1.0 )
  {
    if ( has_better_match_nolock(name1, name2, ratio) )
      return;

    if ( is_debug_enabled() )
    {
      auto p = matched_primary.find(name1);
      if ( p != matched_primary.end() && p->second.ratio < ratio )
        debug_log("Found a better match for function %s -> %s, %f with %f",
                  name1.c_str(), name2.c_str(), p->second.ratio, ratio);
      auto q = matched_secondary.find(name2);
      if ( q != matched_secondary.end() && q->second.ratio < ratio )
        debug_log("Found a better match for function %s -> %s, %f with %f",
                  name1.c_str(), name2.c_str(), q->second.ratio, ratio);
    }
  }

  if ( category >= 0 && category < CAT_COUNT && item != nullptr )
  {
    if ( all_matches_keys[category].insert(item->key()).second )
      all_matches[category].push_back(*item);
  }

  matched_primary[name1] = { name2, ratio };
  matched_secondary[name2] = { name1, ratio };
}

void bindiff_t::cleanup_matches()
{
  std::lock_guard<std::mutex> g(items_lock);
  std::unordered_set<std::string> dones;
  std::unordered_map<uint64, double> ea_ratios;
  std::array<std::vector<match_item_t>, CAT_COUNT> d;
  for ( int key = 0; key < CAT_COUNT; ++key )
  {
    std::vector<match_item_t> l_items = all_matches[key];
    std::stable_sort(l_items.begin(), l_items.end(),
                     [](const match_item_t &x, const match_item_t &y) { return x.ratio > y.ratio; });
    for ( const auto &item : l_items )
    {
      // Ignore duplicated matches (might happen due to parallelism)
      std::string match = item.name1 + "-" + item.name2;
      if ( dones.find(match) != dones.end() )
        continue;

      double ratio = item.ratio;
      if ( item.name1 == item.name2 )
      {
        debug_log("Using a fake 1.0 ratio for match %s - %s", item.name1.c_str(), item.name2.c_str());
        ratio = 1.0;
      }
      dones.insert(match);

      // If the previous ratio for a match with function @ea is worst, ignore
      auto p = ea_ratios.find(item.ea1);
      if ( p != ea_ratios.end() && p->second > ratio )
        continue;
      ea_ratios[item.ea1] = ratio;

      d[key].push_back(item);
    }
  }

  // Update now the dict of matched functions for both databases
  matched_primary.clear();
  matched_secondary.clear();
  for ( int key = 0; key < CAT_COUNT; ++key )
  {
    all_matches_keys[key].clear();
    for ( const auto &item : d[key] )
    {
      matched_primary[item.name1] = { item.name2, item.ratio };
      matched_secondary[item.name2] = { item.name1, item.ratio };
      all_matches_keys[key].insert(item.key());
    }
  }
  all_matches = std::move(d);
}

//------------------------------------------------------------------------------
// internal implementation of the diffing engine
//------------------------------------------------------------------------------
namespace
{
struct differ_t
{
  bindiff_t &bd;
  explicit differ_t(bindiff_t &_bd) : bd(_bd) {}

  //----------------------------------------------------------------------------
  int64 count_different_matches(const std::vector<match_item_t> &items)
  {
    std::unordered_set<uint64> dones;
    for ( const auto &item : items )
      dones.insert(item.ea1);
    return (int64)dones.size();
  }

  int64 get_total_matches_for(int category)
  {
    std::lock_guard<std::mutex> g(bd.items_lock);
    return count_different_matches(bd.all_matches[category]);
  }

  void show_summary()
  {
    int64 best = get_total_matches_for(CAT_BEST);
    int64 partial = get_total_matches_for(CAT_PARTIAL);
    int64 unreliable = get_total_matches_for(CAT_UNRELIABLE);
    int64 total = best + partial + unreliable;
    double percent = bd.total_functions1 != 0 ? (total * 100.0) / bd.total_functions1 : 0;
    log("Current results: Best %lld, Partial %lld, Unreliable %lld", (long long)best, (long long)partial, (long long)unreliable);
    log("Matched %1.2f%% of main binary functions (%lld out of %lld)", percent, (long long)total, (long long)bd.total_functions1);
  }

  int64 get_total_matched_functions()
  {
    std::lock_guard<std::mutex> g(bd.items_lock);
    return (int64)(bd.all_matches[CAT_BEST].size() + bd.all_matches[CAT_PARTIAL].size());
  }

  std::vector<match_item_t> get_sorted_results(int category)
  {
    std::vector<match_item_t> l;
    {
      std::lock_guard<std::mutex> g(bd.items_lock);
      l = bd.all_matches[category];
    }
    std::stable_sort(l.begin(), l.end(),
                     [](const match_item_t &x, const match_item_t &y) { return x.ratio > y.ratio; });
    return l;
  }

  //----------------------------------------------------------------------------
  // check_match(): returns whether the match should be added and its ratio
  std::pair<bool, double> check_match(const sql_row_t &row, const heur_cols_t &cols, bool debug = false)
  {
    func_cmp_t main_d, diff_d;
    cols.build(row, &main_d, &diff_d);
    std::string name1 = main_d.name->str();
    std::string name2 = diff_d.name->str();
    std::string desc = heur_cols_t::get(row, cols.description)->str();
    return check_match_cmp(main_d, diff_d, name1, name2, desc, debug);
  }

  std::pair<bool, double> check_match_cmp(const func_cmp_t &main_d, const func_cmp_t &diff_d,
                                          const std::string &name1, const std::string &name2,
                                          const std::string &desc, bool debug)
  {
    if ( starts_with(name1, "nullsub_") || starts_with(name2, "nullsub_") )
    {
      debug_log("Ignoring nullsub functions %s-%s", name1.c_str(), name2.c_str());
      return { false, 0.0 };
    }

    // Do we already have a 1.0 match for any of these functions?
    {
      std::lock_guard<std::mutex> g(bd.items_lock);
      if ( bd.has_best_match_nolock(name1, name2) )
      {
        debug_log("Ignoring as we have a best match %s-%s", name1.c_str(), name2.c_str());
        return { false, 0.0 };
      }
    }

    double r = bd.check_ratio(main_d, diff_d);
    if ( debug )
      debug_log("0x%llx 0x%llx %f", (long long)main_d.ea->to_int(), (long long)diff_d.ea->to_int(), r);

    // Do we have a previous match with a better comparison ratio than this?
    if ( bd.has_better_match(name1, name2, r) )
    {
      debug_log("Ignoring as there is a better match than %f for %s-%s", r, name1.c_str(), name2.c_str());
      return { false, 0.0 };
    }

    bool should_add = true;
    if ( bd.hooks )
    {
      auto res = bd.hooks->on_match(main_d, diff_d, desc, r);
      should_add = res.first;
      r = res.second;
    }
    return { should_add, r };
  }

  // call_on_match_hook()
  std::pair<bool, double> call_on_match_hook(const std::string &heur, double r,
                                             const sql_row_t &main_row, const sql_row_t &diff_row)
  {
    if ( !bd.hooks )
      return { true, r };
    func_cmp_t d1, d2;
    function_row_cmp(main_row, &d1);
    function_row_cmp(diff_row, &d2);
    return bd.hooks->on_match(d1, d2, heur, r);
  }

  //----------------------------------------------------------------------------
  void check_stop(double t)
  {
    if ( monotonic() - t > bd.timeout || heuristic_should_stop() )
    {
      log("Timeout with heuristic '%s'", t_ctx != nullptr ? t_ctx->name.c_str() : "main");
      throw stop_heuristic_t();
    }
    if ( is_main_thread() && user_cancelled() )
    {
      g_abort = true;
      throw cancelled_error();
    }
  }

  bool continue_getting_sql_rows(int64 i)
  {
    return bd.sql_max_processed_rows != 0 && i < bd.sql_max_processed_rows;
  }

  // add_matches_internal(): best/partial are categories (CAT_NONE for None),
  // val < 0 stands for None
  void add_matches_internal(sql_stmt_t &st, int best, int partial, double val = -1,
                            bool unreliable = false, bool debug = false, double start = -1)
  {
    int64 i = 0;
    double t = start < 0 ? monotonic() : start;
    heur_cols_t cols;
    sql_row_t row;
    while ( continue_getting_sql_rows(i) )
    {
      if ( (i & 0xFF) == 0 )
        check_stop(t);
      ++i;
      if ( i % 50000 == 0 )
        log("Processed %lld rows...", (long long)i);
      if ( !st.fetch(&row) )
        break;
      cols.init(row);

      auto chk = check_match(row, cols, debug);
      if ( !chk.first )
        continue;
      double r = chk.second;

      match_item_t item;
      item.ea1 = (uint64)heur_cols_t::get(row, cols.ea)->to_int();
      item.name1 = heur_cols_t::get(row, cols.name1)->str();
      item.ea2 = (uint64)heur_cols_t::get(row, cols.ea2)->to_int();
      item.name2 = heur_cols_t::get(row, cols.name2)->str();
      item.desc = heur_cols_t::get(row, cols.description)->str();
      item.nodes1 = heur_cols_t::get(row, cols.nodes1)->to_int();
      item.nodes2 = heur_cols_t::get(row, cols.nodes2)->to_int();
      item.ratio = r;

      if ( val < 0 )
        val = config::DEFAULT_PARTIAL_RATIO;

      int chooser = CAT_NONE;
      bool done = true;
      if ( r == 1.0 )
        chooser = best;
      else if ( r >= val && partial != CAT_NONE )
        chooser = partial;
      else
        done = false;

      if ( done )
      {
        bd.add_match(item.name1, item.name2, r, &item, chooser);
      }
      else if ( r < config::DEFAULT_PARTIAL_RATIO && r > val && unreliable )
      {
        bd.add_match(item.name1, item.name2, r, &item, CAT_UNRELIABLE);
      }
    }
  }

  void run_query(const std::string &sql, const std::function<void(sql_stmt_t &)> &fn)
  {
    sql_stmt_t st(bd.get_db(), sql);
    st.bind({});
    try
    {
      fn(st);
    }
    catch ( const stop_heuristic_t & )
    {
    }
    catch ( const cancelled_error & )
    {
      throw;
    }
    catch ( const std::exception &e )
    {
      if ( heuristic_should_stop() )
        return;
      log("Error: %s", e.what());
      msg("%s\n%s\n%s\n", std::string(80, '*').c_str(), sql.c_str(), std::string(80, '*').c_str());
      throw;
    }
  }

  void add_matches_from_query_ratio(const std::string &sql, int best, int partial, bool unreliable = false)
  {
    if ( bd.all_functions_matched() )
      return;
    run_query(sql, [&](sql_stmt_t &st) { add_matches_internal(st, best, partial, -1, unreliable); });
  }

  void add_matches_from_query_ratio_max(const std::string &sql, int best, int partial, double val)
  {
    if ( bd.all_functions_matched() )
      return;
    run_query(sql, [&](sql_stmt_t &st) { add_matches_internal(st, best, partial, val, true); });
  }

  void add_matches_from_query_ratio_max_trusted(const std::string &sql, double val)
  {
    if ( bd.all_functions_matched() )
      return;
    run_query(sql, [&](sql_stmt_t &st) { add_matches_internal(st, CAT_BEST, CAT_PARTIAL, val, true); });
  }

  void add_matches_from_cursor_ratio_max(sql_stmt_t &st, int best, int partial, double val)
  {
    if ( bd.all_functions_matched() )
      return;
    try
    {
      add_matches_internal(st, best, partial, val);
    }
    catch ( const stop_heuristic_t & )
    {
    }
  }

  // Add all matches from this SQL query without performing any check.
  // Warning: use this *only* if the ratio is known to be 1.00
  void add_matches_from_query(const std::string &sql, int category)
  {
    if ( bd.all_functions_matched() )
      return;
    try
    {
      sql_stmt_t st(bd.get_db(), sql);
      st.bind({});
      heur_cols_t cols;
      sql_row_t row;
      int64 i = 0;
      while ( !heuristic_should_stop() )
      {
        ++i;
        if ( i % 1000 == 0 )
          log("Processed %lld rows...", (long long)i);
        if ( !st.fetch(&row) )
          break;
        cols.init(row);
        auto chk = check_match(row, cols);
        if ( !chk.first )
          continue;
        match_item_t item;
        item.ea1 = (uint64)heur_cols_t::get(row, cols.ea)->to_int();
        item.name1 = heur_cols_t::get(row, cols.name1)->str();
        item.ea2 = (uint64)heur_cols_t::get(row, cols.ea2)->to_int();
        item.name2 = heur_cols_t::get(row, cols.name2)->str();
        item.desc = heur_cols_t::get(row, cols.description)->str();
        item.nodes1 = heur_cols_t::get(row, cols.nodes1)->to_int();
        item.nodes2 = heur_cols_t::get(row, cols.nodes2)->to_int();
        item.ratio = 1;
        bd.add_match(item.name1, item.name2, 1.0, &item, category);
        if ( chk.second < config::DEFAULT_PARTIAL_RATIO )
          debug_log("Warning: Best match 0x%llx:%s -> 0x%llx:%s have a bad ratio: %f",
                    (unsigned long long)item.ea1, item.name1.c_str(),
                    (unsigned long long)item.ea2, item.name2.c_str(), chk.second);
      }
    }
    catch ( const std::exception &e )
    {
      if ( !heuristic_should_stop() )
        log("Error: %s", e.what());
    }
  }

  //----------------------------------------------------------------------------
  // threads_apply()
  struct task_t
  {
    std::string name;
    std::function<void()> target;
  };

  void threads_apply(int threads, std::vector<task_t> targets, double timeout)
  {
    struct running_t
    {
      std::unique_ptr<heur_thread_ctx_t> ctx;
      std::thread th;
    };
    std::list<running_t> running;
    bool cancelled = false;
    double last_report = monotonic();

    while ( !targets.empty() || !running.empty() )
    {
      while ( !cancelled && !targets.empty() && (int)running.size() < threads )
      {
        task_t task = std::move(targets.back());
        targets.pop_back();
        running_t r;
        r.ctx = std::make_unique<heur_thread_ctx_t>();
        r.ctx->name = task.name;
        r.ctx->start = monotonic();
        heur_thread_ctx_t *ctx = r.ctx.get();
        bindiff_t *pbd = &bd;
        r.th = std::thread([ctx, pbd, task]()
        {
          t_ctx = ctx;
          try
          {
            sql_db_t &db = pbd->get_db();
            db.set_abort_callback([ctx]() { return g_abort.load() || ctx->timeout.load(); });
            task.target();
          }
          catch ( const std::exception &e )
          {
            if ( !g_abort.load() && !ctx->timeout.load() )
              log("Error in heuristic '%s': %s", ctx->name.c_str(), e.what());
          }
          catch ( ... )
          {
          }
          pbd->release_thread_db();
          t_ctx = nullptr;
          ctx->done = true;
        });
        running.push_back(std::move(r));
      }

      // wait a little for the threads, keeping the UI alive
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      if ( !cancelled && user_cancelled() )
      {
        log("Cancelling, waiting for the running heuristics to finish...");
        cancelled = true;
        g_abort = true;
        targets.clear();
      }

      for ( auto p = running.begin(); p != running.end(); )
      {
        if ( p->ctx->done.load() )
        {
          p->th.join();
          if ( !cancelled )
            log_refresh(strfmt("[Parallel] Heuristic '%s' done", p->ctx->name.c_str()));
          p = running.erase(p);
          continue;
        }
        if ( monotonic() - p->ctx->start > timeout )
          p->ctx->timeout = true;
        ++p;
      }

      if ( monotonic() - last_report > 10 && !running.empty() )
      {
        last_report = monotonic();
        std::vector<std::string> names;
        for ( const auto &r : running )
          names.push_back(r.ctx->name);
        log("[Parallel] %u thread(s) still running: %s", unsigned(running.size()), join(names, ", ").c_str());
      }
    }
    if ( cancelled )
      throw cancelled_error();
  }

  //----------------------------------------------------------------------------
  void run_heuristics_for_category(const std::string &arg_category)
  {
    int total_cpus = std::max(bd.cpu_count, 1);
    const char *mode = total_cpus == 1 ? "[Single thread]" : "[Parallel]";

    std::string postfix;
    if ( bd.ignore_small_functions )
      postfix = config::SQL_DEFAULT_POSTFIX;

    size_t count;
    const heuristic_t *heuristics = get_heuristics(&count);
    std::vector<task_t> heuristic_functions;
    for ( size_t k = 0; k < count; ++k )
    {
      const heuristic_t &heur = heuristics[k];
      {
        std::lock_guard<std::mutex> g(bd.items_lock);
        if ( (int64)bd.matched_primary.size() == bd.total_functions1
          || (int64)bd.matched_secondary.size() == bd.total_functions2 )
        {
          log("All functions matched in at least one database, finishing.");
          break;
        }
      }

      if ( arg_category != heur.category )
        continue;

      std::string name = heur.name;
      double min_value = 0.0;
      if ( heur.ratio == HEUR_TYPE_RATIO_MAX || heur.ratio == HEUR_TYPE_RATIO_MAX_TRUSTED )
        min_value = heur.min;

      if ( heur.has_flag(HEUR_FLAG_UNRELIABLE) && !bd.unreliable )
      {
        log_refresh("Skipping unreliable heuristic '" + name + "'");
        continue;
      }
      if ( heur.has_flag(HEUR_FLAG_SLOW) && !bd.slow_heuristics )
      {
        log_refresh("Skipping slow heuristic '" + name + "'");
        continue;
      }
      if ( heur.has_flag(HEUR_FLAG_SAME_CPU) && !bd.is_same_processor )
      {
        log_refresh("Skipping processor specific heuristic '" + name + "'");
        continue;
      }

      int best, partial;
      if ( to_lower(arg_category) == "unreliable" )
      {
        best = CAT_PARTIAL;
        partial = CAT_UNRELIABLE;
      }
      else
      {
        best = CAT_BEST;
        partial = CAT_PARTIAL;
      }

      log_refresh(strfmt("%s Finding with heuristic '%s'", mode, name.c_str()));
      std::string sql = replace_all(heur.sql, "%POSTFIX%", postfix);

      task_t task;
      task.name = name;
      int ratio = heur.ratio;
      differ_t *self = this;
      task.target = [self, sql, ratio, best, partial, min_value]()
      {
        switch ( ratio )
        {
          case HEUR_TYPE_NO_FPS:
            self->add_matches_from_query(sql, best);
            break;
          case HEUR_TYPE_RATIO:
            self->add_matches_from_query_ratio(sql, best, partial);
            break;
          case HEUR_TYPE_RATIO_MAX:
            self->add_matches_from_query_ratio_max(sql, best, partial, min_value);
            break;
          case HEUR_TYPE_RATIO_MAX_TRUSTED:
            self->add_matches_from_query_ratio_max_trusted(sql, min_value);
            break;
          default:
            throw std::runtime_error("Invalid heuristic ratio calculation value!");
        }
      };
      heuristic_functions.push_back(std::move(task));
    }

    threads_apply(total_cpus, std::move(heuristic_functions), double(config::SQL_TIMEOUT_LIMIT));

    bd.cleanup_matches();
    show_summary();
  }

  //----------------------------------------------------------------------------
  double get_callgraph_difference()
  {
    sql_rows_t rows = bd.get_db().query(R"SQL(select callgraph_primes, callgraph_all_primes from program
        union all
        select callgraph_primes, callgraph_all_primes from diff.program)SQL");
    if ( rows.size() != 2 )
      throw std::runtime_error(strfmt("Not enough rows in databases! Size is %u", unsigned(rows.size())));

    std::string cg1 = rows[0].str("callgraph_primes");
    std::string cg2 = rows[1].str("callgraph_primes");
    if ( cg1 == cg2 )
    {
      bd.equal_callgraph = true;
      log("Call graph signature for both databases is equal, the programs seem to be 100%% equal structurally");
      return 0;
    }

    json_t f1, f2;
    json_parse(rows[0].str("callgraph_all_primes"), &f1);
    json_parse(rows[1].str("callgraph_all_primes"), &f2);
    std::map<std::string, int64> s0, s1;
    for ( const auto &kv : f1.obj )
      s0[kv.first] = kv.second.type == json_t::JINT ? kv.second.i : (int64)kv.second.d;
    for ( const auto &kv : f2.obj )
      s1[kv.first] = kv.second.type == json_t::JINT ? kv.second.i : (int64)kv.second.d;

    // jkutils.factor.difference() with the cached factorizations
    int64 diff = 0;
    for ( const auto &kv : s0 )
    {
      auto p = s1.find(kv.first);
      if ( p == s1.end() )
        diff += kv.second;
      else if ( p->second != kv.second )
        diff += std::abs(p->second - kv.second);
    }
    for ( const auto &kv : s1 )
      if ( s0.find(kv.first) == s0.end() )
        diff += kv.second;

    int64 total = 0;
    for ( const auto &kv : s0 )
      total += kv.second;
    if ( total == 0 || diff == 0 )
      return 0;
    return diff * 100.0 / total;
  }

  void check_callgraph()
  {
    double percent = get_callgraph_difference();
    if ( percent == 0 )
      log("Call graphs are 100%% equal");
    else if ( percent >= 100 )
      log("Call graphs are absolutely different");
    else
      log("Call graphs from both programs differ in %f%%", percent);
    bd.percent = percent;
  }

  //----------------------------------------------------------------------------
  void find_equal_matches()
  {
    sql_db_t &db = bd.get_db();
    sql_rows_t rows = db.query(R"SQL(select count(*) total from functions
        union all
        select count(*) total from diff.functions)SQL");
    if ( rows.size() != 2 )
      throw std::runtime_error("Malformed database!");

    bd.total_functions1 = rows[0].to_int("total");
    bd.total_functions2 = rows[1].to_int("total");

    std::string fields = "id, address, mangled_function, nodes, edges, size, bytes_hash";
    std::string sql = "select address ea, mangled_function, nodes, bytes_hash "
                      "  from (select " + fields + " from functions "
                      " intersect "
                      " select " + fields + " from diff.functions) x";
    for ( const auto &row : db.query(sql) )
    {
      match_item_t item;
      item.name1 = item.name2 = row.str("mangled_function");
      item.ea1 = item.ea2 = (uint64)row.to_int("ea");
      item.nodes1 = item.nodes2 = row.to_int("nodes");
      item.desc = "100% equal";
      item.ratio = 1;
      bd.add_match(item.name1, item.name2, 1.0, &item, CAT_BEST);
    }
  }

  bool same_processor_both_databases()
  {
    sql_row_t row;
    return bd.get_db().query_one(R"SQL( select 1
          from main.program mp,
             diff.program dp
         where mp.processor = dp.processor)SQL", {}, &row);
  }

  //----------------------------------------------------------------------------
  // Find matches by searching for the same name (mangled and unmangled)
  void find_same_name(int choose)
  {
    std::string desc = "Perfect match, same name";
    std::string sql = "select distinct " + get_query_fields(desc) +
      R"SQL(
         from functions f,
          diff.functions df
        where (df.mangled_function = f.mangled_function
         or df.name = f.name)
        and f.name not like 'nullsub_%')SQL";

    log_refresh("Finding with heuristic '" + desc + "'");
    sql_rows_t rows = bd.get_db().query(sql);
    if ( rows.empty() || bd.all_functions_matched() )
      return;

    heur_cols_t cols;
    for ( const auto &row : rows )
    {
      check_cancelled();
      cols.init(row);
      std::string name = heur_cols_t::get(row, cols.mangled1)->str();
      if ( bd.ignore_sub_names && starts_with(name, "sub_") )
        continue;

      auto chk = check_match(row, cols);
      if ( !chk.first )
        continue;
      double ratio = chk.second;

      match_item_t item;
      item.ea1 = (uint64)heur_cols_t::get(row, cols.ea)->to_int();
      item.name1 = heur_cols_t::get(row, cols.name1)->str();
      item.ea2 = (uint64)heur_cols_t::get(row, cols.ea2)->to_int();
      item.name2 = heur_cols_t::get(row, cols.name2)->str();
      item.desc = heur_cols_t::get(row, cols.description)->str();
      item.nodes1 = heur_cols_t::get(row, cols.nodes1)->to_int();
      item.nodes2 = heur_cols_t::get(row, cols.nodes2)->to_int();
      double md1 = heur_cols_t::get(row, cols.md1)->to_double();
      double md2 = heur_cols_t::get(row, cols.md2)->to_double();
      int the_chooser;
      if ( ratio == 1.0 || (bd.relaxed_ratio && md1 != 0 && md1 == md2) )
      {
        the_chooser = CAT_BEST;
        item.ratio = 1;
      }
      else
      {
        the_chooser = choose;
        if ( ratio + config::MATCHES_BONUS_RATIO < 1.0 )
          ratio += config::MATCHES_BONUS_RATIO;
        item.ratio = ratio;
      }
      bd.add_match(item.name1, item.name2, ratio, &item, the_chooser);
    }
  }

  //----------------------------------------------------------------------------
  // Find matches where most used names are the same
  void search_small_differences(int choose)
  {
    std::string name = "Nodes, edges, complexity and mnemonics with small differences";
    std::string sql = " select " + get_query_fields(name) + R"SQL( ,
           f.names  f_names,
           df.names df_names
        from functions f,
           diff.functions df
         where f.nodes = df.nodes
         and f.edges = df.edges
         and f.mnemonics = df.mnemonics
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.names != '[]' )SQL";

    sql_stmt_t st(bd.get_db(), sql);
    st.bind({});
    heur_cols_t cols;
    sql_row_t row;
    int64 i = 0;
    while ( st.fetch(&row) )
    {
      if ( (++i & 0xFF) == 0 )
        check_cancelled();
      cols.init(row);
      std::string name1 = heur_cols_t::get(row, cols.name1)->str();
      std::string name2 = heur_cols_t::get(row, cols.name2)->str();

      std::set<std::string> s1, s2;
      py_set_key_list(row.str("f_names"), &s1);
      py_set_key_list(row.str("df_names"), &s2);
      size_t total = std::max(s1.size(), s2.size());
      size_t commons = 0;
      for ( const auto &x : s1 )
        if ( s2.find(x) != s2.end() )
          ++commons;
      double ratio = total != 0 ? double(commons) / double(total) : 0;
      if ( bd.has_better_match(name1, name2, ratio) )
        continue;

      if ( ratio >= config::DEFAULT_PARTIAL_RATIO )
      {
        auto chk = check_match(row, cols);
        if ( !chk.first )
          continue;
        ratio = chk.second;

        match_item_t item;
        item.ea1 = (uint64)heur_cols_t::get(row, cols.ea)->to_int();
        item.name1 = name1;
        item.ea2 = (uint64)heur_cols_t::get(row, cols.ea2)->to_int();
        item.name2 = name2;
        item.desc = heur_cols_t::get(row, cols.description)->str();
        item.nodes1 = heur_cols_t::get(row, cols.nodes1)->to_int();
        item.nodes2 = heur_cols_t::get(row, cols.nodes2)->to_int();
        item.ratio = ratio;
        bd.add_match(name1, name2, ratio, &item, ratio == 1.0 ? CAT_BEST : choose);
      }
    }
  }

  void find_partial_matches()
  {
    run_heuristics_for_category("Partial");
    if ( bd.slow_heuristics )
    {
      // Search using some of the previous criterias but calculating the edit distance
      log_refresh("Finding with heuristic 'Small names difference'");
      search_small_differences(CAT_PARTIAL);
    }
  }

  //----------------------------------------------------------------------------
  // Brute force the unmatched functions. This is unreliable at best.
  void find_brute_force()
  {
    sql_db_t &db = bd.get_db();
    db.try_exec("drop table if exists temp.unmatched");
    db.exec("create temporary table unmatched(id integer null primary key, address, main)");

    {
      sql_stmt_t ins(db, "insert into unmatched(address,main) values(?,?)");
      for ( const auto &row : db.query("select name, address from functions") )
      {
        std::lock_guard<std::mutex> g(bd.items_lock);
        if ( bd.matched_primary.find(row.str("name")) == bd.matched_primary.end() )
          ins.run({ row[size_t(1)], int64(1) });
      }
      for ( const auto &row : db.query("select name, address from diff.functions") )
      {
        std::lock_guard<std::mutex> g(bd.items_lock);
        if ( bd.matched_secondary.find(row.str("name")) == bd.matched_secondary.end() )
          ins.run({ row[size_t(1)], int64(0) });
      }
    }

    if ( bd.slow_heuristics )
    {
      std::string heur = "Brute forcing (MD-Index and KOKA hash)";
      std::string sql = "select " + get_query_fields(heur) + R"SQL(
        from functions f,
            diff.functions df,
            unmatched um
        where ((f.address = um.address and um.main = 1)
          or (df.address = um.address and um.main = 0))
          and ((f.md_index = df.md_index
          and f.md_index > 1 and df.md_index > 1)
          or (f.kgh_hash = df.kgh_hash
          and f.kgh_hash > 7 and df.kgh_hash > 7))
          )SQL";
      sql_stmt_t st(db, sql);
      st.bind({});
      log_refresh("Finding via brute-forcing (MD-Index and KOKA hash)...");
      add_matches_from_cursor_ratio_max(st, CAT_UNRELIABLE, CAT_UNRELIABLE, config::DEFAULT_PARTIAL_RATIO);
    }

    std::string heur = "Brute forcing (Compilation Unit)";
    std::string sql = "select " + get_query_fields(heur) + R"SQL(
         from functions f,
          diff.functions df,
          unmatched um
        where ((f.address = um.address and um.main = 1)
         or (df.address = um.address and um.main = 0))
        and f.source_file = df.source_file
        and f.source_file != ''
        and df.source_file is not null
        and f.kgh_hash > 7 and df.kgh_hash > 7 )SQL";
    {
      sql_stmt_t st(db, sql);
      st.bind({});
      log_refresh("Finding via brute-forcing (Compilation Unit)...");
      add_matches_from_cursor_ratio_max(st, CAT_UNRELIABLE, CAT_UNRELIABLE, config::DEFAULT_PARTIAL_RATIO);
    }

    if ( db.in_transaction() )
      db.exec("commit");
  }

  void find_experimental_matches()
  {
    run_heuristics_for_category("Experimental");
  }

  void find_unreliable_matches()
  {
    run_heuristics_for_category("Unreliable");
    if ( bd.slow_heuristics && bd.unreliable )
    {
      log_refresh("Brute-forcing...");
      find_brute_force();
    }
  }

  //----------------------------------------------------------------------------
  // dirty heuristics (speed ups)
  bool search_just_stripped_binaries()
  {
    int64 total = bd.total_functions1;
    sql_row_t row;
    bd.get_db().query_one(R"SQL(select count(0)
                 from main.functions f,
                      diff.functions df
                where f.address = df.address )SQL", {}, &row);
    int64 matches = row.empty() ? 0 : row[size_t(0)].to_int();
    double percent = total != 0 ? (matches * 100.0) / total : 0;
    if ( percent >= config::SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT )
    {
      bd.is_symbols_stripped = true;
      log("Symbols stripped detected: A total of %lld matches out of %lld, %f%% percent have the same address",
          (long long)matches, (long long)total, percent);
      std::string heur = "Same binary with symbols stripped";
      std::string sql = "\n    select distinct " + get_query_fields(heur) + R"SQL(
      from functions f,
           diff.functions df
     where f.address = df.address)SQL";
      log_refresh("Finding via " + py_repr(heur));
      add_matches_from_query_ratio(sql, CAT_BEST, CAT_PARTIAL);
      return true;
    }
    return false;
  }

  bool search_patchdiff_with_symbols()
  {
    int64 total = bd.total_functions1;
    sql_row_t row;
    bd.get_db().query_one(R"SQL(select count(0)
                 from main.functions f,
                      diff.functions df
                where f.mangled_function = df.mangled_function )SQL", {}, &row);
    int64 matches = row.empty() ? 0 : row[size_t(0)].to_int();
    double percent = total != 0 ? (matches * 100.0) / total : 0;
    if ( percent > config::SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT )
    {
      bd.is_patch_diff = true;
      if ( config::RUN_DEFAULT_SCRIPTS && !bd.hooks )
      {
        log("Loading default script for patch diffing sessions...");
        bd.hooks = std::make_unique<vuln_hooks_t>(bd);
      }
      log("Patch diffing detected: A total of %lld matches out of %lld, %f%% percent have the same name",
          (long long)matches, (long long)total, percent);
      return true;
    }
    return false;
  }

  bool apply_dirty_heuristics()
  {
    if ( search_just_stripped_binaries() )
      return true;
    if ( search_patchdiff_with_symbols() )
      return true;
    return false;
  }

  //----------------------------------------------------------------------------
  void get_unmatched_functions(std::vector<std::pair<std::string, std::string>> *main,
                               std::vector<std::pair<std::string, std::string>> *diff)
  {
    sql_rows_t rows = bd.get_db().query(R"SQL(select 'main' db_name, name, address from main.functions
        union
         select 'diff' db_name, name, address from diff.functions
    )SQL");
    std::set<std::pair<std::string, std::string>> seen_main, seen_diff;
    std::lock_guard<std::mutex> g(bd.items_lock);
    for ( const auto &row : rows )
    {
      std::string name = row.str("name");
      bool is_diff = row.str("db_name") == "diff";
      auto &d = is_diff ? bd.matched_secondary : bd.matched_primary;
      if ( d.find(name) != d.end() )
        continue;
      std::pair<std::string, std::string> key(row.str("address"), name);
      auto &seen = is_diff ? seen_diff : seen_main;
      if ( seen.insert(key).second )
        (is_diff ? diff : main)->push_back(key);
    }
  }

  // Search potentially renamed functions in a usual patch diffing session
  void find_remaining_functions()
  {
    std::vector<std::pair<std::string, std::string>> main_unmatched, diff_unmatched;
    get_unmatched_functions(&main_unmatched, &diff_unmatched);
    if ( !bd.is_patch_diff )
      return;

    std::string heur = "Renamed or anonymous function match in patch diffing session";
    std::string sql = "select " + get_query_fields("?", false) + R"SQL(
         from main.functions f,
          diff.functions df
        where f.address = ?
        and df.address = ?)SQL";
    sql += " and f.nodes >= 3 and df.nodes >= 3 ";

    sql_stmt_t st(bd.get_db(), sql);
    for ( const auto &m : main_unmatched )
    {
      if ( !starts_with(m.second, "sub_") )
        continue;
      for ( const auto &d : diff_unmatched )
      {
        check_cancelled();
        st.bind({ heur, m.first, d.first });
        try
        {
          add_matches_internal(st, CAT_BEST, CAT_PARTIAL, config::SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO);
        }
        catch ( const stop_heuristic_t & )
        {
          return;
        }
      }
    }
  }

  //----------------------------------------------------------------------------
  // multimatches and the final pass
  struct multi_entry_t
  {
    uint64 ea;
    double ratio;
    match_item_t match;
  };
  using multi_map_t = std::vector<std::pair<uint64, std::vector<multi_entry_t>>>;

  static std::vector<multi_entry_t> &multi_at(multi_map_t &m, std::unordered_map<uint64, size_t> &idx, uint64 key)
  {
    auto p = idx.find(key);
    if ( p == idx.end() )
    {
      idx[key] = m.size();
      m.emplace_back(key, std::vector<multi_entry_t>());
      return m.back().second;
    }
    return m[p->second].second;
  }

  void add_multimatches_to_chooser(const multi_map_t &multi, std::unordered_set<uint64> &ignore_list,
                                   std::unordered_set<std::string> &dones)
  {
    for ( const auto &kv : multi )
    {
      if ( kv.second.size() <= 1 )
        continue;
      for ( const auto &mm : kv.second )
      {
        const match_item_t &item = mm.match;
        std::string key = strfmt("%llu-%llu", (unsigned long long)item.ea1, (unsigned long long)item.ea2);
        if ( dones.insert(key).second )
        {
          bd.multimatch_chooser.add_item(item);
          ignore_list.insert(kv.first);
        }
      }
    }
  }

  void final_pass()
  {
    bd.cleanup_matches();

    // find_unresolved_multimatches()
    std::unordered_map<uint64, double> max_main, max_diff;
    multi_map_t multi_main, multi_diff;
    std::unordered_map<uint64, size_t> multi_main_idx, multi_diff_idx;
    std::unordered_set<std::string> dones;
    for ( int key = 0; key < CAT_COUNT; ++key )
    {
      for ( const auto &match : get_sorted_results(key) )
      {
        std::string k = strfmt("%llu-%llu", (unsigned long long)match.ea1, (unsigned long long)match.ea2);
        if ( !dones.insert(k).second )
          continue;

        if ( max_main.find(match.ea1) == max_main.end() )
          max_main[match.ea1] = match.ratio;
        // If the previous ratio we got is less than this one, ignore
        if ( max_main[match.ea1] > match.ratio )
          continue;
        max_main[match.ea1] = match.ratio;
        multi_at(multi_main, multi_main_idx, match.ea1).push_back({ match.ea2, match.ratio, match });

        if ( max_diff.find(match.ea2) == max_diff.end() )
          max_diff[match.ea2] = match.ratio;
        if ( max_diff[match.ea2] > match.ratio )
          continue;
        max_diff[match.ea2] = match.ratio;
        multi_at(multi_diff, multi_diff_idx, match.ea2).push_back({ match.ea1, match.ratio, match });
      }
    }

    // add them to the corresponding chooser
    std::unordered_set<uint64> ignore_main, ignore_diff;
    std::unordered_set<std::string> chooser_dones;
    add_multimatches_to_chooser(multi_main, ignore_main, chooser_dones);
    add_multimatches_to_chooser(multi_diff, ignore_diff, chooser_dones);

    // add_final_chooser_items()
    chooser_data_t *choosers[CAT_COUNT] = { &bd.best_chooser, &bd.partial_chooser, &bd.unreliable_chooser };
    for ( int key = 0; key < CAT_COUNT; ++key )
    {
      for ( const auto &item : get_sorted_results(key) )
      {
        if ( ignore_main.count(item.ea1) != 0 || ignore_diff.count(item.ea2) != 0 )
          continue;
        auto pm = max_main.find(item.ea1);
        if ( pm != max_main.end() && item.ratio < pm->second )
          continue;
        auto pd = max_diff.find(item.ea2);
        if ( pd != max_diff.end() && item.ratio < pd->second )
          continue;
        choosers[key]->add_item(item);
      }
    }
  }

  //----------------------------------------------------------------------------
  void find_unmatched()
  {
    sql_db_t &db = bd.get_db();
    bd.unmatched_primary.clear();
    bd.unmatched_second.clear();
    std::lock_guard<std::mutex> g(bd.items_lock);
    for ( const auto &row : db.query("select name, address from functions") )
    {
      std::string name = row.str("name");
      if ( bd.matched_primary.find(name) == bd.matched_primary.end() )
        bd.unmatched_primary.add_unmatched((uint64)row[size_t(1)].to_int(), name);
    }
    for ( const auto &row : db.query("select name, address from diff.functions") )
    {
      std::string name = row.str("name");
      if ( bd.matched_secondary.find(name) == bd.matched_secondary.end() )
        bd.unmatched_second.add_unmatched((uint64)row.to_int("address"), name);
    }
  }

  //----------------------------------------------------------------------------
  // find new matches by diffing previously found matches
  bool functions_exists(const std::string &name1, const std::string &name2, sql_rows_t *rows)
  {
    *rows = bd.get_db().query(R"SQL(select * from (
         select 'main' db_name, * from main.functions where name = ?
        union
         select 'diff' db_name, * from diff.functions where name = ?
         ) order by db_name desc
      )SQL", { name1, name2 });
    return rows->size() == 2;
  }

  void find_one_match_diffing(const sql_row_t &input_main_row, const sql_row_t &input_diff_row,
                              const char *field_name, const std::string &heur, int iteration,
                              std::unordered_set<std::string> &dones)
  {
    std::vector<std::string> main_lines = splitlines(input_main_row.str(field_name));
    std::vector<std::string> diff_lines = splitlines(input_diff_row.str(field_name));
    std::vector<std::string> df = unified_diff(main_lines, diff_lines, "");

    std::vector<std::string> minus, plus;
    for ( const auto &row : df )
    {
      if ( row.empty() )
        continue;
      char c = row[0];
      if ( c == '-' )
      {
        minus.push_back(row);
      }
      else if ( c == '+' )
      {
        plus.push_back(row);
      }
      else if ( c == ' ' )
      {
        if ( minus.empty() || plus.empty() )
          continue;
        std::vector<std::string> matches1 = find_cpp_names(join(minus, "\n"));
        std::vector<std::string> matches2 = find_cpp_names(join(plus, "\n"));
        minus.clear();
        plus.clear();

        size_t size = std::min(matches1.size(), matches2.size());
        for ( size_t i = 0; i < size; ++i )
        {
          const std::string &name1 = matches1[i];
          const std::string &name2 = matches2[i];
          std::string key = name1 + "-" + name2;
          if ( !dones.insert(key).second )
            continue;

          // Ignore such functions
          if ( starts_with(name1, "nullsub") || starts_with(name2, "nullsub") )
            continue;

          size_t total = dones.size();
          if ( total > 0 && total % 10000 == 0 )
          {
            log("%u callee matches processed so far...", unsigned(total));
            check_cancelled();
          }

          sql_rows_t l;
          if ( !functions_exists(name1, name2, &l) )
            continue;
          const sql_row_t &main_row = l[0];
          const sql_row_t &diff_row = l[1];
          int64 n1 = main_row.to_int("nodes");
          int64 n2 = diff_row.to_int("nodes");
          int64 min_nodes = std::min(n1, n2);
          int64 max_nodes = std::max(n1, n2);
          if ( max_nodes == 0 )
            continue;

          // If the number of basic blocks differ in more than 75% ignore...
          if ( (min_nodes * 100.0) / max_nodes < config::DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT )
            continue;

          // high risk of false positives with small functions
          if ( n1 < config::DIFFING_MATCHES_MIN_BBLOCKS || n2 < config::DIFFING_MATCHES_MIN_BBLOCKS )
            continue;

          double r = bd.compare_function_rows(main_row, diff_row);
          int chooser;
          if ( r == 1.0 )
            chooser = CAT_BEST;
          else if ( r > config::DEFAULT_TRUSTED_PARTIAL_RATIO )
            chooser = CAT_PARTIAL;
          else
            continue;

          if ( r + config::MATCHES_BONUS_RATIO < 1.0 )
            r += config::MATCHES_BONUS_RATIO;

          auto res = call_on_match_hook(heur, r, main_row, diff_row);
          r = res.second;
          if ( res.first )
          {
            match_item_t item;
            item.ea1 = (uint64)main_row.to_int("address");
            item.name1 = name1;
            item.ea2 = (uint64)diff_row.to_int("address");
            item.name2 = name2;
            item.desc = strfmt("%s (iteration #%d)", heur.c_str(), iteration);
            item.ratio = r;
            item.nodes1 = n1;
            item.nodes2 = n2;
            bd.add_match(name1, name2, r, &item, chooser);
          }
        }
      }
    }
  }

  void find_matches_diffing_internal(const std::string &heur, const char *field_name)
  {
    log_refresh("Finding with heuristic '" + heur + "'");
    int iteration = 1;
    std::unordered_set<std::string> dones;
    // hardcoded upper limit to avoid infinite loops
    while ( iteration <= 3 )
    {
      int64 old_total = get_total_matched_functions();
      for ( int key : { CAT_BEST, CAT_PARTIAL } )
      {
        for ( const auto &match : get_sorted_results(key) )
        {
          std::string match_key = match.name1 + "-" + match.name2;
          if ( !dones.insert(match_key).second )
            continue;
          check_cancelled();

          sql_row_t main_row, diff_row;
          if ( !bd.get_function_row(match.name1, "main", &main_row) || !bd.get_function_row(match.name2, "diff", &diff_row) )
            continue;
          if ( main_row.is_null(field_name) || diff_row.is_null(field_name) )
            continue;
          find_one_match_diffing(main_row, diff_row, field_name, heur, iteration, dones);
        }
      }

      bd.cleanup_matches();
      show_summary();

      int64 new_total = get_total_matched_functions();
      if ( new_total == old_total )
        break;

      log("New iteration with heuristic '%s'...", heur.c_str());
      ++iteration;
    }
  }

  void find_matches_diffing(int iteration)
  {
    qnotused(iteration);
    bd.cleanup_matches();
    // Only if the processor is the same for both databases we diff assembly
    if ( bd.is_same_processor )
      find_matches_diffing_internal("Callee found diffing matches assembly", "assembly");
    find_matches_diffing_internal("Callee found diffing matches pseudo-code", "pseudocode");
  }

  //----------------------------------------------------------------------------
  // Find the 'bester' matches in the functions gap specified by the ranges
  void find_functions_between(const std::pair<std::string, std::string> &range1,
                              const std::pair<std::string, std::string> &range2)
  {
    static const char *const sql = R"SQL(select *
         from %s.functions
        where address > ?
          and address < ?
        order by address desc)SQL";
    std::string heur_text = "Local affinity";
    sql_db_t &db = bd.get_db();

    sql_rows_t main_rows = db.query(strfmt(sql, "main"), { range1.first, range1.second });
    size_t size = main_rows.size();
    if ( size == 0 || size > (size_t)config::MAX_FUNCTIONS_PER_GAP )
      return;
    sql_rows_t diff_rows = db.query(strfmt(sql, "diff"), { range2.first, range2.second });
    size = diff_rows.size();
    if ( size == 0 || size > (size_t)config::MAX_FUNCTIONS_PER_GAP )
      return;

    std::unordered_map<std::string, double> main_score, diff_score;
    for ( const auto &main_row : main_rows )
    {
      for ( const auto &diff_row : diff_rows )
      {
        std::string name1 = main_row.str("name");
        std::string name2 = diff_row.str("name");
        if ( starts_with(name1, "nullsub_") || starts_with(name2, "nullsub_") )
          continue;
        if ( !starts_with(name1, "sub_") && !starts_with(name2, "sub_") )
          continue;

        int64 pl1 = main_row.to_int("pseudocode_lines");
        int64 pl2 = diff_row.to_int("pseudocode_lines");
        if ( pl1 + pl2 != 0 && (pl1 == 3 || pl2 == 3) )
          continue;

        double r = bd.compare_function_rows(main_row, diff_row);
        int chooser;
        if ( r == 1.0 )
          chooser = CAT_BEST;
        else if ( r >= config::DEFAULT_PARTIAL_RATIO )
          chooser = CAT_PARTIAL;
        else
          continue;

        // the first matches are the best ones in this case
        auto pm = main_score.find(name1);
        if ( pm != main_score.end() && pm->second >= r )
          continue;
        auto pd = diff_score.find(name2);
        if ( pd != diff_score.end() && pd->second >= r )
          continue;

        auto res = call_on_match_hook(heur_text, r, main_row, diff_row);
        r = res.second;
        if ( res.first )
        {
          match_item_t item;
          item.ea1 = (uint64)main_row.to_int("address");
          item.name1 = name1;
          item.ea2 = (uint64)diff_row.to_int("address");
          item.name2 = name2;
          item.desc = heur_text;
          item.ratio = r;
          item.nodes1 = main_row.to_int("nodes");
          item.nodes2 = diff_row.to_int("nodes");
          bd.add_match(name1, name2, r, &item, chooser);
          main_score[name1] = r;
          diff_score[name2] = r;
        }
      }
    }
  }

  void find_locally_affine_functions(int iteration)
  {
    qnotused(iteration);
    bd.cleanup_matches();
    log_refresh("Finding locally affine functions");

    std::vector<match_item_t> tmp_matches;
    {
      std::lock_guard<std::mutex> g(bd.items_lock);
      tmp_matches = bd.all_matches[CAT_BEST];
      tmp_matches.insert(tmp_matches.end(), bd.all_matches[CAT_PARTIAL].begin(), bd.all_matches[CAT_PARTIAL].end());
    }
    std::stable_sort(tmp_matches.begin(), tmp_matches.end(), [](const match_item_t &x, const match_item_t &y)
    {
      if ( x.ea1 != y.ea1 )
        return x.ea1 < y.ea1;
      return x.ea2 < y.ea2;
    });

    for ( size_t i = 1; i < tmp_matches.size(); ++i )
    {
      check_cancelled();
      const match_item_t &prev = tmp_matches[i - 1];
      const match_item_t &match = tmp_matches[i];
      find_functions_between({ std::to_string(prev.ea1), std::to_string(match.ea1) },
                             { std::to_string(prev.ea2), std::to_string(match.ea2) });
    }
  }

  //----------------------------------------------------------------------------
  // matches from cross references to constants of good matches
  void find_related_constants(const sql_row_t &main_row, const sql_row_t &diff_row)
  {
    std::string heur = "Same constants related matches";
    json_t j1, j2;
    json_parse(main_row.str("constants"), &j1);
    json_parse(diff_row.str("constants"), &j2);
    std::map<std::string, std::string> main_consts;    // set key -> str(constant)
    for ( const auto &v : j1.arr )
      main_consts[v.set_key()] = v.type == json_t::JSTR || v.type == json_t::JBIGINT ? v.s : v.dump();
    std::set<std::string> diff_keys;
    for ( const auto &v : j2.arr )
      diff_keys.insert(v.set_key());

    std::vector<std::string> inter;
    for ( const auto &kv : main_consts )
      if ( diff_keys.count(kv.first) != 0 )
        inter.push_back(kv.second);
    if ( inter.empty() )
      return;

    std::string sql = " select " + get_query_fields(heur) + R"SQL(
         from main.functions f,
              diff.functions df,
              main.constants mc,
              diff.constants dc
        where f.id = mc.func_id
          and df.id = dc.func_id
          and dc.constant = mc.constant
          and mc.constant = ?
          and abs(mc.constant) == 0 )SQL";
    sql_stmt_t st(bd.get_db(), sql);
    for ( const auto &constant : inter )
    {
      st.bind({ constant });
      try
      {
        add_matches_internal(st, CAT_BEST, CAT_PARTIAL);
      }
      catch ( const stop_heuristic_t & )
      {
        return;
      }
    }
  }

  void find_related_matches(int iteration)
  {
    qnotused(iteration);
    std::string heur = "Same constants related matches";
    bd.cleanup_matches();
    log_refresh("Finding with heuristic '" + heur + "'");

    std::unordered_set<std::string> dones;
    for ( int key : { CAT_BEST, CAT_PARTIAL } )
    {
      for ( const auto &match : get_sorted_results(key) )
      {
        std::string match_key = match.name1 + "-" + match.name2;
        if ( !dones.insert(match_key).second )
          continue;
        if ( match.ratio < config::RELATED_MATCHES_MIN_RATIO )
          break;
        check_cancelled();

        sql_row_t main_row, diff_row;
        if ( !bd.get_function_row(match.name1, "main", &main_row) || !bd.get_function_row(match.name2, "diff", &diff_row) )
          continue;
        if ( main_row.to_int("constants_count") > 0 && diff_row.to_int("constants_count") > 0 )
          find_related_constants(main_row, diff_row);
      }
    }
  }

  // new matches in potential, or existing, compilation units
  void find_related_compilation_unit(int iteration)
  {
    qnotused(iteration);
    std::string heur = "Related compilation unit";
    bd.cleanup_matches();
    log_refresh("Finding with heuristic '" + heur + "'");

    std::vector<match_item_t> l = get_sorted_results(CAT_BEST);
    std::vector<match_item_t> lp = get_sorted_results(CAT_PARTIAL);
    l.insert(l.end(), lp.begin(), lp.end());

    std::string sql_cu = R"SQL(SELECT distinct cus.id cu_id, cus.name cu_name, cus.start_ea start_ea, cus.end_ea end_ea
               FROM {db}.compilation_unit_functions cuf,
                    {db}.compilation_units cus,
                    {db}.functions f
              WHERE f.id = cuf.func_id
                AND cus.id = cuf.cu_id
                AND f.name = ?)SQL";
    std::string sql_main = replace_all(sql_cu, "{db}", "main");
    std::string sql_diff = replace_all(sql_cu, "{db}", "diff");
    // Use the compilation units' member functions instead of their address
    // range: without symbols, LFA-detected units interleave and each range
    // spans most of the binary, turning every query into a near full cross
    // product of both binaries.
    std::string sql = "select " + get_query_fields(heur) + R"SQL(
               from functions f,
                    diff.functions df
              where f.id  in (select func_id from main.compilation_unit_functions where cu_id = ?)
                and df.id in (select func_id from diff.compilation_unit_functions where cu_id = ?) )SQL";

    sql_db_t &db = bd.get_db();
    sql_stmt_t st(db, sql);
    // Many matches share the same pair of compilation units; the query for a
    // given pair always returns the same rows, so run it only once per pair.
    std::set<std::pair<int64, int64>> dones;
    double t = monotonic();
    for ( const auto &match : l )
    {
      if ( match.ratio < config::RELATED_MATCHES_MIN_RATIO )
        break;
      check_cancelled();
      if ( monotonic() - t > bd.timeout )
      {
        log("Timeout with heuristic '%s'", heur.c_str());
        return;
      }

      sql_row_t main_row, diff_row;
      if ( !db.query_one(sql_main, { match.name1 }, &main_row) )
        continue;
      if ( !db.query_one(sql_diff, { match.name2 }, &diff_row) )
        continue;
      int64 main_cu = main_row.to_int("cu_id");
      int64 diff_cu = diff_row.to_int("cu_id");
      if ( !dones.insert({ main_cu, diff_cu }).second )
        continue;

      st.bind({ main_cu, diff_cu });
      try
      {
        add_matches_internal(st, CAT_BEST, CAT_PARTIAL, -1, false, false, t);
      }
      catch ( const stop_heuristic_t & )
      {
        return;
      }
    }
  }

  //----------------------------------------------------------------------------
  bool run(const std::string &diff_db)
  {
    sql_db_t &db = bd.get_db();
    {
      std::lock_guard<std::mutex> g(bd.ratios_lock);
      bd.ratios_cache.clear();
    }
    bd.last_diff_db = diff_db;

    // Try attaching the diff database and ignore errors (issue #151)
    try
    {
      db.execute("attach ? as diff", { diff_db });
    }
    catch ( const std::exception & )
    {
    }

    sql_row_t row;
    try
    {
      if ( !db.query_one("select value from diff.version", {}, &row) )
      {
        log("Invalid database!");
        return false;
      }
    }
    catch ( const std::exception &e )
    {
      log("Error: %s", e.what());
      log("The selected file does not look like a valid Diaphora exported database!");
      return false;
    }

    if ( row[size_t(0)].str() != DIAPHORA_DB_VERSION )
      log("WARNING: The database is from a different version (current %s, database %s)!",
          DIAPHORA_DB_VERSION, row[size_t(0)].str().c_str());

    double t0 = monotonic();
    log_refresh("Diffing...", true);

    bd.do_continue = true;
    if ( bd.equal_db() )
    {
      log("The databases seems to be 100% equal");
      if ( ask_yn(ASKBTN_NO, "HIDECANCEL\nThe databases seems to be 100%% equal. Do you want to continue anyway?") != ASKBTN_YES )
        bd.do_continue = false;
    }

    if ( !bd.do_continue )
      return true;

    // Compare the call graphs
    check_callgraph();

    // Find the unmodified functions
    log_refresh("Finding equal matches...");
    find_equal_matches();

    bool skip_others = false;
    bd.is_same_processor = same_processor_both_databases();
    if ( bd.experimental )
    {
      // Dirty magic. Might or might not work...
      log_refresh("Checking 'dirty' heuristics...");
      skip_others = apply_dirty_heuristics();
    }

    if ( !bd.ignore_all_names )
      find_same_name(CAT_PARTIAL);

    if ( skip_others )
    {
      find_remaining_functions();
    }
    else
    {
      log_refresh("Finding best matches...");
      run_heuristics_for_category("Best");

      // Find the modified functions
      log_refresh("Finding partial matches");
      find_partial_matches();

      if ( bd.unreliable )
      {
        // Find using likely unreliable methods modified functions
        log_refresh("Finding probably unreliable matches");
        find_unreliable_matches();

        log_refresh("Finding experimental matches");
        find_experimental_matches();
      }

      int iteration = 0;
      while ( true )
      {
        bd.cleanup_matches();
        int64 old_total = get_total_matched_functions();

        // Find new matches by diffing assembly and pseudo-code of previous matches
        find_matches_diffing(iteration);

        // Find new matches by digging from previous very good matches
        if ( bd.slow_heuristics )
          find_related_matches(iteration);

        find_related_compilation_unit(iteration);

        // Find new matches in the functions between matches
        find_locally_affine_functions(iteration);

        bd.cleanup_matches();
        int64 new_total = get_total_matched_functions();
        if ( new_total <= old_total )
          break;
        ++iteration;
      }
    }

    final_pass();

    // Show the list of unmatched functions in both databases
    log_refresh("Finding unmatched functions");
    find_unmatched();

    size_t best = bd.best_chooser.items.size();
    size_t partial = bd.partial_chooser.items.size();
    size_t unreliable = bd.unreliable_chooser.items.size();
    size_t multi = bd.multimatch_chooser.items.size();
    size_t total = best + partial + unreliable;
    double percent = bd.total_functions1 != 0 ? (total * 100.0) / bd.total_functions1 : 0;
    log("Final results: Best %u, Partial %u, Unreliable %u, Multimatches %u",
        unsigned(best), unsigned(partial), unsigned(unreliable), unsigned(multi));
    log("Matched %1.2f%% of main binary functions (%u out of %lld)", percent, unsigned(total), (long long)bd.total_functions1);

    double final_t = monotonic() - t0;
    int64 s = (int64)final_t;
    log("Done, time taken: %d:%02d:%02d.", int(s / 3600), int((s / 60) % 60), int(s % 60));
    return true;
  }
};
} // namespace

//------------------------------------------------------------------------------
// public entry points
//------------------------------------------------------------------------------
bool bindiff_t::equal_db()
{
  sql_db_t &db = get_db();
  sql_row_t row;
  db.query_one("select count(*) total from program p, diff.program dp where p.md5sum = dp.md5sum", {}, &row);
  bool ret = !row.empty() && row.to_int("total") == 1;
  if ( !ret )
  {
    db.query_one(R"SQL(select count(*) total
                   from (select id, address, size, nodes, edges
                           from functions
                         except
                         select id, address, size, nodes, edges
                           from diff.functions) x)SQL", {}, &row);
    ret = !row.empty() && row.to_int("total") == 0;
  }
  else
  {
    log("Same MD5 in both databases");
  }
  return ret;
}

bool bindiff_t::diff(const std::string &diff_db)
{
  g_abort = false;

  struct wait_box_guard_t
  {
    ~wait_box_guard_t() { hide_wait_box(); }
  } wbg;

  // allow cancelling long running queries from the main thread
  sql_db_t &db = get_db();
  db.set_abort_callback([]() -> bool
  {
    if ( g_abort.load() )
      return true;
    if ( user_cancelled() )
    {
      g_abort = true;
      return true;
    }
    return false;
  });

  bool ret = false;
  try
  {
    differ_t d(*this);
    ret = d.run(diff_db);
  }
  catch ( ... )
  {
    db.set_abort_callback(nullptr);
    if ( g_abort.load() )
    {
      g_abort = false;
      throw cancelled_error();
    }
    throw;
  }
  db.set_abort_callback(nullptr);
  return ret;
}

//------------------------------------------------------------------------------
// check_ratio / deep_ratio / compare_function_rows
//------------------------------------------------------------------------------
static double deep_ratio(bindiff_t &bd, const func_cmp_t &main_d, const func_cmp_t &diff_d)
{
  double score = 0;
  sql_db_t &db = bd.get_db();
  sql_row_t main_row, diff_row;
  if ( !db.query_one("select * from main.functions where address = ?", { std::to_string(main_d.ea->to_int()) }, &main_row) )
    return score;
  if ( !db.query_one("select * from diff.functions where address = ?", { std::to_string(diff_d.ea->to_int()) }, &diff_row) )
    return score;

  const sql_value_t &source1 = main_row["source_file"];
  const sql_value_t &source2 = diff_row["source_file"];
  if ( !source1.is_null() && !source2.is_null() && source1 == source2 && source1.str() != "" )
    score += 0.001;

  const sql_value_t &pp1 = main_row["pseudocode_primes"];
  const sql_value_t &pp2 = diff_row["pseudocode_primes"];
  if ( !pp1.is_null() && !pp2.is_null() && pp1 == pp2 && pp1.str() != "" )
    score += 0.001;

  const sql_value_t zero(int64(0));
  const sql_value_t &in1 = main_row["indegree"];
  if ( in1 == diff_row["indegree"] && in1 != zero )
    score += 0.001;

  const sql_value_t &out1 = main_row["outdegree"];
  if ( out1 == diff_row["outdegree"] && out1 != zero )
    score += 0.001;

  const sql_value_t &sw1 = main_row["switches"];
  if ( sw1 == diff_row["switches"] && sw1.str() != "[]" )
    score += 0.003;

  const sql_value_t &cc1 = main_row["cyclomatic_complexity"];
  if ( cc1 == diff_row["cyclomatic_complexity"] && cc1 != zero )
    score += 0.001;

  if ( main_row.str("constants") != "[]" )
  {
    std::set<std::string> set1, set2;
    py_set_key_list(main_row.str("constants"), &set1);
    py_set_key_list(diff_row.str("constants"), &set2);
    size_t inter = 0;
    for ( const auto &x : set1 )
      if ( set2.count(x) != 0 )
        ++inter;
    if ( inter > 0 )
    {
      double tmp = bd.is_same_processor
                 ? config::INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU
                 : config::INCREASE_RATIO_PER_CONSTANT_MATCH;
      score += inter * tmp;
    }
  }
  return score;
}

double bindiff_t::check_ratio(const func_cmp_t &main_d, const func_cmp_t &diff_d)
{
  std::string key = main_d.ea->str() + "-" + diff_d.ea->str();
  {
    std::lock_guard<std::mutex> g(ratios_lock);
    auto p = ratios_cache.find(key);
    if ( p != ratios_cache.end() )
      return p->second;
  }
  auto cache = [&](double r)
  {
    std::lock_guard<std::mutex> g(ratios_lock);
    ratios_cache[key] = r;
    return r;
  };

  opt_text_t ast1(main_d.pseudocode_primes), ast2(diff_d.pseudocode_primes);
  opt_text_t pseudo1(main_d.pseudo), pseudo2(diff_d.pseudo);
  opt_text_t clean_assembly1(main_d.clean_assembly), clean_assembly2(diff_d.clean_assembly);
  opt_text_t clean_pseudo1(main_d.clean_pseudo), clean_pseudo2(diff_d.clean_pseudo);
  opt_text_t clean_micro1(main_d.clean_micro), clean_micro2(diff_d.clean_micro);
  double md1 = main_d.md_index->to_double();
  double md2 = diff_d.md_index->to_double();

  using fratio_t = double (*)(const std::string *, const std::string *);
  fratio_t fratio = quick_ratio;
  int decimals = 7;
  if ( relaxed_ratio )
  {
    fratio = real_quick_ratio;
    decimals = 1;
  }

  if ( *main_d.bytes_hash == *diff_d.bytes_hash )
    return cache(1.0);

  double v3 = 0;
  bool ast_done = false;
  if ( relaxed_ratio && ast1.p != nullptr && ast2.p != nullptr && std::max(ast1.p->size(), ast2.p->size()) < 16 )
  {
    ast_done = true;
    // ast_ratio()
    if ( *ast1.p == *ast2.p )
      v3 = 1.0;
    else
      v3 = difference_ratio(parse_uint64(*ast1.p, 10), parse_uint64(*ast2.p, 10));
    if ( v3 == 1.0 )
      return cache(1.0);
  }

  double v1 = 0;
  if ( pseudo1.p != nullptr && pseudo2.p != nullptr && !pseudo1.p->empty() && !pseudo2.p->empty() )
  {
    if ( (clean_pseudo1.p != nullptr && clean_pseudo1.p->empty()) || (clean_pseudo2.p != nullptr && clean_pseudo2.p->empty()) )
    {
      log("Error cleaning pseudo-code!");
    }
    else
    {
      v1 = round_digits(fratio(clean_pseudo1.p, clean_pseudo2.p), decimals);
      if ( v1 == 1.0 && fratio == real_quick_ratio )
      {
        // If real_quick_ratio returns 1 try again with quick_ratio because it
        // can result in false positives.
        v1 = quick_ratio(clean_pseudo1.p, clean_pseudo2.p);
        if ( v1 == 1.0 )
          return cache(1.0);
      }
    }
  }

  double v2 = round_digits(fratio(clean_assembly1.p, clean_assembly2.p), decimals);
  if ( v2 == 1.0 && fratio == real_quick_ratio )
  {
    v2 = quick_ratio(clean_assembly1.p, clean_assembly2.p);
    if ( v2 == 1.0 )
      return cache(1.0);
  }

  if ( relaxed_ratio && !ast_done )
  {
    v3 = round_digits(fratio(ast1.p, ast2.p), decimals);
    if ( v3 == 1.0 )
      return cache(1.0);
  }

  double v4 = 0.0;
  if ( md1 == md2 && md1 > 0.0 )
  {
    // A MD-Index >= 10.0 is somehow rare
    if ( relaxed_ratio && md1 > config::MINIMUM_RARE_MD_INDEX )
      return cache(1.0);
    v4 = std::min((v1 + v2 + v3 + 3.0) / 5, 1.0);
  }

  double v5 = 0.0;
  if ( clean_micro1.p != nullptr && clean_micro2.p != nullptr )
  {
    v5 = round_digits(fratio(clean_micro1.p, clean_micro2.p), decimals);
    if ( v5 == 1.0 )
      return cache(1.0);
  }

  double values[] = { v1, v2, v3, v4, v5 };
  double r = *std::max_element(std::begin(values), std::end(values));
  if ( r == 1.0 && md1 != md2 )
  {
    // We cannot assign a 1.0 ratio if both MD indices are different
    r = 0;
    for ( double v : values )
      if ( v != 1.0 && v > r )
        r = v;
  }

  if ( r < 1.0 )
  {
    double score = deep_ratio(*this, main_d, diff_d);
    if ( r + score < 1.0 )
      r += score;
    else
      r = 0.99;
  }

  debug_log("self.ratios_cache[%s-%s] = %f", main_d.name->str().c_str(), diff_d.name->str().c_str(), r);
  return cache(r);
}

double bindiff_t::compare_function_rows(const sql_row_t &main_row, const sql_row_t &diff_row)
{
  func_cmp_t main_d, diff_d;
  function_row_cmp(main_row, &main_d);
  function_row_cmp(diff_row, &diff_d);
  return check_ratio(main_d, diff_d);
}

//------------------------------------------------------------------------------
// graphs
//------------------------------------------------------------------------------
void bindiff_t::get_graph(uint64 ea, bool primary, const char *asm_type, bb_graph_t *g)
{
  const char *dbn = primary ? "main" : "diff";
  sql_db_t &db = get_db();
  *g = bb_graph_t();

  std::string sql = strfmt(R"SQL(
       select bb.address bb_address, ins.address ins_address,
              ins.mnemonic ins_mnem, ins.disasm ins_disasm
         from %s.function_bblocks fb,
              %s.bb_instructions bbins,
              %s.instructions ins,
              %s.basic_blocks bb,
              %s.functions f
        where ins.id = bbins.instruction_id
          and bbins.basic_block_id = bb.id
          and bb.id = fb.basic_block_id
          and f.id = fb.function_id
          and fb.asm_type = bb.asm_type
          and ins.asm_type = bb.asm_type
          and f.address = ?
          and bb.asm_type = ?
          and ins.address is not null
        order by bb.address asc)SQL", dbn, dbn, dbn, dbn, dbn);
  std::unordered_set<std::string> dones;
  for ( const auto &row : db.query(sql, { std::to_string(ea), asm_type }) )
  {
    std::string bb_ea = std::to_string(row.to_int("bb_address"));
    std::string ins_ea = std::to_string(row.to_int("ins_address"));
    if ( !dones.insert(ins_ea).second )
      continue;
    auto p = g->blocks.find(bb_ea);
    if ( p == g->blocks.end() )
    {
      g->order.push_back(bb_ea);
      p = g->blocks.emplace(bb_ea, std::vector<bb_graph_t::ins_t>()).first;
    }
    p->second.push_back({ ins_ea, row.str("ins_mnem"), row.str("ins_disasm") });
  }

  sql = strfmt(R"SQL(
         select (select address
                   from %s.basic_blocks
                  where id = bbr.parent_id) ea1,
                (select address
                   from %s.basic_blocks
                  where id = bbr.child_id) ea2
          from %s.bb_relations bbr,
               %s.function_bblocks fbs,
               %s.basic_blocks bbs,
               %s.functions f
         where f.id = fbs.function_id
           and bbs.id = fbs.basic_block_id
           and fbs.basic_block_id = bbr.child_id
           and f.address = ?
           and fbs.asm_type = ?
           and bbs.asm_type = fbs.asm_type
         order by 1 asc, 2 asc)SQL", dbn, dbn, dbn, dbn, dbn, dbn);
  for ( const auto &row : db.query(sql, { std::to_string(ea), asm_type }) )
  {
    std::string bb_ea1 = row.str("ea1");
    std::string bb_ea2 = row.str("ea2");
    auto p = g->relations.find(bb_ea1);
    if ( p == g->relations.end() )
    {
      g->rel_order.push_back(bb_ea1);
      p = g->relations.emplace(bb_ea1, std::set<std::string>()).first;
    }
    p->second.insert(bb_ea2);
  }
}

// Compare the basic blocks and calculate each basic block's colour
static void compare_graphs_pass(const bb_graph_t &g1, const bb_graph_t &g2,
                                bb_colours_t &colours1, bb_colours_t &colours2, bool is_second)
{
  std::unordered_set<std::string> dones1, dones2;
  for ( const auto &key1 : g1.order )
  {
    if ( dones1.count(key1) != 0 )
      continue;
    const auto &b1 = g1.blocks.at(key1);
    for ( const auto &key2 : g2.order )
    {
      if ( dones2.count(key2) != 0 )
        continue;
      const auto &b2 = g2.blocks.at(key2);
      // Same number of instructions?
      if ( b1.size() != b2.size() )
        continue;
      bool mod = false;
      bool partial = true;
      size_t i = 0;
      for ( const auto &ins1 : b1 )
      {
        const auto &ins2 = b2[std::min(i, b2.size() - 1)];
        // Same mnemonic? The change can be only partial
        if ( ins1[1] != ins2[1] )
          partial = false;
        // Try to compare the assembly after doing some cleaning
        if ( get_cmp_asm(ins1[2]) != get_cmp_asm(ins2[2]) )
        {
          mod = true;
          if ( !partial )
            continue;
        }
        ++i;
      }

      if ( !mod )
      {
        // Perfect match, a basic block equal in both functions
        colours1[key1] = config::GRAPH_BBLOCK_MATCH_PERFECT;
        colours2[key2] = config::GRAPH_BBLOCK_MATCH_PERFECT;
        dones1.insert(key1);
        dones2.insert(key2);
        break;
      }
      else if ( !is_second && partial )
      {
        // Partial match, same mnemonics but something changed. Do not add the
        // partial matches to the dones lists, as we can have complete matches
        // after a partial match!
        colours1[key1] = config::GRAPH_BBLOCK_MATCH_PARTIAL;
        colours2[key2] = config::GRAPH_BBLOCK_MATCH_PARTIAL;
        break;
      }
    }
  }
}

void bindiff_t::compare_graphs(const bb_graph_t &g1, const bb_graph_t &g2,
                               bb_colours_t *colours1, bb_colours_t *colours2)
{
  colours1->clear();
  colours2->clear();
  // Consider, by default, all blocks added, news
  for ( const auto &k : g1.order )
    (*colours1)[k] = config::GRAPH_BBLOCK_MATCH_NONE;
  for ( const auto &k : g2.order )
    (*colours2)[k] = config::GRAPH_BBLOCK_MATCH_NONE;
  compare_graphs_pass(g1, g2, *colours1, *colours2, false);
  compare_graphs_pass(g1, g2, *colours1, *colours2, true);
}

} // namespace dph
