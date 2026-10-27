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

// Diaphora-ng - export the IDA database to SQLite
// Port of the export related parts of diaphora_ida.CIDABinDiff and
// diaphora.CBinDiff (read_function, save_function, do_export, ...) and of
// jkutils/graph_hashes.py (KOKA hash).
#include "bindiff_impl.hpp"
#include "compunits.hpp"

#include <chrono>
#include <cmath>
#include <hexrays.hpp>

// Hex-Rays dispatcher (required by hexrays.hpp)
hexdsp_t *hexdsp = nullptr;

namespace dph
{

//------------------------------------------------------------------------------
// helpers
//------------------------------------------------------------------------------
static double monotonic()
{
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

// CBinDiff.get_valid_prop() for integers
static sql_value_t valid_prop(int64 v)
{
  if ( v > 0xFFFFFFFFll || v < -0xFFFFFFFFll )
    return sql_value_t(std::to_string(v));
  return sql_value_t(v);
}

static sql_value_t valid_prop_u(uint64 v)
{
  if ( v > 0xFFFFFFFFull )
    return sql_value_t(std::to_string(v));
  return sql_value_t((int64)v);
}

static sql_value_t valid_prop_big(const bignum_t &b)
{
  int64 v;
  if ( b.fits_valid_prop(&v) )
    return sql_value_t(v);
  return sql_value_t(b.str());
}

// idautils.CodeRefsFrom / CodeRefsTo / DataRefsFrom / DataRefsTo
static void code_refs_from(ea_t ea, bool flow, std::vector<ea_t> *out)
{
  out->clear();
  if ( flow )
  {
    for ( ea_t x = get_first_cref_from(ea); x != BADADDR; x = get_next_cref_from(ea, x) )
      out->push_back(x);
  }
  else
  {
    for ( ea_t x = get_first_fcref_from(ea); x != BADADDR; x = get_next_fcref_from(ea, x) )
      out->push_back(x);
  }
}

static void code_refs_to(ea_t ea, bool flow, std::vector<ea_t> *out)
{
  out->clear();
  if ( flow )
  {
    for ( ea_t x = get_first_cref_to(ea); x != BADADDR; x = get_next_cref_to(ea, x) )
      out->push_back(x);
  }
  else
  {
    for ( ea_t x = get_first_fcref_to(ea); x != BADADDR; x = get_next_fcref_to(ea, x) )
      out->push_back(x);
  }
}

static void data_refs_from(ea_t ea, std::vector<ea_t> *out)
{
  out->clear();
  for ( ea_t x = get_first_dref_from(ea); x != BADADDR; x = get_next_dref_from(ea, x) )
    out->push_back(x);
}

static void data_refs_to(ea_t ea, std::vector<ea_t> *out)
{
  out->clear();
  for ( ea_t x = get_first_dref_to(ea); x != BADADDR; x = get_next_dref_to(ea, x) )
    out->push_back(x);
}

static bool contains(const std::vector<ea_t> &v, ea_t x)
{
  return std::find(v.begin(), v.end(), x) != v.end();
}

// idautils.Heads(start, end)
template <typename F>
static void for_each_head(ea_t start, ea_t end, F fn)
{
  ea_t ea = start;
  if ( !is_head(get_flags(ea)) )
    ea = next_head(ea, end);
  while ( ea < end && ea != BADADDR )
  {
    fn(ea);
    ea = next_head(ea, end);
  }
}

static std::string qs(const qstring &q)
{
  return std::string(q.c_str(), q.length());
}

// idc.get_type(): the type at ea without the name
static sql_value_t idc_get_type(ea_t ea)
{
  tinfo_t tif;
  if ( !get_tinfo(&tif, ea) )
    return sql_value_t();
  qstring out;
  if ( !tif.print(&out, nullptr, PRTYPE_1LINE) )
    return sql_value_t();
  return sql_value_t(qs(out));
}

// idc.guess_type()
static sql_value_t idc_guess_type(ea_t ea)
{
  tinfo_t tif;
  if ( guess_tinfo(&tif, ea) == GUESS_FUNC_FAILED )
    return sql_value_t();
  qstring out;
  if ( !tif.print(&out, nullptr, PRTYPE_1LINE) )
    return sql_value_t();
  return sql_value_t(qs(out));
}

// idc.get_operand_value()
static bool get_operand_value(const insn_t &insn, int n, uint64 *out)
{
  const op_t &op = insn.ops[n];
  switch ( op.type )
  {
    case o_mem:
    case o_far:
    case o_near:
    case o_displ:
      *out = op.addr;
      return true;
    case o_reg:
      *out = op.reg;
      return true;
    case o_imm:
      *out = op.value;
      return true;
    case o_phrase:
      *out = op.phrase;
      return true;
    default:
      return false;
  }
}

// get_string_at(): the (C) string at the given address
static bool get_string_at(ea_t ea, std::string *out)
{
  if ( !is_mapped(ea) )
    return false;
  int32 strtype = STRTYPE_C;
  size_t len;
  flags64_t fl = get_flags(ea);
  if ( is_strlit(fl) )
  {
    strtype = (int32)get_str_type(ea);
    len = get_item_size(ea);
  }
  else
  {
    len = get_max_strlit_length(ea, strtype, ALOPT_IGNHEADS);
  }
  qstring buf;
  if ( get_strlit_contents(&buf, ea, len, strtype) < 0 )
    return false;
  *out = qs(buf);
  return true;
}

// Ripped out from REgoogle: filter for certain constants/immediate values
static bool constant_filter(uint64 value)
{
  // no small values
  if ( value < 0x1000 )
    return false;

  if ( (value & 0xFFFFFF00) == 0xFFFFFF00
    || (value & 0xFFFF00) == 0xFFFF00
    || (value & 0xFFFFFFFFFFFFFF00ull) == 0xFFFFFFFFFFFFFF00ull
    || (value & 0xFFFFFFFFFFFF00ull) == 0xFFFFFFFFFFFF00ull )
  {
    return false;
  }

  // no single bits sets - mostly defines / flags
  for ( int i = 0; i < 64; ++i )
    if ( value == (1ull << i) )
      return false;

  return true;
}

static size_t utf8_len(const std::string &s)
{
  size_t n = 0;
  for ( unsigned char c : s )
    if ( (c & 0xC0) != 0x80 )
      ++n;
  return n;
}

static std::string json_str_list(const std::vector<std::string> &v)
{
  std::string out = "[";
  for ( size_t i = 0; i < v.size(); ++i )
  {
    if ( i > 0 )
      out += ", ";
    out += json_quote(v[i]);
  }
  return out + "]";
}

//------------------------------------------------------------------------------
// Hex-Rays
//------------------------------------------------------------------------------
static int g_hexrays_state = -1;

bool hexrays_ready()
{
  if ( g_hexrays_state == 1 )
    return true;
  if ( g_hexrays_state == 0 )
    return false;
  if ( init_hexrays_plugin() )
  {
    g_hexrays_state = 1;
    return true;
  }
  // try loading the decompiler plugin: the one specified by the user or the
  // local decompilers. Not the cloud decompiler of IDA Free (hexcx64): it
  // gives plugins no access to the decompiler API, so in IDA Free only the
  // assembly is exported (GhidraDec and Claude-Rays Decompiler give the
  // pseudo-code diffs instead).
  std::vector<std::string> plugins;
  std::string user = env_str("DIAPHORA_DECOMPILER_PLUGIN");
  if ( !user.empty() )
    plugins.push_back(user);
  // only the ones installed: load_plugin() prints "Plugin ... not found" for
  // the others
#if defined(__NT__)
  const char *ext = ".dll";
#elif defined(__MAC__)
  const char *ext = ".dylib";
#else
  const char *ext = ".so";
#endif
  const std::string dirs[] = { idadir(PLG_SUBDIR), std::string(get_user_idadir()) + "/" PLG_SUBDIR };
  for ( const char *p : { "hexrays", "hexx64" } )
    for ( const auto &dir : dirs )
      if ( file_exists(dir + "/" + p + ext) )
      {
        plugins.push_back(p);
        break;
      }
  for ( const auto &p : plugins )
  {
    if ( load_plugin(p.c_str()) == nullptr )
    {
      log("The decompiler plugin '%s' could not be loaded.", p.c_str());
      continue;
    }
    if ( init_hexrays_plugin() )
    {
      log("Using the decompiler plugin '%s'", p.c_str());
      g_hexrays_state = 1;
      return true;
    }
    log("The decompiler plugin '%s' is loaded but its API is not available (IDA Free's cloud decompiler "
        "offers none to plugins).", p.c_str());
  }
  log("The Hex-Rays decompiler API is not available, pseudo-code will not be exported.");
  g_hexrays_state = 0;
  return false;
}

void hexrays_term()
{
  if ( g_hexrays_state == 1 && hexdsp != nullptr )
    term_hexrays_plugin();
  g_hexrays_state = -1;
}

// names of the microcode instructions (dir(ida_hexrays) "m_*" entries)
static std::vector<std::string> get_microcode_instructions()
{
  static const char *const names[] =
  {
    "nop", "stx", "ldx", "ldc", "mov", "neg", "lnot", "bnot", "xds", "xdu", "low",
    "high", "add", "sub", "mul", "udiv", "sdiv", "umod", "smod", "or", "and", "xor",
    "shl", "shr", "sar", "cfadd", "ofadd", "cfshl", "cfshr", "sets", "seto", "setp",
    "setnz", "setz", "setae", "setb", "seta", "setbe", "setg", "setge", "setl",
    "setle", "jcnd", "jnz", "jz", "jae", "jb", "ja", "jbe", "jg", "jge", "jl", "jle",
    "jtbl", "ijmp", "goto", "call", "icall", "ret", "push", "pop", "und", "ext",
    "f2i", "f2u", "i2f", "u2f", "f2f", "fneg", "fadd", "fsub", "fmul", "fdiv",
  };
  std::vector<std::string> out(std::begin(names), std::end(names));
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

// Converts microcode output to an array of strings (CPrinter_t)
struct lines_printer_t : public vd_printer_t
{
  std::vector<std::string> lines;
  AS_PRINTF(3, 4) int idaapi print(int indent, const char *format, ...) override
  {
    qnotused(indent);
    va_list va;
    va_start(va, format);
    qstring s;
    s.vsprnt(format, va);
    va_end(va);
    for ( const auto &l : split(qs(s), '\n') )
      lines.push_back(l);
    return int(s.length());
  }
};

// CAstVisitor: product of primes of every ctree item opcode
struct ast_visitor_t : public ctree_visitor_t
{
  const std::vector<uint32> &primes;
  bignum_t primes_hash;
  ast_visitor_t(const std::vector<uint32> &p) : ctree_visitor_t(CV_FAST), primes(p), primes_hash(1) {}
  void add(int op)
  {
    if ( op >= 0 && size_t(op) < primes.size() )
      primes_hash.mul(primes[op]);
  }
  int idaapi visit_expr(cexpr_t *e) override { add(e->op); return 0; }
  int idaapi visit_insn(cinsn_t *i) override { add(i->op); return 0; }
};

// remove colors, trailing spaces and the basic block numbers from a line
static void get_plain_microcode_line(const std::string &color_line, std::string *plain, sql_value_t *mnem)
{
  qstring q;
  tag_remove(&q, color_line.c_str());
  std::string plain_line = strip(qs(q), " ");
  *mnem = sql_value_t();
  std::vector<std::string> tokens = split(plain_line, ' ');
  for ( size_t k = 1; k < tokens.size(); ++k )
  {
    if ( !is_digits(tokens[k]) )
    {
      *mnem = sql_value_t(tokens[k]);
      size_t pos = plain_line.find(tokens[k]);
      plain_line = plain_line.substr(pos);
      break;
    }
  }
  *plain = plain_line;
}

static void get_microcode(bindiff_t::impl_t &impl, func_t *pfn, bindiff_t::impl_t::decomp_t *d)
{
  hexrays_failure_t hf;
  mlist_t ml;
  decomp_ranges_t dcr(pfn->start_ea);
  mba_t *mba = gen_microcode(dcr, &hf, &ml, DECOMP_NO_WAIT, MMAT_GENERATED);
  if ( mba == nullptr )
    return;

  lines_printer_t vp;
  mba->print(vp);

  // get_microcode_bblocks()
  mba->build_graph();
  int total = mba->qty;
  for ( int i = 1; i < total; ++i )
  {
    mblock_t *block = mba->get_mblock(i);
    if ( block->type == BLT_STOP )
      continue;

    qstring src;
    qstring_printer_t bp(nullptr, src, true);
    block->print(bp);

    microcode_block_t mb;
    mb.serial = i;
    mb.start = block->start;
    mb.end = block->end;
    for ( const auto &raw : splitlines(qs(src)) )
    {
      microcode_line_t ml_line;
      std::string color_line = strip(strip(raw, "\n"), " ");
      size_t pos = color_line.find(';');
      if ( pos != std::string::npos )
      {
        qstring cq;
        tag_remove(&cq, color_line.substr(pos + 1).c_str());
        std::string comments = strip(qs(cq), " ");
        ml_line.comments = sql_value_t(comments);
        uint64 line_ea;
        int64 tmp;
        if ( parse_int64(split(comments, ' ')[0], 16, &tmp) )
        {
          line_ea = (uint64)tmp;
          ml_line.address = valid_prop_u(line_ea);
        }
        color_line = color_line.substr(0, pos);
      }
      get_plain_microcode_line(color_line, &ml_line.line, &ml_line.mnemonic);
      ml_line.color_line = color_line;
      mb.lines.push_back(std::move(ml_line));
    }
    d->microcode_bblocks.push_back(std::move(mb));
  }

  for ( const auto &mb : d->microcode_bblocks )
  {
    mblock_t *block = mba->get_mblock(mb.serial);
    std::vector<int> &succs = d->microcode_bbrelations[mb.serial];
    for ( int s : block->succset )
      succs.push_back(s);
    if ( succs.empty() )
      d->microcode_bbrelations.erase(mb.serial);
  }

  // the flat list of microcode lines
  d->microcode.clear();
  for ( const auto &raw : vp.lines )
  {
    qstring q;
    tag_remove(&q, raw.c_str());
    std::string line = strip(qs(q), "\n");
    size_t pos = line.find(';');
    if ( pos != std::string::npos )
      line.resize(pos);
    // tokens = re.split(r"\W+", line)
    int tokens = 0;
    bool in_word = false;
    for ( unsigned char c : line )
    {
      bool w = qisalnum(c) || c == '_' || c >= 0x80;
      if ( w && !in_word )
        ++tokens;
      in_word = w;
    }
    if ( tokens > 2 )
      d->microcode.push_back(strip(line, " "));
  }
  d->have_microcode = true;
  delete mba;
  qnotused(impl);
}

bool bindiff_t::decompile_and_get(ea_t ea, std::string *proto)
{
  if ( !impl->decompiler_available || is_spec_ea(ea) )
    return false;
  ensure_export_state(*impl);

  // Workaround for "max non-trivial tinfo_t count has been reached"
  if ( config::DIAPHORA_WORKAROUND_MAX_TINFO_T && impl->funcs_cache.size() % 10000 == 0 && hexrays_ready() )
    clear_cached_cfuncs();

  if ( !hexrays_ready() )
  {
    impl->decompiler_available = false;
    return false;
  }

  func_t *f = get_func(ea);
  if ( f == nullptr )
    return false;

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile_function(f->start_ea, &hf, DECOMP_NO_WAIT);
  if ( cfunc == nullptr )
    return false;

  impl_t::decomp_t &d = impl->decomp[ea];
  d = impl_t::decomp_t();

  ast_visitor_t visitor(impl->ast_primes);
  visitor.apply_to(&cfunc->body, nullptr);
  d.pseudo_hash = visitor.primes_hash;

  user_cmts_t *cmts = restore_user_cmts(cfunc->entry_ea);
  if ( cmts != nullptr )
  {
    ea_t base = get_imagebase();
    for ( auto p = user_cmts_begin(cmts); p != user_cmts_end(cmts); p = user_cmts_next(p) )
    {
      const treeloc_t &tl = user_cmts_first(p);
      const citem_cmt_t &cmt = user_cmts_second(p);
      d.pseudo_comments[int64(tl.ea - base)] = { cmt.c_str(), int(tl.itp) };
    }
    user_cmts_free(cmts);
  }

  const strvec_t &sv = cfunc->get_pseudocode();
  bool first = true;
  for ( const auto &sline : sv )
  {
    qstring q;
    tag_remove(&q, sline.line);
    std::string line = qs(q);
    if ( starts_with(line, "//") )
      continue;
    if ( first )
    {
      *proto = line;
      first = false;
    }
    else
    {
      d.pseudo.push_back(line);
    }
  }
  d.ok = true;

  if ( export_microcode )
    get_microcode(*impl, f, &d);
  return !first;
}

//------------------------------------------------------------------------------
// KOKA hash (jkutils/graph_hashes.py)
//------------------------------------------------------------------------------
static const int NODE_ENTRY = 2;
static const int NODE_EXIT = 3;
static const int NODE_NORMAL = 5;
static const int EDGE_IN_CONDITIONAL = 7;
static const int EDGE_OUT_CONDITIONAL = 11;
static const int FEATURE_LOOP = 19;
static const int FEATURE_CALL = 23;
static const int FEATURE_DATA_REFS = 29;
static const int FEATURE_CALL_REF = 31;
static const int FEATURE_STRONGLY_CONNECTED = 37;
static const int FEATURE_FUNC_NO_RET = 41;
static const int FEATURE_FUNC_LIB = 43;
static const int FEATURE_FUNC_THUNK = 47;

static std::string koka_hash(func_t *func, qflow_chart_t &flow)
{
  bignum_t hash(1);
  ograph_t bb_relations;
  std::vector<ea_t> refs;

  for ( int i = 0; i < flow.size(); ++i )
  {
    const qbasic_block_t &block = flow.blocks[i];
    ea_t block_ea = block.start_ea;
    if ( block.end_ea == 0 )
      continue;

    int nsucc = flow.nsucc(i);
    int npred = flow.npred(i);

    // get_node_value
    uint64 node = 1;
    if ( npred == 0 )
      node *= NODE_ENTRY;
    if ( nsucc == 0 )
      node *= NODE_EXIT;
    node *= NODE_NORMAL;
    hash.mul(node);

    // get_edges_value
    for ( int k = 0; k < nsucc; ++k )
      hash.mul(EDGE_OUT_CONDITIONAL);
    for ( int k = 0; k < npred; ++k )
      hash.mul(EDGE_IN_CONDITIONAL);

    // ...and each instruction on each basic block
    for_each_head(block.start_ea, block.end_ea, [&](ea_t ea)
    {
      insn_t insn;
      decode_insn(&insn, ea);
      if ( is_call_insn(insn) )
        hash.mul(FEATURE_CALL);

      data_refs_from(ea, &refs);
      if ( !refs.empty() )
        hash.mul(FEATURE_DATA_REFS);

      code_refs_from(ea, false, &refs);
      for ( ea_t xref : refs )
      {
        func_t *tmp = get_func(xref);
        if ( tmp == nullptr || tmp->start_ea != func->start_ea )
          hash.mul(FEATURE_CALL_REF);
      }

      // Remember the relationships
      std::vector<gnode_t> &succs = bb_relations.at(block_ea);
      succs.clear();
      for ( int k = 0; k < nsucc; ++k )
        succs.push_back(flow.blocks[flow.succ(i, k)].start_ea);
      for ( int k = 0; k < npred; ++k )
        bb_relations.at(flow.blocks[flow.pred(i, k)].start_ea).push_back(block.start_ea);
    });
  }

  // Calculate the strongly connected components
  std::vector<component_t> strongly_connected = strongly_connected_components(bb_relations);
  for ( const auto &sc : strongly_connected )
  {
    if ( sc.size() > 1 )
    {
      hash.mul(FEATURE_LOOP);
    }
    else
    {
      const std::vector<gnode_t> *rel = bb_relations.find(sc[0]);
      if ( rel != nullptr && std::find(rel->begin(), rel->end(), sc[0]) != rel->end() )
        hash.mul(FEATURE_LOOP);
    }
  }
  for ( size_t k = 0; k < strongly_connected.size(); ++k )
    hash.mul(FEATURE_STRONGLY_CONNECTED);

  uint64 flags = func->flags;
  if ( (flags & FUNC_NORET) != 0 )
    hash.mul(FEATURE_FUNC_NO_RET);
  if ( (flags & FUNC_LIB) != 0 )
    hash.mul(FEATURE_FUNC_LIB);
  if ( (flags & FUNC_THUNK) != 0 )
    hash.mul(FEATURE_FUNC_THUNK);

  return hash.str();
}

//------------------------------------------------------------------------------
// read_function
//------------------------------------------------------------------------------
namespace
{
struct accum_t
{
  int64 nodes = 0;
  int64 edges = 0;
  int64 instructions = 0;
  int64 size = 0;
  int64 indegree = 0;
  int64 outdegree = 0;
  uint64 bytes_sum = 0;
  bignum_t mnemonics_spp{ 1 };
  std::string bytes_hash;       // concatenated instruction bytes
  std::string function_hash;    // concatenated item bytes
  std::vector<std::string> mnems;
  std::set<std::string> names;
  // block rva -> list of [rva, text] lines (python dict order)
  std::vector<std::pair<int64, std::vector<std::pair<int64, std::string>>>> assembly;
  std::unordered_map<int64, size_t> assembly_idx;
  std::vector<std::pair<int64, std::vector<instruction_data_t>>> basic_blocks_data;
  ograph_t bb_relations;
  std::unordered_map<int64, int64> bb_topo_num;
  std::vector<std::vector<gnode_t>> bb_topological;
  std::vector<std::string> switches;
  std::unordered_map<int64, std::pair<int64, int64>> bb_degree;
  std::vector<std::pair<int64, int64>> bb_edges;
  std::vector<constant_t> constants;
  std::vector<ea_t> callees;
  std::vector<ea_t> callers;
};

void add_constant_num(std::vector<constant_t> &c, uint64 v)
{
  constant_t k;
  k.num = v;
  c.push_back(k);
}

void add_constant_str(std::vector<constant_t> &c, const std::string &s)
{
  for ( const auto &x : c )
    if ( x.is_str && x.str == s )
      return;
  constant_t k;
  k.is_str = true;
  k.str = s;
  c.push_back(k);
}
} // namespace

void ensure_export_state(bindiff_t::impl_t &impl)
{
  if ( impl.export_state_ready )
    return;
  impl.primes = primes_below(2048 * 2048);
  impl.ast_primes = primes_below(4096);
  // dict(Names())
  impl.names.clear();
  size_t n = get_nlist_size();
  for ( size_t i = 0; i < n; ++i )
    impl.names[get_nlist_ea(i)] = get_nlist_name(i);
  impl.cpu_ins_list = get_cpu_instruction_list();
  impl.cpu_ins_idx.clear();
  for ( size_t i = 0; i < impl.cpu_ins_list.size(); ++i )
    impl.cpu_ins_idx.emplace(impl.cpu_ins_list[i], i);
  impl.microcode_ins_list = get_microcode_instructions();
  impl.microcode_ins_idx.clear();
  for ( size_t i = 0; i < impl.microcode_ins_list.size(); ++i )
    impl.microcode_ins_idx.emplace(impl.microcode_ins_list[i], i);
  impl.export_state_ready = true;
}

std::unique_ptr<func_props_t> bindiff_t::read_function(ea_t ea)
{
  // lazily initialize the state required to export
  ensure_export_state(*impl);

  // get_function_names(): demangled or true name, true name, demangled
  qstring qtrue_name;
  get_func_name(&qtrue_name, ea);
  std::string true_name = qs(qtrue_name);
  qstring qdemangled;
  // python passes INF_SHORT_DN (the constant itself) as the disable mask
  demangle_name(&qdemangled, true_name.c_str(), INF_SHORT_DEMNAMES);
  std::string name = !qdemangled.empty() ? qs(qdemangled) : true_name;

  ea_t f = ea;
  func_t *func = get_func(f);
  if ( func == nullptr )
  {
    log("Cannot get a function object for 0x%llx", (unsigned long long)f);
    return nullptr;
  }

  // should_skip_function()
  uint64 fflags = func->flags;
  if ( !ida_subs )
  {
    if ( starts_with(name, "sub_") || starts_with(name, "j_") || starts_with(name, "unknown") || starts_with(name, "nullsub_") )
    {
      debug_log("Skipping function '%s'", name.c_str());
      return nullptr;
    }
    if ( (fflags & FUNC_LIB) != 0 )
    {
      debug_log("Skipping library function '%s'", name.c_str());
      return nullptr;
    }
  }
  if ( exclude_library_thunk )
  {
    if ( (fflags & FUNC_LIB) != 0 || (fflags & FUNC_THUNK) != 0 )
    {
      debug_log("Skipping thunk function '%s'", name.c_str());
      return nullptr;
    }
    if ( starts_with(name, "nullsub_") )
    {
      debug_log("Skipping nullsub function '%s'", name.c_str());
      return nullptr;
    }
  }

  // initialize_function_data()
  double export_start = monotonic();
  qflow_chart_t flow("", func, BADADDR, BADADDR, 0);
  ea_t image_base = get_imagebase();
  accum_t acc;
  std::vector<ea_t> refs;
  code_refs_to(f, true, &refs);
  acc.indegree = (int64)refs.size();

  // extract_function_callers(): code references and data references to f
  {
    std::vector<ea_t> all;
    code_refs_to(f, false, &refs);
    all = refs;
    data_refs_to(f, &refs);
    all.insert(all.end(), refs.begin(), refs.end());
    for ( ea_t caller : all )
    {
      func_t *cf = get_func(caller);
      if ( cf != nullptr && !contains(acc.callers, cf->start_ea) )
        acc.callers.push_back(cf->start_ea);
    }
  }

  ea_t current_head = BADADDR;
  std::vector<ea_t> drefs;

  // Process all basic blocks
  for ( int bi = 0; bi < flow.size(); ++bi )
  {
    const qbasic_block_t &block = flow.blocks[bi];
    if ( block.end_ea == 0 || block.end_ea == BADADDR )
    {
      msg("0x%08llx: Skipping bad basic block\n", (unsigned long long)f);
      continue;
    }

    // process_basic_block()
    acc.nodes += 1;
    std::vector<instruction_data_t> instructions_data;
    int64 block_ea = int64(block.start_ea - image_base);
    int64 idx = (int64)acc.bb_topological.size();
    acc.bb_topological.emplace_back();
    acc.bb_topo_num[block_ea] = idx;

    current_head = BADADDR;
    for_each_head(block.start_ea, block.end_ea, [&](ea_t head)
    {
      current_head = head;
      insn_t ins;
      decode_insn(&ins, head);

      // Extract constants from instruction
      data_refs_from(head, &drefs);
      for ( int n = 0; n < UA_MAXOP; ++n )
      {
        const op_t &op = ins.ops[n];
        if ( op.type == o_imm )
        {
          if ( !contains(drefs, ea_t(op.value)) && constant_filter(op.value) )
            add_constant_num(acc.constants, op.value);
        }
        else if ( op.type == o_displ )
        {
          if ( constant_filter(op.addr) )
            add_constant_num(acc.constants, op.addr);
        }
        for ( ea_t dref : drefs )
        {
          if ( get_func(dref) == nullptr )
          {
            std::string s;
            if ( get_string_at(dref, &s) )
              add_constant_str(acc.constants, s);
          }
        }
      }

      // process_instruction()
      qstring qmnem;
      print_insn_mnem(&qmnem, head);
      std::string mnem = qs(qmnem);
      qstring qdis;
      generate_disasm_line(&qdis, head, 0);
      tag_remove(&qdis);
      std::string disasm = qs(qdis);
      int64 inst_size = (int64)get_item_size(head);

      // Calculate mnemonics SPP
      uint64 mnemonics_spp_mult = 1;
      auto pm = impl->cpu_ins_idx.find(mnem);
      if ( pm != impl->cpu_ins_idx.end() )
        mnemonics_spp_mult = prime_at(impl->primes, (int64)pm->second);

      // Add to assembly
      int64 head_rva = int64(head - image_base);
      {
        auto pa = acc.assembly_idx.find(block_ea);
        if ( pa != acc.assembly_idx.end() )
        {
          acc.assembly[pa->second].second.emplace_back(head_rva, disasm);
        }
        else
        {
          acc.assembly_idx[block_ea] = acc.assembly.size();
          acc.assembly.emplace_back();
          acc.assembly.back().first = block_ea;
          auto &lines = acc.assembly.back().second;
          if ( acc.nodes != 1 )
            lines.emplace_back(head_rva, strfmt("loc_%llx:", (unsigned long long)head));
          lines.emplace_back(head_rva, disasm);
        }
      }

      // Get instruction bytes
      size_t decoded_size = ins.size;
      std::string curr_bytes(decoded_size, '\0');
      ssize_t got = decoded_size > 0 ? get_bytes(&curr_bytes[0], decoded_size, head, GMB_READALL) : 0;
      if ( got != (ssize_t)decoded_size )
      {
        log("Failed to read %d bytes at [%08llx]", int(decoded_size), (unsigned long long)head);
        return;
      }
      uint64 bytes_sum = 0;
      for ( unsigned char c : curr_bytes )
        bytes_sum += c;
      std::string function_hash_bytes(size_t(inst_size), '\0');
      if ( inst_size > 0 )
      {
        ssize_t got2 = get_bytes(&function_hash_bytes[0], size_t(inst_size), head, GMB_READALL);
        if ( got2 < 0 )
          function_hash_bytes.clear();
        else
          function_hash_bytes.resize(size_t(got2));
      }
      code_refs_from(head, false, &refs);
      int64 outdegree_inc = (int64)refs.size();

      // Extract operand value and name
      uint64 op_value = 0;
      bool has_op = get_operand_value(ins, 1, &op_value);
      if ( !has_op )
        has_op = get_operand_value(ins, 0, &op_value);

      sql_value_t tmp_name;
      std::string name_to_add;
      if ( has_op && op_value != BADADDR )
      {
        auto pn = impl->names.find(ea_t(op_value));
        if ( pn != impl->names.end() )
        {
          std::string tn = pn->second;
          qstring dn;
          demangle_name(&dn, tn.c_str(), INF_SHORT_DEMNAMES);
          if ( !dn.empty() )
          {
            tn = qs(dn);
            size_t pos = tn.find('(');
            if ( pos != std::string::npos )
              tn.resize(pos);
          }
          tmp_name = sql_value_t(tn);
          if ( !starts_with(tn, "sub_") && !starts_with(tn, "nullsub_") )
            name_to_add = tn;
        }
      }

      // Calculate callees
      std::vector<ea_t> callees_found;
      for ( ea_t callee : refs )
      {
        func_t *cf = get_func(callee);
        if ( cf != nullptr && cf->start_ea != func->start_ea )
          callees_found.push_back(cf->start_ea);
      }

      // Get type from references
      const std::vector<ea_t> &type_refs = refs.empty() ? drefs : refs;
      sql_value_t tmp_type;
      for ( ea_t ref : type_refs )
      {
        auto pn = impl->names.find(ref);
        if ( pn != impl->names.end() )
        {
          tmp_name = sql_value_t(pn->second);
          tmp_type = idc_get_type(ref);
        }
      }

      // Get instruction comments
      sql_value_t ins_cmt1, ins_cmt2;
      qstring cmt;
      if ( get_cmt(&cmt, head, false) >= 0 )
        ins_cmt1 = sql_value_t(qs(cmt));
      if ( get_cmt(&cmt, head, true) >= 0 )
        ins_cmt2 = sql_value_t(qs(cmt));

      // Extract forced operand names
      std::string operands_names = "[";
      bool first_op = true;
      for ( int n = 0; n < UA_MAXOP; ++n )
      {
        if ( is_forced_operand(head, n) )
        {
          qstring fo;
          get_forced_operand(&fo, head, n);
          if ( !first_op )
            operands_names += ", ";
          operands_names += "[" + std::to_string(n) + ", " + json_quote(qs(fo)) + "]";
          first_op = false;
        }
      }
      operands_names += "]";

      // Update accumulators
      acc.size += inst_size;
      acc.instructions += 1;
      acc.mnemonics_spp.mul(mnemonics_spp_mult);
      acc.bytes_hash += curr_bytes;
      acc.bytes_sum += bytes_sum;
      acc.function_hash += function_hash_bytes;
      acc.outdegree += outdegree_inc;
      acc.mnems.push_back(mnem);
      if ( !name_to_add.empty() )
        acc.names.insert(name_to_add);
      for ( ea_t c : callees_found )
        if ( !contains(acc.callees, c) )
          acc.callees.push_back(c);

      instruction_data_t idata;
      idata.rva = head_rva;
      idata.mnem = mnem;
      idata.disasm = disasm;
      idata.cmt1 = ins_cmt1;
      idata.cmt2 = ins_cmt2;
      idata.operand_names = operands_names;
      idata.name = tmp_name;
      idata.type = tmp_type;
      instructions_data.push_back(std::move(idata));

      // extract_function_switches()
      switch_info_t si;
      if ( get_switch_info(&si, head) > 0 )
      {
        uint64 switch_cases = si.get_jtable_size();
        casevec_t cases;
        eavec_t targets;
        if ( calc_switch_cases(&cases, &targets, head, si) )
        {
          std::set<int64> values;
          for ( const auto &cv : cases )
            for ( sval_t v : cv )
              values.insert(v);
          std::string sw = "[" + std::to_string(switch_cases) + ", [";
          bool firstv = true;
          for ( int64 v : values )
          {
            if ( !firstv )
              sw += ", ";
            sw += std::to_string(v);
            firstv = false;
          }
          sw += "]]";
          acc.switches.push_back(sw);
        }
      }
    });

    // Store basic block data
    acc.basic_blocks_data.emplace_back(block_ea, std::move(instructions_data));
    acc.bb_relations.at(block_ea).clear();
    if ( acc.bb_degree.find(block_ea) == acc.bb_degree.end() )
      acc.bb_degree[block_ea] = { 0, 0 };

    // Process successor blocks
    for ( int k = 0; k < flow.nsucc(bi); ++k )
    {
      const qbasic_block_t &succ = flow.blocks[flow.succ(bi, k)];
      if ( succ.end_ea == 0 )
        continue;
      int64 succ_base = int64(succ.start_ea - image_base);
      acc.bb_relations.at(block_ea).push_back(succ_base);
      acc.bb_degree[block_ea].second += 1;
      acc.bb_edges.emplace_back(block_ea, succ_base);
      if ( acc.bb_degree.find(succ_base) == acc.bb_degree.end() )
        acc.bb_degree[succ_base] = { 0, 0 };
      acc.bb_degree[succ_base].first += 1;
      acc.edges += 1;
      acc.indegree += 1;
    }

    // Process predecessor blocks
    for ( int k = 0; k < flow.npred(bi); ++k )
    {
      const qbasic_block_t &pred = flow.blocks[flow.pred(bi, k)];
      if ( pred.end_ea == 0 )
        continue;
      acc.bb_relations.at(int64(pred.start_ea - image_base)).push_back(block_ea);
      acc.edges += 1;
      acc.outdegree += 1;
    }
  }

  // build_topological_relations()
  for ( int bi = 0; bi < flow.size(); ++bi )
  {
    const qbasic_block_t &block = flow.blocks[bi];
    if ( block.end_ea == 0 )
      continue;
    int64 block_ea = int64(block.start_ea - image_base);
    auto pb = acc.bb_topo_num.find(block_ea);
    if ( pb == acc.bb_topo_num.end() )
      continue;
    for ( int k = 0; k < flow.nsucc(bi); ++k )
    {
      const qbasic_block_t &succ = flow.blocks[flow.succ(bi, k)];
      if ( succ.end_ea == 0 )
        continue;
      auto ps = acc.bb_topo_num.find(int64(succ.start_ea - image_base));
      if ( ps != acc.bb_topo_num.end() )
        acc.bb_topological[size_t(pb->second)].push_back(ps->second);
    }
  }

  //----------------------------------------------------------------------------
  // extract_all_features()
  auto props = std::make_unique<func_props_t>();
  func_props_t &p = *props;

  // topological information
  ograph_t topo_graph;
  for ( size_t k = 0; k < acc.bb_topological.size(); ++k )
    topo_graph.at((gnode_t)k) = acc.bb_topological[k];
  std::vector<component_t> strongly_connected = strongly_connected_components(acc.bb_relations);
  std::vector<component_t> bb_topological_sorted = robust_topological_sort(topo_graph);
  std::string bb_topological_json = components_to_json(bb_topological_sorted);
  bignum_t strongly_connected_spp(1);
  for ( const auto &item : strongly_connected )
  {
    if ( item.size() > 1 )
      strongly_connected_spp.mul(prime_at(impl->primes, (int64)item.size()));
  }
  int64 loops = 0;
  for ( const auto &sc : strongly_connected )
  {
    if ( sc.size() > 1 )
    {
      ++loops;
    }
    else
    {
      const std::vector<gnode_t> *rel = acc.bb_relations.find(sc[0]);
      if ( rel != nullptr && std::find(rel->begin(), rel->end(), sc[0]) != rel->end() )
        ++loops;
    }
  }

  // assembly features: the entry point always first, then sorted by address
  {
    std::vector<int64> keys;
    for ( const auto &kv : acc.assembly )
      keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());
    int64 base = int64(f - image_base);
    auto pos = std::find(keys.begin(), keys.end(), base);
    if ( pos != keys.end() )
      keys.erase(pos);
    keys.insert(keys.begin(), base);
    std::vector<std::string> asm_lines;
    for ( int64 key : keys )
    {
      auto pa = acc.assembly_idx.find(key);
      if ( pa == acc.assembly_idx.end() )
        continue;
      for ( const auto &line : acc.assembly[pa->second].second )
      {
        p.assembly_addrs.push_back(line.first);
        asm_lines.push_back(line.second);
      }
    }
    p.asm_text = join(asm_lines, "\n");
  }
  p.clean_assembly = get_cmp_asm_lines(p.asm_text);

  // Calculate cyclomatic complexity and get function metadata
  p.cc = acc.edges - acc.nodes + 2;

  // guess_type(): the decompiler prototype when available
  impl->decomp.erase(f);
  p.proto = idc_guess_type(f);
  if ( use_decompiler )
  {
    try
    {
      std::string proto;
      if ( decompile_and_get(f, &proto) )
        p.proto = sql_value_t(proto);
    }
    catch ( const std::exception &e )
    {
      log("Cannot decompile 0x%llx: %s", (unsigned long long)f, e.what());
    }
  }
  p.proto2 = idc_get_type(f);
  bool prime_ok;
  uint32 prime = prime_at(impl->primes, p.cc, &prime_ok);
  if ( prime_ok )
  {
    p.prime = sql_value_t(std::to_string(prime));
  }
  else
  {
    log("Cyclomatic complexity too big: 0x%llx -> %lld", (unsigned long long)f, (long long)p.cc);
    p.prime = sql_value_t(int64(0));
  }

  // Get function comment and compute hashes
  qstring fcmt;
  get_func_cmt_ea(&fcmt, f, true);
  p.comment = sql_value_t(qs(fcmt));
  p.bytes_hash = md5_hex(acc.bytes_hash.data(), acc.bytes_hash.size());
  p.function_hash = md5_hex(acc.function_hash.data(), acc.function_hash.size());
  p.function_flags = fflags;

  // pseudo-code features
  auto pd = impl->decomp.find(f);
  impl_t::decomp_t *decomp = (pd != impl->decomp.end() && pd->second.ok) ? &pd->second : nullptr;
  if ( decomp != nullptr )
  {
    std::string pseudo = join(decomp->pseudo, "\n");
    p.pseudo = sql_value_t(pseudo);
    p.pseudo_lines = (int64)decomp->pseudo.size();
    std::vector<std::string> hashes = split(kfuzzy_hash_bytes(pseudo, config::FUZZY_HASHING_BLOCK_SIZE), ';');
    hashes.resize(3);
    p.pseudo_hash1 = hashes[0].empty() ? sql_value_t() : sql_value_t(hashes[0]);
    p.pseudo_hash2 = hashes[1].empty() ? sql_value_t() : sql_value_t(hashes[1]);
    p.pseudo_hash3 = hashes[2].empty() ? sql_value_t() : sql_value_t(hashes[2]);
    p.pseudocode_primes = sql_value_t(decomp->pseudo_hash.str());
    p.pseudo_comments = decomp->pseudo_comments;
  }

  // extract_microcode()
  p.microcode_spp = bignum_t(1);
  if ( export_microcode && decomp != nullptr && decomp->have_microcode )
  {
    p.microcode = sql_value_t(join(decomp->microcode, "\n"));
    std::vector<std::string> ret;
    std::string mnem;
    for ( const auto &line : decomp->microcode )
    {
      std::vector<std::string> tokens = split(line, ' ');
      for ( size_t k = 1; k < tokens.size(); ++k )
      {
        if ( !is_digits(tokens[k]) )
        {
          mnem = tokens[k];
          size_t pos = mnem.find('.');
          if ( pos != std::string::npos )
            mnem.resize(pos);
          break;
        }
      }
      if ( mnem.empty() )
        continue;
      size_t pos = line.find(mnem);
      ret.push_back(pos != std::string::npos ? line.substr(pos) : line);
      auto pm = impl->microcode_ins_idx.find(mnem);
      if ( pm != impl->microcode_ins_idx.end() )
        p.microcode_spp.mul(prime_at(impl->primes, (int64)pm->second));
      else
        log("Warning: Mnemonic '%s' not found in the list of microcode instructions!", mnem.c_str());
    }
    p.clean_microcode = sql_value_t(get_cmp_asm_lines(join(ret, "\n")));
    p.microcode_bblocks = decomp->microcode_bblocks;
    p.microcode_bbrelations = decomp->microcode_bbrelations;
  }

  if ( !p.pseudo.is_null() )
    p.clean_pseudo = sql_value_t(get_cmp_pseudo_lines(p.pseudo.s));

  // MD-Index
  p.md_index = sql_value_t(int64(0));
  if ( !bb_topological_json.empty() )
  {
    std::unordered_map<int64, size_t> bb_topo_order;
    for ( size_t i = 0; i < bb_topological_sorted.size(); ++i )
      for ( gnode_t bb : bb_topological_sorted[i] )
        bb_topo_order[bb] = i;
    const double rt2 = std::sqrt(2.0), rt3 = std::sqrt(3.0), rt5 = std::sqrt(5.0), rt7 = std::sqrt(7.0);
    double md_index = 0;
    for ( const auto &e : acc.bb_edges )
    {
      int64 src = e.first, dst = e.second;
      double z0 = double(bb_topo_order[acc.bb_topo_num[src]]);
      const auto &ds = acc.bb_degree[src];
      const auto &dd = acc.bb_degree[dst];
      double emb = z0 + ds.first * rt2 + ds.second * rt3 + dd.first * rt5 + dd.second * rt7;
      if ( emb > 0 )
        md_index += 1.0 / std::sqrt(emb);
    }
    if ( acc.bb_edges.empty() )
      p.md_index = sql_value_t("0");
    else
      p.md_index = sql_value_t(strfmt("%.17g", md_index));
  }

  // Calculate segment RVA and other hashes
  segment_t *seg = getseg(current_head);
  ea_t seg_start = seg != nullptr ? seg->start_ea : BADADDR;
  p.seg_rva = int64(current_head) - int64(seg_start);
  p.kgh_hash = koka_hash(func, flow);
  p.rva = int64(f - get_imagebase());

  // build_props_list()
  p.name = name;
  p.nodes = acc.nodes;
  p.edges = acc.edges;
  p.indegree = acc.indegree;
  p.outdegree = acc.outdegree;
  p.size = acc.size;
  p.instructions = acc.instructions;
  p.mnems = std::move(acc.mnems);
  p.names.assign(acc.names.begin(), acc.names.end());
  p.f = f;
  p.true_name = true_name;
  p.strongly_connected_size = (int64)strongly_connected.size();
  p.loops = loops;
  p.bb_topological = sql_value_t(bb_topological_json);
  p.strongly_connected_spp = strongly_connected_spp;
  p.mnemonics_spp = acc.mnemonics_spp;
  p.switches = "[" + join(acc.switches, ", ") + "]";
  p.bytes_sum = acc.bytes_sum;
  p.constants = std::move(acc.constants);
  p.export_time = float_repr(monotonic() - export_start);
  p.callers = std::move(acc.callers);
  p.callees = std::move(acc.callees);
  p.basic_blocks_data = std::move(acc.basic_blocks_data);
  p.bb_relations = std::move(acc.bb_relations);
  return props;
}

//------------------------------------------------------------------------------
// save_function
//------------------------------------------------------------------------------
void bindiff_t::save_function(func_props_t &p)
{
  sql_db_t &db = get_db();

  // Phase 1: insert the function row
  std::string constants_json = "[";
  for ( size_t i = 0; i < p.constants.size(); ++i )
  {
    if ( i > 0 )
      constants_json += ", ";
    constants_json += p.constants[i].json();
  }
  constants_json += "]";
  std::string addrs_json = "[";
  for ( size_t i = 0; i < p.assembly_addrs.size(); ++i )
  {
    if ( i > 0 )
      addrs_json += ", ";
    addrs_json += std::to_string(p.assembly_addrs[i]);
  }
  addrs_json += "]";

  sql_params_t params =
  {
    p.name, valid_prop(p.nodes), valid_prop(p.edges), valid_prop(p.indegree), valid_prop(p.outdegree),
    valid_prop(p.size), valid_prop(p.instructions), json_str_list(p.mnems), json_str_list(p.names),
    p.proto, valid_prop(p.cc), p.prime, valid_prop_u(p.f), p.comment, p.true_name, p.bytes_hash,
    p.pseudo, valid_prop(p.pseudo_lines), p.pseudo_hash1, p.pseudocode_primes, valid_prop_u(p.function_flags),
    p.asm_text, p.proto2, p.pseudo_hash2, p.pseudo_hash3, valid_prop(p.strongly_connected_size),
    valid_prop(p.loops), valid_prop(p.rva), p.bb_topological, valid_prop_big(p.strongly_connected_spp),
    p.clean_assembly, p.clean_pseudo, valid_prop_big(p.mnemonics_spp), p.switches, p.function_hash,
    valid_prop_u(p.bytes_sum), p.md_index, constants_json, valid_prop((int64)p.constants.size()),
    valid_prop(p.seg_rva), addrs_json, p.kgh_hash, sql_value_t(), sql_value_t(), p.microcode,
    p.clean_microcode, valid_prop_big(p.microcode_spp), p.export_time,
  };

  static const char *const sql_func = R"SQL(insert into main.functions (name, nodes, edges, indegree, outdegree, size,
                    instructions, mnemonics, names, prototype,
                    cyclomatic_complexity, primes_value, address,
                    comment, mangled_function, bytes_hash, pseudocode,
                    pseudocode_lines, pseudocode_hash1, pseudocode_primes,
                    function_flags, assembly, prototype2, pseudocode_hash2,
                    pseudocode_hash3, strongly_connected, loops, rva,
                    tarjan_topological_sort, strongly_connected_spp,
                    clean_assembly, clean_pseudo, mnemonics_spp, switches,
                    function_hash, bytes_sum, md_index, constants,
                    constants_count, segment_rva, assembly_addrs, kgh_hash,
                    source_file, userdata, microcode, clean_microcode,
                    microcode_spp, export_time)
                  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))SQL";
  try
  {
    db.execute(sql_func, params);
  }
  catch ( const std::exception &e )
  {
    log("Error handling props in save_function() for '%s': %s", p.name.c_str(), e.what());
    throw;
  }

  int64 func_id = db.last_insert_rowid();
  // Save a list of [ id, primes_value, pseudocode_primes ]
  impl->add_func_cache(p.f, func_id, p.prime, p.pseudocode_primes);

  // Phase 2: Save the callers and callees of the function
  {
    sql_stmt_t st(db, "insert into callgraph (func_id, address, type) values (?, ?, ?)");
    for ( ea_t caller : p.callers )
      st.run({ func_id, std::to_string(caller), "caller" });
    for ( ea_t callee : p.callees )
      st.run({ func_id, std::to_string(callee), "callee" });
  }

  // Phase 3: Insert the constants of the function
  {
    sql_stmt_t st(db, "insert into constants (func_id, constant) values (?, ?)");
    for ( const auto &c : p.constants )
    {
      if ( c.is_str )
      {
        if ( utf8_len(c.str) > 4 )
          st.run({ func_id, c.str });
      }
      else
      {
        st.run({ func_id, std::to_string(c.num) });
      }
    }
  }

  // Phase 4: Save the basic blocks relationships
  if ( function_summaries_only )
    return;

  // save_instructions_to_database()
  std::unordered_map<int64, int64> instructions_ids;
  {
    sql_stmt_t st(db, R"SQL(insert into main.instructions (address, mnemonic, disasm,
                      comment1, comment2, operand_names, name,
                      type, pseudocomment, pseudoitp, func_id,
                      asm_type)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'native'))SQL");
    for ( const auto &bb : p.basic_blocks_data )
    {
      for ( const auto &ins : bb.second )
      {
        sql_value_t pseudocomment, pseudoitp;
        auto pc = p.pseudo_comments.find(ins.rva);
        if ( pc != p.pseudo_comments.end() )
        {
          pseudocomment = sql_value_t(pc->second.first);
          pseudoitp = sql_value_t(int64(pc->second.second));
        }
        st.run({ ins.rva, ins.mnem, ins.disasm, ins.cmt1, ins.cmt2, ins.operand_names,
                 ins.name, ins.type, pseudocomment, pseudoitp, func_id });
        instructions_ids[ins.rva] = db.last_insert_rowid();
      }
    }
  }

  // insert_basic_blocks_to_database()
  {
    int64 num = 0;
    std::vector<std::pair<int64, int64>> bb_ids;   // key -> id, insertion order
    std::unordered_map<int64, int64> bb_ids_map;
    sql_stmt_t sel(db, "select id from basic_blocks where address = ?");
    sql_stmt_t ins_bb(db, "insert into main.basic_blocks (num, address, asm_type) values (?, ?, 'native')");
    sql_stmt_t ins_bbi(db, "insert into main.bb_instructions (basic_block_id, instruction_id) values (?, ?)");
    for ( const auto &bb : p.basic_blocks_data )
    {
      num += 1;
      std::string ins_ea = std::to_string(bb.first);
      int64 last_bb_id = 0;
      sel.bind({ ins_ea });
      sql_row_t row;
      if ( sel.fetch(&row) && !row[size_t(0)].is_null() )
      {
        last_bb_id = row[size_t(0)].to_int();
      }
      else
      {
        ins_bb.run({ num, ins_ea });
        last_bb_id = db.last_insert_rowid();
      }
      if ( bb_ids_map.find(bb.first) == bb_ids_map.end() )
        bb_ids.emplace_back(bb.first, last_bb_id);
      bb_ids_map[bb.first] = last_bb_id;

      for ( const auto &ins : bb.second )
        ins_bbi.run({ last_bb_id, instructions_ids[ins.rva] });
    }

    sql_stmt_t ins_rel(db, "insert into main.bb_relations (parent_id, child_id) values (?, ?)");
    for ( gnode_t key : p.bb_relations.order )
    {
      auto pk = bb_ids_map.find(key);
      if ( pk == bb_ids_map.end() )
        continue;
      for ( gnode_t child : p.bb_relations.adj.at(key) )
      {
        auto pc = bb_ids_map.find(child);
        if ( pc == bb_ids_map.end() )
          continue;
        ins_rel.run({ pk->second, pc->second });
      }
    }

    sql_stmt_t ins_fb(db, "insert into main.function_bblocks (function_id, basic_block_id, asm_type) values (?, ?, 'native')");
    for ( const auto &kv : bb_ids )
      ins_fb.run({ func_id, bb_ids_map[kv.first] });
  }

  // save_microcode_instructions()
  if ( !p.microcode_bblocks.empty() && !p.microcode_bbrelations.empty() )
  {
    sql_stmt_t ins_inst(db, R"SQL(insert into main.instructions (address, mnemonic, disasm, comment1,
                         pseudocomment, func_id, asm_type)
                values (?, ?, ?, ?, ?, ?, 'microcode'))SQL");
    sql_stmt_t ins_bb(db, "insert into main.basic_blocks (num, address, asm_type) values (?, ?, 'microcode')");
    sql_stmt_t ins_bbi(db, "insert into main.bb_instructions (basic_block_id, instruction_id) values (?, ?)");
    sql_stmt_t ins_rel(db, "insert into main.bb_relations (parent_id, child_id) values (?, ?)");
    sql_stmt_t ins_fb(db, "insert into main.function_bblocks (function_id, basic_block_id, asm_type) values (?, ?, 'microcode')");
    std::map<int, int64> block_ids;
    int64 num = 0;
    for ( auto &mb : p.microcode_bblocks )
    {
      ins_bb.run({ num, valid_prop_u(mb.start) });
      int64 bblock_id = db.last_insert_rowid();
      mb.bblock_id = bblock_id;
      block_ids[mb.serial] = bblock_id;
      ins_fb.run({ func_id, bblock_id });
      for ( const auto &line : mb.lines )
      {
        if ( line.mnemonic.is_null() )
          continue;
        ins_inst.run({ line.address, line.mnemonic, line.line, line.color_line, line.comments, func_id });
        ins_bbi.run({ bblock_id, db.last_insert_rowid() });
      }
      num += 1;
    }
    for ( const auto &rel : p.microcode_bbrelations )
    {
      auto pp = block_ids.find(rel.first);
      if ( pp == block_ids.end() )
        continue;
      for ( int child : rel.second )
      {
        auto pc = block_ids.find(child);
        if ( pc != block_ids.end() )
          ins_rel.run({ pp->second, pc->second });
      }
    }
  }
}

//------------------------------------------------------------------------------
// structures, type libraries and the program row
//------------------------------------------------------------------------------
static void export_structures(bindiff_t &bd)
{
  uint32 local_types = get_ordinal_limit(nullptr);
  if ( local_types == uint32(-1) || (local_types & 0x80000000) != 0 )
  {
    log("warning: get_ordinal_limit returned an invalid number (0x%x)!", local_types);
    return;
  }

  for ( uint32 ord = 1; ord < local_types; ++ord )
  {
    const char *tname = get_numbered_type_name(nullptr, ord);
    if ( tname == nullptr )
      continue;
    std::string name = tname;
    tinfo_t tif;
    std::string definition;
    if ( tif.get_numbered_type(nullptr, ord) )
    {
      qstring out;
      if ( tif.print(&out, name.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA) )
        definition = qs(out);
    }

    const char *type_name = "struct";
    if ( starts_with(definition, "enum") )
      type_name = "enum";
    else if ( starts_with(definition, "union") )
      type_name = "union";

    // IDA may return types with the form "__int128 unsigned", fix it
    if ( name.find(' ') != std::string::npos )
    {
      std::vector<std::string> names = split(name, ' ');
      name = names[0];
      if ( names.size() > 1 && names[1] == "unsigned" )
        name = "unsigned " + name;
    }

    bd.add_program_data(type_name, name, sql_value_t(definition));
  }
}

static void export_til(bindiff_t &bd)
{
  const til_t *ti = get_idati();
  if ( ti == nullptr )
    return;
  for ( int i = 0; i < ti->nbases; ++i )
  {
    const til_t *base = ti->base[i];
    if ( base != nullptr && base->name != nullptr )
      bd.add_program_data("til", base->name, sql_value_t());
  }
}

static void save_callgraph(bindiff_t &bd, const std::string &primes, const std::string &all_primes, const std::string &md5sum)
{
  std::string proc = inf_get_procname().c_str();
  // BADADDR is always 64 bits wide in IDA 9
  proc += "64";
  bd.get_db().execute("insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)",
                      { primes, all_primes, proc, md5sum });
}

//------------------------------------------------------------------------------
// export
//------------------------------------------------------------------------------
void bindiff_t::export_db()
{
  // the decompiler may be available now (e.g. a decompiler plugin loaded since)
  if ( g_hexrays_state == 0 )
    g_hexrays_state = -1;
  bool crashed_before = false;
  std::string crash_file = db_name + "-crash";
  if ( file_exists(crash_file) )
  {
    log("Resuming a previously crashed session...");
    crashed_before = true;
  }

  log("Creating crash file %s...", crash_file.c_str());
  write_text_file(crash_file, "");

  struct wait_box_t
  {
    wait_box_t() { show_wait_box("Exporting database"); }
    ~wait_box_t() { hide_wait_box(); }
  };

  bool cancelled = false;
  {
    wait_box_t wb;
    try
    {
      //------------------------------------------------------------------------
      // do_export()
      decimal28_t callgraph_primes;
      bool any_prime = false;
      std::vector<std::pair<std::string, int64>> callgraph_all_primes;
      std::unordered_map<std::string, size_t> all_primes_idx;
      auto add_prime = [&](const std::string &ret)
      {
        any_prime = true;
        callgraph_primes.mul(ret);
        auto p = all_primes_idx.find(ret);
        if ( p == all_primes_idx.end() )
        {
          all_primes_idx[ret] = callgraph_all_primes.size();
          callgraph_all_primes.emplace_back(ret, 1);
        }
        else
        {
          callgraph_all_primes[p->second].second++;
        }
      };

      log("Exporting range 0x%08llx - 0x%08llx", (unsigned long long)min_ea, (unsigned long long)max_ea);
      std::vector<ea_t> func_list;
      func_t *fn = get_func(min_ea);
      if ( fn == nullptr )
        fn = get_next_func(min_ea);
      while ( fn != nullptr && fn->start_ea < max_ea )
      {
        func_list.push_back(fn->start_ea);
        fn = get_next_func(fn->start_ea);
      }
      size_t total_funcs = func_list.size();
      double t = monotonic();

      int64 start_func = 0;
      if ( crashed_before )
      {
        sql_row_t row;
        if ( !get_db().query_one("select address from functions order by id desc limit 1", {}, &row) )
        {
          warning("Diaphora cannot resume the previous crashed session, the export process will start from scratch.");
          crashed_before = false;
        }
        else
        {
          start_func = row[size_t(0)].to_int();
          // recalculate_primes()
          for ( const auto &r : get_db().query("select primes_value from functions") )
            add_prime(r[size_t(0)].str());
        }
      }

      commit_and_start_transaction();

      impl->funcs_cache.clear();
      impl->funcs_cache_idx.clear();
      size_t i = 0;
      for ( ea_t func : func_list )
      {
        if ( user_cancelled() )
          throw cancelled_error();

        ++i;
        if ( (total_funcs >= 100 && i % (total_funcs / 100) == 0) || i == 1 )
        {
          if ( config::COMMIT_AFTER_EACH_GUI_UPDATE )
            commit_and_start_transaction();
          double elapsed = monotonic() - t;
          double remaining = (elapsed / i) * (total_funcs - i);
          int64 rs = (int64)remaining, es = (int64)elapsed;
          replace_wait_box("Exported %u function(s) out of %u total.\n"
                           "Elapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d",
                           unsigned(i), unsigned(total_funcs),
                           int(es / 3600), int((es / 60) % 60), int(es % 60),
                           int(rs / 3600), int((rs / 60) % 60), int(rs % 60));
        }

        if ( crashed_before )
        {
          int64 rva = int64(func - get_imagebase());
          if ( rva != start_func )
            continue;
          // When we get to the last function that was previously exported,
          // switch off the 'crash' flag and continue with the next row.
          crashed_before = false;
          continue;
        }

        std::unique_ptr<func_props_t> props = read_function(func);
        impl->decomp.clear();
        if ( !props )
          continue;

        add_prime(props->prime.str());
        save_function(*props);

        if ( total_funcs > (size_t)config::EXPORTING_FUNCTIONS_TO_COMMIT && i % (total_funcs / 10) == 0 )
          commit_and_start_transaction();
      }

      commit_and_start_transaction();
      uchar md5[16];
      std::string md5sum;
      if ( retrieve_input_file_md5(md5) )
      {
        static const char hexd[] = "0123456789abcdef";
        for ( int k = 0; k < 16; ++k )
        {
          md5sum += hexd[md5[k] >> 4];
          md5sum += hexd[md5[k] & 15];
        }
      }
      std::string all_primes_json = "{";
      for ( size_t k = 0; k < callgraph_all_primes.size(); ++k )
      {
        if ( k > 0 )
          all_primes_json += ", ";
        all_primes_json += json_quote(callgraph_all_primes[k].first) + ": " + std::to_string(callgraph_all_primes[k].second);
      }
      all_primes_json += "}";
      save_callgraph(*this, any_prime ? callgraph_primes.str() : "1", all_primes_json, md5sum);
      // where the binary was: GhidraDec decompiles it when this database is
      // the other version of a diff (not in the python version)
      char input_path[QMAXPATH];
      if ( get_input_file_path(input_path, sizeof(input_path)) > 0 )
        add_program_data("input_file", "path", sql_value_t(std::string(input_path)));
      export_structures(*this);
      try
      {
        export_til(*this);
      }
      catch ( const std::exception &e )
      {
        log("Error reading type libraries: %s", e.what());
      }

      if ( config::EXPORTING_COMPILATION_UNITS )
        save_compilation_units(*this, impl->funcs_cache);

      log_refresh("Creating indices...");
      create_indices();
    }
    catch ( const cancelled_error & )
    {
      cancelled = true;
      log("Cancelled.");
    }
    catch ( const std::exception &e )
    {
      log("Error: %s", e.what());
    }
  }

  commit();
  if ( cancelled )
  {
    // Aborted by the user: keep the crash file so the export can be resumed
    db_close();
    throw cancelled_error();
  }
  log("Removing crash file %s...", crash_file.c_str());
  remove_file_quiet(crash_file);

  get_db().try_exec("analyze");
  db_close();
}

} // namespace dph
