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

// Diaphora-ng - user interface: result choosers, diff viewers and
// graph viewers.
// Port of CIDAChooser, CHtmlViewer, CHtmlDiff, CDiffGraphViewer,
// CCallGraphViewer and the 'show_*' members of CIDABinDiff (diaphora_ida.py)
// and of extras/diaphora_local.py.
#include "ui.hpp"
#include "bindiff_impl.hpp"
#include "claude_diff.hpp"
#include "ghidra_diff.hpp"
#include "difflib.hpp"

#include <graph.hpp>
#include <registry.hpp>

namespace dph
{

//------------------------------------------------------------------------------
// current results
//------------------------------------------------------------------------------
static std::unique_ptr<bindiff_t> g_bindiff;

// Claude and GhidraDec diff pseudo-code: whether the open database is the new
// version, asked once per results (-1: not asked yet)
static int g_claude_a_is_new = -1;

bindiff_t *current_bindiff()
{
  return g_bindiff.get();
}

void set_current_bindiff(std::unique_ptr<bindiff_t> bd)
{
  if ( g_bindiff.get() != bd.get() )
  {
    close_choosers();
    g_claude_a_is_new = -1;
  }
  g_bindiff = std::move(bd);
}

void release_current_bindiff()
{
  close_choosers();
  g_bindiff.reset();
  g_claude_a_is_new = -1;
}

//------------------------------------------------------------------------------
// colors
//------------------------------------------------------------------------------
static int g_dark_mode = -1;

bool dark_mode()
{
  if ( g_dark_mode < 0 )
    g_dark_mode = reg_read_bool("diaphora_dark_mode", false) ? 1 : 0;
  return g_dark_mode == 1;
}

void toggle_dark_mode()
{
  g_dark_mode = dark_mode() ? 0 : 1;
  reg_write_bool("diaphora_dark_mode", g_dark_mode);
  msg("Diaphora-ng: %s colors enabled for the diff viewers.\n", g_dark_mode ? "dark" : "light");
}


// colors defined as white in the python version follow the theme here
static bgcolor_t theme_color(bgcolor_t c)
{
  return c == 0xFFFFFF ? DEFCOLOR : c;
}

//------------------------------------------------------------------------------
// colored text helpers
//------------------------------------------------------------------------------
static std::string sanitize(const std::string &s)
{
  std::string out;
  out.reserve(s.size());
  for ( unsigned char c : s )
    out += (c >= 1 && c <= 4) ? '?' : (char)c;
  return out;
}

static std::string expand_tabs(const std::string &s)
{
  std::string out;
  for ( char c : s )
  {
    if ( c == '\t' )
      out += "    ";
    else
      out += c;
  }
  return out;
}

static std::string col(const char *color, const std::string &text)
{
  if ( text.empty() )
    return text;
  std::string out;
  out += SCOLOR_ON;
  out += color;
  out += text;
  out += SCOLOR_OFF;
  out += color;
  return out;
}

static size_t visible_len(const std::string &s)
{
  size_t n = 0;
  for ( unsigned char c : s )
    if ( (c & 0xC0) != 0x80 )
      ++n;
  return n;
}

static bool is_word_char(char c)
{
  return qisalnum((uchar)c) || c == '_' || c == '$' || c == '@' || c == '?' || (uchar)c >= 0x80;
}

static bool is_number_token(const std::string &t)
{
  if ( t.empty() || !qisdigit((uchar)t[0]) )
    return false;
  return true;
}

// minimal assembly syntax highlighting (pygments' NasmLexer in the original)
static std::string color_asm(const std::string &line)
{
  std::string s = sanitize(line);
  size_t first = s.find_first_not_of(" \t");
  if ( first == std::string::npos )
    return s;
  std::string lead = s.substr(0, first);
  std::string body = s.substr(first);
  if ( body[0] == ';' )
    return lead + col(SCOLOR_AUTOCMT, body);
  if ( ends_with(body, ":") && body.find(' ') == std::string::npos )
    return lead + col(SCOLOR_CODNAME, body);
  if ( ends_with(body, " proc near") || ends_with(body, " endp") )
    return lead + col(SCOLOR_ASMDIR, body);

  std::string comment;
  size_t sc = body.find(';');
  if ( sc != std::string::npos )
  {
    comment = body.substr(sc);
    body.resize(sc);
  }
  std::string out = lead;
  size_t sp = body.find(' ');
  std::string mnem = body.substr(0, sp);
  out += col(SCOLOR_INSN, mnem);
  if ( sp != std::string::npos )
  {
    std::string ops = body.substr(sp);
    size_t i = 0;
    while ( i < ops.size() )
    {
      if ( is_word_char(ops[i]) )
      {
        size_t j = i;
        while ( j < ops.size() && is_word_char(ops[j]) )
          ++j;
        std::string tok = ops.substr(i, j - i);
        out += is_number_token(tok) ? col(SCOLOR_NUMBER, tok) : tok;
        i = j;
      }
      else
      {
        out += col(SCOLOR_SYMBOL, std::string(1, ops[i]));
        ++i;
      }
    }
  }
  if ( !comment.empty() )
    out += col(SCOLOR_AUTOCMT, comment);
  return out;
}

// minimal C syntax highlighting (pygments' CppLexer in the original)
static std::string color_c(const std::string &line)
{
  static const std::set<std::string> keywords =
  {
    "if", "else", "while", "for", "do", "return", "switch", "case", "break",
    "continue", "goto", "default", "sizeof", "struct", "union", "enum",
    "typedef", "const", "volatile", "unsigned", "signed", "int", "char",
    "short", "long", "float", "double", "void", "bool", "true", "false",
    "__int8", "__int16", "__int32", "__int64", "__int128", "_BYTE", "_WORD",
    "_DWORD", "_QWORD", "_OWORD", "_BOOL1", "_BOOL2", "_BOOL4", "_BOOL8",
    "__fastcall", "__cdecl", "__stdcall", "__thiscall", "__usercall",
    "__userpurge", "__noreturn", "static", "extern", "inline",
  };
  std::string s = sanitize(line);
  std::string out;
  size_t i = 0, n = s.size();
  while ( i < n )
  {
    char c = s[i];
    if ( c == '/' && i + 1 < n && s[i + 1] == '/' )
    {
      out += col(SCOLOR_AUTOCMT, s.substr(i));
      break;
    }
    if ( c == '"' || c == '\'' )
    {
      size_t j = i + 1;
      while ( j < n && s[j] != c )
      {
        if ( s[j] == '\\' )
          ++j;
        ++j;
      }
      j = std::min(j + 1, n);
      out += col(c == '"' ? SCOLOR_DSTR : SCOLOR_DCHAR, s.substr(i, j - i));
      i = j;
      continue;
    }
    if ( qisalpha((uchar)c) || c == '_' )
    {
      size_t j = i;
      while ( j < n && (qisalnum((uchar)s[j]) || s[j] == '_') )
        ++j;
      std::string tok = s.substr(i, j - i);
      out += keywords.count(tok) != 0 ? col(SCOLOR_KEYWORD, tok) : tok;
      i = j;
      continue;
    }
    if ( qisdigit((uchar)c) )
    {
      size_t j = i;
      while ( j < n && (qisalnum((uchar)s[j]) || s[j] == '.') )
        ++j;
      out += col(SCOLOR_DNUM, s.substr(i, j - i));
      i = j;
      continue;
    }
    out += c;
    ++i;
  }
  return out;
}

using colorizer_t = std::string (*)(const std::string &);

//------------------------------------------------------------------------------
// text viewers (CHtmlViewer)
//------------------------------------------------------------------------------
// A background behind some characters of a line (the <span class="diff_*">
// of the html diffs). IDA draws it through ui_get_lines_rendering_info, so
// it covers only those characters: a simpleline_t background would cover
// the whole width of the window, both sides of a side by side diff at once.
struct view_seg_t
{
  int cpx;                        // first character (codepoints, no color tags)
  int nchars;
  bgcolor_t bg;                   // 0xAABBGGRR, with alpha
};

struct view_line_t
{
  std::string text;               // may contain color tags
  bgcolor_t bg = DEFCOLOR;
  std::vector<view_seg_t> segs;
};

struct text_view_t
{
  strvec_t lines;
  std::vector<std::vector<view_seg_t>> segs;    // per line
};

// open viewers: their callbacks live in this DLL, so they are closed when the
// plugin is unloaded
static std::map<TWidget *, text_view_t *> g_text_views;

static void idaapi text_view_close(TWidget *w, void *ud)
{
  g_text_views.erase(w);
  delete (text_view_t *)ud;
}

// The diff colors of the original (DIFF_COLOR_ADDED, _CHANGED, _SUBTRACTED:
// green, yellow, red) made translucent, so the text keeps the theme's color
// and stays readable over both the light and the dark themes of IDA. The
// dark mode colors only make them a bit more opaque.
static const bgcolor_t SEG_ADDED      = 0x0000B000;   // green  (0xAABBGGRR)
static const bgcolor_t SEG_CHANGED    = 0x0000C8E0;   // yellow
static const bgcolor_t SEG_SUBTRACTED = 0x000000E0;   // red

static bgcolor_t seg_color(char kind)
{
  bgcolor_t alpha = dark_mode() ? 0x48000000 : 0x30000000;
  return alpha | (kind == '+' ? SEG_ADDED : kind == '-' ? SEG_SUBTRACTED : SEG_CHANGED);
}

void text_view_rendering_info(lines_rendering_output_t *out, const TWidget *widget,
                              const lines_rendering_input_t *info)
{
  auto p = g_text_views.find(const_cast<TWidget *>(widget));
  if ( p == g_text_views.end() || out == nullptr || info == nullptr )
    return;
  const text_view_t *tv = p->second;
  for ( const auto &section : info->sections_lines )
  {
    for ( const twinline_t *line : section )
    {
      if ( line == nullptr || line->at == nullptr )
        continue;
      size_t n = static_cast<const simpleline_place_t *>(line->at)->n;
      if ( n >= tv->segs.size() )
        continue;
      for ( const auto &s : tv->segs[n] )
        if ( s.nchars > 0 )
          out->entries.push_back(new line_rendering_output_entry_t(line, s.cpx, s.nchars, 0, s.bg));
    }
  }
}

static const custom_viewer_handlers_t text_view_handlers(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, text_view_close);

static void show_text_view(const std::string &title, const std::vector<view_line_t> &lines)
{
  TWidget *old = find_widget(title.c_str());
  if ( old != nullptr )
    close_widget(old, 0);

  text_view_t *tv = new text_view_t();
  for ( const auto &l : lines )
  {
    simpleline_t sl(l.text.c_str());
    sl.bgcolor = l.bg;
    tv->lines.push_back(sl);
    tv->segs.push_back(l.segs);
  }
  if ( tv->lines.empty() )
    tv->lines.push_back(simpleline_t(""));

  simpleline_place_t s1;
  simpleline_place_t s2(int(tv->lines.size() - 1));
  TWidget *w = create_custom_viewer(title.c_str(), &s1, &s2, &s1, nullptr, &tv->lines, &text_view_handlers, tv);
  if ( w == nullptr )
  {
    delete tv;
    warning("Cannot create the viewer '%s'", title.c_str());
    return;
  }
  g_text_views[w] = tv;
  display_widget(w, WOPN_DP_TAB | WOPN_RESTORE);
}

// a source with line numbers (HtmlFormatter(linenos=True) + highlight())
static std::vector<view_line_t> numbered_source(const std::string &src, colorizer_t colorize)
{
  std::vector<view_line_t> out;
  std::vector<std::string> lines = split(src, '\n');
  if ( !lines.empty() && lines.back().empty() )
    lines.pop_back();
  int width = int(std::to_string(lines.size()).size());
  for ( size_t i = 0; i < lines.size(); ++i )
  {
    view_line_t vl;
    vl.text = col(SCOLOR_NUMBER, strfmt("%*u ", width, unsigned(i + 1))) + colorize(expand_tabs(lines[i]));
    out.push_back(std::move(vl));
  }
  return out;
}

// Lines compared through 'normalize' (when given) and shown as they are: what
// the normalizer masks never counts as a change.
static void normalized_lines(const std::vector<std::string> &lines, colorizer_t normalize,
                             std::vector<std::string> *out)
{
  for ( const auto &l : lines )
    out->push_back(normalize != nullptr ? normalize(l) : l);
}

static std::vector<view_line_t> render_sbs_rows(const std::vector<sbs_row_t> &rows, colorizer_t colorize, size_t nlines);

// CHtmlDiff.make_file(): a side by side diff
static std::vector<view_line_t> side_by_side_view(const std::vector<std::string> &lhs,
                                                  const std::vector<std::string> &rhs,
                                                  colorizer_t colorize,
                                                  colorizer_t normalize = nullptr)
{
  std::vector<std::string> a, b;
  for ( const auto &l : lhs )
    a.push_back(sanitize(expand_tabs(l)));
  for ( const auto &l : rhs )
    b.push_back(sanitize(expand_tabs(l)));
  std::vector<std::string> an, bn;
  normalized_lines(a, normalize, &an);
  normalized_lines(b, normalize, &bn);
  std::vector<sbs_row_t> rows = side_by_side_diff(an, bn);
  if ( normalize != nullptr )
  {
    // back to the original text; the changed spans only hold for lines the
    // normalizer left alone
    for ( auto &r : rows )
    {
      if ( r.lno > 0 && size_t(r.lno) <= a.size() && a[r.lno - 1] != r.ltxt )
      {
        r.ltxt = a[r.lno - 1];
        r.lspans.clear();
      }
      if ( r.rno > 0 && size_t(r.rno) <= b.size() && b[r.rno - 1] != r.rtxt )
      {
        r.rtxt = b[r.rno - 1];
        r.rspans.clear();
      }
    }
  }

  return render_sbs_rows(rows, colorize, std::max(a.size(), b.size()));
}

// the rows of a side by side diff, painted: "<lno> <left><pad>  | <rno> <right>".
// 'nlines' is the longest side, for the width of the line numbers.
static std::vector<view_line_t> render_sbs_rows(const std::vector<sbs_row_t> &rows, colorizer_t colorize, size_t nlines)
{
  size_t width = 0;
  for ( const auto &r : rows )
    width = std::max(width, visible_len(r.ltxt));
  int lnw = int(std::to_string(nlines).size());

  // the changed spans of one side as backgrounds behind their characters,
  // 'base' being the column where that side starts. Without spans (the line
  // was normalized) the whole text of the side is marked.
  auto add_segs = [](view_line_t *vl, int base, const std::string &txt, const std::vector<sbs_span_t> &spans,
                     char whole_kind)
  {
    if ( spans.empty() )
    {
      int n = int(visible_len(txt));
      if ( n > 0 )
        vl->segs.push_back({ base, n, seg_color(whole_kind) });
      return;
    }
    for ( const auto &sp : spans )
    {
      size_t s = std::min<size_t>(sp.start, txt.size());
      size_t e = std::min<size_t>(sp.end, txt.size());
      int cpx = base + int(visible_len(txt.substr(0, s)));
      int n = int(visible_len(txt.substr(s, e - s)));
      if ( n > 0 )
        vl->segs.push_back({ cpx, n, seg_color(sp.kind) });
    }
  };

  std::vector<view_line_t> out;
  for ( const auto &r : rows )
  {
    view_line_t vl;
    std::string lno = r.lno != 0 ? strfmt("%*d", lnw, r.lno) : std::string(lnw, ' ');
    std::string rno = r.rno != 0 ? strfmt("%*d", lnw, r.rno) : std::string(lnw, ' ');
    std::string pad(width - std::min(width, visible_len(r.ltxt)), ' ');
    // "<lno> <left><pad>  | <rno> <right>"
    int left_col = lnw + 1;
    int right_col = left_col + int(width) + 4 + lnw + 1;
    vl.text = col(SCOLOR_NUMBER, lno) + " " + colorize(r.ltxt) + pad + "  " + col(SCOLOR_SYMBOL, "|") + " "
            + col(SCOLOR_NUMBER, rno) + " " + colorize(r.rtxt);
    if ( r.changed )
    {
      if ( r.lno != 0 )
        add_segs(&vl, left_col, r.ltxt, r.lspans, r.rno == 0 ? '-' : '^');
      if ( r.rno != 0 )
        add_segs(&vl, right_col, r.rtxt, r.rspans, r.lno == 0 ? '+' : '^');
    }
    out.push_back(std::move(vl));
  }
  return out;
}

// difflib.unified_diff() highlighted with pygments' DiffLexer
static std::vector<view_line_t> unified_view(const std::vector<std::string> &lhs,
                                             const std::vector<std::string> &rhs,
                                             colorizer_t normalize = nullptr)
{
  std::vector<std::string> ln, rn;
  normalized_lines(lhs, normalize, &ln);
  normalized_lines(rhs, normalize, &rn);
  std::vector<std::string> lines = unified_diff(ln, rn);
  std::vector<view_line_t> out;
  // position in lhs / rhs, from the hunk headers: the lines are shown as
  // they are, not normalized
  size_t ia = 0, ib = 0;
  auto hunk_start = [](const std::string &range) -> size_t
  {
    // "-12,3" / "+7" (1-based; an empty range gives the line before it)
    size_t comma = range.find(',');
    long start = atol(range.substr(1, comma == std::string::npos ? std::string::npos : comma - 1).c_str());
    long len = comma == std::string::npos ? 1 : atol(range.substr(comma + 1).c_str());
    return size_t(len == 0 ? start : std::max(start - 1, 0L));
  };
  for ( size_t i = 2; i < lines.size(); ++i )
  {
    std::string raw = strip(lines[i], "\n");
    if ( normalize != nullptr && !raw.empty() )
    {
      if ( starts_with(raw, "@@") )
      {
        std::vector<std::string> f = split(raw, ' ');
        if ( f.size() >= 3 )
        {
          ia = hunk_start(f[1]);
          ib = hunk_start(f[2]);
        }
      }
      else if ( raw[0] == '-' && ia < lhs.size() )
      {
        raw = "-" + lhs[ia++];
      }
      else if ( raw[0] == '+' && ib < rhs.size() )
      {
        raw = "+" + rhs[ib++];
      }
      else if ( raw[0] == ' ' && ia < lhs.size() )
      {
        raw = " " + lhs[ia++];
        ib++;
      }
    }
    std::string line = sanitize(expand_tabs(raw));
    view_line_t vl;
    if ( starts_with(line, "@@") )
    {
      vl.text = col(SCOLOR_MACRO, line);
    }
    else if ( starts_with(line, "+") || starts_with(line, "-") )
    {
      // behind the text only, not across the whole window
      vl.text = line;
      int n = int(visible_len(line));
      if ( n > 0 )
        vl.segs.push_back({ 0, n, seg_color(line[0]) });
    }
    else
    {
      vl.text = line;
    }
    out.push_back(std::move(vl));
  }
  return out;
}

// a unified diff of rows aligned elsewhere (GhidraDec), 3 lines of context
static std::vector<view_line_t> unified_rows_view(const std::vector<sbs_row_t> &rows)
{
  const size_t CONTEXT = 3;
  std::vector<view_line_t> out;
  auto add = [&out](char kind, const std::string &text)
  {
    std::string line = sanitize(expand_tabs(std::string(1, kind) + text));
    view_line_t vl;
    vl.text = line;
    int n = int(visible_len(line));
    if ( kind != ' ' && n > 0 )
      vl.segs.push_back({ 0, n, seg_color(kind) });
    out.push_back(std::move(vl));
  };
  size_t i = 0;
  while ( i < rows.size() )
  {
    if ( !rows[i].changed )
    {
      i++;
      continue;
    }
    // the hunk: changed rows closer than 2 * CONTEXT unchanged rows
    size_t first = i >= CONTEXT ? i - CONTEXT : 0;
    size_t last = i;
    for ( size_t k = i; k < rows.size(); k++ )
    {
      if ( rows[k].changed )
        last = k;
      else if ( k - last > 2 * CONTEXT )
        break;
    }
    size_t end = std::min(rows.size(), last + 1 + CONTEXT);
    int os = 0, ns = 0, ol = 0, nl = 0, prev_l = 0, prev_r = 0;
    for ( size_t k = 0; k < first; k++ )
    {
      if ( rows[k].lno != 0 )
        prev_l = rows[k].lno;
      if ( rows[k].rno != 0 )
        prev_r = rows[k].rno;
    }
    for ( size_t k = first; k < end; k++ )
    {
      if ( rows[k].lno != 0 )
      {
        if ( os == 0 )
          os = rows[k].lno;
        ol++;
      }
      if ( rows[k].rno != 0 )
      {
        if ( ns == 0 )
          ns = rows[k].rno;
        nl++;
      }
    }
    view_line_t hdr;
    hdr.text = col(SCOLOR_MACRO, strfmt("@@ -%d,%d +%d,%d @@", os != 0 ? os : prev_l, ol, ns != 0 ? ns : prev_r, nl));
    out.push_back(std::move(hdr));
    for ( size_t k = first; k < end; )
    {
      if ( !rows[k].changed )
      {
        add(' ', rows[k].ltxt);
        k++;
        continue;
      }
      // a run of changed rows: the old lines, then the new ones
      size_t e = k;
      while ( e < end && rows[e].changed )
        e++;
      for ( size_t x = k; x < e; x++ )
        if ( rows[x].lno != 0 )
          add('-', rows[x].ltxt);
      for ( size_t x = k; x < e; x++ )
        if ( rows[x].rno != 0 )
          add('+', rows[x].rtxt);
      k = e;
    }
    i = end;
  }
  return out;
}

//------------------------------------------------------------------------------
// show_* / diff commands
//------------------------------------------------------------------------------
// get_sources_diff_data(): rows of both functions having `field`
static bool get_sources_diff_data(bindiff_t &bd, uint64 ea1, uint64 ea2, const char *field,
                                  const char *label, sql_row_t *row1, sql_row_t *row2)
{
  std::string sql = strfmt(R"SQL(select *
                  from (select prototype, %s, name, 1 as side
                          from functions
                         where address = ?
                           and %s is not null
                         union
                        select prototype, %s, name, 2 as side
                          from diff.functions
                         where address = ?
                           and %s is not null)
                 order by side asc)SQL", field, field, field, field);
  sql_rows_t rows = bd.get_db().query(sql, { std::to_string(ea1), std::to_string(ea2) });
  if ( rows.size() != 2 )
  {
    warning("Sorry, there is no %s available for either the first or the second database.", label);
    return false;
  }
  *row1 = rows[0];
  *row2 = rows[1];
  return true;
}

static void generate_asm_diff(bindiff_t &bd, uint64 ea1, uint64 ea2, const char *field,
                              const char *title_fmt, bool html)
{
  sql_row_t row1, row2;
  if ( !get_sources_diff_data(bd, ea1, ea2, field, field, &row1, &row2) )
    return;
  std::string name1 = row1.str("name"), name2 = row2.str("name");
  std::string buf1 = name1 + " proc near\n" + prettify_asm(row1.str(field)) + "\n" + name1 + " endp";
  std::string buf2 = name2 + " proc near\n" + prettify_asm(row2.str(field)) + "\n" + name2 + " endp";
  std::vector<view_line_t> lines = html
                                 ? side_by_side_view(split(buf1, '\n'), split(buf2, '\n'), color_asm)
                                 : unified_view(split(buf1, '\n'), split(buf2, '\n'));
  std::string title = strfmt(title_fmt, name1.c_str(), name2.c_str());
  if ( !html )
    title = "Patch: " + title;
  show_text_view(title, lines);
}

static void show_asm_diff(bindiff_t &bd, const chooser_item_t &item, bool html)
{
  generate_asm_diff(bd, item.ea1, item.ea2, "assembly", "Diff assembly %s - %s", html);
}

static void show_microcode_diff(bindiff_t &bd, const chooser_item_t &item)
{
  generate_asm_diff(bd, item.ea1, item.ea2, "microcode", "Diff microcode %s - %s", true);
}

static void show_asm(bindiff_t &bd, const chooser_item_t &item, bool primary)
{
  const char *dbn = primary ? "main" : "diff";
  sql_row_t row;
  if ( !bd.get_db().query_one(strfmt("select prototype, assembly, name from %s.functions where address = ?", dbn),
                              { std::to_string(item.ea1) }, &row) )
  {
    warning("Sorry, there is no assembly available for the selected function.");
    return;
  }
  std::string name = row.str("name");
  std::string src = "; " + row.str("prototype") + "\n" + name + " proc near\n"
                  + prettify_asm(row.str("assembly")) + "\n" + name + " endp\n";
  show_text_view("Assembly for " + name, numbered_source(src, color_asm));
}

static void show_pseudo(bindiff_t &bd, const chooser_item_t &item, bool primary)
{
  const char *dbn = primary ? "main" : "diff";
  sql_row_t row;
  if ( !bd.get_db().query_one(strfmt("select prototype, pseudocode, name from %s.functions where address = ?", dbn),
                              { std::to_string(item.ea1) }, &row)
    || row.is_null("prototype") || row.is_null("pseudocode") )
  {
    warning("Sorry, there is no pseudo-code available for the selected function.");
    return;
  }
  std::string src = row.str("prototype") + "\n" + row.str("pseudocode");
  show_text_view("Pseudo-code for " + row.str("name"), numbered_source(src, color_c));
}

static void show_pseudo_diff(bindiff_t &bd, const chooser_item_t &item, bool html)
{
  sql_rows_t rows = bd.get_db().query(R"SQL(select *
        from (
        select prototype, pseudocode, name, 1 side
         from functions
        where address = ?
          and pseudocode is not null
    union
       select prototype, pseudocode, name, 2 side
         from diff.functions
        where address = ?
          and pseudocode is not null)
        order by side asc)SQL", { std::to_string(item.ea1), std::to_string(item.ea2) });
  if ( rows.size() != 2 )
  {
    warning("Sorry, there is no pseudo-code available for either the first or the second database.");
    return;
  }
  const sql_row_t &row1 = rows[0];
  const sql_row_t &row2 = rows[1];

  std::string buf1;
  std::string proto1;
  if ( bd.decompile_and_get(ea_t(item.ea1), &proto1) )
  {
    auto p = bd.impl->decomp.find(ea_t(item.ea1));
    buf1 = proto1 + "\n" + (p != bd.impl->decomp.end() ? join(p->second.pseudo, "\n") : std::string());
  }
  else
  {
    log("warning: cannot retrieve the current pseudo-code for the function, using the previously saved one...");
    buf1 = row1.str("prototype") + "\n" + row1.str("pseudocode");
  }
  bd.impl->decomp.clear();
  std::string buf2 = row2.str("prototype") + "\n" + row2.str("pseudocode");

  if ( buf1 == buf2 )
    warning("Both pseudo-codes are equal.");

  std::vector<view_line_t> lines = html
                                 ? side_by_side_view(split(buf1, '\n'), split(buf2, '\n'), color_c)
                                 : unified_view(split(buf1, '\n'), split(buf2, '\n'));
  std::string title = strfmt("Diff pseudo-code %s - %s", row1.str("name").c_str(), row2.str("name").c_str());
  if ( !html )
    title = "Patch: " + title;
  show_text_view(title, lines);
}

//------------------------------------------------------------------------------
// Claude diff pseudo-code (Claude-Rays Decompiler, not in the python version)
//------------------------------------------------------------------------------
// true if the orientation is known (asked now if needed or 'ask_again')
static bool claude_orientation(bindiff_t &bd, const chooser_item_t &item, bool ask_again, bool *a_is_new)
{
  if ( g_claude_a_is_new < 0 || ask_again )
  {
    int r = ask_yn(g_claude_a_is_new == 0 ? ASKBTN_NO : ASKBTN_YES,
                   "Claude / GhidraDec diff pseudo-code\n\n"
                   "Is the open database the NEW version (after the patch)?\n\n"
                   "Yes: the open database (%s) is NEW and the other one (%s) is OLD.\n"
                   "No: the open database is OLD and the other one is NEW.\n\n"
                   "The answer is kept for these results (Set the new version for Claude/GhidraDec... changes it).",
                   item.name1.c_str(), basename_any(bd.last_diff_db).c_str());
    if ( r == ASKBTN_CANCEL )
      return false;
    g_claude_a_is_new = r == ASKBTN_YES ? 1 : 0;
  }
  *a_is_new = g_claude_a_is_new == 1;
  return true;
}

// 'text' cut in lines of at most 'width' characters, on spaces
static std::vector<std::string> wrap_text(const std::string &text, size_t width)
{
  std::vector<std::string> out;
  for ( const auto &para : split(text, '\n') )
  {
    std::string line;
    for ( const auto &word : split(para, ' ') )
    {
      if ( !line.empty() && visible_len(line) + 1 + visible_len(word) > width )
      {
        out.push_back(line);
        line.clear();
      }
      line += (line.empty() ? "" : " ") + word;
    }
    out.push_back(line);
  }
  return out;
}

// WIL diagnostics carry the source line number, which moves whenever the
// source file changes: wil::details::in1diag3::Return_Hr(_ReturnAddress(),
// 0x339, "file.cxx", hr). It is masked for the comparison, so those lines
// only count as changed when something else changed.
static std::string normalize_wil(const std::string &line)
{
  size_t from = line.find("_ReturnAddress()");
  if ( from != std::string::npos )
  {
    from += strlen("_ReturnAddress()");
  }
  else
  {
    size_t d = line.find("in1diag");
    if ( d == std::string::npos )
      return line;
    from = line.find('(', d);
    if ( from == std::string::npos )
      return line;
  }
  // the first number after it
  for ( size_t i = from; i < line.size(); i++ )
  {
    if ( !qisdigit((uchar)line[i]) )
      continue;
    if ( i > 0 && (qisalnum((uchar)line[i - 1]) || line[i - 1] == '_') )
      return line;    // part of an identifier: not the argument we want
    size_t e = i;
    while ( e < line.size() && (qisxdigit((uchar)line[e]) || line[e] == 'x' || line[e] == 'X') )
      e++;
    return line.substr(0, i) + "#" + line.substr(e);
  }
  return line;
}

// "public: virtual long CZoneIdentifier::Load(unsigned short const *,unsigned
// long)" -> "CZoneIdentifier::Load": without the arguments, the access, the
// storage class and the return type
static std::string short_func_name(const std::string &name)
{
  std::string s = name.substr(0, name.find('('));
  int depth = 0;
  size_t start = 0;
  for ( size_t i = 0; i < s.size(); i++ )
  {
    if ( s[i] == '<' )
      depth++;
    else if ( s[i] == '>' )
      depth--;
    else if ( s[i] == ' ' && depth == 0 && i + 1 < s.size() )
      start = i + 1;
  }
  std::string out = strip(s.substr(start));
  return out.empty() ? name : out;
}

static std::string address_list(const std::vector<std::string> &v)
{
  std::string out;
  for ( size_t i = 0; i < v.size() && i < 6; i++ )
    out += (i == 0 ? "" : ", ") + v[i];
  if ( v.size() > 6 )
    out += strfmt(" (+%u)", unsigned(v.size() - 6));
  return out.empty() ? "-" : out;
}

static void show_claude_pseudo_diff(bindiff_t &bd, const chooser_item_t &item, bool html, bool force)
{
  bool a_is_new = false;
  if ( !claude_orientation(bd, item, false, &a_is_new) )
    return;
  claude_diff_t d;
  std::string err;
  if ( !claude_diff(bd, item, a_is_new, force, &d, &err) )
  {
    if ( err != "cancelled" )
      warning("Claude diff pseudo-code: %s", err.c_str());
    else
      log("Claude diff cancelled.");
    return;
  }

  std::string name_old = short_func_name(a_is_new ? item.name2 : item.name1);
  std::string name_new = short_func_name(a_is_new ? item.name1 : item.name2);
  std::vector<view_line_t> lines;
  auto note = [&](const char *color, const std::string &text)
  {
    for ( const auto &l : wrap_text(sanitize(expand_tabs(text)), 140) )
    {
      view_line_t vl;
      vl.text = col(color, "// " + l);
      lines.push_back(std::move(vl));
    }
  };
  std::string model = d.model;
  if ( !d.model_id.empty() && d.model_id != d.model )
    model += " -> " + d.model_id;
  if ( !d.effort.empty() )
    model += ", effort " + d.effort;
  note(SCOLOR_AUTOCMT, strfmt("Claude diff pseudo-code: OLD = %s (%s), NEW = %s (%s)",
                              name_old.c_str(), a_is_new ? "other database" : "open database",
                              name_new.c_str(), a_is_new ? "open database" : "other database"));
  note(SCOLOR_AUTOCMT, "The diff ignores the source line numbers of the WIL diagnostics (Return_Hr, Log_Hr...): "
                       "they move whenever the source file changes.");
  note(SCOLOR_AUTOCMT, strfmt("Claude-Rays Decompiler: C reconstructed by Claude (%s, %s) from the two disassemblies%s. "
                              "Plausible, not proven: check it against the listings.",
                              model.c_str(), d.date.c_str(), d.cached ? ", from the cache" : ""));
  if ( d.input_tokens > 0 || d.output_tokens > 0 )
    note(SCOLOR_AUTOCMT, strfmt("Usage: %lld input / %lld output tokens, $%.4f at API prices "
                                "(on a subscription it counts against the plan usage).",
                                (long long)d.input_tokens, (long long)d.output_tokens, d.cost_usd));
  note(SCOLOR_MACRO, strfmt("ASSESSMENT (a hypothesis): security relevant: %s, class: %s, confidence: %s",
                            d.security_relevant.c_str(), d.fix_class.c_str(), d.confidence.c_str()));
  if ( !d.reasoning.empty() )
    note(SCOLOR_MACRO, "  " + d.reasoning);
  for ( const auto &f : d.follow_up )
    note(SCOLOR_MACRO, "  Follow up: " + f);
  if ( d.changes.empty() )
    note(SCOLOR_AUTOCMT, "CHANGES: none reported.");
  else
    note(SCOLOR_AUTOCMT, strfmt("CHANGES (%u):", unsigned(d.changes.size())));
  for ( size_t i = 0; i < d.changes.size(); i++ )
  {
    const claude_change_t &c = d.changes[i];
    note(SCOLOR_AUTOCMT, strfmt("  %u. [%s] %s (old: %s; new: %s)", unsigned(i + 1), c.kind.c_str(),
                                c.description.c_str(), address_list(c.old_addresses).c_str(),
                                address_list(c.new_addresses).c_str()));
  }
  for ( const auto &w : d.warnings )
    note(SCOLOR_ERROR, "WARNING: " + w);
  for ( const auto &n : d.notes )
    note(SCOLOR_ERROR, "NOTE: " + n);
  for ( const auto &u : d.old_side.uncertain )
    note(SCOLOR_MACRO, "UNCERTAIN old " + u.first + ": " + u.second);
  for ( const auto &u : d.new_side.uncertain )
    note(SCOLOR_MACRO, "UNCERTAIN new " + u.first + ": " + u.second);
  if ( !d.old_side.summary.empty() )
    note(SCOLOR_AUTOCMT, "OLD: " + d.old_side.summary);
  if ( !d.new_side.summary.empty() )
    note(SCOLOR_AUTOCMT, "NEW: " + d.new_side.summary);
  lines.push_back(view_line_t());

  std::vector<std::string> old_code;
  std::vector<std::string> new_code;
  for ( const auto &l : d.old_side.lines )
    old_code.push_back(l.text);
  for ( const auto &l : d.new_side.lines )
    new_code.push_back(l.text);
  std::vector<view_line_t> body = html ? side_by_side_view(old_code, new_code, color_c, normalize_wil)
                                       : unified_view(old_code, new_code, normalize_wil);
  lines.insert(lines.end(), body.begin(), body.end());
  std::string title = strfmt("Claude diff pseudo-code %s - %s", name_old.c_str(), name_new.c_str());
  if ( !html )
    title = "Patch: " + title;
  show_text_view(title, lines);
}

//------------------------------------------------------------------------------
// GhidraDec diff pseudo-code (GhidraDec, not in the python version)
//------------------------------------------------------------------------------
static std::string line_range(int first, int last)
{
  if ( first == 0 )
    return "-";
  return first == last ? std::to_string(first) : strfmt("%d-%d", first, last);
}

static void show_ghidra_pseudo_diff(bindiff_t &bd, const chooser_item_t &item, bool html)
{
  bool a_is_new = false;
  if ( !claude_orientation(bd, item, false, &a_is_new) )
    return;
  ghidra_diff_t d;
  std::string err;
  if ( !ghidra_diff(bd, item, a_is_new, &d, &err) )
  {
    warning("GhidraDec diff pseudo-code: %s", err.c_str());
    return;
  }

  std::string name_old = short_func_name(a_is_new ? item.name2 : item.name1);
  std::string name_new = short_func_name(a_is_new ? item.name1 : item.name2);
  std::vector<view_line_t> lines;
  auto note = [&](const char *color, const std::string &text)
  {
    for ( const auto &l : wrap_text(sanitize(expand_tabs(text)), 140) )
    {
      view_line_t vl;
      vl.text = col(color, "// " + l);
      lines.push_back(std::move(vl));
    }
  };
  note(SCOLOR_AUTOCMT, strfmt("GhidraDec diff pseudo-code: OLD = %s (%s), NEW = %s (%s)",
                              name_old.c_str(), d.old_side.source.c_str(), name_new.c_str(), d.new_side.source.c_str()));
  note(SCOLOR_AUTOCMT, strfmt("GhidraDec %s, Ghidra's decompiler (%s), %lld s. Deterministic, no model: the same "
                              "decompiler and settings for both versions, without parameter identification.",
                              d.version.c_str(), d.ghidra.c_str(), (long long)d.seconds));
  note(SCOLOR_AUTOCMT, std::string(d.canonical_names
                         ? "The locals are named v1, v2... on both sides, in the order of first use."
                         : "The locals keep Ghidra's names (uVar3, local_28...): canonical names are off.")
                     + (d.rename_locals
                         ? " The locals of NEW are renamed after those of OLD (matched by where they are used), so "
                           "the same variable has the same name on both sides."
                         : " NEW is not renamed after OLD: a variable named differently shows as a change.")
                     + " See Diaphora-ng > GhidraDec diff settings...");
  note(SCOLOR_AUTOCMT, strfmt("The diff ignores addresses (sub_/DAT_/LAB_..., pointers into the image), the WIL "
                              "line numbers and the indentation: %d line(s) differ only in those and are not marked.",
                              d.normalized_rows));
  if ( d.identical )
    note(SCOLOR_MACRO, "NO CHANGES: both decompilations are the same once normalized.");
  else
    note(SCOLOR_AUTOCMT, strfmt("CHANGES (%u):", unsigned(d.changes.size())));
  for ( size_t i = 0; i < d.changes.size(); i++ )
  {
    const ghidra_change_t &c = d.changes[i];
    note(SCOLOR_AUTOCMT, strfmt("  %u. [%s] old %s, new %s: %s", unsigned(i + 1), c.kind.c_str(),
                                line_range(c.old_first, c.old_last).c_str(), line_range(c.new_first, c.new_last).c_str(),
                                c.description.c_str()));
  }
  auto list = [&](const char *label, const std::vector<std::string> &v)
  {
    if ( !v.empty() )
      note(SCOLOR_MACRO, std::string(label) + join(v, ", "));
  };
  list("CALLS ADDED: ", d.calls_added);
  list("CALLS REMOVED: ", d.calls_removed);
  list("CONSTANTS ADDED: ", d.constants_added);
  list("CONSTANTS REMOVED: ", d.constants_removed);
  for ( const auto &w : d.warnings )
    note(SCOLOR_ERROR, "WARNING: " + w);
  lines.push_back(view_line_t());

  // the spans are byte offsets in the text as GhidraDec sent it
  std::vector<sbs_row_t> rows = d.rows;
  for ( auto &r : rows )
  {
    std::string l = sanitize(expand_tabs(r.ltxt));
    std::string t = sanitize(expand_tabs(r.rtxt));
    if ( l != r.ltxt )
    {
      r.ltxt = l;
      r.lspans.clear();
    }
    if ( t != r.rtxt )
    {
      r.rtxt = t;
      r.rspans.clear();
    }
  }
  std::vector<view_line_t> body = html
                                ? render_sbs_rows(rows, color_c, std::max(d.old_side.lines.size(), d.new_side.lines.size()))
                                : unified_rows_view(rows);
  lines.insert(lines.end(), body.begin(), body.end());
  std::string title = strfmt("GhidraDec diff pseudo-code %s - %s", name_old.c_str(), name_new.c_str());
  if ( !html )
    title = "Patch: " + title;
  show_text_view(title, lines);
}

//------------------------------------------------------------------------------
// graph viewers (CDiffGraphViewer, CCallGraphViewer)
//------------------------------------------------------------------------------
struct graph_data_t
{
  std::string title;
  std::vector<std::string> texts;
  std::vector<bgcolor_t> colors;
  std::vector<std::string> hints;
  std::vector<std::pair<int, int>> edges;
  graph_viewer_t *gv = nullptr;
};
static std::vector<std::unique_ptr<graph_data_t>> g_graphs;

static ssize_t idaapi graph_callback(void *ud, int code, va_list va)
{
  graph_data_t *g = (graph_data_t *)ud;
  switch ( code )
  {
    case grcode_user_refresh:
      {
        interactive_graph_t *ig = va_arg(va, interactive_graph_t *);
        ig->clear();
        ig->resize(int(g->texts.size()));
        for ( const auto &e : g->edges )
          ig->add_edge(e.first, e.second, nullptr);
        return 1;
      }
    case grcode_user_text:
      {
        interactive_graph_t *ig = va_arg(va, interactive_graph_t *);
        int node = va_arg(va, int);
        const char **text = va_arg(va, const char **);
        bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
        qnotused(ig);
        if ( node < 0 || size_t(node) >= g->texts.size() )
          return 0;
        *text = g->texts[node].c_str();
        if ( bgcolor != nullptr )
          *bgcolor = g->colors[node];
        return 1;
      }
    case grcode_user_hint:
      {
        interactive_graph_t *ig = va_arg(va, interactive_graph_t *);
        int mousenode = va_argi(va, int);
        int src = va_argi(va, int);
        int dst = va_argi(va, int);
        char **hint = va_arg(va, char **);
        qnotused(ig);
        qnotused(src);
        qnotused(dst);
        if ( mousenode >= 0 && size_t(mousenode) < g->hints.size() && !g->hints[mousenode].empty() )
        {
          *hint = qstrdup(g->hints[mousenode].c_str());
          return 1;
        }
        return 0;
      }
  }
  return 0;
}

static graph_data_t *show_graph(std::unique_ptr<graph_data_t> data)
{
  TWidget *old = find_widget(data->title.c_str());
  if ( old != nullptr )
    close_widget(old, 0);

  netnode id;
  std::string node_name = "$ diaphora graph " + data->title;
  id.create(node_name.c_str());
  graph_data_t *g = data.get();
  g->gv = create_graph_viewer(g->title.c_str(), id, graph_callback, g, 0);
  if ( g->gv == nullptr )
  {
    warning("Cannot create the graph viewer '%s'", g->title.c_str());
    return nullptr;
  }
  g_graphs.push_back(std::move(data));
  display_widget(g->gv, WOPN_DP_TAB);
  return g;
}

void close_all_views()
{
  std::vector<TWidget *> widgets;
  for ( const auto &kv : g_text_views )
    widgets.push_back(kv.first);
  for ( TWidget *w : widgets )
    close_widget(w, 0);
  g_text_views.clear();
  std::vector<TWidget *> graphs;
  for ( const auto &g : g_graphs )
    graphs.push_back((TWidget *)g->gv);
  for ( TWidget *w : graphs )
    close_widget(w, 0);
  g_graphs.clear();
}

void on_widget_closed(TWidget *widget)
{
  for ( auto p = g_graphs.begin(); p != g_graphs.end(); ++p )
  {
    if ( (TWidget *)(*p)->gv == widget )
    {
      g_graphs.erase(p);
      return;
    }
  }
}

static int idaapi fit_graphs_timer(void *ud)
{
  std::vector<std::string> *titles = (std::vector<std::string> *)ud;
  for ( const auto &t : *titles )
  {
    TWidget *w = find_widget(t.c_str());
    if ( w == nullptr )
      continue;
    graph_viewer_t *gv = get_graph_viewer(w);
    if ( gv != nullptr )
      viewer_fit_window(gv);
  }
  delete titles;
  return -1;
}

// show_graph_pair(): display two related graphs side-by-side and zoom-fit them
static void show_graph_pair(std::unique_ptr<graph_data_t> g1, std::unique_ptr<graph_data_t> g2)
{
  std::string title1 = g1->title, title2 = g2->title;
  if ( show_graph(std::move(g1)) == nullptr || show_graph(std::move(g2)) == nullptr )
    return;
  set_dock_pos(title2.c_str(), title1.c_str(), DP_RIGHT);
  register_timer(100, fit_graphs_timer, new std::vector<std::string>{ title1, title2 });
}

static std::unique_ptr<graph_data_t> build_diff_graph(const std::string &title, const bb_graph_t &g,
                                                      const bb_colours_t &colours)
{
  auto data = std::make_unique<graph_data_t>();
  data->title = title;
  std::unordered_map<std::string, int> nodes;
  auto add_node = [&](const std::string &key, const std::string &text) -> int
  {
    auto p = nodes.find(key);
    if ( p != nodes.end() )
      return p->second;
    int id = int(data->texts.size());
    nodes[key] = id;
    data->texts.push_back(text);
    auto c = colours.find(key);
    data->colors.push_back(theme_color(c != colours.end() ? c->second : 0xFFFFFF));
    data->hints.push_back(std::string());
    return id;
  };

  for ( const auto &key : g.order )
  {
    std::vector<std::string> label;
    for ( const auto &ins : g.blocks.at(key) )
      label.push_back(sanitize(ins[2]));
    add_node(key, join(label, "\n"));
  }
  for ( const auto &key : g.rel_order )
  {
    int parent = add_node(key, "");
    for ( const auto &child : g.relations.at(key) )
      data->edges.emplace_back(parent, add_node(child, ""));
  }
  return data;
}

static void graph_diff(bindiff_t &bd, const chooser_item_t &item, const char *asm_type, const char *title_prefix)
{
  log("Diff %s graph for 0x%llx - 0x%llx", asm_type, (unsigned long long)item.ea1, (unsigned long long)item.ea2);
  bb_graph_t g1, g2;
  bd.get_graph(item.ea1, true, asm_type, &g1);
  bd.get_graph(item.ea2, false, asm_type, &g2);
  if ( g1.empty() || g2.empty() )
  {
    warning("Sorry, graph information is not available for one of the databases.");
    return;
  }
  bb_colours_t c1, c2;
  bd.compare_graphs(g1, g2, &c1, &c2);
  std::string title1 = strfmt("%s for %s (primary)", title_prefix, item.name1.c_str());
  std::string title2 = strfmt("%s for %s (secondary)", title_prefix, item.name2.c_str());
  show_graph_pair(build_diff_graph(title1, g1, c1), build_diff_graph(title2, g2, c2));
}

static sql_rows_t get_calls_graph(bindiff_t &bd, const std::string &name, const char *mtype, const char *dbn)
{
  std::string sql = strfmt(R"SQL(select cg.type type, f2.address ea1, f2.name name1,
             f1.address ea2, f1.name name2
          from %s.callgraph cg,
             %s.functions f1,
             %s.functions f2
         where f1.name = ?
           and cg.func_id = f1.id
           and cg.type = ?
           and f2.address = cg.address )SQL", dbn, dbn, dbn);
  return bd.get_db().query(sql, { name, mtype });
}

static std::unique_ptr<graph_data_t> build_calls_graph(const std::string &title, const sql_rows_t &callers,
                                                       const sql_rows_t &callees, const std::string &target)
{
  auto data = std::make_unique<graph_data_t>();
  data->title = title;
  auto add = [&](const std::string &name, bgcolor_t color, const char *type) -> int
  {
    data->texts.push_back(sanitize(name));
    data->colors.push_back(theme_color(color));
    data->hints.push_back(type);
    return int(data->texts.size() - 1);
  };
  int root = add(target, config::CALLGRAPH_COLOR_TARGET, "target");
  for ( const auto &caller : callers )
    data->edges.emplace_back(add(caller.str("name1"), config::CALLGRAPH_COLOR_CALLER, "caller"), root);
  for ( const auto &callee : callees )
    data->edges.emplace_back(root, add(callee.str("name1"), config::CALLGRAPH_COLOR_CALLEE, "callee"));
  return data;
}

static void show_callgraph_context(bindiff_t &bd, const chooser_item_t &item)
{
  log("Showing call graph context for 0x%llx - 0x%llx", (unsigned long long)item.ea1, (unsigned long long)item.ea2);
  sql_rows_t main_callers = get_calls_graph(bd, item.name1, "caller", "main");
  sql_rows_t main_callees = get_calls_graph(bd, item.name1, "callee", "main");
  sql_rows_t diff_callers = get_calls_graph(bd, item.name2, "caller", "diff");
  sql_rows_t diff_callees = get_calls_graph(bd, item.name2, "callee", "diff");
  std::string title1 = "Call graph context for " + item.name1;
  std::string title2 = "Call graph context for " + item.name2;
  if ( title1 == title2 )
    title2 += " (secondary)";
  show_graph_pair(build_calls_graph(title1, main_callers, main_callees, item.name1),
                  build_calls_graph(title2, diff_callers, diff_callees, item.name2));
}

//------------------------------------------------------------------------------
// external diffing tool
//------------------------------------------------------------------------------
static int run_external_diff_tool(const std::string &buf1, const std::string &buf2,
                                  const chooser_item_t &item, const char *ext, const std::string &cmd_line)
{
  std::string filename1 = strfmt("main_%s.%s", hex_ea(item.ea1).c_str(), ext);
  std::string filename2 = strfmt("diff_%s.%s", hex_ea(item.ea2).c_str(), ext);
  write_text_file(filename1, buf1);
  write_text_file(filename2, buf2);
  std::string line = replace_all(replace_all(cmd_line, "$1", filename1), "$2", filename2);
  return call_system(line.c_str());
}

static void diff_external(bindiff_t &bd, const chooser_item_t &item)
{
  static const char form[] =
    "STARTITEM 0\n"
    "BUTTON YES* Diff Pseudo-code\n"
    "BUTTON NO Diff Assembler\n"
    "External Diffing Tool\n"
    "<#Use $1 and $2 for the two files#Enter command line:q:1023:80::>\n";
  qstring cmd;
  if ( !reg_read_string(&cmd, "diaphora_external_command") || cmd.empty() )
    cmd = "your_command $1 $2";
  int ok = ask_form(form, &cmd);
  if ( ok < 0 )
    return;
  bool diff_asm = ok == 0;
  reg_write_string("diaphora_external_command", cmd.c_str());

  sql_row_t row1, row2;
  int ret;
  if ( diff_asm )
  {
    if ( !get_sources_diff_data(bd, item.ea1, item.ea2, "assembly", "assembly", &row1, &row2) )
      return;
    std::string name1 = row1.str("name"), name2 = row2.str("name");
    std::string buf1 = name1 + " proc near\n" + prettify_asm(row1.str("assembly")) + "\n" + name1 + " endp";
    std::string buf2 = name2 + " proc near\n" + prettify_asm(row2.str("assembly")) + "\n" + name2 + " endp";
    ret = run_external_diff_tool(buf1, buf2, item, "asm", cmd.c_str());
  }
  else
  {
    if ( !get_sources_diff_data(bd, item.ea1, item.ea2, "pseudocode", "pseudo-code", &row1, &row2) )
      return;
    std::string buf1 = row1.str("prototype") + "\n" + row1.str("pseudocode");
    std::string buf2 = row2.str("prototype") + "\n" + row2.str("pseudocode");
    ret = run_external_diff_tool(buf1, buf2, item, "cpp", cmd.c_str());
  }
  msg("External command returned %d\n", ret);
}

//------------------------------------------------------------------------------
// results choosers (CIDAChooser)
//------------------------------------------------------------------------------
struct results_chooser_t;
static std::map<std::string, results_chooser_t *> g_open_choosers;

static const int match_widths[] = { 8, 10, 20, 10, 20, 8, 5, 5, 30 };
static const char *const match_header[] =
{
  "Line", "Address", "Name", "Address 2", "Name 2", "Ratio", "BBlocks 1", "BBlocks 2", "Description",
};
static const int unmatched_widths[] = { 8, 10, 20 };
static const char *const unmatched_header[] = { "Line", "Address", "Name" };

// seems_false_positive(): the names are different
static bool seems_false_positive(const chooser_item_t &item)
{
  std::string name1 = strip(rstrip(item.name1, "_0"), ".");
  std::string name2 = strip(rstrip(item.name2, "_0"), ".");
  if ( !starts_with(name1, "sub_") && !starts_with(name2, "sub_") && name1 != name2 )
  {
    if ( name2.find(name1) == std::string::npos && name1.find(name2) != std::string::npos )
      return true;
  }
  return false;
}

// The row colors (by ratio, as in the original) are mixed with the
// background of the theme, so they are softer: ROW_COLOR_STRENGTH 1.0 keeps
// them as they are, 0 leaves the plain background. The background follows
// "Toggle dark mode colors".
static const double ROW_COLOR_STRENGTH = 0.55;

static bgcolor_t soften_row_color(bgcolor_t c)
{
  bgcolor_t base = dark_mode() ? 0x202020 : 0xFFFFFF;
  bgcolor_t out = 0;
  for ( int shift = 0; shift <= 16; shift += 8 )
  {
    int x = int((c >> shift) & 0xFF);
    int b = int((base >> shift) & 0xFF);
    int v = b + int((x - b) * ROW_COLOR_STRENGTH);
    out |= bgcolor_t(std::min(std::max(v, 0), 255)) << shift;
  }
  return out;
}

struct results_chooser_t : public chooser_multi_t
{
  bindiff_t *bd;
  chooser_data_t *data;
  std::string title_str;
  // IDA paints a selected row that has its own color in a light shade, where
  // the white text of the dark theme cannot be read, and the selection and
  // text colors cannot be set. The selected rows are drawn without their
  // color instead: IDA uses its normal selection colors for them.
  mutable std::set<size_t> selected;

  results_chooser_t(bindiff_t *_bd, chooser_data_t *_data)
    : chooser_multi_t(CH_ATTRS | CH_CAN_DEL | CH_CAN_REFRESH,
                      _data->is_unmatched() ? qnumber(unmatched_widths) : qnumber(match_widths),
                      _data->is_unmatched() ? unmatched_widths : match_widths,
                      _data->is_unmatched() ? unmatched_header : match_header,
                      _data->title.c_str()),
      bd(_bd), data(_data), title_str(_data->title)
  {
  }

  const void *get_obj_id(size_t *len) const override
  {
    *len = title_str.size();
    return title_str.c_str();
  }

  size_t idaapi get_count() const override
  {
    return data->items.size();
  }

  void idaapi get_row(qstrvec_t *out, int *, chooser_item_attrs_t *attrs, size_t n) const override
  {
    if ( n >= data->items.size() )
      return;
    const chooser_item_t &item = data->items[n];
    if ( data->is_unmatched() )
    {
      out->resize(3);
      (*out)[0] = item.line.c_str();
      (*out)[1] = hex_ea(item.ea1).c_str();
      (*out)[2] = item.name1.c_str();
      return;
    }
    out->resize(9);
    (*out)[0] = item.line.c_str();
    (*out)[1] = hex_ea(item.ea1).c_str();
    (*out)[2] = item.name1.c_str();
    (*out)[3] = hex_ea(item.ea2).c_str();
    (*out)[4] = item.name2.c_str();
    (*out)[5] = format_ratio(item.ratio).c_str();
    (*out)[6] = std::to_string(item.nodes1).c_str();
    (*out)[7] = std::to_string(item.nodes2).c_str();
    (*out)[8] = item.desc.c_str();

    // OnGetLineAttr()
    if ( attrs != nullptr && selected.count(n) == 0 )
    {
      if ( seems_false_positive(item) )
      {
        attrs->color = soften_row_color(config::LITTLE_ORANGE);
      }
      else
      {
        double ratio = item.ratio;
        int red = std::abs(int(164 * (1 - ratio)));
        int green = std::abs(int(128 * ratio));
        int blue = std::abs(int(255 * (1 - ratio)));
        attrs->color = soften_row_color(bgcolor_t((blue << 16) | (green << 8) | red));
      }
    }
  }

  // the selected rows lose their color: repaint the chooser once the
  // selection changed (from the event loop, not inside the callback)
  void idaapi select(const sizevec_t &sel) const override
  {
    std::set<size_t> s(sel.begin(), sel.end());
    if ( s == selected )
      return;
    selected.swap(s);
    register_timer(0, repaint_timer, new std::string(title_str));
  }

  static int idaapi repaint_timer(void *ud)
  {
    std::string *title = (std::string *)ud;
    // nothing happens if the chooser was closed in the meantime
    refresh_chooser(title->c_str());
    delete title;
    return -1;
  }

  ea_t idaapi get_ea(size_t n) const override
  {
    if ( n >= data->items.size() || !data->primary )
      return BADADDR;
    return ea_t(data->items[n].ea1);
  }

  // OnSelectLine()
  cbres_t idaapi enter(sizevec_t *sel) override
  {
    if ( sel == nullptr || sel->empty() || sel->front() >= data->items.size() )
      return NOTHING_CHANGED;
    const chooser_item_t &item = data->items[sel->front()];
    if ( data->primary )
    {
      ea_t jump_ea = ea_t(item.ea1);
      // Only jump for valid addresses
      if ( is_mapped(jump_ea) )
        jumpto(jump_ea);
    }
    else
    {
      show_asm(*bd, item, data->primary);
    }
    return NOTHING_CHANGED;
  }

  // OnDeleteLine()
  cbres_t idaapi del(sizevec_t *sel) override
  {
    if ( sel == nullptr || sel->empty() )
      return NOTHING_CHANGED;
    std::vector<size_t> rows(sel->begin(), sel->end());
    std::sort(rows.rbegin(), rows.rend());
    std::lock_guard<std::mutex> g(bd->items_lock);
    for ( size_t n : rows )
    {
      if ( n >= data->items.size() )
        continue;
      std::string name1 = data->items[n].name1;
      std::string name2 = data->items[n].name2;
      data->items.erase(data->items.begin() + n);
      bd->matched_primary.erase(name1);
      bd->matched_secondary.erase(name2);
    }
    sel->clear();
    return ALL_CHANGED;
  }

  cbres_t idaapi refresh(sizevec_t *) override
  {
    return ALL_CHANGED;
  }

  void idaapi closed() override
  {
    auto p = g_open_choosers.find(title_str);
    if ( p != g_open_choosers.end() && p->second == this )
      g_open_choosers.erase(p);
  }
};

bool is_diaphora_chooser(TWidget *widget)
{
  qstring title;
  get_widget_title(&title, widget);
  return g_open_choosers.find(title.c_str()) != g_open_choosers.end();
}

static void show_chooser(bindiff_t &bd, chooser_data_t &data)
{
  auto p = g_open_choosers.find(data.title);
  if ( p != g_open_choosers.end() )
  {
    TWidget *w = find_widget(data.title.c_str());
    if ( w != nullptr )
    {
      refresh_chooser(data.title.c_str());
      activate_widget(w, true);
      return;
    }
    g_open_choosers.erase(p);
  }

  // Sort items by ratio
  if ( data.show_commands )
    std::stable_sort(data.items.begin(), data.items.end(),
                     [](const chooser_item_t &a, const chooser_item_t &b) { return a.ratio > b.ratio; });

  results_chooser_t *ch = new results_chooser_t(&bd, &data);
  g_open_choosers[data.title] = ch;
  ssize_t r = ch->choose();
  if ( r == chooser_base_t::ALREADY_EXISTS || r == chooser_base_t::EMPTY_CHOOSER || r == chooser_base_t::NO_ATTR )
  {
    g_open_choosers.erase(data.title);
    delete ch;
  }
}

void show_choosers(bindiff_t &bd, bool force)
{
  qnotused(force);
  for ( chooser_data_t *c : bd.all_choosers() )
    if ( !c->items.empty() )
      show_chooser(bd, *c);
}

void close_choosers()
{
  std::vector<std::string> titles;
  for ( const auto &kv : g_open_choosers )
    titles.push_back(kv.first);
  for ( const auto &t : titles )
  {
    TWidget *w = find_widget(t.c_str());
    if ( w != nullptr )
      close_widget(w, 0);
  }
  g_open_choosers.clear();
}

void refresh_all_choosers(bindiff_t &bd)
{
  qnotused(bd);
  for ( const auto &kv : g_open_choosers )
    refresh_chooser(kv.first.c_str());
}

//------------------------------------------------------------------------------
// chooser commands
//------------------------------------------------------------------------------
enum chooser_cmd_t
{
  CMD_REDIFF,
  CMD_SAVE_RESULTS,
  CMD_MANUAL_MATCH,
  CMD_DIFF_ASM,
  CMD_DIFF_MICROCODE,
  CMD_DIFF_C,
  CMD_DIFF_GRAPH,
  CMD_DIFF_GRAPH_MICROCODE,
  CMD_DIFF_EXTERNAL,
  CMD_DIFF_ASM_PATCH,
  CMD_DIFF_C_PATCH,
  CMD_CALLGRAPH,
  CMD_IMPORT_SELECTED,
  CMD_IMPORT_SELECTED_AUTO,
  CMD_IMPORT_ALL,
  CMD_IMPORT_ALL_FUNCS,
  CMD_HIGHLIGHT,
  CMD_UNHIGHLIGHT,
  CMD_SHOW_ASM,
  CMD_SHOW_PSEUDO,
  CMD_CLAUDE_DIFF_C,
  CMD_CLAUDE_DIFF_C_PATCH,
  CMD_CLAUDE_REGENERATE,
  CMD_CLAUDE_ORIENTATION,
  CMD_GHIDRA_DIFF_C,
  CMD_GHIDRA_DIFF_C_PATCH,
  CMD_SEPARATOR = -1,
};

struct cmd_def_t
{
  int cmd;
  const char *name;
  const char *label;
  const char *shortcut;
};

static const cmd_def_t match_cmds[] =
{
  { CMD_REDIFF,               "Diaphora-ng:DiffAgain",           "Diff again",                            nullptr },
  { CMD_SAVE_RESULTS,         "Diaphora-ng:SaveResults",         "Save results",                          nullptr },
  { CMD_MANUAL_MATCH,         "Diaphora-ng:AddManualMatch",      "Add manual match",                      nullptr },
  { CMD_SEPARATOR,            nullptr,                        nullptr,                                 nullptr },
  { CMD_DIFF_ASM,             "Diaphora-ng:DiffAssembly",        "Diff assembly",                         nullptr },
  { CMD_DIFF_MICROCODE,       "Diaphora-ng:DiffMicrocode",       "Diff microcode",                        nullptr },
  { CMD_DIFF_C,               "Diaphora-ng:DiffPseudo-code",     "Diff pseudo-code",                      nullptr },
  { CMD_DIFF_GRAPH,           "Diaphora-ng:DiffAssemblyGraph",   "Diff assembly in a graph",              nullptr },
  { CMD_DIFF_GRAPH_MICROCODE, "Diaphora-ng:DiffMicrocodeGraph",  "Diff microcode in a graph",             nullptr },
  { CMD_DIFF_EXTERNAL,        "Diaphora-ng:DiffExternal",        "Diff using an external tool",           nullptr },
  { CMD_DIFF_ASM_PATCH,       "Diaphora-ng:ShowAssemblyPatch",   "Show assembly patch",                   nullptr },
  { CMD_DIFF_C_PATCH,         "Diaphora-ng:ShowPseudo-codePatch", "Show pseudo-code patch",               nullptr },
  { CMD_CALLGRAPH,            "Diaphora-ng:ShowCallGraph",       "Show callers and callees graph",        nullptr },
  { CMD_SEPARATOR,            nullptr,                        nullptr,                                 nullptr },
  { CMD_CLAUDE_DIFF_C,        "Diaphora-ng:ClaudeDiffPseudo-code", "Claude diff pseudo-code",             nullptr },
  { CMD_CLAUDE_DIFF_C_PATCH,  "Diaphora-ng:ClaudePseudo-codePatch", "Claude pseudo-code patch",           nullptr },
  { CMD_CLAUDE_REGENERATE,    "Diaphora-ng:ClaudeRegenerate",    "Regenerate Claude diff",                nullptr },
  { CMD_GHIDRA_DIFF_C,        "Diaphora-ng:GhidraDecDiffPseudo-code", "GhidraDec diff pseudo-code",     nullptr },
  { CMD_GHIDRA_DIFF_C_PATCH,  "Diaphora-ng:GhidraDecPseudo-codePatch", "GhidraDec pseudo-code patch",   nullptr },
  { CMD_CLAUDE_ORIENTATION,   "Diaphora-ng:ClaudeOrientation",   "Set the new version for Claude/GhidraDec...", nullptr },
  { CMD_SEPARATOR,            nullptr,                        nullptr,                                 nullptr },
  { CMD_IMPORT_SELECTED,     "Diaphora-ng:ImportSelected",      "Import selected",                       "Ctrl+Alt+i" },
  { CMD_IMPORT_SELECTED_AUTO, "Diaphora-ng:ImportSelectedSub",   "Import selected sub_*",                 nullptr },
  { CMD_IMPORT_ALL,           "Diaphora-ng:ImportAll",           "Import *all* functions",                nullptr },
  { CMD_IMPORT_ALL_FUNCS,     "Diaphora-ng:ImportAllSub",        "Import *all* data for sub_* functions", nullptr },
  { CMD_SEPARATOR,            nullptr,                        nullptr,                                 nullptr },
  { CMD_HIGHLIGHT,            "Diaphora-ng:HighlightMatches",    "Highlight matches",                     nullptr },
  { CMD_UNHIGHLIGHT,          "Diaphora-ng:UnhighlightMatches",  "Unhighlight matches",                   nullptr },
};

static const cmd_def_t unmatched_cmds[] =
{
  { CMD_SHOW_ASM,    "Diaphora-ng:ShowAssembly",   "Show assembly",   nullptr },
  { CMD_SHOW_PSEUDO, "Diaphora-ng:ShowPseudo-code", "Show pseudo-code", nullptr },
};

// CBasicChooser: modal chooser with the functions of the diff database
struct basic_chooser_t : public chooser_t
{
  const sql_rows_t &rows;
  basic_chooser_t(const char *title, const sql_rows_t &r)
    : chooser_t(CH_MODAL | CH_KEEP, 2, basic_widths(), basic_header(), title), rows(r) {}
  static const int *basic_widths() { static const int w[] = { 10 | CHCOL_PLAIN, 30 | CHCOL_PLAIN }; return w; }
  static const char *const *basic_header() { static const char *const h[] = { "Id", "Name" }; return h; }
  size_t idaapi get_count() const override { return rows.size(); }
  void idaapi get_row(qstrvec_t *out, int *, chooser_item_attrs_t *, size_t n) const override
  {
    out->resize(2);
    (*out)[0] = rows[n].str("id").c_str();
    (*out)[1] = rows[n].str("name").c_str();
  }
};

static void add_manual_match_internal(bindiff_t &bd, ea_t ea1, ea_t ea2)
{
  sql_row_t main_row, diff_row;
  if ( !bd.get_function_row_by_ea(ea1, "main", &main_row) )
  {
    warning("Can't find the local function!");
    return;
  }
  if ( !bd.get_function_row_by_ea(ea2, "diff", &diff_row) )
  {
    warning("Can't find the foreign function!");
    return;
  }

  double ratio = bd.compare_function_rows(main_row, diff_row);
  match_item_t item;
  item.ea1 = (uint64)main_row.to_int("address");
  item.name1 = main_row.str("name");
  item.ea2 = (uint64)diff_row.to_int("address");
  item.name2 = diff_row.str("name");
  item.desc = "Manual match";
  item.ratio = ratio;
  item.nodes1 = main_row.to_int("nodes");
  item.nodes2 = diff_row.to_int("nodes");

  {
    std::lock_guard<std::mutex> g(bd.items_lock);
    if ( bd.matched_primary.count(item.name1) != 0 || bd.matched_secondary.count(item.name2) != 0 )
    {
      warning("Either the local function or the foreign function is already matched!\n"
              "Please remove the previously assigned match before adding a manual match.");
      return;
    }
    bd.partial_chooser.add_item(item);
    bd.matched_primary[item.name1] = { item.name2, ratio };
    bd.matched_secondary[item.name2] = { item.name1, ratio };
  }
  show_chooser(bd, bd.partial_chooser);
  refresh_chooser(bd.partial_chooser.title.c_str());
}

static void add_manual_match(bindiff_t &bd)
{
  ea_t ea1 = choose_func_ea("Select a function from the current database...", BADADDR);
  if ( ea1 == BADADDR )
    return;
  sql_rows_t diff_funcs = bd.get_db().query("select cast(id as text) id, name, address from diff.functions order by id");
  basic_chooser_t ch("Select a function from the external database...", diff_funcs);
  ssize_t ret = ch.choose();
  if ( ret < 0 || size_t(ret) >= diff_funcs.size() )
    return;
  func_t *f = get_func(ea1);
  if ( f != nullptr )
    ea1 = f->start_ea;
  ea_t ea2 = ea_t(diff_funcs[ret].to_int("address"));
  log("Adding manual match between 0x%08llx and 0x%08llx", (unsigned long long)ea1, (unsigned long long)ea2);
  add_manual_match_internal(bd, ea1, ea2);
}

static int idaapi rediff_timer(void *ud)
{
  std::string *file_in = (std::string *)ud;
  std::string f = *file_in;
  delete file_in;
  diff_or_export(true, f);
  return -1;
}

static void set_functions_color(chooser_data_t &data, bgcolor_t color)
{
  for ( const auto &item : data.items )
  {
    func_t *f = get_func(ea_t(item.ea1));
    if ( f == nullptr )
    {
      msg("Error setting color for %llx\n", (unsigned long long)item.ea1);
      continue;
    }
    f->color = color;
    update_func(f);
  }
  refresh_idaview_anyway();
}

static void run_command(results_chooser_t *ch, int cmd, const sizevec_t &selection)
{
  bindiff_t &bd = *ch->bd;
  chooser_data_t &data = *ch->data;
  size_t n = selection.empty() ? 0 : selection.front();
  bool have_item = n < data.items.size();
  chooser_item_t item = have_item ? data.items[n] : chooser_item_t();

  try
  {
    switch ( cmd )
    {
      case CMD_SHOW_ASM:
        if ( have_item )
          show_asm(bd, item, data.primary);
        break;
      case CMD_SHOW_PSEUDO:
        if ( have_item )
          show_pseudo(bd, item, data.primary);
        break;
      case CMD_IMPORT_ALL:
        if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nDo you want to import all functions, comments, prototypes and definitions?") == ASKBTN_YES )
          bd.import_all(std::vector<chooser_item_t>(data.items));
        break;
      case CMD_IMPORT_ALL_FUNCS:
        if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nDo you really want to import all IDA named matched functions, comments, prototypes and definitions?") == ASKBTN_YES )
          bd.import_all_auto(std::vector<chooser_item_t>(data.items));
        break;
      case CMD_IMPORT_SELECTED:
      case CMD_IMPORT_SELECTED_AUTO:
        if ( selection.size() <= 1 )
        {
          if ( have_item )
            bd.import_one(item);
        }
        else if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nDo you really want to import all selected IDA named matched functions, comments, prototypes and definitions?") == ASKBTN_YES )
        {
          bd.import_selected(std::vector<chooser_item_t>(data.items), selection, cmd == CMD_IMPORT_SELECTED_AUTO);
        }
        break;
      case CMD_DIFF_C:
        if ( have_item )
          show_pseudo_diff(bd, item, true);
        break;
      case CMD_DIFF_C_PATCH:
        if ( have_item )
          show_pseudo_diff(bd, item, false);
        break;
      case CMD_CLAUDE_DIFF_C:
        if ( have_item )
          show_claude_pseudo_diff(bd, item, true, false);
        break;
      case CMD_CLAUDE_DIFF_C_PATCH:
        if ( have_item )
          show_claude_pseudo_diff(bd, item, false, false);
        break;
      case CMD_CLAUDE_REGENERATE:
        if ( have_item )
          show_claude_pseudo_diff(bd, item, true, true);
        break;
      case CMD_GHIDRA_DIFF_C:
        if ( have_item )
          show_ghidra_pseudo_diff(bd, item, true);
        break;
      case CMD_GHIDRA_DIFF_C_PATCH:
        if ( have_item )
          show_ghidra_pseudo_diff(bd, item, false);
        break;
      case CMD_CLAUDE_ORIENTATION:
        {
          bool a_is_new;
          if ( have_item )
            claude_orientation(bd, item, true, &a_is_new);
        }
        break;
      case CMD_DIFF_ASM_PATCH:
        if ( have_item )
          show_asm_diff(bd, item, false);
        break;
      case CMD_DIFF_ASM:
        if ( have_item )
          show_asm_diff(bd, item, true);
        break;
      case CMD_DIFF_MICROCODE:
        if ( have_item )
          show_microcode_diff(bd, item);
        break;
      case CMD_HIGHLIGHT:
        if ( ask_yn(ASKBTN_YES, "HIDECANCEL\nDo you want to change the background color of each matched function?") == ASKBTN_YES )
          set_functions_color(data, data.get_color());
        break;
      case CMD_UNHIGHLIGHT:
        set_functions_color(data, DEFCOLOR);
        break;
      case CMD_DIFF_GRAPH:
        if ( have_item )
          graph_diff(bd, item, "native", "Graph");
        break;
      case CMD_DIFF_GRAPH_MICROCODE:
        if ( have_item )
          graph_diff(bd, item, "microcode", "Microcode graph");
        break;
      case CMD_CALLGRAPH:
        if ( have_item )
          show_callgraph_context(bd, item);
        break;
      case CMD_SAVE_RESULTS:
        {
          const char *filename = ask_file(true, "*.diaphora", "Select the file to store diffing results");
          if ( filename != nullptr )
            bd.save_results(filename);
        }
        break;
      case CMD_MANUAL_MATCH:
        add_manual_match(bd);
        break;
      case CMD_REDIFF:
        {
          std::string file_in = bd.last_diff_db;
          bd.get_db().try_exec("detach diff");
          // re_diff(): close the choosers and run the diff/export dialog again
          register_timer(1000, rediff_timer, new std::string(file_in));
        }
        break;
      case CMD_DIFF_EXTERNAL:
        if ( have_item )
          diff_external(bd, item);
        break;
    }
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
}

struct chooser_cmd_ah_t : public action_handler_t
{
  int cmd;
  explicit chooser_cmd_ah_t(int c) : cmd(c) {}

  int idaapi activate(action_activation_ctx_t *ctx) override
  {
    auto p = g_open_choosers.find(ctx->widget_title.c_str());
    if ( p == g_open_choosers.end() )
      return 0;
    run_command(p->second, cmd, ctx->chooser_selection);
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ctx->widget_type == BWN_CHOOSER ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
  }
};

static std::vector<std::unique_ptr<chooser_cmd_ah_t>> g_cmd_handlers;
static std::vector<std::string> g_cmd_names;

void register_chooser_actions(plugmod_t *owner)
{
  auto reg = [&](const cmd_def_t &d)
  {
    if ( d.cmd == CMD_SEPARATOR )
      return;
    auto h = std::make_unique<chooser_cmd_ah_t>(d.cmd);
    action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(d.name, d.label, h.get(), owner, d.shortcut, nullptr, -1);
    if ( register_action(desc) )
      g_cmd_names.push_back(d.name);
    g_cmd_handlers.push_back(std::move(h));
  };
  for ( const auto &d : match_cmds )
    reg(d);
  for ( const auto &d : unmatched_cmds )
    reg(d);
}

void unregister_chooser_actions()
{
  for ( const auto &name : g_cmd_names )
    unregister_action(name.c_str());
  g_cmd_names.clear();
  g_cmd_handlers.clear();
}

void attach_chooser_popup(TWidget *widget, TPopupMenu *popup)
{
  qstring title;
  get_widget_title(&title, widget);
  auto p = g_open_choosers.find(title.c_str());
  if ( p == g_open_choosers.end() )
    return;
  if ( p->second->data->show_commands )
  {
    for ( const auto &d : match_cmds )
      attach_action_to_popup(widget, popup, d.cmd == CMD_SEPARATOR ? nullptr : d.name);
  }
  else
  {
    for ( const auto &d : unmatched_cmds )
      attach_action_to_popup(widget, popup, d.name);
  }
}

//------------------------------------------------------------------------------
// extras/diaphora_local.py
//------------------------------------------------------------------------------
static std::string local_get_disasm(ea_t ea)
{
  qstring mnem, op1, op2;
  print_insn_mnem(&mnem, ea);
  print_operand(&op1, ea, 0);
  print_operand(&op2, ea, 1);
  tag_remove(&op1);
  tag_remove(&op2);
  std::string line = strfmt("%-8s %s", mnem.c_str(), op1.c_str());
  if ( !op2.empty() )
    line += std::string(", ") + op2.c_str();
  return line;
}

static std::string local_get_assembly(ea_t ea)
{
  func_t *func = get_func(ea);
  if ( func == nullptr )
    return std::string();
  std::vector<std::string> lines;
  qflow_chart_t flow("", func, BADADDR, BADADDR, 0);
  for ( int i = 0; i < flow.size(); ++i )
  {
    const qbasic_block_t &block = flow.blocks[i];
    if ( block.end_ea == 0 || block.end_ea == BADADDR )
      continue;
    if ( block.start_ea != func->start_ea )
      lines.push_back(strfmt("loc_%08llx:", (unsigned long long)block.start_ea));
    ea_t head = block.start_ea;
    if ( !is_head(get_flags(head)) )
      head = next_head(head, block.end_ea);
    while ( head < block.end_ea && head != BADADDR )
    {
      lines.push_back("     " + local_get_disasm(head));
      head = next_head(head, block.end_ea);
    }
  }
  return join(lines, "\n");
}

void cmd_local_diff()
{
  ea_t ea = get_screen_ea();
  func_t *func = get_func(ea);
  if ( func == nullptr )
  {
    warning("Please place the cursor over a function before calling this plugin.");
    return;
  }
  qstring func_name;
  get_func_name(&func_name, ea);
  std::string line = strfmt("Select the function to diff %s against", func_name.c_str());
  ea_t diff_ea = choose_func_ea(line.c_str(), BADADDR);
  if ( diff_ea == BADADDR )
    return;
  func_t *f2 = get_func(diff_ea);
  if ( f2 != nullptr )
    diff_ea = f2->start_ea;
  log("Selected function address 0x%08llx", (unsigned long long)diff_ea);
  ea = func->start_ea;

  qstring name1, name2;
  get_func_name(&name1, ea);
  get_func_name(&name2, diff_ea);

  // assembly
  std::string buf1 = std::string(name1.c_str()) + " proc near\n" + local_get_assembly(ea) + "\n" + name1.c_str() + " endp";
  std::string buf2 = std::string(name2.c_str()) + " proc near\n" + local_get_assembly(diff_ea) + "\n" + name2.c_str() + " endp";
  show_text_view(strfmt("Diff assembly %s - %s", name1.c_str(), name2.c_str()),
                 side_by_side_view(split(buf1, '\n'), split(buf2, '\n'), color_asm));

  // pseudo-code
  bindiff_t tmp(":memory:");
  tmp.use_decompiler = true;
  tmp.export_microcode = false;
  std::string proto1, proto2;
  if ( !tmp.decompile_and_get(ea, &proto1) )
  {
    log("[i] Cannot get the pseudo-code for the current function");
    return;
  }
  std::string p1 = proto1 + "\n" + join(tmp.impl->decomp[ea].pseudo, "\n");
  if ( !tmp.decompile_and_get(diff_ea, &proto2) )
  {
    log("Cannot get the pseudo-code for the second function");
    return;
  }
  std::string p2 = proto2 + "\n" + join(tmp.impl->decomp[diff_ea].pseudo, "\n");
  if ( p1 == p2 )
    warning("Both pseudo-codes are equal.");
  show_text_view(strfmt("Diff pseudo-code %s - %s", name1.c_str(), name2.c_str()),
                 side_by_side_view(split(p1, '\n'), split(p2, '\n'), color_c));
}

} // namespace dph
