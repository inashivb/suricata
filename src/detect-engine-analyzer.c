/* Copyright (C) 2007-2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Eileen Donlon <emdonlo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Rule analyzers for the detection engine
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"
#include "action-globals.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-uint.h"
#include "conf.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-bytejump.h"
#include "detect-bytetest.h"
#include "detect-isdataat.h"
#include "detect-flow.h"
#include "detect-tcp-flags.h"
#include "detect-tcp-ack.h"
#include "detect-ipopts.h"
#include "detect-tcp-seq.h"
#include "feature.h"
#include "util-print.h"
#include "util-time.h"
#include "util-validate.h"
#include "util-conf.h"
#include "detect-flowbits.h"
#include "util-var-name.h"
#include "detect-icmp-id.h"
#include "detect-tcp-window.h"

static int rule_warnings_only = 0;

/* Details for each buffer being tracked */
typedef struct DetectEngineAnalyzerItems {
    int16_t     item_id;
    bool        item_seen;
    bool        export_item_seen;
    bool        check_encoding_match;
    const char  *item_name;
    const char  *display_name;
} DetectEngineAnalyzerItems;

typedef struct FpPatternStats_ {
    uint16_t min;
    uint16_t max;
    uint32_t cnt;
    uint64_t tot;
} FpPatternStats;

/* Track which items require the item_seen value to be exposed */
struct ExposedItemSeen {
    const char  *bufname;
    bool        *item_seen_ptr;
};

typedef struct EngineAnalysisCtx_ {

    FILE *rule_engine_analysis_fp;
    FILE *fp_engine_analysis_fp;

    DetectEngineAnalyzerItems *analyzer_items;
    char *file_prefix;
    pcre2_code *percent_re;

    /*
     * This array contains the map between the `analyzer_items` array listed above and
     * the item ids returned by DetectBufferTypeGetByName. Iterating signature's sigmatch
     * array provides list_ids. The map converts those ids into elements of the
     * analyzer items array.
     *
     * Ultimately, the g_buffer_type_hash is searched for each buffer name. The size of that
     * hashlist is 256, so that's the value we use here.
     */
    int16_t analyzer_item_map[256];
    FpPatternStats fp_pattern_stats[DETECT_SM_LIST_MAX];
    /*
     * Certain values must be directly accessible. This array contains items that are directly
     * accessed when checking if they've been seen or not.
     */
    struct ExposedItemSeen exposed_item_seen_list[2];

    bool analyzer_initialized;
} EngineAnalysisCtx;

const DetectEngineAnalyzerItems analyzer_items[] = {
    /* request keywords */
    { 0, false, false, true, "http_uri", "http uri" },
    { 0, false, false, false, "http_raw_uri", "http raw uri" },
    { 0, false, true, false, "http_method", "http method" },
    { 0, false, false, false, "http_request_line", "http request line" },
    { 0, false, false, false, "http_client_body", "http client body" },
    { 0, false, false, true, "http_header", "http header" },
    { 0, false, false, false, "http_raw_header", "http raw header" },
    { 0, false, false, true, "http_cookie", "http cookie" },
    { 0, false, false, false, "http_user_agent", "http user agent" },
    { 0, false, false, false, "http_host", "http host" },
    { 0, false, false, false, "http_raw_host", "http raw host" },
    { 0, false, false, false, "http_accept_enc", "http accept enc" },
    { 0, false, false, false, "http_referer", "http referer" },
    { 0, false, false, false, "http_content_type", "http content type" },
    { 0, false, false, false, "http_header_names", "http header names" },

    /* response keywords not listed above */
    { 0, false, false, false, "http_stat_msg", "http stat msg" },
    { 0, false, false, false, "http_stat_code", "http stat code" },
    { 0, false, true, false, "file_data", "http server body" },

    /* missing request keywords */
    { 0, false, false, false, "http_request_line", "http request line" },
    { 0, false, false, false, "http_accept", "http accept" },
    { 0, false, false, false, "http_accept_lang", "http accept lang" },
    { 0, false, false, false, "http_connection", "http connection" },
    { 0, false, false, false, "http_content_len", "http content len" },
    { 0, false, false, false, "http_protocol", "http protocol" },
    { 0, false, false, false, "http_start", "http start" },

    /* missing response keywords; some of the missing are listed above*/
    { 0, false, false, false, "http_response_line", "http response line" },
    { 0, false, false, false, "http.server", "http server" },
    { 0, false, false, false, "http.location", "http location" },
};

static void FpPatternStatsAdd(FpPatternStats *fp, int list, uint16_t patlen)
{
    if (list < 0 || list >= DETECT_SM_LIST_MAX)
        return;

    FpPatternStats *f = &fp[list];

    if (f->min == 0)
        f->min = patlen;
    else if (patlen < f->min)
        f->min = patlen;

    if (patlen > f->max)
        f->max = patlen;

    f->cnt++;
    f->tot += patlen;
}

void EngineAnalysisFP(const DetectEngineCtx *de_ctx, const Signature *s, const char *line)
{
    int fast_pattern_set = 0;
    int fast_pattern_only_set = 0;
    int fast_pattern_chop_set = 0;
    const DetectContentData *fp_cd = NULL;
    const SigMatch *mpm_sm = s->init_data->mpm_sm;
    const int mpm_sm_list = s->init_data->mpm_sm_list;

    if (mpm_sm != NULL) {
        fp_cd = (DetectContentData *)mpm_sm->ctx;
        if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN) {
            fast_pattern_set = 1;
            if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                fast_pattern_only_set = 1;
            } else if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                fast_pattern_chop_set = 1;
            }
        }
    }

    FILE *fp = de_ctx->ea->rule_engine_analysis_fp;
    fprintf(fp, "== Sid: %u ==\n", s->id);
    fprintf(fp, "%s\n", line);

    fprintf(fp, "    Fast Pattern analysis:\n");
    if (s->init_data->prefilter_sm != NULL) {
        fprintf(fp, "        Prefilter on: %s\n",
                sigmatch_table[s->init_data->prefilter_sm->type].name);
        fprintf(fp, "\n");
        return;
    }

    if (fp_cd == NULL) {
        fprintf(fp, "        No content present\n");
        fprintf(fp, "\n");
        return;
    }

    fprintf(fp, "        Fast pattern matcher: ");
    int list_type = mpm_sm_list;
    if (list_type == DETECT_SM_LIST_PMATCH)
        fprintf(fp, "content\n");
    else {
        const char *desc = DetectEngineBufferTypeGetDescriptionById(de_ctx, list_type);
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, list_type);
        if (desc && name) {
            fprintf(fp, "%s (%s)\n", desc, name);
        }
    }

    int flags_set = 0;
    fprintf(fp, "        Flags:");
    if (fp_cd->flags & DETECT_CONTENT_OFFSET) {
        fprintf(fp, " Offset");
        flags_set = 1;
    } if (fp_cd->flags & DETECT_CONTENT_DEPTH) {
        fprintf(fp, " Depth");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_WITHIN) {
        fprintf(fp, " Within");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_DISTANCE) {
        fprintf(fp, " Distance");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NOCASE) {
        fprintf(fp, " Nocase");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NEGATED) {
        fprintf(fp, " Negated");
        flags_set = 1;
    }
    if (flags_set == 0)
        fprintf(fp, " None");
    fprintf(fp, "\n");

    fprintf(fp, "        Fast pattern set: %s\n", fast_pattern_set ? "yes" : "no");
    fprintf(fp, "        Fast pattern only set: %s\n", fast_pattern_only_set ? "yes" : "no");
    fprintf(fp, "        Fast pattern chop set: %s\n", fast_pattern_chop_set ? "yes" : "no");
    if (fast_pattern_chop_set) {
        fprintf(fp, "        Fast pattern offset, length: %u, %u\n", fp_cd->fp_chop_offset,
                fp_cd->fp_chop_len);
    }

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        FatalError("Error allocating memory");
    }
    memcpy(pat, fp_cd->content, fp_cd->content_len);
    pat[fp_cd->content_len] = '\0';
    fprintf(fp, "        Original content: ");
    PrintRawUriFp(fp, pat, patlen);
    fprintf(fp, "\n");

    if (fast_pattern_chop_set) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';
        fprintf(fp, "        Final content: ");
        PrintRawUriFp(fp, pat, patlen);
        fprintf(fp, "\n");

        FpPatternStatsAdd(&de_ctx->ea->fp_pattern_stats[0], list_type, patlen);
    } else {
        fprintf(fp, "        Final content: ");
        PrintRawUriFp(fp, pat, patlen);
        fprintf(fp, "\n");

        FpPatternStatsAdd(&de_ctx->ea->fp_pattern_stats[0], list_type, patlen);
    }
    SCFree(pat);

    fprintf(fp, "\n");
}

/**
 * \brief Sets up the fast pattern analyzer according to the config.
 *
 * \retval 1 If rule analyzer successfully enabled.
 * \retval 0 If not enabled.
 */
static int SetupFPAnalyzer(DetectEngineCtx *de_ctx)
{
    int fp_engine_analysis_set = 0;

    if ((SCConfGetBool("engine-analysis.rules-fast-pattern", &fp_engine_analysis_set)) == 0) {
        return false;
    }

    if (fp_engine_analysis_set == 0)
        return false;

    const char *log_dir = SCConfigGetLogDirectory();
    char *log_path = SCMalloc(PATH_MAX);
    if (log_path == NULL) {
        FatalError("Unable to allocate scratch memory for rule filename");
    }
    snprintf(log_path, PATH_MAX, "%s/%s%s", log_dir,
            de_ctx->ea->file_prefix ? de_ctx->ea->file_prefix : "", "rules_fast_pattern.txt");

    FILE *fp = fopen(log_path, "w");
    if (fp == NULL) {
        SCLogError("failed to open %s: %s", log_path, strerror(errno));
        SCFree(log_path);
        return false;
    }

    de_ctx->ea->fp_engine_analysis_fp = fp;

    SCLogInfo("Engine-Analysis for fast_pattern printed to file - %s",
              log_path);
    SCFree(log_path);

    struct timeval tval;
    gettimeofday(&tval, NULL);
    struct tm local_tm;
    struct tm *tms = SCLocalTime(tval.tv_sec, &local_tm);
    fprintf(fp, "----------------------------------------------"
                "---------------------\n");
    fprintf(fp,
            "Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d\n",
            tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
            tms->tm_sec);
    fprintf(fp, "----------------------------------------------"
                "---------------------\n");

    memset(&de_ctx->ea->fp_pattern_stats[0], 0, sizeof(de_ctx->ea->fp_pattern_stats));
    return true;
}

/**
 * \brief Compiles regex for rule analysis
 * \retval 1 if successful
 * \retval 0 if on error
 */
static bool PerCentEncodingSetup(EngineAnalysisCtx *ea_ctx)
{
#define DETECT_PERCENT_ENCODING_REGEX "%[0-9|a-f|A-F]{2}"
    int en;
    PCRE2_SIZE eo = 0;
    int opts = 0; // PCRE2_NEWLINE_ANY??

    ea_ctx->percent_re = pcre2_compile((PCRE2_SPTR8)DETECT_PERCENT_ENCODING_REGEX,
            PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (ea_ctx->percent_re == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError("Compile of \"%s\" failed at offset %d: %s", DETECT_PERCENT_ENCODING_REGEX,
                (int)eo, errbuffer);
        return false;
    }

    return true;
}
/**
 * \brief Sets up the rule analyzer according to the config
 * \retval 1 if rule analyzer successfully enabled
 * \retval 0 if not enabled
 */
static int SetupRuleAnalyzer(DetectEngineCtx *de_ctx)
{
    SCConfNode *conf = SCConfGetNode("engine-analysis");
    int enabled = 0;
    if (conf != NULL) {
        const char *value = SCConfNodeLookupChildValue(conf, "rules");
        if (value && SCConfValIsTrue(value)) {
            enabled = 1;
        } else if (value && strcasecmp(value, "warnings-only") == 0) {
            enabled = 1;
            rule_warnings_only = 1;
        }
        if (enabled) {
            const char *log_dir;
            log_dir = SCConfigGetLogDirectory();
            char log_path[PATH_MAX];
            snprintf(log_path, sizeof(log_path), "%s/%s%s", log_dir,
                    de_ctx->ea->file_prefix ? de_ctx->ea->file_prefix : "", "rules_analysis.txt");
            de_ctx->ea->rule_engine_analysis_fp = fopen(log_path, "w");
            if (de_ctx->ea->rule_engine_analysis_fp == NULL) {
                SCLogError("failed to open %s: %s", log_path, strerror(errno));
                return 0;
            }

            SCLogInfo("Engine-Analysis for rules printed to file - %s",
                      log_path);

            struct timeval tval;
            gettimeofday(&tval, NULL);
            struct tm local_tm;
            struct tm *tms = SCLocalTime(tval.tv_sec, &local_tm);
            fprintf(de_ctx->ea->rule_engine_analysis_fp,
                    "----------------------------------------------"
                    "---------------------\n");
            fprintf(de_ctx->ea->rule_engine_analysis_fp,
                    "Date: %" PRId32 "/%" PRId32 "/%04d -- "
                    "%02d:%02d:%02d\n",
                    tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                    tms->tm_sec);
            fprintf(de_ctx->ea->rule_engine_analysis_fp,
                    "----------------------------------------------"
                    "---------------------\n");

            /*compile regex's for rule analysis*/
            if (!PerCentEncodingSetup(de_ctx->ea)) {
                fprintf(de_ctx->ea->rule_engine_analysis_fp,
                        "Error compiling regex; can't check for percent encoding in normalized "
                        "http content.\n");
            }
        }
    }
    else {
        SCLogInfo("Conf parameter \"engine-analysis.rules\" not found. "
                                      "Defaulting to not printing the rules analysis report.");
    }
    if (!enabled) {
        SCLogInfo("Engine-Analysis for rules disabled in conf file.");
        return 0;
    }
    return 1;
}

static void CleanupFPAnalyzer(DetectEngineCtx *de_ctx)
{
    FILE *fp = de_ctx->ea->rule_engine_analysis_fp;
    fprintf(fp, "============\n"
                "Summary:\n============\n");

    for (int i = 0; i < DETECT_SM_LIST_MAX; i++) {
        FpPatternStats *f = &de_ctx->ea->fp_pattern_stats[i];
        if (f->cnt == 0)
            continue;

        fprintf(fp,
                "%s, smallest pattern %u byte(s), longest pattern %u byte(s), number of patterns "
                "%u, avg pattern len %.2f byte(s)\n",
                DetectSigmatchListEnumToString(i), f->min, f->max, f->cnt,
                (float)((double)f->tot / (float)f->cnt));
    }

    fclose(de_ctx->ea->rule_engine_analysis_fp);
    de_ctx->ea->rule_engine_analysis_fp = NULL;
}

static void CleanupRuleAnalyzer(DetectEngineCtx *de_ctx)
{
    if (de_ctx->ea->fp_engine_analysis_fp != NULL) {
        fclose(de_ctx->ea->fp_engine_analysis_fp);
        de_ctx->ea->fp_engine_analysis_fp = NULL;
    }
    if (de_ctx->ea->percent_re != NULL) {
        pcre2_code_free(de_ctx->ea->percent_re);
    }
}

void SetupEngineAnalysis(DetectEngineCtx *de_ctx, bool *fp_analysis, bool *rule_analysis)
{
    *fp_analysis = false;
    *rule_analysis = false;

    EngineAnalysisCtx *ea = SCCalloc(1, sizeof(EngineAnalysisCtx));
    if (ea == NULL) {
        FatalError("Unable to allocate per-engine analysis context");
    }

    ea->file_prefix = NULL;
    size_t cfg_prefix_len = strlen(de_ctx->config_prefix);
    if (cfg_prefix_len > 0) {
        /* length of prefix + NULL + "." */
        ea->file_prefix = SCCalloc(1, cfg_prefix_len + 1 + 1);
        if (ea->file_prefix == NULL) {
            FatalError("Unable to allocate per-engine analysis context name buffer");
        }

        snprintf(ea->file_prefix, cfg_prefix_len + 1 + 1, "%s.", de_ctx->config_prefix);
    }

    de_ctx->ea = ea;

    *fp_analysis = SetupFPAnalyzer(de_ctx);
    *rule_analysis = SetupRuleAnalyzer(de_ctx);

    if (!(*fp_analysis || *rule_analysis)) {
        if (ea->file_prefix)
            SCFree(ea->file_prefix);
        if (ea->analyzer_items)
            SCFree(ea->analyzer_items);
        SCFree(ea);
    }
}

void CleanupEngineAnalysis(DetectEngineCtx *de_ctx)
{
    if (de_ctx->ea) {
        CleanupRuleAnalyzer(de_ctx);
        CleanupFPAnalyzer(de_ctx);
        if (de_ctx->ea->file_prefix)
            SCFree(de_ctx->ea->file_prefix);
        if (de_ctx->ea->analyzer_items)
            SCFree(de_ctx->ea->analyzer_items);
        SCFree(de_ctx->ea);
        de_ctx->ea = NULL;
    }
}

/**
 * \brief Checks for % encoding in content.
 * \param Pointer to content
 * \retval number of matches if content has % encoding
 * \retval 0 if it doesn't have % encoding
 * \retval -1 on error
 */
static int PerCentEncodingMatch(EngineAnalysisCtx *ea_ctx, uint8_t *content, uint16_t content_len)
{
    int ret = 0;

    pcre2_match_data *match = pcre2_match_data_create_from_pattern(ea_ctx->percent_re, NULL);
    ret = pcre2_match(ea_ctx->percent_re, (PCRE2_SPTR8)content, content_len, 0, 0, match, NULL);
    if (ret == -1) {
        return 0;
    } else if (ret < -1) {
        SCLogError("Error parsing content - %s; error code is %d", content, ret);
        ret = -1;
    }
    pcre2_match_data_free(match);
    return ret;
}

static void EngineAnalysisRulesPrintFP(const DetectEngineCtx *de_ctx, const Signature *s)
{
    const DetectContentData *fp_cd = NULL;
    const SigMatch *mpm_sm = s->init_data->mpm_sm;
    const int mpm_sm_list = s->init_data->mpm_sm_list;

    if (mpm_sm != NULL) {
        fp_cd = (DetectContentData *)mpm_sm->ctx;
    }

    if (fp_cd == NULL) {
        return;
    }

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        FatalError("Error allocating memory");
    }

    EngineAnalysisCtx *ea_ctx = de_ctx->ea;

    memcpy(pat, fp_cd->content, fp_cd->content_len);
    pat[fp_cd->content_len] = '\0';

    if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';
        fprintf(ea_ctx->rule_engine_analysis_fp, "    Fast Pattern \"");
        PrintRawUriFp(ea_ctx->rule_engine_analysis_fp, pat, patlen);
    } else {
        fprintf(ea_ctx->rule_engine_analysis_fp, "    Fast Pattern \"");
        PrintRawUriFp(ea_ctx->rule_engine_analysis_fp, pat, patlen);
    }
    SCFree(pat);

    fprintf(ea_ctx->rule_engine_analysis_fp, "\" on \"");

    const int list_type = mpm_sm_list;
    if (list_type == DETECT_SM_LIST_PMATCH) {
        int payload = 0;
        int stream = 0;
        if (SignatureHasPacketContent(s))
            payload = 1;
        if (SignatureHasStreamContent(s))
            stream = 1;
        fprintf(ea_ctx->rule_engine_analysis_fp, "%s",
                payload ? (stream ? "payload and reassembled stream" : "payload")
                        : "reassembled stream");
    }
    else {
        const char *desc = DetectEngineBufferTypeGetDescriptionById(de_ctx, list_type);
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, list_type);
        if (desc && name) {
            fprintf(ea_ctx->rule_engine_analysis_fp, "%s (%s)", desc, name);
        } else if (desc || name) {
            fprintf(ea_ctx->rule_engine_analysis_fp, "%s", desc ? desc : name);
        }

    }

    fprintf(ea_ctx->rule_engine_analysis_fp, "\" ");
    const DetectBufferType *bt = DetectEngineBufferTypeGetById(de_ctx, list_type);
    if (bt && bt->transforms.cnt) {
        fprintf(ea_ctx->rule_engine_analysis_fp, "(with %d transform(s)) ", bt->transforms.cnt);
    }
    fprintf(ea_ctx->rule_engine_analysis_fp, "buffer.\n");
}

void EngineAnalysisRulesFailure(
        const DetectEngineCtx *de_ctx, const char *line, const char *file, int lineno)
{
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "== Sid: UNKNOWN ==\n");
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "%s\n", line);
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "    FAILURE: invalid rule.\n");
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "    File: %s.\n", file);
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "    Line: %d.\n", lineno);
    fprintf(de_ctx->ea->fp_engine_analysis_fp, "\n");
}

typedef struct RuleAnalyzer {
    SCJsonBuilder *js; /* document root */

    SCJsonBuilder *js_warnings;
    SCJsonBuilder *js_notes;
} RuleAnalyzer;

static void ATTR_FMT_PRINTF(2, 3) AnalyzerNote(RuleAnalyzer *ctx, char *fmt, ...)
{
    va_list ap;
    char str[1024];

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    if (!ctx->js_notes)
        ctx->js_notes = SCJbNewArray();
    if (ctx->js_notes)
        SCJbAppendString(ctx->js_notes, str);
}

static void ATTR_FMT_PRINTF(2, 3) AnalyzerWarning(RuleAnalyzer *ctx, char *fmt, ...)
{
    va_list ap;
    char str[1024];

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    if (!ctx->js_warnings)
        ctx->js_warnings = SCJbNewArray();
    if (ctx->js_warnings)
        SCJbAppendString(ctx->js_warnings, str);
}

#define CHECK(pat) if (strlen((pat)) <= len && memcmp((pat), buf, MIN(len, strlen((pat)))) == 0) return true;

static bool LooksLikeHTTPMethod(const uint8_t *buf, uint16_t len)
{
    CHECK("GET /");
    CHECK("POST /");
    CHECK("HEAD /");
    CHECK("PUT /");
    return false;
}

static bool LooksLikeHTTPUA(const uint8_t *buf, uint16_t len)
{
    CHECK("User-Agent: ");
    CHECK("\nUser-Agent: ");
    return false;
}

static void DumpContent(SCJsonBuilder *js, const DetectContentData *cd)
{
    char pattern_str[1024] = "";
    DetectContentPatternPrettyPrint(cd, pattern_str, sizeof(pattern_str));

    SCJbSetString(js, "pattern", pattern_str);
    SCJbSetUint(js, "length", cd->content_len);
    SCJbSetBool(js, "nocase", cd->flags & DETECT_CONTENT_NOCASE);
    SCJbSetBool(js, "negated", cd->flags & DETECT_CONTENT_NEGATED);
    SCJbSetBool(js, "starts_with", cd->flags & DETECT_CONTENT_STARTS_WITH);
    SCJbSetBool(js, "ends_with", cd->flags & DETECT_CONTENT_ENDS_WITH);
    SCJbSetBool(js, "is_mpm", cd->flags & DETECT_CONTENT_MPM);
    SCJbSetBool(js, "no_double_inspect", cd->flags & DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED);
    if (cd->flags & DETECT_CONTENT_OFFSET) {
        SCJbSetUint(js, "offset", cd->offset);
    }
    if (cd->flags & DETECT_CONTENT_DEPTH) {
        SCJbSetUint(js, "depth", cd->depth);
    }
    if (cd->flags & DETECT_CONTENT_DISTANCE) {
        SCJbSetInt(js, "distance", cd->distance);
    }
    if (cd->flags & DETECT_CONTENT_WITHIN) {
        SCJbSetInt(js, "within", cd->within);
    }
    SCJbSetBool(js, "fast_pattern", cd->flags & DETECT_CONTENT_FAST_PATTERN);
    SCJbSetBool(js, "relative_next", cd->flags & DETECT_CONTENT_RELATIVE_NEXT);
}

static void DumpPcre(SCJsonBuilder *js, const DetectPcreData *cd)
{
    SCJbSetBool(js, "relative", cd->flags & DETECT_PCRE_RELATIVE);
    SCJbSetBool(js, "relative_next", cd->flags & DETECT_PCRE_RELATIVE_NEXT);
    SCJbSetBool(js, "nocase", cd->flags & DETECT_PCRE_CASELESS);
    SCJbSetBool(js, "negated", cd->flags & DETECT_PCRE_NEGATE);
}

static void DumpMatches(RuleAnalyzer *ctx, SCJsonBuilder *js, const SigMatchData *smd)
{
    if (smd == NULL)
        return;

    SCJbOpenArray(js, "matches");
    do {
        SCJbStartObject(js);
        const char *mname = sigmatch_table[smd->type].name;
        SCJbSetString(js, "name", mname);

        switch (smd->type) {
            case DETECT_CONTENT: {
                const DetectContentData *cd = (const DetectContentData *)smd->ctx;

                SCJbOpenObject(js, "content");
                DumpContent(js, cd);
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    AnalyzerNote(ctx, (char *)"'fast_pattern:only' option is silently ignored and "
                                              "is interpreted as regular 'fast_pattern'");
                }
                if (LooksLikeHTTPMethod(cd->content, cd->content_len)) {
                    AnalyzerNote(ctx,
                            (char *)"pattern looks like it inspects HTTP, use http.request_line or "
                                    "http.method and http.uri instead for improved performance");
                }
                if (LooksLikeHTTPUA(cd->content, cd->content_len)) {
                    AnalyzerNote(ctx,
                            (char *)"pattern looks like it inspects HTTP, use http.user_agent "
                                    "or http.header for improved performance");
                }
                if (cd->flags & DETECT_CONTENT_WITHIN2DEPTH) {
                    AnalyzerNote(ctx, (char *)"'within' option for pattern w/o previous content "
                                              "was converted to 'depth'");
                }
                if (cd->flags & DETECT_CONTENT_DISTANCE2OFFSET) {
                    AnalyzerNote(ctx, (char *)"'distance' option for pattern w/o previous content "
                                              "was converted to 'offset'");
                }
                SCJbClose(js);
                break;
            }
            case DETECT_PCRE: {
                const DetectPcreData *cd = (const DetectPcreData *)smd->ctx;

                SCJbOpenObject(js, "pcre");
                DumpPcre(js, cd);
                SCJbClose(js);
                if (cd->flags & DETECT_PCRE_RAWBYTES) {
                    AnalyzerNote(ctx,
                            (char *)"'/B' (rawbytes) option is a no-op and is silently ignored");
                }
                break;
            }
            case DETECT_BYTEJUMP: {
                const DetectBytejumpData *cd = (const DetectBytejumpData *)smd->ctx;

                SCJbOpenObject(js, "byte_jump");
                SCJbSetUint(js, "nbytes", cd->nbytes);
                SCJbSetInt(js, "offset", cd->offset);
                SCJbSetUint(js, "multiplier", cd->multiplier);
                SCJbSetInt(js, "post_offset", cd->post_offset);
                switch (cd->base) {
                    case DETECT_BYTEJUMP_BASE_UNSET:
                        SCJbSetString(js, "base", "unset");
                        break;
                    case DETECT_BYTEJUMP_BASE_OCT:
                        SCJbSetString(js, "base", "oct");
                        break;
                    case DETECT_BYTEJUMP_BASE_DEC:
                        SCJbSetString(js, "base", "dec");
                        break;
                    case DETECT_BYTEJUMP_BASE_HEX:
                        SCJbSetString(js, "base", "hex");
                        break;
                }
                SCJbOpenArray(js, "flags");
                if (cd->flags & DETECT_BYTEJUMP_BEGIN)
                    SCJbAppendString(js, "from_beginning");
                if (cd->flags & DETECT_BYTEJUMP_LITTLE)
                    SCJbAppendString(js, "little_endian");
                if (cd->flags & DETECT_BYTEJUMP_BIG)
                    SCJbAppendString(js, "big_endian");
                if (cd->flags & DETECT_BYTEJUMP_STRING)
                    SCJbAppendString(js, "string");
                if (cd->flags & DETECT_BYTEJUMP_RELATIVE)
                    SCJbAppendString(js, "relative");
                if (cd->flags & DETECT_BYTEJUMP_ALIGN)
                    SCJbAppendString(js, "align");
                if (cd->flags & DETECT_BYTEJUMP_DCE)
                    SCJbAppendString(js, "dce");
                if (cd->flags & DETECT_BYTEJUMP_OFFSET_BE)
                    SCJbAppendString(js, "offset_be");
                if (cd->flags & DETECT_BYTEJUMP_END)
                    SCJbAppendString(js, "from_end");
                SCJbClose(js);
                SCJbClose(js);
                break;
            }
            case DETECT_BYTETEST: {
                const DetectBytetestData *cd = (const DetectBytetestData *)smd->ctx;

                SCJbOpenObject(js, "byte_test");
                SCJbSetUint(js, "nbytes", cd->nbytes);
                SCJbSetInt(js, "offset", cd->offset);
                switch (cd->base) {
                    case DETECT_BYTETEST_BASE_UNSET:
                        SCJbSetString(js, "base", "unset");
                        break;
                    case DETECT_BYTETEST_BASE_OCT:
                        SCJbSetString(js, "base", "oct");
                        break;
                    case DETECT_BYTETEST_BASE_DEC:
                        SCJbSetString(js, "base", "dec");
                        break;
                    case DETECT_BYTETEST_BASE_HEX:
                        SCJbSetString(js, "base", "hex");
                        break;
                }
                SCJbOpenArray(js, "flags");
                if (cd->flags & DETECT_BYTETEST_LITTLE)
                    SCJbAppendString(js, "little_endian");
                if (cd->flags & DETECT_BYTETEST_BIG)
                    SCJbAppendString(js, "big_endian");
                if (cd->flags & DETECT_BYTETEST_STRING)
                    SCJbAppendString(js, "string");
                if (cd->flags & DETECT_BYTETEST_RELATIVE)
                    SCJbAppendString(js, "relative");
                if (cd->flags & DETECT_BYTETEST_DCE)
                    SCJbAppendString(js, "dce");
                SCJbClose(js);
                SCJbClose(js);
                break;
            }
            case DETECT_ABSENT: {
                const DetectAbsentData *dad = (const DetectAbsentData *)smd->ctx;
                SCJbOpenObject(js, "absent");
                SCJbSetBool(js, "or_else", dad->or_else);
                SCJbClose(js);
                break;
            }

            case DETECT_IPOPTS: {
                const DetectIpOptsData *cd = (const DetectIpOptsData *)smd->ctx;

                SCJbOpenObject(js, "ipopts");
                const char *flag = IpOptsFlagToString(cd->ipopt);
                SCJbSetString(js, "option", flag);
                SCJbClose(js);
                break;
            }
            case DETECT_FLOWBITS: {
                const DetectFlowbitsData *cd = (const DetectFlowbitsData *)smd->ctx;

                SCJbOpenObject(js, "flowbits");
                switch (cd->cmd) {
                    case DETECT_FLOWBITS_CMD_ISSET:
                        SCJbSetString(js, "cmd", "isset");
                        break;
                    case DETECT_FLOWBITS_CMD_ISNOTSET:
                        SCJbSetString(js, "cmd", "isnotset");
                        break;
                    case DETECT_FLOWBITS_CMD_SET:
                        SCJbSetString(js, "cmd", "set");
                        break;
                    case DETECT_FLOWBITS_CMD_UNSET:
                        SCJbSetString(js, "cmd", "unset");
                        break;
                    case DETECT_FLOWBITS_CMD_TOGGLE:
                        SCJbSetString(js, "cmd", "toggle");
                        break;
                }
                bool is_or = false;
                SCJbOpenArray(js, "names");
                if (cd->or_list_size == 0) {
                    SCJbAppendString(js, VarNameStoreSetupLookup(cd->idx, VAR_TYPE_FLOW_BIT));
                } else if (cd->or_list_size > 0) {
                    is_or = true;
                    for (uint8_t i = 0; i < cd->or_list_size; i++) {
                        const char *varname =
                                VarNameStoreSetupLookup(cd->or_list[i], VAR_TYPE_FLOW_BIT);
                        SCJbAppendString(js, varname);
                    }
                }
                SCJbClose(js); // array
                if (is_or) {
                    SCJbSetString(js, "operator", "or");
                }
                SCJbClose(js); // object
                break;
            }
            case DETECT_ACK: {
                const DetectAckData *cd = (const DetectAckData *)smd->ctx;

                SCJbOpenObject(js, "ack");
                SCJbSetUint(js, "number", cd->ack);
                SCJbClose(js);
                break;
            }
            case DETECT_SEQ: {
                const DetectSeqData *cd = (const DetectSeqData *)smd->ctx;
                SCJbOpenObject(js, "seq");
                SCJbSetUint(js, "number", cd->seq);
                SCJbClose(js);
                break;
            }
            case DETECT_TCPMSS: {
                const DetectU16Data *cd = (const DetectU16Data *)smd->ctx;
                SCJbOpenObject(js, "tcp_mss");
                SCDetectU16ToJson(js, cd);
                SCJbClose(js);
                break;
            }
            case DETECT_DSIZE: {
                const DetectU16Data *cd = (const DetectU16Data *)smd->ctx;
                SCJbOpenObject(js, "dsize");
                SCDetectU16ToJson(js, cd);
                SCJbClose(js);
                break;
            }
            case DETECT_ICODE: {
                const DetectU8Data *cd = (const DetectU8Data *)smd->ctx;
                SCJbOpenObject(js, "code");
                SCDetectU8ToJson(js, cd);
                SCJbClose(js);
                break;
            }
            case DETECT_ICMP_ID: {
                const DetectIcmpIdData *cd = (const DetectIcmpIdData *)smd->ctx;
                SCJbOpenObject(js, "id");
                SCJbSetUint(js, "number", SCNtohs(cd->id));
                SCJbClose(js);
                break;
            }
            case DETECT_WINDOW: {
                const DetectWindowData *wd = (const DetectWindowData *)smd->ctx;
                SCJbOpenObject(js, "window");
                SCJbSetUint(js, "size", wd->size);
                SCJbSetBool(js, "negated", wd->negated);
                SCJbClose(js);
                break;
            }
            case DETECT_FLOW_AGE: {
                const DetectU32Data *cd = (const DetectU32Data *)smd->ctx;
                SCJbOpenObject(js, "flow_age");
                SCDetectU32ToJson(js, cd);
                SCJbClose(js);
                break;
            }
        }
        SCJbClose(js);

        if (smd->is_last)
            break;
        smd++;
    } while (1);
    SCJbClose(js);
}

SCMutex g_rules_analyzer_write_m = SCMUTEX_INITIALIZER;
void EngineAnalysisRules2(const DetectEngineCtx *de_ctx, const Signature *s)
{
    SCEnter();

    RuleAnalyzer ctx = { NULL, NULL, NULL };

    ctx.js = SCJbNewObject();
    if (ctx.js == NULL)
        SCReturn;

    if (s->init_data->firewall_rule) {
        JB_SET_STRING(ctx.js, "class", "firewall");
    } else {
        JB_SET_STRING(ctx.js, "class", "threat detection");
    }

    SCJbSetString(ctx.js, "raw", s->sig_str);
    SCJbSetUint(ctx.js, "id", s->id);
    SCJbSetUint(ctx.js, "gid", s->gid);
    SCJbSetUint(ctx.js, "rev", s->rev);
    SCJbSetString(ctx.js, "msg", s->msg);

    const char *alproto = AppProtoToString(s->alproto);
    SCJbSetString(ctx.js, "app_proto", alproto);

    SCJbOpenArray(ctx.js, "requirements");
    if (s->mask & SIG_MASK_REQUIRE_PAYLOAD) {
        SCJbAppendString(ctx.js, "payload");
    }
    if (s->mask & SIG_MASK_REQUIRE_NO_PAYLOAD) {
        SCJbAppendString(ctx.js, "no_payload");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLOW) {
        SCJbAppendString(ctx.js, "flow");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLAGS_INITDEINIT) {
        SCJbAppendString(ctx.js, "tcp_flags_init_deinit");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLAGS_UNUSUAL) {
        SCJbAppendString(ctx.js, "tcp_flags_unusual");
    }
    if (s->mask & SIG_MASK_REQUIRE_ENGINE_EVENT) {
        SCJbAppendString(ctx.js, "engine_event");
    }
    if (s->mask & SIG_MASK_REQUIRE_REAL_PKT) {
        SCJbAppendString(ctx.js, "real_pkt");
    }
    SCJbClose(ctx.js);

    SCJbOpenObject(ctx.js, "match_policy");
    SCJbOpenArray(ctx.js, "actions");
    if (s->action & ACTION_ALERT) {
        SCJbAppendString(ctx.js, "alert");
    }
    if (s->action & ACTION_DROP) {
        SCJbAppendString(ctx.js, "drop");
    }
    if (s->action & ACTION_REJECT) {
        SCJbAppendString(ctx.js, "reject");
    }
    if (s->action & ACTION_REJECT_DST) {
        SCJbAppendString(ctx.js, "reject_dst");
    }
    if (s->action & ACTION_REJECT_BOTH) {
        SCJbAppendString(ctx.js, "reject_both");
    }
    if (s->action & ACTION_CONFIG) {
        SCJbAppendString(ctx.js, "config");
    }
    if (s->action & ACTION_PASS) {
        SCJbAppendString(ctx.js, "pass");
    }
    if (s->action & ACTION_ACCEPT) {
        SCJbAppendString(ctx.js, "accept");
    }
    SCJbClose(ctx.js);

    if (s->action_scope == ACTION_SCOPE_AUTO) {
        enum SignaturePropertyFlowAction flow_action = signature_properties[s->type].flow_action;
        switch (flow_action) {
            case SIG_PROP_FLOW_ACTION_PACKET:
                SCJbSetString(ctx.js, "scope", "packet");
                break;
            case SIG_PROP_FLOW_ACTION_FLOW:
                SCJbSetString(ctx.js, "scope", "flow");
                break;
            case SIG_PROP_FLOW_ACTION_FLOW_IF_STATEFUL:
                SCJbSetString(ctx.js, "scope", "flow_if_stateful");
                break;
        }
    } else {
        enum ActionScope as = s->action_scope;
        switch (as) {
            case ACTION_SCOPE_PACKET:
                SCJbSetString(ctx.js, "scope", "packet");
                break;
            case ACTION_SCOPE_FLOW:
                SCJbSetString(ctx.js, "scope", "flow");
                break;
            case ACTION_SCOPE_HOOK:
                SCJbSetString(ctx.js, "scope", "hook");
                break;
            case ACTION_SCOPE_TX:
                SCJbSetString(ctx.js, "scope", "tx");
                break;
            case ACTION_SCOPE_AUTO: /* should be unreachable */
                break;
        }
    }
    SCJbClose(ctx.js);

    switch (s->type) {
        case SIG_TYPE_NOT_SET:
            SCJbSetString(ctx.js, "type", "unset");
            break;
        case SIG_TYPE_IPONLY:
            SCJbSetString(ctx.js, "type", "ip_only");
            break;
        case SIG_TYPE_LIKE_IPONLY:
            SCJbSetString(ctx.js, "type", "like_ip_only");
            break;
        case SIG_TYPE_PDONLY:
            SCJbSetString(ctx.js, "type", "pd_only");
            break;
        case SIG_TYPE_DEONLY:
            SCJbSetString(ctx.js, "type", "de_only");
            break;
        case SIG_TYPE_PKT:
            SCJbSetString(ctx.js, "type", "pkt");
            break;
        case SIG_TYPE_PKT_STREAM:
            SCJbSetString(ctx.js, "type", "pkt_stream");
            break;
        case SIG_TYPE_STREAM:
            SCJbSetString(ctx.js, "type", "stream");
            break;
        case SIG_TYPE_APPLAYER:
            SCJbSetString(ctx.js, "type", "app_layer");
            break;
        case SIG_TYPE_APP_TX:
            SCJbSetString(ctx.js, "type", "app_tx");
            break;
        case SIG_TYPE_MAX:
            SCJbSetString(ctx.js, "type", "error");
            break;
    }

    // dependencies object and its subfields only logged if we have values
    if (s->init_data->is_rule_state_dependant) {
        SCJbOpenObject(ctx.js, "dependencies");
        SCJbOpenObject(ctx.js, "flowbits");
        SCJbOpenObject(ctx.js, "upstream");
        if (s->init_data->rule_state_dependant_sids_size > 0) {
            SCJbOpenObject(ctx.js, "state_modifying_rules");
            SCJbOpenArray(ctx.js, "sids");
            for (uint32_t i = 0; i < s->init_data->rule_state_dependant_sids_idx; i++) {
                SCJbAppendUint(ctx.js, s->init_data->rule_state_dependant_sids_array[i]);
            }
            SCJbClose(ctx.js); // sids
            SCJbOpenArray(ctx.js, "names");
            for (uint32_t i = 0; i < s->init_data->rule_state_flowbits_ids_size - 1; i++) {
                if (s->init_data->rule_state_flowbits_ids_array[i] != 0) {
                    SCJbAppendString(ctx.js,
                            VarNameStoreSetupLookup(s->init_data->rule_state_flowbits_ids_array[i],
                                    VAR_TYPE_FLOW_BIT));
                }
            }
            SCJbClose(ctx.js); // names
            SCJbClose(ctx.js); // state_modifying_rules
        }
        SCJbClose(ctx.js); // upstream
        SCJbClose(ctx.js); // flowbits
        SCJbClose(ctx.js); // dependencies
    }

    SCJbOpenArray(ctx.js, "flags");
    if (s->flags & SIG_FLAG_SRC_ANY) {
        SCJbAppendString(ctx.js, "src_any");
    }
    if (s->flags & SIG_FLAG_DST_ANY) {
        SCJbAppendString(ctx.js, "dst_any");
    }
    if (s->flags & SIG_FLAG_SP_ANY) {
        SCJbAppendString(ctx.js, "sp_any");
    }
    if (s->flags & SIG_FLAG_DP_ANY) {
        SCJbAppendString(ctx.js, "dp_any");
    }
    if ((s->action & ACTION_ALERT) == 0) {
        SCJbAppendString(ctx.js, "noalert");
    }
    if (s->flags & SIG_FLAG_DSIZE) {
        SCJbAppendString(ctx.js, "dsize");
    }
    if (s->flags & SIG_FLAG_APPLAYER) {
        SCJbAppendString(ctx.js, "applayer");
    }
    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        SCJbAppendString(ctx.js, "need_packet");
    }
    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        SCJbAppendString(ctx.js, "need_stream");
    }
    if (s->flags & SIG_FLAG_MPM_NEG) {
        SCJbAppendString(ctx.js, "negated_mpm");
    }
    if (s->flags & SIG_FLAG_FLUSH) {
        SCJbAppendString(ctx.js, "flush");
    }
    if (s->flags & SIG_FLAG_REQUIRE_FLOWVAR) {
        SCJbAppendString(ctx.js, "need_flowvar");
    }
    if (s->flags & SIG_FLAG_FILESTORE) {
        SCJbAppendString(ctx.js, "filestore");
    }
    if (s->flags & SIG_FLAG_TOSERVER) {
        SCJbAppendString(ctx.js, "toserver");
    }
    if (s->flags & SIG_FLAG_TOCLIENT) {
        SCJbAppendString(ctx.js, "toclient");
    }
    if (s->flags & SIG_FLAG_TLSSTORE) {
        SCJbAppendString(ctx.js, "tlsstore");
    }
    if (s->flags & SIG_FLAG_BYPASS) {
        SCJbAppendString(ctx.js, "bypass");
    }
    if (s->flags & SIG_FLAG_PREFILTER) {
        SCJbAppendString(ctx.js, "prefilter");
    }
    if (s->flags & SIG_FLAG_SRC_IS_TARGET) {
        SCJbAppendString(ctx.js, "src_is_target");
    }
    if (s->flags & SIG_FLAG_DEST_IS_TARGET) {
        SCJbAppendString(ctx.js, "dst_is_target");
    }
    SCJbClose(ctx.js);

    const DetectEnginePktInspectionEngine *pkt_mpm = NULL;
    const DetectEngineAppInspectionEngine *app_mpm = NULL;

    SCJbOpenArray(ctx.js, "pkt_engines");
    const DetectEnginePktInspectionEngine *pkt = s->pkt_inspect;
    for ( ; pkt != NULL; pkt = pkt->next) {
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, pkt->sm_list);
        if (name == NULL) {
            switch (pkt->sm_list) {
                case DETECT_SM_LIST_PMATCH:
                    name = "payload";
                    break;
                case DETECT_SM_LIST_MATCH:
                    name = "packet";
                    break;
                default:
                    name = "unknown";
                    break;
            }
        }
        SCJbStartObject(ctx.js);
        SCJbSetString(ctx.js, "name", name);
        SCJbSetBool(ctx.js, "is_mpm", pkt->mpm);
        if (pkt->v1.transforms != NULL) {
            SCJbOpenArray(ctx.js, "transforms");
            for (int t = 0; t < pkt->v1.transforms->cnt; t++) {
                SCJbStartObject(ctx.js);
                SCJbSetString(ctx.js, "name",
                        sigmatch_table[pkt->v1.transforms->transforms[t].transform].name);
                SCJbClose(ctx.js);
            }
            SCJbClose(ctx.js);
        }
        DumpMatches(&ctx, ctx.js, pkt->smd);
        SCJbClose(ctx.js);
        if (pkt->mpm) {
            pkt_mpm = pkt;
        }
    }
    SCJbClose(ctx.js);
    SCJbOpenArray(ctx.js, "frame_engines");
    const DetectEngineFrameInspectionEngine *frame = s->frame_inspect;
    for (; frame != NULL; frame = frame->next) {
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, frame->sm_list);
        SCJbStartObject(ctx.js);
        SCJbSetString(ctx.js, "name", name);
        SCJbSetBool(ctx.js, "is_mpm", frame->mpm);
        if (frame->v1.transforms != NULL) {
            SCJbOpenArray(ctx.js, "transforms");
            for (int t = 0; t < frame->v1.transforms->cnt; t++) {
                SCJbStartObject(ctx.js);
                SCJbSetString(ctx.js, "name",
                        sigmatch_table[frame->v1.transforms->transforms[t].transform].name);
                SCJbClose(ctx.js);
            }
            SCJbClose(ctx.js);
        }
        DumpMatches(&ctx, ctx.js, frame->smd);
        SCJbClose(ctx.js);
    }
    SCJbClose(ctx.js);

    if (s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH) {
        bool has_stream = false;
        bool has_client_body_mpm = false;
        bool has_file_data_mpm = false;

        SCJbOpenArray(ctx.js, "engines");
        const DetectEngineAppInspectionEngine *app = s->app_inspect;
        for ( ; app != NULL; app = app->next) {
            const char *name = DetectEngineBufferTypeGetNameById(de_ctx, app->sm_list);
            if (name == NULL) {
                switch (app->sm_list) {
                    case DETECT_SM_LIST_PMATCH:
                        name = "stream";
                        break;
                    default:
                        name = "unknown";
                        break;
                }
            }

            if (app->sm_list == DETECT_SM_LIST_PMATCH && !app->mpm) {
                has_stream = true;
            } else if (app->mpm && strcmp(name, "http_client_body") == 0) {
                has_client_body_mpm = true;
            } else if (app->mpm && strcmp(name, "file_data") == 0) {
                has_file_data_mpm = true;
            }

            SCJbStartObject(ctx.js);
            SCJbSetString(ctx.js, "name", name);
            const char *direction = app->dir == 0 ? "toserver" : "toclient";
            SCJbSetString(ctx.js, "direction", direction);
            SCJbSetBool(ctx.js, "is_mpm", app->mpm);
            SCJbSetString(ctx.js, "app_proto", AppProtoToString(app->alproto));
            SCJbSetUint(ctx.js, "progress", app->progress);

            if (app->v2.transforms != NULL) {
                SCJbOpenArray(ctx.js, "transforms");
                for (int t = 0; t < app->v2.transforms->cnt; t++) {
                    SCJbStartObject(ctx.js);
                    SCJbSetString(ctx.js, "name",
                            sigmatch_table[app->v2.transforms->transforms[t].transform].name);
                    SCJbClose(ctx.js);
                }
                SCJbClose(ctx.js);
            }
            DumpMatches(&ctx, ctx.js, app->smd);
            SCJbClose(ctx.js);
            if (app->mpm) {
                app_mpm = app;
            }
        }
        SCJbClose(ctx.js);

        if (has_stream && has_client_body_mpm)
            AnalyzerNote(&ctx, (char *)"mpm in http_client_body combined with stream match leads to stream buffering");
        if (has_stream && has_file_data_mpm)
            AnalyzerNote(&ctx, (char *)"mpm in file_data combined with stream match leads to stream buffering");
    }

    SCJbOpenObject(ctx.js, "lists");
    for (int i = 0; i < DETECT_SM_LIST_MAX; i++) {
        if (s->sm_arrays[i] != NULL) {
            SCJbOpenObject(ctx.js, DetectListToHumanString(i));
            DumpMatches(&ctx, ctx.js, s->sm_arrays[i]);
            SCJbClose(ctx.js);
        }
    }
    SCJbClose(ctx.js);

    if (pkt_mpm || app_mpm) {
        SCJbOpenObject(ctx.js, "mpm");

        int mpm_list = pkt_mpm ? DETECT_SM_LIST_PMATCH : app_mpm->sm_list;
        const char *name;
        if (mpm_list < DETECT_SM_LIST_DYNAMIC_START)
            name = DetectListToHumanString(mpm_list);
        else
            name = DetectEngineBufferTypeGetNameById(de_ctx, mpm_list);
        SCJbSetString(ctx.js, "buffer", name);

        SigMatchData *smd = pkt_mpm ? pkt_mpm->smd : app_mpm->smd;
        if (smd == NULL && mpm_list == DETECT_SM_LIST_PMATCH) {
            smd = s->sm_arrays[mpm_list];
        }
        do {
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;
                    if (cd->flags & DETECT_CONTENT_MPM) {
                        DumpContent(ctx.js, cd);
                    }
                    break;
                }
            }

            if (smd->is_last)
                break;
            smd++;
        } while (1);
        SCJbClose(ctx.js);
    } else if (s->init_data->prefilter_sm) {
        SCJbOpenObject(ctx.js, "prefilter");
        int prefilter_list = SigMatchListSMBelongsTo(s, s->init_data->prefilter_sm);
        const char *name;
        if (prefilter_list < DETECT_SM_LIST_DYNAMIC_START)
            name = DetectListToHumanString(prefilter_list);
        else
            name = DetectEngineBufferTypeGetNameById(de_ctx, prefilter_list);
        SCJbSetString(ctx.js, "buffer", name);
        const char *mname = sigmatch_table[s->init_data->prefilter_sm->type].name;
        SCJbSetString(ctx.js, "name", mname);
        SCJbClose(ctx.js);
    }

    if (ctx.js_warnings) {
        SCJbClose(ctx.js_warnings);
        SCJbSetObject(ctx.js, "warnings", ctx.js_warnings);
        SCJbFree(ctx.js_warnings);
        ctx.js_warnings = NULL;
    }
    if (ctx.js_notes) {
        SCJbClose(ctx.js_notes);
        SCJbSetObject(ctx.js, "notes", ctx.js_notes);
        SCJbFree(ctx.js_notes);
        ctx.js_notes = NULL;
    }
    SCJbClose(ctx.js);

    const char *filename = "rules.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char json_path[PATH_MAX] = "";
    snprintf(json_path, sizeof(json_path), "%s/%s%s", log_dir,
            de_ctx->ea->file_prefix ? de_ctx->ea->file_prefix : "", filename);

    SCMutexLock(&g_rules_analyzer_write_m);
    FILE *fp = fopen(json_path, "a");
    if (fp != NULL) {
        fwrite(SCJbPtr(ctx.js), SCJbLen(ctx.js), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_rules_analyzer_write_m);
    SCJbFree(ctx.js);
    SCReturn;
}

void DumpPatterns(DetectEngineCtx *de_ctx)
{
    if (de_ctx->pattern_hash_table == NULL)
        return;

    SCJsonBuilder *root_jb = SCJbNewObject();
    SCJsonBuilder *arrays[de_ctx->buffer_type_id];
    memset(&arrays, 0, sizeof(SCJsonBuilder *) * de_ctx->buffer_type_id);

    SCJbOpenArray(root_jb, "buffers");

    for (HashListTableBucket *htb = HashListTableGetListHead(de_ctx->pattern_hash_table);
            htb != NULL; htb = HashListTableGetListNext(htb)) {
        char str[1024] = "";
        DetectPatternTracker *p = HashListTableGetListData(htb);
        DetectContentPatternPrettyPrint(p->cd, str, sizeof(str));

        SCJsonBuilder *jb = arrays[p->sm_list];
        if (arrays[p->sm_list] == NULL) {
            jb = arrays[p->sm_list] = SCJbNewObject();
            const char *name;
            if (p->sm_list < DETECT_SM_LIST_DYNAMIC_START)
                name = DetectListToHumanString(p->sm_list);
            else
                name = DetectEngineBufferTypeGetNameById(de_ctx, p->sm_list);
            SCJbSetString(jb, "name", name);
            SCJbSetUint(jb, "list_id", p->sm_list);

            SCJbOpenArray(jb, "patterns");
        }

        SCJbStartObject(jb);
        SCJbSetString(jb, "pattern", str);
        SCJbSetUint(jb, "patlen", p->cd->content_len);
        SCJbSetUint(jb, "cnt", p->cnt);
        SCJbSetUint(jb, "mpm", p->mpm);
        SCJbOpenObject(jb, "flags");
        SCJbSetBool(jb, "nocase", p->cd->flags & DETECT_CONTENT_NOCASE);
        SCJbSetBool(jb, "negated", p->cd->flags & DETECT_CONTENT_NEGATED);
        SCJbSetBool(jb, "depth", p->cd->flags & DETECT_CONTENT_DEPTH);
        SCJbSetBool(jb, "offset", p->cd->flags & DETECT_CONTENT_OFFSET);
        SCJbSetBool(jb, "endswith", p->cd->flags & DETECT_CONTENT_ENDS_WITH);
        SCJbClose(jb);
        SCJbClose(jb);
    }

    for (uint32_t i = 0; i < de_ctx->buffer_type_id; i++) {
        SCJsonBuilder *jb = arrays[i];
        if (jb == NULL)
            continue;

        SCJbClose(jb); // array
        SCJbClose(jb); // object

        SCJbAppendObject(root_jb, jb);
        SCJbFree(jb);
    }
    SCJbClose(root_jb);
    SCJbClose(root_jb);

    const char *filename = "patterns.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char json_path[PATH_MAX] = "";
    snprintf(json_path, sizeof(json_path), "%s/%s%s", log_dir,
            de_ctx->ea->file_prefix ? de_ctx->ea->file_prefix : "", filename);

    SCMutexLock(&g_rules_analyzer_write_m);
    FILE *fp = fopen(json_path, "a");
    if (fp != NULL) {
        fwrite(SCJbPtr(root_jb), SCJbLen(root_jb), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_rules_analyzer_write_m);
    SCJbFree(root_jb);

    HashListTableFree(de_ctx->pattern_hash_table);
    de_ctx->pattern_hash_table = NULL;
}

static void EngineAnalysisItemsReset(EngineAnalysisCtx *ea_ctx)
{
    for (size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
        ea_ctx->analyzer_items[i].item_seen = false;
    }
}

static void EngineAnalysisItemsInit(EngineAnalysisCtx *ea_ctx)
{
    if (ea_ctx->analyzer_initialized) {
        EngineAnalysisItemsReset(ea_ctx);
        return;
    }

    ea_ctx->exposed_item_seen_list[0].bufname = "http_method";
    ea_ctx->exposed_item_seen_list[1].bufname = "file_data";
    ea_ctx->analyzer_items = SCCalloc(1, sizeof(analyzer_items));
    if (!ea_ctx->analyzer_items) {
        FatalError("Unable to allocate analysis scratch pad");
    }
    memset(ea_ctx->analyzer_item_map, -1, sizeof(ea_ctx->analyzer_item_map));

    for (size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
        ea_ctx->analyzer_items[i] = analyzer_items[i];
        DetectEngineAnalyzerItems *analyzer_item = &ea_ctx->analyzer_items[i];

        int item_id = DetectBufferTypeGetByName(analyzer_item->item_name);
        DEBUG_VALIDATE_BUG_ON(item_id < 0 || item_id > UINT16_MAX);
        analyzer_item->item_id = (uint16_t)item_id;
        if (analyzer_item->item_id == -1) {
            /* Mismatch between the analyzer_items array and what's supported */
            FatalError("unable to initialize engine-analysis table: detect buffer \"%s\" not "
                       "recognized.",
                    analyzer_item->item_name);
        }
        analyzer_item->item_seen = false;

        if (analyzer_item->export_item_seen) {
            for (size_t k = 0; k < ARRAY_SIZE(ea_ctx->exposed_item_seen_list); k++) {
                if (0 ==
                        strcmp(ea_ctx->exposed_item_seen_list[k].bufname, analyzer_item->item_name))
                    ea_ctx->exposed_item_seen_list[k].item_seen_ptr = &analyzer_item->item_seen;
            }
        }
        ea_ctx->analyzer_item_map[analyzer_item->item_id] = (int16_t)i;
    }

    ea_ctx->analyzer_initialized = true;
}

/**
 * \brief Prints analysis of loaded rules.
 *
 *        Warns if potential rule issues are detected. For example,
 *        warns if a rule uses a construct that may perform poorly,
 *        e.g. pcre without content or with http_method content only;
 *        warns if a rule uses a construct that may not be consistent with intent,
 *        e.g. client side ports only, http and content without any http_* modifiers, etc.
 *
 * \param s Pointer to the signature.
 */
void EngineAnalysisRules(const DetectEngineCtx *de_ctx,
        const Signature *s, const char *line)
{
    uint32_t rule_bidirectional = 0;
    uint32_t rule_pcre = 0;
    uint32_t rule_pcre_http = 0;
    uint32_t rule_content = 0;
    uint32_t rule_flow = 0;
    uint32_t rule_flags = 0;
    uint32_t rule_flow_toserver = 0;
    uint32_t rule_flow_toclient = 0;
    uint32_t rule_flow_nostream = 0;
    uint32_t rule_ipv4_only = 0;
    uint32_t rule_ipv6_only = 0;
    uint32_t rule_flowbits = 0;
    uint32_t rule_flowint = 0;
    uint32_t rule_content_http = 0;
    uint32_t rule_content_offset_depth = 0;
    int32_t list_id = 0;
    uint32_t rule_warning = 0;
    uint32_t stream_buf = 0;
    uint32_t packet_buf = 0;
    uint32_t file_store = 0;
    uint32_t warn_pcre_no_content = 0;
    uint32_t warn_pcre_http_content = 0;
    uint32_t warn_pcre_http = 0;
    uint32_t warn_content_http_content = 0;
    uint32_t warn_content_http = 0;
    uint32_t warn_tcp_no_flow = 0;
    uint32_t warn_client_ports = 0;
    uint32_t warn_direction = 0;
    uint32_t warn_method_toclient = 0;
    uint32_t warn_method_serverbody = 0;
    uint32_t warn_pcre_method = 0;
    uint32_t warn_encoding_norm_http_buf = 0;
    uint32_t warn_file_store_not_present = 0;
    uint32_t warn_offset_depth_pkt_stream = 0;
    uint32_t warn_offset_depth_alproto = 0;
    uint32_t warn_non_alproto_fp_for_alproto_sig = 0;
    uint32_t warn_no_direction = 0;
    uint32_t warn_both_direction = 0;

    EngineAnalysisItemsInit(de_ctx->ea);

    bool *http_method_item_seen_ptr = de_ctx->ea->exposed_item_seen_list[0].item_seen_ptr;
    bool *http_server_body_item_seen_ptr = de_ctx->ea->exposed_item_seen_list[1].item_seen_ptr;

    if (s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        rule_bidirectional = 1;
    }

    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        packet_buf += 1;
    }
    if (s->flags & SIG_FLAG_FILESTORE) {
        file_store += 1;
    }
    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        stream_buf += 1;
    }

    if (s->proto.flags & DETECT_PROTO_IPV4) {
        rule_ipv4_only += 1;
    }
    if (s->proto.flags & DETECT_PROTO_IPV6) {
        rule_ipv6_only += 1;
    }

    for (list_id = 0; list_id < DETECT_SM_LIST_MAX; list_id++) {
        SigMatch *sm = NULL;
        for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) {
            int16_t item_slot = de_ctx->ea->analyzer_item_map[list_id];
            if (sm->type == DETECT_PCRE) {
                if (item_slot == -1) {
                    rule_pcre++;
                    continue;
                }

                rule_pcre_http++;
                de_ctx->ea->analyzer_items[item_slot].item_seen = true;
            } else if (sm->type == DETECT_CONTENT) {
                if (item_slot == -1) {
                    rule_content++;
                    if (list_id == DETECT_SM_LIST_PMATCH) {
                        DetectContentData *cd = (DetectContentData *)sm->ctx;
                        if (cd->flags & (DETECT_CONTENT_OFFSET | DETECT_CONTENT_DEPTH)) {
                            rule_content_offset_depth++;
                        }
                    }
                    continue;
                }

                rule_content_http++;
                de_ctx->ea->analyzer_items[item_slot].item_seen = true;

                if (de_ctx->ea->analyzer_items[item_slot].check_encoding_match) {
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd != NULL &&
                            PerCentEncodingMatch(de_ctx->ea, cd->content, cd->content_len) > 0) {
                        warn_encoding_norm_http_buf += 1;
                    }
                }
            }
            else if (sm->type == DETECT_FLOW) {
                rule_flow += 1;
                if ((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_TOCLIENT)) {
                    rule_flow_toserver = 1;
                }
                else if ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_TOSERVER)) {
                    rule_flow_toclient = 1;
                }
                DetectFlowData *fd = (DetectFlowData *)sm->ctx;
                if (fd != NULL) {
                    if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM)
                        rule_flow_nostream = 1;
                }
            }
            else if (sm->type == DETECT_FLOWBITS) {
                if (list_id == DETECT_SM_LIST_MATCH) {
                    rule_flowbits += 1;
                }
            }
            else if (sm->type == DETECT_FLOWINT) {
                if (list_id == DETECT_SM_LIST_MATCH) {
                    rule_flowint += 1;
                }
            }
            else if (sm->type == DETECT_FLAGS) {
                DetectFlagsData *fd = (DetectFlagsData *)sm->ctx;
                if (fd != NULL) {
                    rule_flags = 1;
                }
            }
        } /* for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) */

    } /* for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) */

    if (file_store && !RequiresFeature("output::file-store")) {
        rule_warning += 1;
        warn_file_store_not_present = 1;
    }

    if (rule_pcre > 0 && rule_content == 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_pcre_no_content = 1;
    }

    if (rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http_content = 1;
    } else if (s->alproto == ALPROTO_HTTP1 && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http = 1;
    }

    if (rule_content > 0 && rule_content_http > 0) {
        rule_warning += 1;
        warn_content_http_content = 1;
    }
    if (s->alproto == ALPROTO_HTTP1 && rule_content > 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_content_http = 1;
    }
    if (rule_content == 1) {
         //todo: warning if content is weak, separate warning for pcre + weak content
    }
    if (rule_flow == 0 && rule_flags == 0 && !(s->proto.flags & DETECT_PROTO_ANY) &&
            DetectProtoContainsProto(&s->proto, IPPROTO_TCP) &&
            (rule_content || rule_content_http || rule_pcre || rule_pcre_http || rule_flowbits ||
                    rule_flowint)) {
        rule_warning += 1;
        warn_tcp_no_flow = 1;
    }
    if (rule_flow && !rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)
                  && !((s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))) {
        if (((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))
          || ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_DP_ANY) && (s->flags & SIG_FLAG_SP_ANY))) {
            rule_warning += 1;
            warn_client_ports = 1;
        }
    }
    if (rule_flow && rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)) {
        rule_warning += 1;
        warn_direction = 1;
    }

    if (*http_method_item_seen_ptr) {
        if (rule_flow && rule_flow_toclient) {
            rule_warning += 1;
            warn_method_toclient = 1;
        }
        if (*http_server_body_item_seen_ptr) {
            rule_warning += 1;
            warn_method_serverbody = 1;
        }
        if (rule_content == 0 && rule_content_http == 0 && (rule_pcre > 0 || rule_pcre_http > 0)) {
            rule_warning += 1;
            warn_pcre_method = 1;
        }
    }
    if (rule_content_offset_depth > 0 && stream_buf && packet_buf) {
        rule_warning += 1;
        warn_offset_depth_pkt_stream = 1;
    }
    if (rule_content_offset_depth > 0 && !stream_buf && packet_buf && s->alproto != ALPROTO_UNKNOWN) {
        rule_warning += 1;
        warn_offset_depth_alproto = 1;
    }
    if (s->init_data->mpm_sm != NULL && s->alproto == ALPROTO_HTTP1 &&
            s->init_data->mpm_sm_list == DETECT_SM_LIST_PMATCH) {
        rule_warning += 1;
        warn_non_alproto_fp_for_alproto_sig = 1;
    }

    if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == 0) {
        warn_no_direction += 1;
        rule_warning += 1;
    }

    /* No warning about direction for ICMP protos */
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_ICMPV6) && DetectProtoContainsProto(&s->proto, IPPROTO_ICMP))) {
        if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) {
            warn_both_direction += 1;
            rule_warning += 1;
        }
    }

    if (!rule_warnings_only || (rule_warnings_only && rule_warning > 0)) {
        FILE *fp = de_ctx->ea->rule_engine_analysis_fp;
        fprintf(fp, "== Sid: %u ==\n", s->id);
        fprintf(fp, "%s\n", line);

        switch (s->type) {
            case SIG_TYPE_NOT_SET:
                break;
            case SIG_TYPE_IPONLY:
                fprintf(fp, "    Rule is ip only.\n");
                break;
            case SIG_TYPE_LIKE_IPONLY:
                fprintf(fp, "    Rule is like ip only.\n");
                break;
            case SIG_TYPE_PDONLY:
                fprintf(fp, "    Rule is PD only.\n");
                break;
            case SIG_TYPE_DEONLY:
                fprintf(fp, "    Rule is DE only.\n");
                break;
            case SIG_TYPE_PKT:
                fprintf(fp, "    Rule is packet inspecting.\n");
                break;
            case SIG_TYPE_PKT_STREAM:
                fprintf(fp, "    Rule is packet and stream inspecting.\n");
                break;
            case SIG_TYPE_STREAM:
                fprintf(fp, "    Rule is stream inspecting.\n");
                break;
            case SIG_TYPE_APPLAYER:
                fprintf(fp, "    Rule is app-layer inspecting.\n");
                break;
            case SIG_TYPE_APP_TX:
                fprintf(fp, "    Rule is App-layer TX inspecting.\n");
                break;
            case SIG_TYPE_MAX:
                break;
        }
        if (rule_ipv6_only)
            fprintf(fp, "    Rule is IPv6 only.\n");
        if (rule_ipv4_only)
            fprintf(fp, "    Rule is IPv4 only.\n");
        if (packet_buf)
            fprintf(fp, "    Rule matches on packets.\n");
        if (!rule_flow_nostream && stream_buf &&
                (rule_flow || rule_flowbits || rule_flowint || rule_content || rule_pcre)) {
            fprintf(fp, "    Rule matches on reassembled stream.\n");
        }
        for(size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
            DetectEngineAnalyzerItems *ai = &de_ctx->ea->analyzer_items[i];
            if (ai->item_seen) {
                fprintf(fp, "    Rule matches on %s buffer.\n", ai->display_name);
            }
        }
        if (s->alproto != ALPROTO_UNKNOWN) {
            fprintf(fp, "    App layer protocol is %s.\n", AppProtoToString(s->alproto));
        }
        if (rule_content || rule_content_http || rule_pcre || rule_pcre_http) {
            fprintf(fp,
                    "    Rule contains %u content options, %u http content options, %u pcre "
                    "options, and %u pcre options with http modifiers.\n",
                    rule_content, rule_content_http, rule_pcre, rule_pcre_http);
        }

        /* print fast pattern info */
        if (s->init_data->prefilter_sm) {
            fprintf(fp, "    Prefilter on: %s.\n",
                    sigmatch_table[s->init_data->prefilter_sm->type].name);
        } else {
            EngineAnalysisRulesPrintFP(de_ctx, s);
        }

        /* this is where the warnings start */
        if (warn_pcre_no_content /*rule_pcre > 0 && rule_content == 0 && rule_content_http == 0*/) {
            fprintf(fp, "    Warning: Rule uses pcre without a content option present.\n"
                        "             -Consider adding a content to improve performance of this "
                        "rule.\n");
        }
        if (warn_pcre_http_content /*rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0*/) {
            fprintf(fp, "    Warning: Rule uses content options with http_* and pcre options "
                        "without http modifiers.\n"
                        "             -Consider adding http pcre modifier.\n");
        }
        else if (warn_pcre_http /*s->alproto == ALPROTO_HTTP1 && rule_pcre > 0 && rule_pcre_http == 0*/) {
            fprintf(fp, "    Warning: Rule app layer protocol is http, but pcre options do not "
                        "have http modifiers.\n"
                        "             -Consider adding http pcre modifiers.\n");
        }
        if (warn_content_http_content /*rule_content > 0 && rule_content_http > 0*/) {
            fprintf(fp,
                    "    Warning: Rule contains content with http_* and content without http_*.\n"
                    "             -Consider adding http content modifiers.\n");
        }
        if (warn_content_http /*s->alproto == ALPROTO_HTTP1 && rule_content > 0 && rule_content_http == 0*/) {
            fprintf(fp, "    Warning: Rule app layer protocol is http, but content options do not "
                        "have http_* modifiers.\n"
                        "             -Consider adding http content modifiers.\n");
        }
        if (rule_content == 1) {
             //todo: warning if content is weak, separate warning for pcre + weak content
        }
        if (warn_encoding_norm_http_buf) {
            fprintf(fp, "    Warning: Rule may contain percent encoded content for a normalized "
                        "http buffer match.\n");
        }
        if (warn_tcp_no_flow /*rule_flow == 0 && rule_flags == 0
                && !(s->proto.flags & DETECT_PROTO_ANY) && DetectProtoContainsProto(&s->proto, IPPROTO_TCP)*/) {
            fprintf(fp, "    Warning: TCP rule without a flow or flags option.\n"
                        "             -Consider adding flow or flags to improve performance of "
                        "this rule.\n");
        }
        if (warn_client_ports /*rule_flow && !rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)
                      && !((s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY)))
            if (((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))
                || ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_DP_ANY) && (s->flags & SIG_FLAG_SP_ANY))*/) {
            fprintf(fp,
                    "    Warning: Rule contains ports or port variables only on the client side.\n"
                    "             -Flow direction possibly inconsistent with rule.\n");
        }
        if (warn_direction /*rule_flow && rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)*/) {
            fprintf(fp, "    Warning: Rule is bidirectional and has a flow option with a specific "
                        "direction.\n");
        }
        if (warn_method_toclient /*http_method_buf && rule_flow && rule_flow_toclient*/) {
            fprintf(fp, "    Warning: Rule uses content or pcre for http_method with "
                        "flow:to_client or from_server\n");
        }
        if (warn_method_serverbody /*http_method_buf && http_server_body_buf*/) {
            fprintf(fp, "    Warning: Rule uses content or pcre for http_method with content or "
                        "pcre for http_server_body.\n");
        }
        if (warn_pcre_method /*http_method_buf && rule_content == 0 && rule_content_http == 0
                               && (rule_pcre > 0 || rule_pcre_http > 0)*/) {
            fprintf(fp, "    Warning: Rule uses pcre with only a http_method content; possible "
                        "performance issue.\n");
        }
        if (warn_offset_depth_pkt_stream) {
            fprintf(fp, "    Warning: Rule has depth"
                        "/offset with raw content keywords.  Please note the "
                        "offset/depth will be checked against both packet "
                        "payloads and stream.  If you meant to have the offset/"
                        "depth checked against just the payload, you can update "
                        "the signature as \"alert tcp-pkt...\"\n");
        }
        if (warn_offset_depth_alproto) {
            fprintf(fp,
                    "    Warning: Rule has "
                    "offset/depth set along with a match on a specific "
                    "app layer protocol - %d.  This can lead to FNs if we "
                    "have a offset/depth content match on a packet payload "
                    "before we can detect the app layer protocol for the "
                    "flow.\n",
                    s->alproto);
        }
        if (warn_non_alproto_fp_for_alproto_sig) {
            fprintf(fp, "    Warning: Rule app layer "
                        "protocol is http, but the fast_pattern is set on the raw "
                        "stream.  Consider adding fast_pattern over a http "
                        "buffer for increased performance.");
        }
        if (warn_no_direction) {
            fprintf(fp, "    Warning: Rule has no direction indicator.\n");
        }
        if (warn_both_direction) {
            fprintf(fp, "    Warning: Rule is inspecting both the request and the response.\n");
        }
        if (warn_file_store_not_present) {
            fprintf(fp, "    Warning: Rule requires file-store but the output file-store is not "
                        "enabled.\n");
        }
        if (rule_warning == 0) {
            fprintf(fp, "    No warnings for this rule.\n");
        }
        fprintf(fp, "\n");
    }
}

#include "app-layer-parser.h"

static void FirewallAddRulesForState(const DetectEngineCtx *de_ctx, const AppProto a,
        const uint8_t state, const uint8_t direction, RuleAnalyzer *ctx)
{
    uint32_t accept_rules = 0;
    SCJbSetString(ctx->js, "policy", "drop:flow");
    SCJbOpenArray(ctx->js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) == 0)
            break;
        if (s->type != SIG_TYPE_APP_TX)
            continue;
        if (s->alproto != a)
            continue;

        if (direction == STREAM_TOSERVER) {
            if (s->flags & SIG_FLAG_TOCLIENT) {
                continue;
            }
        } else {
            if (s->flags & SIG_FLAG_TOSERVER) {
                continue;
            }
        }

        if (s->app_progress_hook == state) {
            SCJbAppendString(ctx->js, s->sig_str);
            accept_rules += ((s->action & ACTION_ACCEPT) != 0);
        }
    }
    SCJbClose(ctx->js);

    if (accept_rules == 0) {
        AnalyzerWarning(ctx, (char *)"no accept rules for state, default policy will be applied");
    }
}

int FirewallAnalyzer(const DetectEngineCtx *de_ctx)
{
    RuleAnalyzer ctx = { NULL, NULL, NULL };
    ctx.js = SCJbNewObject();
    if (ctx.js == NULL)
        return -1;

    SCJbOpenObject(ctx.js, "tables");
    SCJbOpenObject(ctx.js, "packet:filter");
    SCJbSetString(ctx.js, "policy", "drop:packet");
    SCJbOpenArray(ctx.js, "rules");
    uint32_t accept_rules = 0;
    uint32_t last_sid = 0;
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) == 0)
            break;
        if (s->type != SIG_TYPE_PKT)
            continue;
        /* don't double list <> sigs */
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
        accept_rules += ((s->action & ACTION_ACCEPT) != 0);
    }
    SCJbClose(ctx.js);
    if (accept_rules == 0) {
        AnalyzerWarning(&ctx,
                (char *)"no accept rules for \'packet:filter\', default policy will be applied");
    }
    if (ctx.js_warnings) {
        SCJbClose(ctx.js_warnings);
        SCJbSetObject(ctx.js, "warnings", ctx.js_warnings);
        SCJbFree(ctx.js_warnings);
        ctx.js_warnings = NULL;
    }
    SCJbClose(ctx.js); // packet_filter

    for (AppProto a = 0; a < g_alproto_max; a++) {
        if (!AppProtoIsValid(a))
            continue;

        // HACK not all protocols have named states yet
        const char *hack = AppLayerParserGetStateNameById(IPPROTO_TCP, a, 0, STREAM_TOSERVER);
        if (!hack)
            continue;

        SCJbOpenObject(ctx.js, AppProtoToString(a));
        const uint8_t complete_state_ts =
                (const uint8_t)AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOSERVER);
        for (uint8_t state = 0; state < complete_state_ts; state++) {
            const char *name =
                    AppLayerParserGetStateNameById(IPPROTO_TCP, a, state, STREAM_TOSERVER);
            char table_name[128];
            snprintf(table_name, sizeof(table_name), "app:%s:%s", AppProtoToString(a), name);
            SCJbOpenObject(ctx.js, table_name);
            FirewallAddRulesForState(de_ctx, a, state, STREAM_TOSERVER, &ctx);
            if (ctx.js_warnings) {
                SCJbClose(ctx.js_warnings);
                SCJbSetObject(ctx.js, "warnings", ctx.js_warnings);
                SCJbFree(ctx.js_warnings);
                ctx.js_warnings = NULL;
            }
            SCJbClose(ctx.js);
        }
        const uint8_t complete_state_tc =
                (const uint8_t)AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOCLIENT);
        for (uint8_t state = 0; state < complete_state_tc; state++) {
            const char *name =
                    AppLayerParserGetStateNameById(IPPROTO_TCP, a, state, STREAM_TOCLIENT);
            char table_name[128];
            snprintf(table_name, sizeof(table_name), "app:%s:%s", AppProtoToString(a), name);
            SCJbOpenObject(ctx.js, table_name);
            FirewallAddRulesForState(de_ctx, a, state, STREAM_TOCLIENT, &ctx);
            if (ctx.js_warnings) {
                SCJbClose(ctx.js_warnings);
                SCJbSetObject(ctx.js, "warnings", ctx.js_warnings);
                SCJbFree(ctx.js_warnings);
                ctx.js_warnings = NULL;
            }
            SCJbClose(ctx.js);
        }
        SCJbClose(ctx.js); // app layer
    }
    SCJbOpenObject(ctx.js, "packet:td");
    SCJbSetString(ctx.js, "policy", "accept:hook");
    last_sid = 0;
    SCJbOpenArray(ctx.js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) != 0)
            continue;
        if (s->type == SIG_TYPE_APP_TX)
            continue;
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
    }
    SCJbClose(ctx.js); // rules
    SCJbClose(ctx.js); // packet:td
    SCJbOpenObject(ctx.js, "app:td");
    SCJbSetString(ctx.js, "policy", "accept:hook");
    last_sid = 0;
    SCJbOpenArray(ctx.js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) != 0)
            continue;
        if (s->type != SIG_TYPE_APP_TX)
            continue;
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
    }
    SCJbClose(ctx.js); // rules
    SCJbClose(ctx.js); // app:td
    SCJbClose(ctx.js); // tables

    SCJbOpenObject(ctx.js, "lists");
    SCJbOpenObject(ctx.js, "firewall");
    last_sid = 0;
    SCJbOpenArray(ctx.js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) == 0)
            continue;
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
    }
    SCJbClose(ctx.js); // rules
    SCJbClose(ctx.js); // firewall

    SCJbOpenObject(ctx.js, "td");
    last_sid = 0;
    SCJbOpenArray(ctx.js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if ((s->flags & SIG_FLAG_FIREWALL) != 0)
            continue;
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
    }
    SCJbClose(ctx.js); // rules
    SCJbClose(ctx.js); // td

    SCJbOpenObject(ctx.js, "all");
    last_sid = 0;
    SCJbOpenArray(ctx.js, "rules");
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (last_sid == s->id)
            continue;
        last_sid = s->id;
        SCJbAppendString(ctx.js, s->sig_str);
    }
    SCJbClose(ctx.js); // rules
    SCJbClose(ctx.js); // all

    SCJbClose(ctx.js); // lists

    SCJbClose(ctx.js); // top level object

    const char *filename = "firewall.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char json_path[PATH_MAX] = "";
    snprintf(json_path, sizeof(json_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rules_analyzer_write_m);
    FILE *fp = fopen(json_path, "w");
    if (fp != NULL) {
        fwrite(SCJbPtr(ctx.js), SCJbLen(ctx.js), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_rules_analyzer_write_m);
    SCJbFree(ctx.js);
    return 0;
}
