/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 *
 * Common utility for Graphs
 */

#ifndef SURICATA_UTIL_GRAPH_H
#define SURICATA_UTIL_GRAPH_H

typedef struct SCGNode_ {
    uint32_t id;
    bool type; /* false = Signature; true = Flowbit; */
    int8_t state; /* -1 = Not visited; 0 = Visited but not all edges; 1 = Finished visiting; */
    SCGNode *next;
} SCGNode;

typedef struct SCGraph_ {
    uint16_t size;
    bool has_cycle;
    SCGNode *nodes;
} SCGraph;

SCGraph *SCGCreateGraph(uint16_t);
SCGNode *SCGCreateNode(void *);
void SCGFreeGraph(SCGraph *);
void SCGFreeNode(SCGNode *);
void SCGCreateEdge(SCGraph *, SCGNode *, SCGNode *);

bool SCGHasCycle(SCGraph *);
uint16_t SCGInDegreeOfNode(SCGraph *, SCGNode *);

void SCGDirectedBFSTraverse(SGGraph *);

#endif /* SURICATA_UTIL_GRAPH_H */
