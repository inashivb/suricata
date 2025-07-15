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
#define STACK_DEPTH 100 /* TODO: Dynamic alloc? incr if reached limit? */

SCGraph *SCGCreateGraph(uint16_t size)
{
    SCGraph *g = SCCalloc(1, sizeof(SCGraph *));
    if (g == NULL) {
        SCLogError("Unable to allocate Graph");
        return NULL;
    }
    g->size = size;
    g->has_cycle = false;
    g->nodes = SCCalloc(size, sizeof(SCGNode *));
    if (g->nodes == NULL) {
        SCLogError("Unable to allocate nodes in the Graph");
        return NULL;
    }

    return g;
}

SCGNode *SCGCreateNode(void *data)
{
    SCGNode *node = SCCalloc(1, sizeof(SCGNode *));
    if (node == NULL) {
        SCLogError("Unable to allocate node");
    }
    node->data = data;
    node->state = -1;

    return node;
}

void SCGCreateEdge(SCGraph *g, SCGNode *src, SCGNode *dst)
{
    for (uint16_t i = 0; i < g->size; i++) {
        if (memcmp(g->nodes[i]->data, src->data) == 0) {
            dst->next = g->nodes[i]->next;
            g->nodes[i]->next = dst;
        }
    }
}

static uint16_t SCGGetNodeIdxFromGraph(SCGraph *g, uint32_t id, bool type)
{
    for (uint16_t i = 0; i < g->size; i++) {
        if ((g->nodes[i]->id == id) && (g->nodes[i]->type == type))
            return i;
    }
}

static void SCGDirectedDFSTraverseDo(SCGraph *g, uint32_t id, bool type, SCGNode *tstack, uint16_t sidx)
{
    if (sidx == STACK_DEPTH) {
        SCLogError("Exceeded recursion depth of 100");
        return;
    }

    uint16_t idx = SCGGetNodeIdxFromGraph(g, id, type);

    if (g->nodes[idx]->state == -1) { /* The node is being visited for the first time */
        tstack[sidx++] = g->nodes[idx]; /* Push to the stack */
        SCLogNotice("DFS Traversal: Node => %d; Type => %d", g->nodes[idx]->id, g->nodes[idx]->type);
        g->nodes[idx]->state = 0; /* Node is now in the stack */
        SCGNode *next_node = g->nodes[idx]->next;
        if (next_node != NULL) {
            SCGDirectedDFSTraverseDo(g, next_node->id, next_node->type, tstack, sidx);
        } else {
            SCGDirectedDFSTraverseDo(g, g->nodes[idx]->id, g->nodes[idx]->type, tstack, sidx);
        }
    } else if (g->nodes[idx]->state == 0) { /* The node is already in the stack */
        SCGNode *tmp = g->nodes[idx]->next;
        for (; tmp != NULL ; tmp = tmp->next) { /* Find the next unvisited node in the adjacency list */
            if (tmp->state == -1) {
                SCGDirectedDFSTraverseDo(g, tmp->id, tmp->type, tstack, sidx);
            } else if (tmp->state == 0) {
                g->has_cycle = true;
                SCLogNotice("There's a cycle in the graph! Can't move forward.");
                return;
            }
        }
        /* All the adjacent nodes have been visited for this node */
        g->nodes[idx]->state = 1; /* The node has been completely visited */
        sidx--;
        if (sidx > 0) {
            SCGDirectedDFSTraverseDo(g, tstack[sidx]->id, tstack[sidx]->type, tstack, sidx);
        }
    }

    return; /* Every node in the graph has been visited */
}

static void SCGResetGraphState(SCGraph *g)
{
    for (uint16_t i = 0; i < g->size; i++) {
        g->nodes[i]->state = -1;
    }
}

void SCGDirectedBFSTraverse(SCGraph *g)
{
    if (g->size == 0) {
        return; /* Nothing to do */
    }

    SCGResetGraphState(g);
    SCGNode *tqueue = SCCalloc(g->size, sizeof(SCGNode *));

    uint16_t tqi = 0; /* Starting index in the queue */
    tqueue[tqi++] = g->nodes[0];
    uint16_t j = 0;
    while (j < g->size) {
        for (SCGNode *tmp_node = tqueue[j]; tmp_node != NULL; tmp_node = tmp_node->next) {
            if (tmp_node->state == -1) {
                tqueue[tqi++] = tmp_node;
                SCLogNotice("BFS Traversal: Node => %d; Type => %d", tmp_node->id, tmp_node->type);
                tmp_node->state = 0;
            }
        }
        tqueue[j++]->state = 1;
    }

    SCFree(tqueue); /* Work is done */
}

static void SCGDirectedDFSTraverse(SCGraph *g)
{
    if (g->size == 0) {
        return; /* Nothing to do */
    }

    SCGResetGraphState(g);
    SCGNode *tstack = SCCalloc(STACK_DEPTH, sizeof(SCGNode *));
    if (tstack == NULL) {
        SCLogNotice("Couldn't alloc memory for stack");
        return;
    }
    SCGNode *node = g->nodes[0];
    SCGDirectedDFSTraverseDo(g, node->id, node->type, tstack, 0);

    SCFree(tstack); /* Work is done */
}

uint16_t SCGInDegreeOfNode(SCGraph *g, SCGNode *node)
{
    uint16_t cnt = 0;

    for (uint16_t i = 0; i < g->size; i++) {
        SCGNode *tnode = g->nodes[i];
        if ((tnode->id == node->id) && (tnode->type == node->type)) { /* Skip the row of the node itself */
            continue;
        }
        tnode = tnode->next;
        for (; tnode != NULL; tnode = tnode->next) {
            if ((tnode->id == node->id) && (tnode->type == node->type)) {
                cnt++;
            }
        }
    }

    return cnt;
}

bool SCGHasCycle(SCGraph *g)
{
    SCGDirectedDFSTraverse(g);

    return g->has_cycle;
}

void SCGFreeNode(SCGNode *node)
{
    SCFree(node);
}

void SCGFreeGraph(SCGraph *g)
{
    for (uint16_t i = 0; i < g->size; i ++) {
        SCGNode *node = g->nodes[i];
        SCGNode *adj_node = node->next;
        for (; adj_node != NULL; adj_node = adj_node->next) {
            SCGFreeNode(adj_node);
        }
        SCGFreeNode(node);
    }
    SCFree(g);
}
