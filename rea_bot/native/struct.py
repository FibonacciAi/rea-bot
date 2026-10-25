"""Region structurer for the owned decompiler.

Each block is emitted once, in its immediate dominator's region. If / else,
while, do-while, for, break, continue, and switch come from dominators and
post-dominators. A goto is the fallback for an edge the region does not own,
including an irreducible cross edge. Nothing is executed.
"""
import re

_FLIP = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}
_RET_INSNS = {"ret", "retn", "leave", "nop", "endbr64", "endbr32"}
_CAST = re.compile(r"\((int|long|short|char|void|bool|unsigned|signed)\)\s*\(\1\)")
_ARITH = (" + ", " - ", " * ", " / ")


def structure_function(entry, by, succs, dom, ipdom, loops):
    """Lines for one function. `by` maps a block start to its decompiler block.

    Dominators are recomputed on the blocks reachable from the entry. An unreachable
    block with an edge into the function would otherwise wipe the dominator sets.
    """
    del dom, ipdom, loops
    reach = _reachable(entry, succs)
    by = {node: by[node] for node in reach if node in by}
    if entry not in by:
        return []
    succs = {node: [target for target in succs.get(node, []) if target in by] for node in by}
    by, succs, entry = _collapse_empty(by, succs, entry)
    if entry not in by:
        return []
    preds = _preds(succs)
    dom = _dominators(entry, list(by), succs, preds)
    ipdom = _ipdom(by, succs)
    loops = _loops(succs, dom)
    builder = _Structurer(entry, by, succs, dom, ipdom, loops)
    try:
        builder.run()
    except RecursionError:
        # A very long straight chain would overflow the call stack before the
        # depth cap. Emit each block once, in walk order, and let the goto
        # tidy drop a jump that lands on the next label. This path does not
        # run for a function the region walk already finished.
        builder = _Structurer(entry, by, succs, dom, ipdom, loops)
        builder.emit_flat_cfg()
    return builder.render()


def structure_cfg(blocks):
    """Structure a synthetic CFG. Each block needs start, kind, succs, and stmts."""
    normalized = []
    for block in blocks:
        item = dict(block)
        item.setdefault("stmts", [])
        item.setdefault("succs", [])
        item.setdefault("kind", "fall")
        item.setdefault("cond", None)
        item.setdefault("switch", None)
        normalized.append(item)
    by = {block["start"]: block for block in normalized}
    succs = {block["start"]: list(block["succs"]) for block in normalized}
    for block in normalized:
        for _index, target in (block.get("switch") or {}).get("cases") or []:
            if target in by and target not in succs[block["start"]]:
                succs[block["start"]].append(target)
    entry = normalized[0]["start"]
    preds = _preds(succs)
    dom = _dominators(entry, list(by), succs, preds)
    loops = _loops(succs, dom)
    ipdom = _ipdom(by, succs)
    return structure_function(entry, by, succs, dom, ipdom, loops)


def simplify_line(text):
    """Fold identities and integer arithmetic outside string literals."""
    if not text or "goto " in text or text.rstrip().endswith(":"):
        return text
    current = text
    for _ in range(8):
        folded = _simplify_parens(current)
        folded = _CAST.sub(r"(\1)", folded)
        folded = re.sub(r"\(\(([^()]+)\)\)", r"(\1)", folded)
        if folded == current:
            break
        current = folded
    return current


class _Structurer(object):
    def __init__(self, entry, by, succs, dom, ipdom, loops):
        self.entry = entry
        self.by = by
        self.succs = succs
        self.ipdom = ipdom or {}
        self.loops = loops or {}
        self.dom = dom or {}
        self.preds = _preds(succs)
        self.idom = _idoms(self.dom)
        self.kids = {}
        for node, parent in self.idom.items():
            self.kids.setdefault(parent, []).append(node)
        for parent in self.kids:
            self.kids[parent].sort()
        self.emitted = set()
        self.out = []
        self.indent = 0
        self.leave_used = set()
        self.leave_sets = 0
        self.last_stop = None
        self.case_targets = set()
        self.dup_left = 16

    def run(self):
        self._emit(self.entry, set(), [], 0)
        self._sweep()

    def render(self):
        self._drop_fallthrough_gotos()
        self._drop_empty_ifs()
        needed = set()
        for kind, val in self.out:
            if kind != "line":
                continue
            match = re.search(r"\bgoto loc_([0-9a-fA-F]+);", val)
            if match:
                needed.add(int(match.group(1), 16))
        lines = []
        placed = set()
        for kind, val in self.out:
            if kind == "at":
                if val in needed and val not in placed:
                    lines.append("loc_%x:" % val)
                    placed.add(val)
            elif kind == "leave_init":
                header, indent = val
                if header in self.leave_used:
                    lines.append(("  " * indent) + "leave_%x = 0;" % header)
            elif kind == "line":
                lines.append(simplify_line(val))
        for addr in sorted(needed):
            if addr not in placed:
                lines.append("loc_%x:" % addr)
                lines.append(";")
        return _tidy_gotos(lines)

    def emit_flat_cfg(self):
        """One block at a time, with no nested calls. Used only after a stack overflow."""
        seen = set()
        order = []
        stack = [self.entry]
        while stack:
            node = stack.pop()
            if node in seen or node not in self.by:
                continue
            seen.add(node)
            order.append(node)
            for target in reversed(self.succs.get(node, [])):
                if target in self.by:
                    stack.append(target)
        for node in order:
            self.emitted.add(node)
            self.here(node)
            block = self.by[node]
            for stmt in block.get("stmts") or []:
                self.emit_line(stmt)
            targets = [item for item in self.succs.get(node, []) if item in self.by]
            if block.get("kind") == "ijmp" and not (block.get("switch") or {}).get("cases"):
                tail = block.get("tail_call")
                if tail and "(" in tail:
                    self.emit_line(tail if str(tail).endswith(";") else tail + ";")
                elif tail:
                    self.emit_line("%s();" % tail)
                else:
                    self.emit_line("indirect();")
                continue
            if block.get("kind") == "if" and len(targets) >= 2:
                cond = block.get("cond") or "1"
                self.emit_line("if (%s) {" % cond)
                self.emit_line("  goto loc_%x;" % targets[0])
                self.emit_line("} else {")
                self.emit_line("  goto loc_%x;" % targets[1])
                self.emit_line("}")
                continue
            if len(targets) == 1:
                self.emit_line("goto loc_%x;" % targets[0])

    def emit_line(self, text):
        pad = "  " * self.indent
        self.out.append(("line", pad + text))

    def here(self, node):
        self.out.append(("at", node))

    def _emit(self, node, barriers, ctx, depth):
        if node is None or node not in self.by or node in self.emitted or node in barriers:
            return
        if depth > 1500:
            self.emitted.add(node)
            self.here(node)
            self.emit_line("goto loc_%x;" % node)
            return
        if node in self.loops and not _in_loop(node, ctx):
            self._emit_loop(node, barriers, ctx, depth)
            return
        self.emitted.add(node)
        self.here(node)
        if self._emit_stmts(node):
            self._emit_kids(node, barriers, ctx, depth)
            return
        block = self.by[node]
        targets = self.succs.get(node, [])
        if block.get("kind") == "if" and len(targets) >= 2:
            fall = self.by.get(targets[1])
            if fall and fall.get("kind") == "ijmp" and (fall.get("switch") or {}).get("cases"):
                self._emit_switch(fall, targets[0], barriers, ctx, depth, owner=node)
                self._emit_follow(node, barriers, ctx, depth)
                self._emit_kids(node, barriers, ctx, depth)
                return
            self._write_if(node, barriers, ctx, depth)
            self._emit_kids(node, barriers, ctx, depth)
            return
        if block.get("kind") == "ijmp" and (block.get("switch") or {}).get("cases"):
            self._emit_switch(block, None, barriers, ctx, depth, owner=node)
            self._emit_kids(node, barriers, ctx, depth)
            return
        if block.get("kind") == "ijmp":
            # An indirect tail is a call through a register, not a goto to a local
            # label. A named PLT stub uses that name; an unknown target stays
            # `indirect();`.
            tail = block.get("tail_call")
            if not tail:
                self.emit_line("indirect();")
            elif "(" in tail:
                self.emit_line(tail if tail.endswith(";") else tail + ";")
            else:
                self.emit_line("%s();" % tail)
            self._emit_kids(node, barriers, ctx, depth)
            return
        if len(targets) == 1:
            self._realize(node, targets[0], barriers, ctx, depth)
        elif len(targets) > 1:
            self._realize(node, targets[0], barriers, ctx, depth)
        self._emit_kids(node, barriers, ctx, depth)

    def _emit_stmts(self, node):
        returned = False
        for stmt in self.by[node].get("stmts") or []:
            self.emit_line(stmt)
            if stmt.startswith("return "):
                returned = True
        return returned

    def _emit_kids(self, node, barriers, ctx, depth):
        for kid in self.kids.get(node, []):
            if kid in self.emitted or kid in barriers:
                continue
            self._emit(kid, barriers, ctx, depth + 1)

    def _emit_follow(self, node, barriers, ctx, depth):
        follow = self._follow(node, ctx)
        if follow is None or follow in barriers or follow in self.emitted or _in_loop(follow, ctx):
            return
        self._emit(follow, barriers, ctx, depth + 1)

    def _follow(self, node, ctx=None):
        follow = self.ipdom.get(node)
        if follow is None or follow not in self.by:
            return None
        # Already emitted by another entry: a barrier would fall through past it.
        if follow in self.emitted and self.idom.get(follow) != node:
            return None
        if self.idom.get(follow) == node:
            return follow
        # Dominated, but not immediately: the immediate dominator emits it.
        if node in self.dom.get(follow, ()):
            return None
        # Multi-entry post-dominator. Emit it once after this node so each arm
        # falls through, and do not pull it out of a loop that is already open.
        loop = _loop_of(ctx or [])
        if loop:
            body = (self.loops.get(loop["header"]) or {}).get("body") or set()
            if follow not in body and follow != loop.get("exit"):
                return None
        return follow

    def _write_if(self, node, barriers, ctx, depth):
        cond, then_n, else_n, consumed = self._fold(node)
        for extra in consumed:
            self.emitted.add(extra)
        # A comparison the lifter already rendered as two literals has one live arm.
        # Emitting both arms keeps a dead goto. The same check covers a cleared
        # overflow test (`0 != 0` / `1 == 1`).
        truth = _const_bool(cond)
        if truth is False and else_n is not None:
            self._realize(node, else_n, barriers, ctx, depth)
            self._bury_dead(then_n, node)
            self._after_if(self._follow(node, ctx), barriers, ctx, depth, consumed)
            return
        if truth is True:
            self._realize(node, then_n, barriers, ctx, depth)
            self._bury_dead(else_n, node)
            self._after_if(self._follow(node, ctx), barriers, ctx, depth, consumed)
            return
        follow = self._follow(node, ctx)
        merges = self._merges(node)
        branch_barriers = set(barriers)
        if follow is not None:
            branch_barriers.add(follow)
        for merge in merges:
            branch_barriers.add(merge)
        then_d = self._branch_decision(node, then_n, branch_barriers, ctx)
        else_d = self._branch_decision(node, else_n, branch_barriers, ctx)
        if _empty(then_d) and not _empty(else_d):
            cond = _negate(cond)
            then_n, else_n = else_n, None
            then_d, else_d = else_d, ("empty", None)
        if _empty(then_d) and _empty(else_d):
            # Both arms were scheduled elsewhere. The condition still chooses which
            # one runs when a flag join copied this branch per incoming compare.
            if (self.by[node].get("flag_join") and cond and then_n is not None and else_n is not None
                    and then_n != else_n):
                self.emit_line("if (%s) {" % cond)
                self.indent += 1
                self.emit_line("goto loc_%x;" % then_n)
                self.indent -= 1
                self.emit_line("} else {")
                self.indent += 1
                self.emit_line("goto loc_%x;" % else_n)
                self.indent -= 1
                self.emit_line("}")
            self._after_if(follow, barriers, ctx, depth, consumed, merges)
            return
        if _empty(else_d) and then_d[0] == "line":
            self.emit_line("if (%s) %s" % (cond, then_d[1]))
            self._after_if(follow, barriers, ctx, depth, consumed, merges)
            return
        self.emit_line("if (%s) {" % cond)
        self.indent += 1
        self._realize_decision(then_d, node, then_n, branch_barriers, ctx, depth)
        self.indent -= 1
        if _empty(else_d):
            self.emit_line("}")
        else:
            self.emit_line("} else {")
            self.indent += 1
            self._realize_decision(else_d, node, else_n, branch_barriers, ctx, depth)
            self.indent -= 1
            self.emit_line("}")
        self._after_if(follow, barriers, ctx, depth, consumed, merges)

    def _bury_dead(self, node, pred):
        """A constant branch's dead arm is not emitted again by the final sweep."""
        if node is None or self.preds.get(node) != [pred]:
            return
        self.emitted.add(node)
        for succ in self.succs.get(node, []):
            if self.preds.get(succ) == [node]:
                self._bury_dead(succ, node)

    def _after_if(self, follow, barriers, ctx, depth, consumed, merges=()):
        for merge in merges:
            if merge not in self.emitted and merge not in barriers and not _in_loop(merge, ctx):
                self._emit(merge, barriers, ctx, depth + 1)
        if follow is not None and follow not in barriers and follow not in self.emitted and not _in_loop(follow, ctx):
            self._emit(follow, barriers, ctx, depth + 1)
        for extra in consumed:
            self._emit_kids(extra, barriers, ctx, depth)

    def _merges(self, node):
        """Kids of an if that both arms reach. They are emitted once, after the if."""
        if node in self.loops:
            return []
        targets = self.succs.get(node, [])
        if len(targets) < 2:
            return []
        taken, fall = targets[0], targets[1]
        found = []
        for kid in self.kids.get(node, []):
            if kid in self.loops or kid in self.case_targets:
                continue
            from_taken = kid == taken or self._reaches(taken, kid, node)
            from_fall = kid == fall or self._reaches(fall, kid, node)
            if from_taken and from_fall:
                found.append(kid)
        return found

    def _reaches(self, start, goal, stop):
        if start is None or goal is None:
            return False
        if start == goal:
            return True
        stack = [start]
        seen = {stop}
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for nxt in self.succs.get(node, []):
                if nxt == goal:
                    return True
                # A join past a loop is still a merge of the if that dominates both
                # arms. The loop header itself is excluded by the caller.
                if nxt not in seen:
                    stack.append(nxt)
        return False

    def _fold(self, node):
        block = self.by[node]
        cond = block.get("cond") or "1"
        targets = self.succs.get(node, [])
        if len(targets) < 2:
            taken = targets[0] if targets else None
            return cond, taken, None, []
        taken, fall = targets[0], targets[1]
        ors = [cond]
        consumed = []
        else_node = fall
        cursor = fall
        previous = node
        for _ in range(6):
            if not self._pure_cond(cursor) or not self._sole_pred(cursor, previous):
                break
            nxt = self.succs.get(cursor, [])
            if len(nxt) < 2 or nxt[0] != taken:
                break
            ors.append(self.by[cursor].get("cond") or "1")
            consumed.append(cursor)
            else_node = nxt[1]
            previous, cursor = cursor, nxt[1]
        if len(ors) > 1:
            expr = _join_bool(ors, "||")
            if expr == "1":
                return "1", taken, else_node, consumed
            if expr == "0":
                return "0", taken, else_node, consumed
            return expr, taken, else_node, consumed
        ands = [cond]
        consumed = []
        then_node = taken
        cursor = taken
        previous = node
        for _ in range(6):
            if not self._pure_cond(cursor) or not self._sole_pred(cursor, previous):
                break
            nxt = self.succs.get(cursor, [])
            if len(nxt) < 2 or nxt[1] != fall:
                break
            ands.append(self.by[cursor].get("cond") or "1")
            consumed.append(cursor)
            then_node = nxt[0]
            previous, cursor = cursor, nxt[0]
        if len(ands) > 1:
            expr = _join_bool(ands, "&&")
            if expr == "1":
                return "1", then_node, fall, consumed
            if expr == "0":
                return "0", then_node, fall, consumed
            return expr, then_node, fall, consumed
        return cond, taken, fall, []

    def _pure_cond(self, node):
        block = self.by.get(node)
        if not block or block.get("kind") != "if" or node in self.loops or node in self.emitted:
            return False
        return not [stmt for stmt in block.get("stmts") or [] if not stmt.startswith("return ")]

    def _sole_pred(self, node, pred):
        return self.preds.get(node, []) == [pred]

    def _branch_decision(self, src, target, barriers, ctx):
        if target is None:
            return ("empty", None)
        # The branch head is this region's to emit, even when a folded condition
        # sits between it and the if in the dominator tree.
        return self._prefer_inline(self._decide(src, target, barriers, ctx), target, src)

    def _prefer_inline(self, decision, target, src):
        """Inline a goto target only when this node dominates it.

        A folded condition can sit between an if and its branch in the dominator
        tree. A block reached from outside the branch stays a goto.
        """
        if decision[0] != "line" or not str(decision[1]).startswith("goto "):
            return decision
        if target in self.case_targets or target in self.emitted or target not in self.by:
            return decision
        if src in self.dom.get(target, ()):
            return ("inline", None)
        return decision

    def _realize_decision(self, decision, src, target, barriers, ctx, depth):
        if decision[0] == "dup":
            for line in decision[1]:
                self.emit_line(line)
            return
        if decision[0] == "inline":
            if target in self.emitted:
                dup = self._small_tail(target)
                if dup:
                    for line in dup:
                        self.emit_line(line)
                    return
                self.emit_line("goto loc_%x;" % target)
                return
            self._emit(target, barriers, ctx, depth + 1)
            return
        self._apply(decision, src, target, barriers, ctx, depth)

    def _realize(self, src, target, barriers, ctx, depth):
        decision = self._decide(src, target, barriers, ctx)
        self._realize_decision(decision, src, target, barriers, ctx, depth)

    def _decide(self, src, target, barriers, ctx):
        if target is None:
            return ("empty", None)
        if target not in self.by:
            return ("line", "goto loc_%x;" % target)
        loop = _loop_of(ctx)
        if loop and target == loop["header"]:
            return ("line", "continue;")
        if loop and target == loop["exit"]:
            if _break_reaches_loop(ctx):
                return ("line", "break;")
            if _inside_switch(ctx):
                return ("leave", loop["header"])
            return ("line", "goto loc_%x;" % target)
        if target in barriers:
            switch = _switch_of(ctx)
            if switch and target == switch.get("follow"):
                return ("line", "break;")
            # Another switch arm is emitted as its own case. A jump there is a goto,
            # not a fall into that arm, so the arm is not inlined here.
            if target in self.case_targets:
                return ("line", "goto loc_%x;" % target)
            return ("stop", target)
        if self.idom.get(target) != src:
            copied = self._return_copy(src, target)
            if copied is not None:
                return ("line", "return %s;" % copied)
        # First reach owns the block. A detected follow is already a barrier, so it
        # is not pulled into the first branch. Later reaches goto, unless the tail is
        # a constant return that can be duplicated.
        if target not in self.emitted:
            return ("inline", None)
        dup = self._small_tail(target) or self._structured_tail(target, ctx)
        if dup:
            return ("dup", dup)
        copied = self._copy_region(target, barriers, ctx, set(), 8, 8, [0])
        if copied:
            return ("dup", copied)
        if self.dup_left > 0 and target not in self.loops:
            wider = self._copy_region(target, barriers, ctx, set(), 12, 3, [0])
            if wider and not any("goto " in line for line in wider):
                cost = sum(1 for line in wider if line.strip() and not line.strip().startswith(("if ", "}", "else")))
                if 0 < cost <= self.dup_left:
                    self.dup_left -= cost
                    return ("dup", wider)
        return ("line", "goto loc_%x;" % target)

    def _copy_region(self, target, barriers, ctx, seen, blocks_left, stmts_left, visits=None):
        """Duplicate a tiny region whose every path ends at a barrier, continue, or return.

        The block was already emitted on another path. Copying it here removes the
        goto. Each path runs the copy once, so a call in the region stays one call.
        """
        if visits is None:
            visits = [0]
        visits[0] += 1
        if visits[0] > 48 or blocks_left < 0 or stmts_left < 0 or target in seen or target not in self.by:
            return None
        if target in barriers:
            return []
        loop = _loop_of(ctx)
        if loop and target == loop["header"]:
            return ["continue;"]
        if loop and target == loop.get("exit") and _break_reaches_loop(ctx):
            return ["break;"]
        if target in self.loops:
            return None
        block = self.by[target]
        if block.get("switch") or block.get("kind") == "ijmp":
            return None
        seen = set(seen)
        seen.add(target)
        if block.get("kind") == "ret":
            stmts = [stmt for stmt in block.get("stmts") or [] if stmt.startswith("return ")]
            line = stmts[0] if stmts else "return;"
            return [line]
        stmts = [stmt for stmt in block.get("stmts") or [] if not stmt.startswith("return ")]
        if len(stmts) > stmts_left:
            return None
        succs = [item for item in self.succs.get(target, []) if item in self.by or item in barriers]
        if block.get("kind") == "if" and len(succs) >= 2:
            then_lines = self._copy_region(succs[0], barriers, ctx, seen, blocks_left - 1, stmts_left - len(stmts), visits)
            else_lines = self._copy_region(succs[1], barriers, ctx, seen, blocks_left - 1, stmts_left - len(stmts), visits)
            if then_lines is None or else_lines is None:
                return None
            cond = block.get("cond")
            # A missing condition is not the constant true. Copying it as `if (1)`
            # would hide the branch. The caller keeps the goto.
            if not cond:
                return None
            lines = list(stmts)
            truth = _const_bool(cond)
            if truth is True:
                return lines + then_lines
            if truth is False:
                return lines + else_lines
            lines.append("if (%s) {" % cond)
            lines.extend("  " + line for line in then_lines)
            if else_lines:
                lines.append("} else {")
                lines.extend("  " + line for line in else_lines)
            lines.append("}")
            return lines
        if len(succs) == 1:
            rest = self._copy_region(succs[0], barriers, ctx, seen, blocks_left - 1, stmts_left - len(stmts), visits)
            if rest is None:
                return None
            return stmts + rest
        return stmts or None

    def _structured_tail(self, target, ctx):
        """Copy a short straight line that reaches the loop header, its exit, or a return.

        The copy replaces one goto with continue, break, or return. A call is not
        copied: that would run it twice.
        """
        loop = _loop_of(ctx)
        lines = []
        node = target
        seen = set()
        for _ in range(6):
            if node in seen or node not in self.by:
                return None
            seen.add(node)
            if lines and loop and node == loop["header"]:
                lines.append("continue;")
                return lines
            if lines and loop and node == loop.get("exit"):
                lines.append("break;")
                return lines
            block = self.by[node]
            if block.get("kind") == "ret" or (not self.succs.get(node) and any(
                    stmt.startswith("return ") for stmt in block.get("stmts") or [])):
                stmts = [stmt for stmt in block.get("stmts") or [] if stmt.startswith("return ")]
                lines.append(stmts[0] if stmts else "return;")
                return lines
            if block.get("kind") == "if" or block.get("switch") or node in self.loops:
                return None
            stmts = list(block.get("stmts") or [])
            if any(stmt.startswith("goto ") for stmt in stmts):
                return None
            lines.extend(stmts)
            if len(lines) > 6:
                return None
            succs = self.succs.get(node, [])
            if len(succs) != 1:
                return None
            node = succs[0]
        return None

    def _small_tail(self, target):
        """Duplicate a tiny tail that ends in a constant return.

        Splitting that tail removes a goto without falling into the original copy.
        A region that reaches a loop or another join is left shared.
        """
        return _constant_tail(self.by, self.succs, self.loops, target, set(), 4)

    def _drop_fallthrough_gotos(self):
        for _ in range(4):
            if not self._drop_fallthrough_once():
                return

    def _drop_fallthrough_once(self):
        visible = []
        for index, (kind, val) in enumerate(self.out):
            if kind == "at":
                visible.append((None, "loc_%x:" % val))
            elif kind == "line":
                visible.append((index, val))
            elif kind == "leave_init" and val[0] in self.leave_used:
                visible.append((None, "leave_%x = 0;" % val[0]))
        lines = [text for _, text in visible]
        stack = []
        states = []
        for text in lines:
            states.append(list(stack))
            _track_brace(stack, text)
        drop = []
        for pos, (index, text) in enumerate(visible):
            if index is None:
                continue
            match = re.fullmatch(r"goto loc_([0-9a-fA-F]+);", text.strip())
            if not match:
                continue
            if _falls_to(lines, pos, match.group(1), states[pos]):
                drop.append(index)
        if not drop:
            return False
        gone = set(drop)
        self.out = [item for index, item in enumerate(self.out) if index not in gone]
        return True

    def _drop_empty_ifs(self):
        lines = [(index, val) for index, (kind, val) in enumerate(self.out) if kind == "line"]
        drop = []
        for pos, (index, text) in enumerate(lines[:-1]):
            match = re.fullmatch(r"if \((.*)\) \{", text.strip())
            if not match or "(" in match.group(1):
                continue
            if lines[pos + 1][1].strip() != "}":
                continue
            drop.extend((index, lines[pos + 1][0]))
        if drop:
            gone = set(drop)
            self.out = [item for index, item in enumerate(self.out) if index not in gone]

    def _apply(self, decision, src, target, barriers, ctx, depth):
        kind, payload = decision
        if kind == "line":
            self.emit_line(payload)
        elif kind == "leave":
            self.leave_used.add(payload)
            self.leave_sets += 1
            self.emit_line("leave_%x = 1;" % payload)
            self.emit_line("break;")
        elif kind == "stop":
            self.last_stop = payload
        elif kind == "inline":
            self._emit(target, barriers, ctx, depth + 1)

    def _emit_loop(self, header, barriers, ctx, depth):
        info = self.loops[header]
        self.emitted.add(header)
        self.here(header)
        counted = self._for_parts(header, info)
        do_loop = None if counted else self._do_while(header, info)
        if counted:
            latch, cond, inc = counted
            self.emitted.add(latch)
            self._open_loop(header, cond, barriers, ctx, depth, inc=inc, latch=latch, do_exit=None)
            return
        if do_loop:
            latch, exit_, cond = do_loop
            self.emitted.add(latch)
            self._open_do(header, info, latch, exit_, cond, barriers, ctx, depth)
            return
        self._open_while(header, info, barriers, ctx, depth)

    def _open_while(self, header, info, barriers, ctx, depth):
        block = self.by[header]
        stmts = [stmt for stmt in block.get("stmts") or [] if not stmt.startswith("return ")]
        exit_ = info.get("exit")
        targets = self.succs.get(header, [])
        header_exits = block.get("kind") == "if" and exit_ is not None and exit_ in targets
        stay = self._stay_cond(header, info) if header_exits else "1"
        self.out.append(("leave_init", (header, self.indent)))
        ctx2 = ctx + [{"kind": "loop", "header": header, "exit": exit_}]
        body_barriers = set(barriers)
        body_barriers.add(header)
        if exit_ is not None:
            body_barriers.add(exit_)
        if header_exits and not stmts and stay != "1":
            self.emit_line("while (%s) {" % stay)
            self.indent += 1
            self._emit_loop_body(header, info, body_barriers, ctx2, depth)
            self.indent -= 1
            self.emit_line("}")
        else:
            self.emit_line("while (1) {")
            self.indent += 1
            for stmt in stmts:
                self.emit_line(stmt)
            if header_exits:
                self.emit_line("if (%s) break;" % _negate(stay))
            self._emit_loop_body(header, info, body_barriers, ctx2, depth)
            self.indent -= 1
            self.emit_line("}")
        self._after_loop(header, info, exit_, barriers, ctx, depth)

    def _open_loop(self, header, cond, barriers, ctx, depth, inc, latch, do_exit):
        info = self.loops[header]
        exit_ = info.get("exit")
        self.out.append(("leave_init", (header, self.indent)))
        self.emit_line("for (; %s; %s) {" % (cond, inc))
        self.indent += 1
        ctx2 = ctx + [{"kind": "loop", "header": header, "exit": exit_}]
        body_barriers = set(barriers)
        body_barriers.update({header, latch})
        if exit_ is not None:
            body_barriers.add(exit_)
        enter = info.get("enter")
        if enter is not None and enter != latch:
            self._emit(enter, body_barriers, ctx2, depth + 1)
        self._strip_trailing_continue()
        self.indent -= 1
        self.emit_line("}")
        self._after_loop(header, info, exit_, barriers, ctx, depth)

    def _open_do(self, header, info, latch, exit_, cond, barriers, ctx, depth):
        self.out.append(("leave_init", (header, self.indent)))
        self.emit_line("do {")
        self.indent += 1
        ctx2 = ctx + [{"kind": "loop", "header": header, "exit": exit_}]
        body_barriers = set(barriers)
        body_barriers.update({header, latch})
        if exit_ is not None:
            body_barriers.add(exit_)
        targets = self.succs.get(header, [])
        # The header test chooses an arm inside the loop. Emitting only the
        # first successor drops a call on the other arm, which is what a
        # virtual call in `do { if (p) p->area(); } while (...)` looks like.
        if self.by[header].get("kind") == "if" and len(targets) >= 2:
            self._write_if(header, body_barriers, ctx2, depth)
        else:
            self._emit_stmts(header)
            enter = targets[0] if targets else None
            if enter is not None and enter not in {header, latch}:
                self._emit(enter, body_barriers, ctx2, depth + 1)
        for stmt in self.by[latch].get("stmts") or []:
            if not stmt.startswith("return "):
                self.emit_line(stmt)
        self._strip_trailing_continue()
        self.indent -= 1
        self.emit_line("} while (%s);" % cond)
        self._after_loop(header, info, exit_, barriers, ctx, depth)

    def _emit_loop_body(self, header, info, barriers, ctx, depth):
        body = info.get("body") or set()
        enter = info.get("enter")
        if enter is not None and enter != header:
            self._emit(enter, barriers, ctx, depth + 1)
        for kid in self.kids.get(header, []):
            if kid in self.emitted or kid in barriers or kid not in body:
                continue
            self._emit(kid, barriers, ctx, depth + 1)
        self._strip_trailing_continue()

    def _after_loop(self, header, info, exit_, barriers, ctx, depth):
        if exit_ is not None and exit_ not in barriers and exit_ not in self.emitted:
            self._emit(exit_, barriers, ctx, depth + 1)
        body = info.get("body") or set()
        for kid in self.kids.get(header, []):
            if kid in self.emitted or kid in barriers or kid in body:
                continue
            self._emit(kid, barriers, ctx, depth + 1)

    def _stay_cond(self, header, info):
        block = self.by[header]
        cond = block.get("cond") or "1"
        targets = self.succs.get(header, [])
        leave = info.get("exit")
        stays = bool(targets) and leave is not None and targets[0] != leave
        return cond if stays else _negate(cond)

    def _for_parts(self, header, info):
        block = self.by[header]
        if block.get("kind") != "if":
            return None
        if [stmt for stmt in block.get("stmts") or [] if not stmt.startswith("return ")]:
            return None
        exit_ = info.get("exit")
        targets = self.succs.get(header, [])
        if exit_ is None or exit_ not in targets:
            return None
        latches = [latch for latch in info.get("latches") or [] if latch != header]
        if len(latches) != 1:
            return None
        latch = latches[0]
        latch_block = self.by.get(latch) or {}
        if latch_block.get("kind") not in {"goto", "fall"}:
            return None
        if self.succs.get(latch) != [header]:
            return None
        stmts = [stmt for stmt in latch_block.get("stmts") or [] if not stmt.startswith("return ")]
        if len(stmts) != 1:
            return None
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*) = \(\1 ([+-]) (\d+)\);", stmts[0])
        if not match:
            return None
        cond = self._stay_cond(header, info)
        if match.group(1) not in cond:
            return None
        enter = info.get("enter")
        if enter is None or not self._straight(enter, latch, info.get("body") or set(), header):
            return None
        inc = "%s = (%s %s %s)" % (match.group(1), match.group(1), match.group(2), match.group(3))
        return latch, cond, inc

    def _do_while(self, header, info):
        body = info.get("body") or set()
        targets = self.succs.get(header, [])
        if not targets or any(target not in body for target in targets):
            return None
        latches = [latch for latch in info.get("latches") or [] if latch != header]
        if len(latches) != 1:
            return None
        latch = latches[0]
        block = self.by.get(latch) or {}
        if block.get("kind") != "if":
            return None
        suc = self.succs.get(latch, [])
        if header not in suc or len(suc) < 2:
            return None
        outside = [target for target in suc if target not in body]
        if len(outside) != 1:
            return None
        enter = targets[0]
        if enter != latch and not self._straight(enter, latch, body, header):
            return None
        cond = block.get("cond") or "1"
        if suc[0] != header:
            cond = _negate(cond)
        return latch, outside[0], cond

    def _straight(self, start, goal, body, header):
        if start == goal:
            return True
        node = start
        seen = set()
        while node != goal:
            if node in seen or node not in body or node == header:
                return False
            seen.add(node)
            block = self.by.get(node) or {}
            if block.get("kind") == "if":
                return False
            suc = self.succs.get(node, [])
            if len(suc) != 1:
                return False
            node = suc[0]
        return True

    def _strip_trailing_continue(self):
        for index in range(len(self.out) - 1, -1, -1):
            kind, val = self.out[index]
            if kind != "line":
                continue
            if val.strip() == "continue;":
                del self.out[index]
            break

    def _emit_switch(self, block, default, barriers, ctx, depth, owner):
        switch = block.get("switch") or {}
        start = block["start"]
        if start not in self.emitted:
            self.emitted.add(start)
            self.here(start)
        for stmt in block.get("stmts") or []:
            if not stmt.startswith("return "):
                self.emit_line(stmt)
        groups = {}
        order = []
        for index, target in switch.get("cases") or []:
            if target not in self.by:
                continue
            if target not in groups:
                order.append(target)
                groups[target] = []
            groups[target].append(index)
        follow = self._follow(start, ctx) or (self._follow(owner, ctx) if owner != start else None)
        ctx2 = ctx + [{"kind": "switch", "follow": follow}]
        previous_cases = self.case_targets
        self.case_targets = set(order)
        if default in self.by:
            self.case_targets.add(default)
        case_barriers = set(barriers) | set(self.case_targets)
        if follow is not None:
            case_barriers.add(follow)
        before = self.leave_sets
        self.emit_line("switch (%s) {" % switch.get("expr", "expr"))
        self.indent += 1
        for position, target in enumerate(order):
            for index in groups[target]:
                self.emit_line("case %d:" % index)
            upcoming = order[position + 1] if position + 1 < len(order) else None
            if upcoming is None and default in self.by and default not in groups:
                upcoming = default
            self.indent += 1
            started = len(self.out)
            self._emit_case(start, target, case_barriers, ctx2, depth)
            self._finish_case(started, upcoming)
            self.indent -= 1
        if default in self.by and default not in groups:
            self.emit_line("default:")
            self.indent += 1
            started = len(self.out)
            # The default edge leaves the guarding compare, which dominates that block.
            self._emit_case(owner, default, case_barriers, ctx2, depth)
            self._finish_case(started, None)
            self.indent -= 1
        self.indent -= 1
        self.emit_line("}")
        loop = _loop_of(ctx)
        if loop and self.leave_sets > before:
            self.emit_line("if (leave_%x) break;" % loop["header"])
        self.case_targets = previous_cases
        self._emit_kids(start, barriers, ctx, depth)
        if owner != start:
            self._emit_kids(owner, barriers, ctx, depth)

    def _emit_case(self, src, target, barriers, ctx, depth):
        local = set(barriers)
        local.discard(target)
        decision = self._prefer_inline(self._decide(src, target, local, ctx), target, src)
        self._realize_decision(decision, src, target, local, ctx, depth)

    def _finish_case(self, started, upcoming):
        last = self._last_stmt(started)
        if upcoming is not None and last == "goto loc_%x;" % upcoming:
            self._pop_last_stmt(started)
            return
        if last in {"break;", "continue;"} or last.startswith("return ") or last.startswith("goto "):
            return
        self.emit_line("break;")

    def _last_stmt(self, started):
        for kind, val in reversed(self.out[started:]):
            if kind == "line" and val.strip():
                return val.strip()
        return ""

    def _pop_last_stmt(self, started):
        for index in range(len(self.out) - 1, started - 1, -1):
            kind, val = self.out[index]
            if kind == "line" and val.strip():
                del self.out[index]
                return

    def _return_copy(self, src, target):
        found = self._leads_to_ret(target, 0)
        if found is None:
            return None
        if target != found:
            expr = self._expr_if_set(self.by.get(target))
            if expr is not None:
                return expr
        return self._expr_if_set(self.by.get(src))

    def _leads_to_ret(self, target, depth):
        if depth > 4 or target not in self.by:
            return None
        block = self.by[target]
        if self._pure_ret(block):
            return target
        if _side_effect(block):
            return None
        if block.get("kind") in {"goto", "fall"}:
            suc = self.succs.get(target, [])
            if len(suc) == 1:
                return self._leads_to_ret(suc[0], depth + 1)
        return None

    def _pure_ret(self, block):
        if not block or block.get("kind") != "ret":
            return False
        insns = block.get("insns") or []
        if not insns:
            return True
        return all(_mnem(item) in _RET_INSNS for item in insns)

    def _expr_if_set(self, block):
        regs = ((block or {}).get("out") or {}).get("regs") or {}
        for name in ("eax", "rax", "w0", "x0"):
            value = regs.get(name)
            if value and str(value) not in {name, "eax", "rax", "w0", "x0"}:
                return _num(value)
        return None

    def _sweep(self):
        reach = set()
        stack = [self.entry]
        while stack:
            node = stack.pop()
            if node in reach or node not in self.by:
                continue
            reach.add(node)
            stack.extend(self.succs.get(node, []))
        for node in sorted(reach):
            if node not in self.emitted:
                self._emit(node, set(), [], 0)


def _constant_tail(by, succs, loops, target, seen, left):
    """A small region with no internal goto. Copying it replaces one goto.

    The copy has to end on every path, so it does not also fall into the original.
    Names that count as unnamed are not duplicated: that would trade one metric for the other.
    """
    if left < 0 or target in seen or target in loops or target not in by:
        return None
    seen = set(seen)
    seen.add(target)
    block = by[target]
    if block.get("kind") == "ijmp" or block.get("switch"):
        return None
    stmts = list(block.get("stmts") or [])
    if any(stmt.startswith("goto ") for stmt in stmts) or len(stmts) > 4:
        return None
    plain = [stmt for stmt in stmts if not stmt.startswith("return ")]
    ret = [stmt for stmt in stmts if stmt.startswith("return ")]
    if ret:
        if len(ret) != 1 or _has_unnamed(plain + ret):
            return None
        return plain + ret
    targets = succs.get(target, [])
    if block.get("kind") == "if" and len(targets) >= 2 and not plain:
        then_tail = _constant_tail(by, succs, loops, targets[0], seen, left - 1)
        else_tail = _constant_tail(by, succs, loops, targets[1], seen, left - 1)
        if not then_tail or not else_tail or len(then_tail) > 3 or len(else_tail) > 3:
            return None
        cond = block.get("cond") or "1"
        lines = ["if (%s) {" % cond, *("  " + line for line in then_tail), "} else {",
                 *("  " + line for line in else_tail), "}"]
        if _has_unnamed(lines):
            return None
        return lines
    if block.get("kind") in {"goto", "fall"} and len(targets) == 1:
        rest = _constant_tail(by, succs, loops, targets[0], seen, left - 1)
        if rest is None or _has_unnamed(plain):
            return None
        return plain + rest
    return None


_UNNAMED_TAIL = re.compile(
    r"\b(?:param_\d+|arg\d+\??|FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+|local_[0-9A-Fa-f]+|mem_[0-9A-Fa-f]+|"
    r"data_[0-9A-Fa-f]+|undefined\d*|DAT_[0-9A-Fa-f]+)\b")


def _has_unnamed(lines):
    return any(_UNNAMED_TAIL.search(line) for line in lines)


_CALL_IN_STMT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(")


def _calls_in(lines):
    return any(_CALL_IN_STMT.search(line) for line in lines)


def _track_brace(stack, text):
    raw = re.sub(r'"[^"]*"', '""', text.strip())
    if raw.startswith("} else"):
        if stack:
            stack.pop()
        stack.append("else")
    elif raw.startswith("} while"):
        if stack:
            stack.pop()
    elif raw == "}":
        if stack:
            stack.pop()
    elif raw.endswith("{") and "{" in raw:
        stack.append(_open_kind(raw))


def _open_kind(text):
    if text.startswith("if "):
        return "if"
    if text.startswith("while "):
        return "while"
    if text.startswith("for "):
        return "for"
    if text.startswith("do ") or text == "do {":
        return "do"
    if text.startswith("switch "):
        return "switch"
    if text.startswith("} else"):
        return "else"
    return "block"


def _falls_to(lines, index, target, stack):
    stack = list(stack)
    pos = index + 1
    while pos < len(lines):
        raw = lines[pos].strip()
        if raw.lower() == "loc_%s:" % target.lower():
            return True
        if re.fullmatch(r"loc_[0-9a-fA-F]+:", raw) or raw == ";":
            pos += 1
            continue
        if raw.startswith("} else"):
            pos = _skip_else(lines, pos)
            if stack:
                stack.pop()
            continue
        if raw.startswith("} while"):
            return False
        if raw == "}":
            if not stack:
                return False
            kind = stack.pop()
            if kind in {"while", "for", "do", "switch"}:
                return False
            pos += 1
            continue
        return False
    return False


def _skip_else(lines, pos):
    depth = 1
    pos += 1
    while pos < len(lines):
        raw = re.sub(r'"[^"]*"', '""', lines[pos].strip())
        depth += raw.count("{") - raw.count("}")
        if depth <= 0:
            return pos + 1
        pos += 1
    return pos


def _empty(decision):
    return decision[0] in {"empty", "stop"}


def _side_effect(block):
    return any(not stmt.startswith("return ") for stmt in block.get("stmts") or [])


def _loop_of(ctx):
    for item in reversed(ctx):
        if item["kind"] == "loop":
            return item
    return None


def _switch_of(ctx):
    for item in reversed(ctx):
        if item["kind"] == "switch":
            return item
    return None


def _inside_switch(ctx):
    return _switch_of(ctx) is not None


def _break_reaches_loop(ctx):
    for item in reversed(ctx):
        if item["kind"] == "switch":
            return False
        if item["kind"] == "loop":
            return True
    return False


def _in_loop(node, ctx):
    return any(item["kind"] == "loop" and item["header"] == node for item in ctx)


def _negate(cond):
    if not cond or cond == "1":
        return "0"
    if cond == "0":
        return "1"
    text = cond.strip()
    if text.startswith("!(") and text.endswith(")") and _match_paren(text, 0) == len(text) - 1:
        return text[2:-1].strip()
    # Flipping the first operator of `a && b` is not the negation.
    if "&&" in text or "||" in text:
        return "!(%s)" % text
    padded = " %s " % text
    for op, flipped in sorted(_FLIP.items(), key=lambda item: -len(item[0])):
        token = " %s " % op
        if token in padded:
            return padded.replace(token, " %s " % flipped, 1).strip()
    return "!(%s)" % text


def _num(value):
    text = str(value)
    try:
        number = int(text, 0) if text.startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return text
    if number >= 2 ** 63:
        number -= 2 ** 64
    if number < 0:
        return "(%d)" % number
    return str(number)


def _reachable(entry, succs):
    seen = set()
    stack = [entry]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(succs.get(node, []))
    return seen


def _const_bool(cond):
    """True or False when `cond` is a comparison of two literals, else None.

    The literals are the ones the lifter already printed. Folding them drops a
    dead arm of that printed test. A value that is not a literal stays unknown.
    """
    if cond is None:
        return None
    text = simplify_line(str(cond)).strip()
    while text.startswith("(") and text.endswith(")") and _match_paren(text, 0) == len(text) - 1:
        inner = text[1:-1].strip()
        if inner == text:
            break
        text = inner
    if text in {"1", "0 == 0", "1 != 0", "1 == 1"}:
        return True
    if text in {"0", "0 != 0", "1 == 0"}:
        return False
    if "&&" in text or "||" in text:
        return None
    match = re.fullmatch(r"(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+)", text)
    if not match:
        return None
    left, op, right = match.group(1).strip(), match.group(2), match.group(3).strip()
    left_n, right_n = _literal(left), _literal(right)
    if left_n is None or right_n is None:
        return None
    return {">": left_n > right_n, "<": left_n < right_n, ">=": left_n >= right_n,
            "<=": left_n <= right_n, "==": left_n == right_n, "!=": left_n != right_n}[op]


def _literal(text):
    text = text.strip()
    if len(text) >= 3 and text[0] == "'" and text[-1] == "'" and "\\" not in text[1:-1]:
        body = text[1:-1]
        if len(body) == 1:
            return ord(body)
        return None
    return _int_or_none(text)


def _join_bool(parts, op):
    """Fold a chain of && or ||. A constant arm is dropped or short-circuits."""
    live = []
    for part in parts:
        truth = _const_bool(part)
        if op == "||" and truth is True:
            return "1"
        if op == "&&" and truth is False:
            return "0"
        if truth is True and op == "&&":
            continue
        if truth is False and op == "||":
            continue
        live.append(part)
    if not live:
        return "1" if op == "&&" else "0"
    if len(live) == 1:
        return live[0]
    return (" %s " % op).join("(%s)" % part for part in live)


def _tidy_gotos(lines):
    """Drop a goto that lands on the next statement, and fold identical arms.

    `if (c) { goto loc_x; } else { body } loc_x:` is `if (!c) { body }`.
    Both arms jumping to the same label are one jump. A label with no goto is
    removed. This does not move a call or invent a condition.
    """
    current = list(lines)
    for _ in range(8):
        nxt = _fold_header_loops(_fold_terminal_labels(
            _close_backward_gotos(_drop_unreachable(_tidy_once(current)))))
        if nxt == current:
            return _drop_unused_labels(current)
        current = nxt
    return _drop_unused_labels(current)


def _fold_terminal_labels(lines):
    """A goto to a label that only continues or breaks is that same statement."""
    replace = {}
    for index, line in enumerate(lines[:-1]):
        match = re.fullmatch(r"loc_([0-9a-fA-F]+):", line.strip())
        if not match:
            continue
        action = lines[index + 1].strip()
        if action not in {"continue;", "break;"}:
            continue
        nxt = lines[index + 2].strip() if index + 2 < len(lines) else ""
        if nxt.startswith("}") or nxt.startswith("loc_") or nxt == "":
            replace[match.group(1)] = action
    if not replace:
        return lines
    label_at = {}
    for index, line in enumerate(lines):
        match = re.fullmatch(r"loc_([0-9a-fA-F]+):", line.strip())
        if match and match.group(1) in replace:
            label_at[match.group(1)] = index
    blocked = set()
    for index, line in enumerate(lines):
        match = re.fullmatch(r"\s*goto loc_([0-9a-fA-F]+);", line)
        if not match or match.group(1) not in replace:
            continue
        start = label_at.get(match.group(1), index)
        lo, hi = sorted((start, index))
        between = "\n".join(lines[lo:hi])
        # A loop keyword between the label and the goto means the two
        # continues would not leave the same loop. Leave that goto.
        if re.search(r"\b(while|for)\b", between):
            blocked.add(match.group(1))
    rewritten = []
    for line in lines:
        match = re.fullmatch(r"(\s*)goto loc_([0-9a-fA-F]+);", line)
        if match and match.group(2) in replace and match.group(2) not in blocked:
            rewritten.append(match.group(1) + replace[match.group(2)])
            continue
        label = re.fullmatch(r"loc_([0-9a-fA-F]+):", line.strip())
        if label and label.group(1) in replace and label.group(1) not in blocked:
            continue
        rewritten.append(line)
    return rewritten


def _fold_header_loops(lines):
    """`loc: if (c) { body; goto loc; }` is `while (c) { body; }` when that goto is the only one."""
    for index, line in enumerate(lines[:-1]):
        match = re.fullmatch(r"loc_([0-9a-fA-F]+):", line.strip())
        if not match:
            continue
        head = re.fullmatch(r"if \((.*)\) \{", lines[index + 1].strip())
        if not head:
            continue
        close = _matching_close(lines, index + 1)
        if close is None or lines[close].strip() != "}":
            continue
        if close - 1 <= index + 1:
            continue
        if lines[close - 1].strip() != "goto loc_%s;" % match.group(1):
            continue
        gotos = [pos for pos, item in enumerate(lines) if re.search(r"\bgoto loc_%s;" % match.group(1), item)]
        if gotos != [close - 1]:
            continue
        indent = re.match(r"\s*", lines[index + 1]).group(0)
        body = lines[index + 2:close - 1]
        rewritten = [indent + "while (%s) {" % head.group(1)]
        rewritten.extend(body)
        rewritten.append(indent + "}")
        return lines[:index] + rewritten + lines[close + 1:]
    return lines


def _indent_of(line):
    return len(line) - len(line.lstrip(" "))


def _matching_close(lines, open_at):
    """Index of the line that closes the `{` on `open_at`, or None.

    `} else {` closes the then-arm and also opens the else, so a later call
    on that line starts a new arm.
    """
    raw0 = re.sub(r'"[^"]*"', '""', lines[open_at].strip())
    depth = raw0.count("{") - raw0.count("}")
    if raw0.startswith("}") and "{" in raw0:
        depth = 1
    if depth < 1:
        depth = max(raw0.count("{"), 1)
    for index in range(open_at + 1, len(lines)):
        raw = re.sub(r'"[^"]*"', '""', lines[index].strip())
        if raw.startswith("}") and depth == 1:
            return index
        depth += raw.count("{") - raw.count("}")
        if depth <= 0:
            return index
    return None


def _goto_only(lines):
    body = [line.strip() for line in lines if line.strip()]
    if len(body) != 1:
        return None
    match = re.fullmatch(r"goto loc_([0-9a-fA-F]+);", body[0])
    return match.group(1) if match else None


def _tidy_once(lines):
    out = []
    index = 0
    while index < len(lines):
        raw = lines[index].strip()
        bare = re.fullmatch(r"goto loc_([0-9a-fA-F]+);", raw)
        if bare and index + 1 < len(lines) and lines[index + 1].strip().lower() == "loc_%s:" % bare.group(1).lower():
            index += 1
            continue
        single = re.fullmatch(r"if \((.*)\) goto loc_([0-9a-fA-F]+);", raw)
        if single and index + 1 < len(lines) and lines[index + 1].strip().lower() == "loc_%s:" % single.group(2).lower():
            index += 1
            continue
        match = re.fullmatch(r"if \((.*)\) \{", raw)
        close = _matching_close(lines, index) if match else None
        if match and close is not None:
            cond = match.group(1)
            pad = " " * _indent_of(lines[index])
            close_text = lines[close].strip()
            if close_text == "} else {":
                else_close = _matching_close(lines, close)
            else:
                else_close = None
            then_lines = lines[index + 1:close]
            then_goto = _goto_only(then_lines)
            else_goto = _goto_only(lines[close + 1:else_close]) if else_close is not None else None
            nxt = else_close + 1 if else_close is not None else close + 1
            nxt_label = lines[nxt].strip().lower() if nxt < len(lines) else ""
            if then_goto and else_goto and then_goto.lower() == else_goto.lower() and else_close is not None:
                out.append("%sgoto loc_%s;" % (pad, then_goto))
                index = else_close + 1
                continue
            if then_goto and else_close is not None and nxt_label == "loc_%s:" % then_goto.lower():
                if not any(line.strip() for line in lines[close + 1:else_close]):
                    index = nxt
                    continue
                inner = _reindent(lines[close + 1:else_close], _indent_of(lines[index]) + 2)
                out.append("%sif (%s) {" % (pad, _negate(cond)))
                out.extend(inner)
                out.append("%s}" % pad)
                index = nxt
                continue
            if then_goto and else_close is None and nxt_label == "loc_%s:" % then_goto.lower():
                index = nxt
                continue
            if else_goto and else_close is not None and nxt_label == "loc_%s:" % else_goto.lower():
                inner = _reindent(then_lines, _indent_of(lines[index]) + 2)
                out.append("%sif (%s) {" % (pad, cond))
                out.extend(inner)
                out.append("%s}" % pad)
                index = nxt
                continue
        out.append(lines[index])
        index += 1
    return out


def _reindent(lines, spaces):
    body = [line for line in lines if line.strip()]
    if not body:
        return []
    base = min(_indent_of(line) for line in body)
    pad = " " * spaces
    return [pad + line[base:] for line in body]


def _drop_unreachable(lines):
    """A goto immediately after a return, break, or continue does not run."""
    out = []
    dead = False
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        if raw.endswith(":") or raw == "}" or raw.startswith("} ") or raw.startswith("} else"):
            dead = False
        if dead and raw.startswith("goto "):
            continue
        out.append(line)
        dead = raw.startswith("return ") or raw in {"return;", "break;", "continue;"}
    return out


def _close_backward_gotos(lines):
    """`loc_x: body goto loc_x;` is `while (1) { body }` when the body is straight.

    Other jumps to the same label stay, and the label stays with them.
    """
    targets = {}
    for line in lines:
        match = re.search(r"\bgoto loc_([0-9a-fA-F]+);", line)
        if match:
            targets[match.group(1).lower()] = targets.get(match.group(1).lower(), 0) + 1
    out = []
    index = 0
    while index < len(lines):
        match = re.fullmatch(r"loc_([0-9a-fA-F]+):", lines[index].strip())
        if not match:
            out.append(lines[index])
            index += 1
            continue
        label = match.group(1).lower()
        if targets.get(label, 0) != 1:
            out.append(lines[index])
            index += 1
            continue
        depth = 0
        end = None
        for pos in range(index + 1, len(lines)):
            raw = lines[pos].strip()
            if depth == 0 and re.fullmatch(r"goto loc_%s;" % label, raw, flags=re.I):
                end = pos
                break
            if depth == 0 and re.fullmatch(r"loc_[0-9a-fA-F]+:", raw):
                break
            depth += raw.count("{") - raw.count("}")
            if depth < 0:
                break
        if end is None:
            out.append(lines[index])
            index += 1
            continue
        pad = " " * _indent_of(lines[index])
        body = [line for line in lines[index + 1:end] if line.strip() and not re.fullmatch(r"loc_[0-9a-fA-F]+:", line.strip())]
        out.append("%swhile (1) {" % pad)
        out.extend(_reindent(body, len(pad) + 2) or [pad + "  ;"])
        out.append("%s}" % pad)
        index = end + 1
    return out


def _drop_unused_labels(lines):
    needed = set()
    for line in lines:
        match = re.search(r"\bgoto loc_([0-9a-fA-F]+);", line)
        if match:
            needed.add(match.group(1).lower())
    kept = []
    index = 0
    while index < len(lines):
        match = re.fullmatch(r"loc_([0-9a-fA-F]+):", lines[index].strip())
        if match and match.group(1).lower() not in needed:
            if index + 1 < len(lines) and lines[index + 1].strip() == ";":
                index += 2
                continue
            index += 1
            continue
        kept.append(lines[index])
        index += 1
    return kept


def _collapse_empty(by, succs, entry):
    """Redirect edges through blocks that only fall into their successor.

    A compiler join is often an empty block in front of the real post-dominator.
    Leaving that block in the graph makes later entries `goto` the empty label
    instead of falling into the block the branch already post-dominates.
    """
    preds = _preds(succs)

    def final_dest(node, seen):
        block = by.get(node)
        targets = succs.get(node, [])
        # One-predecessor relays are branch arms. Folding those into the
        # successor gives the branch two identical edges and deletes the
        # condition. Shared joins are the blocks later entries goto.
        shared = len(preds.get(node, [])) >= 2
        if (not shared or not block or block.get("stmts") or block.get("switch")
                or block.get("kind") not in {"fall", "goto"} or len(targets) != 1):
            return node
        nxt = targets[0]
        if nxt == node or nxt in seen or nxt not in by:
            return node
        seen.add(nxt)
        return final_dest(nxt, seen)

    mapping = {node: final_dest(node, set()) for node in by}
    remove = {node for node, dest in mapping.items() if dest != node and not by[node].get("stmts")}
    if not remove:
        return by, succs, entry
    new_by = {node: block for node, block in by.items() if node not in remove}
    new_succs = {}
    for node, targets in succs.items():
        if node in remove:
            continue
        redirected = []
        for target in targets:
            target = mapping.get(target, target)
            if target in remove:
                target = mapping.get(target, target)
            if target not in redirected:
                redirected.append(target)
        new_succs[node] = redirected
    if entry in remove:
        entry = mapping.get(entry, entry)
    return new_by, new_succs, entry


def _preds(succs):
    preds = {addr: [] for addr in succs}
    for addr, targets in succs.items():
        for target in targets:
            if target in preds and addr not in preds[target]:
                preds[target].append(addr)
    return preds


def _dominators(entry, nodes, succs, preds):
    dom = {node: set(nodes) for node in nodes}
    dom[entry] = {entry}
    order = [node for node in nodes if node != entry]
    for _ in range(len(nodes) + 1):
        changed = False
        for node in order:
            sets = [dom[pred] for pred in preds.get(node, []) if pred in dom]
            new = set.intersection(*sets) if sets else set()
            new.add(node)
            if new != dom[node]:
                dom[node] = new
                changed = True
        if not changed:
            break
    return dom


def _idoms(dom):
    idom = {}
    for node, dset in dom.items():
        strict = [item for item in dset if item != node]
        if not strict:
            continue
        idom[node] = max(strict, key=lambda cand: (len(dom.get(cand, ())), cand))
    return idom


def _loops(succs, dom):
    preds = _preds(succs)
    headers = {}
    for src, targets in succs.items():
        for target in targets:
            if target in dom.get(src, ()):
                headers.setdefault(target, set()).add(src)
    loops = {}
    for header, latches in headers.items():
        body = {header}
        stack = list(latches)
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            stack.extend(preds.get(node, []))
        leave = [succ for succ in succs.get(header, []) if succ not in body]
        stay = [succ for succ in succs.get(header, []) if succ in body and succ != header]
        loops[header] = {"body": body, "exit": leave[0] if leave else None,
                         "enter": stay[0] if stay else None, "latches": latches}
    # A natural loop misses entries the header does not dominate. Pull those cycle
    # nodes into the body so an edge back to the header can be `continue`.
    for header, info in loops.items():
        forward = _reachable(header, succs)
        backward = _reachable(header, preds)
        cycle = (forward & backward) | {header}
        # Bodies larger than a small cycle are one irreducible component. Pulling
        # them into every header stops if/else from using the real loop exits.
        if len(cycle) <= len(info["body"]) or len(cycle) > 400:
            continue
        info["body"] = cycle
        leave = [succ for succ in succs.get(header, []) if succ not in cycle]
        stay = [succ for succ in succs.get(header, []) if succ in cycle and succ != header]
        if leave:
            info["exit"] = leave[0]
        if stay:
            info["enter"] = stay[0]
    return loops


def _ipdom(by, succs):
    nodes = list(by)
    rev = {node: [] for node in nodes}
    exits = []
    for node, targets in succs.items():
        if not targets:
            exits.append(node)
        for target in targets:
            if target in rev:
                rev[target].append(node)
    if not exits:
        return {}
    exit_id = -1
    rev_nodes = nodes + [exit_id]
    rev_succs = {node: list(rev.get(node, [])) for node in nodes}
    rev_succs[exit_id] = []
    for node in exits:
        rev_succs[exit_id].append(node)
    rev_preds = _preds(rev_succs)
    dom = _dominators(exit_id, rev_nodes, rev_succs, rev_preds)
    ipdom = {}
    for node in nodes:
        candidates = [item for item in dom.get(node, ()) if item != node]
        if not candidates:
            continue
        best = max(candidates, key=lambda cand: (len(dom.get(cand, ())), cand if isinstance(cand, int) else 0))
        if best != exit_id:
            ipdom[node] = best
    return ipdom


def _mnem(item):
    return str(item.get("mnem", "")).split()[-1]


def _simplify_parens(text):
    out = []
    index = 0
    in_string = False
    while index < len(text):
        char = text[index]
        if char == '"' and (index == 0 or text[index - 1] != "\\"):
            in_string = not in_string
        if char == "(" and not in_string:
            end = _match_paren(text, index)
            if end is not None and "(" not in text[index + 1:end] and ")" not in text[index + 1:end]:
                folded = _fold_flat(text[index + 1:end])
                if folded is not None:
                    out.append(folded)
                    index = end + 1
                    continue
        out.append(char)
        index += 1
    return "".join(out)


def _match_paren(text, start):
    depth = 0
    in_string = False
    for index in range(start, len(text)):
        char = text[index]
        if char == '"' and (index == start or text[index - 1] != "\\"):
            in_string = not in_string
        if in_string:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _fold_flat(inner):
    for op in _ARITH:
        if op not in inner:
            continue
        if any(other in inner for other in _ARITH if other != op):
            return None
        if inner.count(op) != 1:
            return None
        left, right = inner.split(op, 1)
        return _fold_pair(left.strip(), op.strip(), right.strip())
    return None


def _fold_pair(left, op, right):
    if not left or not right:
        return None
    left_n = _int_or_none(left)
    right_n = _int_or_none(right)
    if left_n is not None and right_n is not None:
        if op == "+":
            return _fmt_int(left_n + right_n)
        if op == "-" :
            return _fmt_int(left_n - right_n)
        if op == "*":
            return _fmt_int(left_n * right_n)
        if op == "/" and right_n != 0:
            return _fmt_int(int(left_n / right_n))
        return None
    if op == "+" and right == "0":
        return left
    if op == "+" and left == "0":
        return right
    if op == "-" and right == "0":
        return left
    if op == "*" and right == "1":
        return left
    if op == "*" and left == "1":
        return right
    return None


def _int_or_none(text):
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    try:
        return int(text, 0) if text.startswith(("0x", "-0x")) else int(text)
    except ValueError:
        return None


def _fmt_int(number):
    if number < 0:
        return "(%d)" % number
    return str(number)
