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
    preds = _preds(succs)
    dom = _dominators(entry, list(by), succs, preds)
    builder = _Structurer(entry, by, succs, dom, _ipdom(by, succs), _loops(succs, dom))
    builder.run()
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

    def run(self):
        self._emit(self.entry, set(), [], 0)
        self._sweep()

    def render(self):
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
        return lines

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
            self.emit_line("goto indirect;")
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
        follow = self._follow(node)
        if follow is None or follow in barriers or follow in self.emitted or _in_loop(follow, ctx):
            return
        self._emit(follow, barriers, ctx, depth + 1)

    def _follow(self, node):
        follow = self.ipdom.get(node)
        if follow is None or follow not in self.by:
            return None
        if self.idom.get(follow) == node:
            return follow
        return None

    def _write_if(self, node, barriers, ctx, depth):
        cond, then_n, else_n, consumed = self._fold(node)
        for extra in consumed:
            self.emitted.add(extra)
        follow = self._follow(node)
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
            expr = " || ".join("(%s)" % part for part in ors)
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
            expr = " && ".join("(%s)" % part for part in ands)
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
        if decision[0] == "inline":
            if target in self.emitted:
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
        # is not pulled into the first branch. Later reaches goto.
        if target not in self.emitted:
            return ("inline", None)
        return ("line", "goto loc_%x;" % target)

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
        self._emit_stmts(header)
        ctx2 = ctx + [{"kind": "loop", "header": header, "exit": exit_}]
        body_barriers = set(barriers)
        body_barriers.update({header, latch})
        if exit_ is not None:
            body_barriers.add(exit_)
        targets = self.succs.get(header, [])
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
        follow = self._follow(start) or (self._follow(owner) if owner != start else None)
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
    padded = " %s " % cond
    for op, flipped in sorted(_FLIP.items(), key=lambda item: -len(item[0])):
        token = " %s " % op
        if token in padded:
            return padded.replace(token, " %s " % flipped, 1).strip()
    return "!(%s)" % cond


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
