"""Condition-based structurer.

Each statement is emitted once. A second entry is the condition under which
that statement runs: a flat DAG of empty compares becomes a guard, and an
entry into the middle of a loop sets one integer for that entry. A call is
not copied. Nothing is executed.
"""
import heapq
import re

from .struct import _const_bool, _negate, _preds, _reachable, _tidy_gotos, simplify_line


class _Budget(Exception):
    pass


class _Bools(object):
    def __init__(self, limit):
        self.true = ("T",)
        self.false = ("F",)
        self.memo = {}
        self.rank = {id(self.true): 0, id(self.false): 1}
        self.count = 1
        self.limit = limit

    def atom(self, text):
        truth = _const_bool(text)
        if truth is True:
            return self.true
        if truth is False:
            return self.false
        return self._node(("A", str(text)))

    def not_(self, node):
        if node == self.true:
            return self.false
        if node == self.false:
            return self.true
        if node[0] == "N":
            return node[1]
        if node[0] == "A":
            return self.atom(_negate(node[1]))
        return self._node(("N", node))

    def and_(self, left, right):
        if left == self.false or right == self.false or _complements(left, right):
            return self.false
        if left == self.true:
            return right
        if right == self.true:
            return left
        if left is right:
            return left
        if self.rank.get(id(left), 0) > self.rank.get(id(right), 0):
            left, right = right, left
        return self._node(("&", left, right))

    def or_(self, left, right):
        if left == self.true or right == self.true or _complements(left, right):
            return self.true
        if left == self.false:
            return right
        if right == self.false:
            return left
        if left is right:
            return left
        if self.rank.get(id(left), 0) > self.rank.get(id(right), 0):
            left, right = right, left
        return self._node(("|", left, right))

    def _node(self, key):
        # Identity of the children, not a walk of the formula. A shared
        # subformula is a DAG, and hashing the tuple would expand it.
        if key[0] == "A":
            sig = key
        elif key[0] == "N":
            sig = ("N", id(key[1]))
        else:
            sig = (key[0], id(key[1]), id(key[2]))
        hit = self.memo.get(sig)
        if hit is not None:
            return hit
        self.count += 1
        if self.count > self.limit:
            raise _Budget("formula")
        self.rank[id(key)] = self.count
        self.memo[sig] = key
        return key


def _complements(left, right):
    if left is right:
        return False
    if left[0] == "N" and left[1] is right:
        return True
    if right[0] == "N" and right[1] is left:
        return True
    if left[0] == "A" and right[0] == "A" and _negate(left[1]) == right[1]:
        return True
    return False


def structure_reaching(entry, by, succs):
    """Lines for one function, or None when this structurer declines.

    An indirect jump with no table declines. A guard that would not fit on a
    line also declines, and the caller keeps the region text.
    """
    if len(by) > 2500:
        return None
    walker = _Reach(by, {node: list(targets) for node, targets in succs.items()}, max(256, len(by) * 12))
    try:
        lines = walker.function(entry)
    except _Budget as exc:
        structure_reaching.reason = str(exc)
        return None
    if not lines or any(len(line) > 4000 for line in lines):
        structure_reaching.reason = "empty" if not lines else "long"
        return None
    return _tidy_gotos(lines)


class _Reach(object):
    def __init__(self, by, full, limit):
        self.by = by
        self.full = full
        self.bools = _Bools(limit)
        self.fresh = 0
        self.depth = 0
        self.synth = {}
        self.exit_cond = {}
        self._edge_memo = {}
        # Spilled predicates are reused for one statement list. A nested loop
        # gets its own map so a name assigned inside it is not used outside.
        self._spill = {}

    def function(self, entry):
        nodes = set(_reachable(entry, self.full))
        succs = {node: [t for t in self.full.get(node, []) if t in nodes] for node in nodes}
        entries, nodes, succs = self._reduce([entry], nodes, succs, banned=set())
        self._spill = {}
        return self._straight(entries, nodes, succs, None)

    def _reduce(self, entries, nodes, succs, banned):
        """Collapse loops until the graph is a DAG. `banned` headers stay put."""
        self.depth += 1
        if self.depth > 48:
            raise _Budget("nest")
        try:
            while True:
                bodies = {}
                for root in entries:
                    if root not in nodes:
                        continue
                    for header, body in _loop_bodies(root, succs).items():
                        if header in banned:
                            continue
                        if banned & body:
                            continue
                        bodies.setdefault(header, set()).update(body & nodes)
                inner = _innermost(_components(bodies))
                if not inner:
                    return entries, nodes, succs
                headers, body = min(inner, key=lambda item: (len(item[1]), _sort_key(min(item[0], key=_sort_key))))
                entries, nodes, succs = self._collapse(entries, nodes, succs, headers, body)
        finally:
            self.depth -= 1

    def _collapse(self, entries, nodes, succs, headers, body):
        headers = set(headers)
        body = set(body) & set(nodes)
        preds = _preds(succs)
        loop_entries = []
        for node in sorted(body, key=_sort_key):
            if any(pred not in body for pred in preds.get(node, [])):
                loop_entries.append(node)
        for header in sorted(headers, key=_sort_key):
            if header not in loop_entries:
                loop_entries.append(header)
        loop_entries = _unique(loop_entries)
        dag = {node: [] for node in body}
        for node in body:
            for target in succs.get(node, []):
                if target in body and target not in headers:
                    dag[node].append(target)
        # Inner loops keep their own back edges; this loop's headers are banned.
        inner_entries, inner_nodes, inner_succs = self._reduce(loop_entries, set(body), dag, banned=set(headers))
        enter_name = "enter_%s" % _label(min(headers, key=_sort_key)) if len(loop_entries) > 1 else None
        exits = []
        for node in body:
            for target in succs.get(node, []):
                if target not in body:
                    exits.append((node, target, self._edge(node, target)))
        back = []
        for node in body:
            for target in succs.get(node, []):
                if target in headers:
                    back.append((node, target, self._edge(node, target)))
        # Map sources that the inner reduction replaced. Inner synths are the
        # sources that remain in inner_nodes; original nodes inside an inner
        # loop are gone from inner_succs.
        saved_spill = self._spill
        self._spill = {}
        lines = self._straight(inner_entries, inner_nodes, inner_succs, enter_name)
        lines.extend(self._closing(inner_entries, inner_nodes, inner_succs, back, exits, enter_name, headers))
        self._spill = saved_spill
        wrapped = ["while (1) {"]
        wrapped.extend(_indent(lines, 2))
        wrapped.append("}")
        self.fresh += 1
        synth_id = ("L", self.fresh)
        exit_targets = _unique([target for _src, target, _cond in exits])
        leave = None
        exit_map = {}
        if len(exit_targets) <= 1:
            for target in exit_targets:
                exit_map[target] = self.bools.true
        else:
            leave = "leave_%s" % _label(min(headers, key=_sort_key))
            for index, target in enumerate(exit_targets, start=1):
                exit_map[target] = self.bools.atom("%s == %d" % (leave, index))
        arrivals = []
        for pred, targets in succs.items():
            if pred in body:
                continue
            for target in targets:
                if target in body:
                    arrivals.append((pred, self._edge(pred, target), target))
        self.synth[synth_id] = {
            "lines": wrapped,
            "entries": loop_entries,
            "enter_name": enter_name,
            "multi": enter_name is not None,
            "arrivals": arrivals,
        }
        self.exit_cond[synth_id] = exit_map
        new_nodes = set(node for node in nodes if node not in body)
        new_nodes.add(synth_id)
        new_succs = {}
        for node, targets in succs.items():
            if node in body:
                continue
            mapped = []
            for target in targets:
                mapped_target = synth_id if target in body else target
                if mapped_target not in mapped:
                    mapped.append(mapped_target)
            new_succs[node] = mapped
        new_succs[synth_id] = list(exit_targets)
        new_entries = []
        for entry in entries:
            mapped = synth_id if entry in body else entry
            if mapped not in new_entries:
                new_entries.append(mapped)
        if not new_entries:
            new_entries = [synth_id]
        return new_entries, new_nodes, new_succs

    def _closing(self, entries, nodes, succs, back, exits, enter_name, headers):
        guards = self._guard_map(entries, nodes, succs, enter_name)
        # A back edge whose source was collapsed into an inner loop is carried
        # by that loop's exit condition, which the guard of the synth already
        # names. Fall back to the recorded condition when the source is still
        # in this graph.
        lines = []
        exit_targets = _unique([target for _src, target, _cond in exits])
        leave = "leave_%s" % _label(min(headers, key=_sort_key)) if len(exit_targets) > 1 else None
        if leave:
            lines.insert(0, "%s = 0;" % leave)
            grouped = {target: self.bools.false for target in exit_targets}
            for src, target, cond in exits:
                term = self._at(src, cond, guards)
                grouped[target] = self.bools.or_(grouped[target], term)
            for index, target in enumerate(exit_targets, start=1):
                text = self._text(grouped[target], lines)
                if text == "0":
                    continue
                if text == "1":
                    lines.append("%s = %d;" % (leave, index))
                    lines.append("break;")
                    continue
                lines.append("if (%s) {" % text)
                lines.append("  %s = %d;" % (leave, index))
                lines.append("  break;")
                lines.append("}")
        by_target = {}
        back_term = self.bools.false
        for src, target, cond in back:
            term = self._at(src, cond, guards)
            back_term = self.bools.or_(back_term, term)
            by_target[target] = self.bools.or_(by_target.get(target, self.bools.false), term)
        if enter_name and by_target:
            arms = []
            for target, term in by_target.items():
                temps = []
                text = self._text(term, temps)
                if text == "0":
                    continue
                arms.append((text, temps, target))
            for _text, temps, _target in arms:
                lines.extend(temps)
            opened = False
            for text, _temps, target in arms:
                if text == "1" and not opened:
                    lines.append("%s = %s;" % (enter_name, _label(target)))
                    return lines
                word = "if" if not opened else "else if"
                opened = True
                lines.append("%s (%s) %s = %s;" % (word, text, enter_name, _label(target)))
            if opened:
                lines.append("else break;")
            else:
                lines.append("break;")
            return lines
        text = self._text(back_term, lines)
        if text == "1":
            return lines
        if text == "0":
            lines.append("break;")
            return lines
        lines.append("if (!(%s)) break;" % text)
        return lines

    def _at(self, src, cond, guards):
        """Condition of an edge out of `src`, after inner loops were collapsed."""
        if src in guards:
            return self.bools.and_(guards[src], cond)
        # The source was folded into a synth that is still in this graph.
        for node, synth in self.synth.items():
            if node not in guards:
                continue
            for _pred, _cond, entry in synth["arrivals"]:
                del _pred, _cond, entry
            # No arrival list points at the collapsed source. Use the synth
            # guard when this edge's source block is not in the graph.
        for node in guards:
            if not self._is_synth(node):
                continue
            exit_map = self.exit_cond.get(node, {})
            # Prefer a synth that names this condition's target via exit_cond
            # only when src itself is gone. The caller passes the original src.
        if self._is_synth(src):
            return self.bools.and_(guards.get(src, self.bools.true), cond)
        return cond

    def _straight(self, entries, nodes, succs, enter_name):
        nodes = set(_reachable_any(entries, succs)) & set(nodes)
        succs = {node: [t for t in succs.get(node, []) if t in nodes] for node in nodes}
        if not nodes:
            return []
        order = _topo(entries, succs, nodes)
        guards = self._guard_map(entries, nodes, succs, enter_name)
        return self._emit(order, guards, succs)

    def _guard_map(self, entries, nodes, succs, enter_name):
        nodes = set(nodes)
        entries = [entry for entry in _unique(entries) if entry in nodes]
        if not entries:
            return {}
        clipped = {node: [t for t in succs.get(node, []) if t in nodes] for node in nodes}
        preds = _preds(clipped)
        per_entry = {}
        for entry in entries:
            reach = _reachable(entry, clipped) & nodes
            rc = {entry: self.bools.true}
            for node in _topo([entry], clipped, reach):
                if node == entry:
                    continue
                term = self.bools.false
                for pred in preds.get(node, []):
                    if pred not in rc:
                        continue
                    term = self.bools.or_(term, self.bools.and_(rc[pred], self._edge(pred, node)))
                rc[node] = term
            per_entry[entry] = rc
        guards = {}
        if enter_name is None or len(entries) == 1:
            rc = per_entry[entries[0]]
            for node in nodes:
                guards[node] = rc.get(node, self.bools.false)
            return guards
        for node in nodes:
            term = self.bools.false
            for entry in entries:
                sel = self.bools.atom("%s == %s" % (enter_name, _label(entry)))
                term = self.bools.or_(term, self.bools.and_(sel, per_entry[entry].get(node, self.bools.false)))
            guards[node] = term
        return guards

    def _emit(self, order, guards, succs):
        try:
            folded = self._try_switches(order, guards, succs)
        except _Budget:
            folded = None
        if folded is not None:
            return folded
        return self._emit_linear(order, guards)

    def _emit_linear(self, order, guards):
        lines = []
        bucket = []
        bucket_guard = None

        def flush():
            if not bucket:
                return
            if bucket_guard == self.bools.true:
                lines.extend(bucket)
            elif bucket_guard != self.bools.false:
                text = self._text(bucket_guard, lines)
                if text == "1":
                    lines.extend(bucket)
                elif text != "0":
                    lines.append("if (%s) {" % text)
                    lines.extend(_indent(bucket, 2))
                    lines.append("}")
            bucket.clear()

        for node in order:
            if self._pure(node):
                continue
            guard = guards.get(node, self.bools.false)
            if guard == self.bools.false:
                continue
            if self._is_synth(node):
                flush()
                stmts = self._open_synth(node, guards)
            else:
                stmts = self._stmts(node)
            if not stmts:
                continue
            if bucket and guard != bucket_guard:
                flush()
            if not bucket:
                bucket_guard = guard
            bucket.extend(stmts)
            if self._is_synth(node):
                flush()
        flush()
        return lines

    def _try_switches(self, order, guards, succs):
        """Emit a jump table as `switch` when each arm's statements are private to it.

        A statement reached from two arms stays after the switch, under the
        condition that already names those arms. A call is still printed once.
        """
        nodes = set(order)
        switches = []
        for node in order:
            if self._is_synth(node):
                continue
            rows = ((self.by.get(node) or {}).get("switch") or {}).get("cases") or []
            if len(rows) >= 2:
                switches.append(node)
        if not switches:
            return None
        ncases = sum(len(((self.by.get(node) or {}).get("switch") or {}).get("cases") or [])
                     for node in switches)
        if ncases * max(len(order), 1) > 250000:
            return None
        claimed = {}
        planned = {}
        for switch in switches:
            groups = self._case_groups(switch, nodes)
            if not groups:
                continue
            atoms = []
            for group in groups:
                group["atoms"] = [self.bools.atom("(%s) == %s" % (group["expr"], index))
                                  for index in group["indices"]]
                atoms.extend(group["atoms"])
            reachers = self._case_reach(switch, groups, succs, nodes, set(switches))
            for node in order:
                if node == switch or node in claimed or self._pure(node):
                    continue
                owners = reachers.get(node) or ()
                if len(owners) != 1:
                    continue
                gid = next(iter(owners))
                guard = guards.get(node, self.bools.false)
                if guard == self.bools.false:
                    continue
                if not self._only_group(guard, groups, gid, atoms):
                    continue
                simplified = self._assume_group(guard, groups, gid, atoms)
                if simplified == self.bools.false:
                    continue
                claimed[node] = simplified
                groups[gid].setdefault("body", []).append(node)
            if any(group.get("body") for group in groups):
                planned[switch] = groups
        if not planned:
            return None
        lines = []
        bucket = []
        bucket_guard = None

        def flush():
            if not bucket:
                return
            if bucket_guard == self.bools.true:
                lines.extend(bucket)
            elif bucket_guard != self.bools.false:
                text = self._text(bucket_guard, lines)
                if text == "1":
                    lines.extend(bucket)
                elif text != "0":
                    lines.append("if (%s) {" % text)
                    lines.extend(_indent(bucket, 2))
                    lines.append("}")
            bucket.clear()

        for node in order:
            if node in claimed:
                continue
            if node in planned:
                flush()
                guard = guards.get(node, self.bools.true)
                body = self._switch_lines(planned[node], claimed)
                if guard not in (self.bools.true, self.bools.false):
                    text = self._text(guard, lines)
                    if text not in {"1", "0"}:
                        lines.append("if (%s) {" % text)
                        lines.extend(_indent(body, 2))
                        lines.append("}")
                        continue
                lines.extend(body)
                continue
            if self._pure(node):
                continue
            guard = guards.get(node, self.bools.false)
            if guard == self.bools.false:
                continue
            if self._is_synth(node):
                flush()
                stmts = self._open_synth(node, guards)
            else:
                stmts = self._stmts(node)
            if not stmts:
                continue
            if bucket and guard != bucket_guard:
                flush()
            if not bucket:
                bucket_guard = guard
            bucket.extend(stmts)
            if self._is_synth(node):
                flush()
        flush()
        return lines

    def _case_groups(self, switch, nodes):
        info = (self.by.get(switch) or {}).get("switch") or {}
        expr = info.get("expr") or "expr"
        grouped = {}
        order = []
        for index, target in info.get("cases") or []:
            if target not in nodes:
                continue
            if target not in grouped:
                order.append(target)
                grouped[target] = []
            if index not in grouped[target]:
                grouped[target].append(index)
        return [{"expr": expr, "target": target, "indices": grouped[target]} for target in order]

    def _case_reach(self, switch, groups, succs, nodes, switches):
        reachers = {}
        for gid, group in enumerate(groups):
            target = group["target"]
            if target not in nodes:
                continue
            stack = [target]
            seen = set()
            while stack:
                node = stack.pop()
                if node in seen or node not in nodes:
                    continue
                if node in switches and node != target:
                    reachers.setdefault(node, set()).add(gid)
                    seen.add(node)
                    continue
                seen.add(node)
                reachers.setdefault(node, set()).add(gid)
                for nxt in succs.get(node, []):
                    if nxt != switch:
                        stack.append(nxt)
        return reachers

    def _only_group(self, guard, groups, gid, atoms):
        blank = {id(atom): self.bools.false for atom in atoms}
        if self._assume(guard, blank) != self.bools.false:
            return False
        for other in range(len(groups)):
            if other == gid:
                continue
            if self._assume_group(guard, groups, other, atoms) != self.bools.false:
                return False
        return True

    def _assume_group(self, guard, groups, gid, atoms):
        forced = {id(atom): self.bools.false for atom in atoms}
        for atom in groups[gid]["atoms"]:
            forced[id(atom)] = self.bools.true
        return self._assume(guard, forced)

    def _assume(self, node, forced, memo=None):
        if memo is None:
            memo = {}
        hit = memo.get(id(node))
        if hit is not None:
            return hit
        if node == self.bools.true or node == self.bools.false:
            result = node
        elif node[0] == "A":
            result = forced.get(id(node), node)
        elif node[0] == "N":
            result = self.bools.not_(self._assume(node[1], forced, memo))
        else:
            left = self._assume(node[1], forced, memo)
            right = self._assume(node[2], forced, memo)
            result = self.bools.and_(left, right) if node[0] == "&" else self.bools.or_(left, right)
        memo[id(node)] = result
        return result

    def _switch_lines(self, groups, claimed):
        lines = ["switch (%s) {" % _unwrap(groups[0]["expr"])]
        saved_spill = self._spill
        for group in groups:
            body_nodes = group.get("body") or []
            if not body_nodes:
                continue
            for index in group["indices"]:
                lines.append("  case %s:" % index)
            guards = {node: claimed[node] for node in body_nodes}
            # A predicate spilled inside one arm must not be reused after the
            # switch: the assignment would be inside the arm.
            self._spill = dict(saved_spill)
            body = self._emit_linear(body_nodes, guards)
            self._spill = saved_spill
            lines.extend(_indent(body, 4))
            last = ""
            for line in reversed(body):
                if line.strip():
                    last = line.strip()
                    break
            if last not in {"break;", "continue;"} and not last.startswith("return"):
                lines.append("    break;")
        lines.append("}")
        return lines

    def _open_synth(self, node, guards):
        synth = self.synth[node]
        lines = []
        if synth.get("multi") and synth.get("enter_name") and synth.get("entries"):
            name = synth["enter_name"]
            default = synth["entries"][0]
            lines.append("%s = %s;" % (name, _label(default)))
            for pred, cond, entry in synth["arrivals"]:
                if entry == default or pred not in guards:
                    continue
                text = self._text(self.bools.and_(guards[pred], cond), lines)
                if text == "0":
                    continue
                if text == "1":
                    lines.append("%s = %s;" % (name, _label(entry)))
                else:
                    lines.append("if (%s) %s = %s;" % (text, name, _label(entry)))
        lines.extend(synth["lines"])
        return lines

    def _stmts(self, node):
        return [simplify_line(stmt) for stmt in (self.by[node].get("stmts") or []) if str(stmt).strip()]

    def _pure(self, node):
        if self._is_synth(node):
            return False
        block = self.by.get(node) or {}
        if any(str(stmt).strip() for stmt in block.get("stmts") or []):
            return False
        return True

    def _is_synth(self, node):
        return isinstance(node, tuple) and bool(node) and node[0] == "L"

    def _edge(self, src, dst):
        key = (src, dst)
        hit = self._edge_memo.get(key)
        if hit is not None:
            return hit
        result = self._edge_body(src, dst)
        self._edge_memo[key] = result
        return result

    def _edge_body(self, src, dst):
        if self._is_synth(src):
            return self.exit_cond.get(src, {}).get(dst, self.bools.true)
        if self._is_synth(dst):
            synth = self.synth.get(dst)
            if not synth:
                return self.bools.true
            terms = [cond for pred, cond, _entry in synth["arrivals"] if pred == src]
            if not terms:
                return self.bools.true
            acc = terms[0]
            for term in terms[1:]:
                acc = self.bools.or_(acc, term)
            return acc
        owned = list(self.full.get(src, []))
        block = self.by.get(src) or {}
        switch_cond = self._switch_cond(block, dst, owned)
        if switch_cond is not None:
            return switch_cond
        if block.get("kind") == "ijmp" and dst in owned:
            # No table. Each target stays a separate edge, named as an indirect
            # dispatch, so the block is still emitted once.
            return self.bools.atom("ijmp_%x == %d" % (src, owned.index(dst)))
        if block.get("kind") == "if" and len(owned) >= 2 and owned[0] != owned[1]:
            cond = self.bools.atom(block.get("cond") or "1")
            if dst == owned[0]:
                return cond
            if dst == owned[1]:
                return self.bools.not_(cond)
        return self.bools.true

    def _switch_cond(self, block, dst, owned):
        """Condition of one edge out of a jump table. None when this is not a switch."""
        cases = (block.get("switch") or {}).get("cases") or []
        if not cases:
            return None
        expr = (block.get("switch") or {}).get("expr") or "expr"
        indices = [index for index, target in cases if target == dst]
        if indices:
            acc = None
            for index in indices:
                atom = self.bools.atom("(%s) == %s" % (expr, index))
                acc = atom if acc is None else self.bools.or_(acc, atom)
            return acc
        if dst not in owned:
            return None
        acc = self.bools.true
        seen = []
        for index, _target in cases:
            if index in seen:
                continue
            seen.append(index)
            acc = self.bools.and_(acc, self.bools.not_(self.bools.atom("(%s) == %s" % (expr, index))))
        return acc

    def _text(self, node, into=None):
        self._temps = []
        rendered = self._render(node)
        if into is not None:
            into.extend(self._temps)
        self._temps = []
        return rendered

    def _take_temps(self):
        temps = getattr(self, "_temps", [])
        self._temps = []
        return temps

    def _render(self, node):
        hit = self._spill.get(id(node))
        if hit is not None:
            return hit
        if node == self.bools.true:
            return "1"
        if node == self.bools.false:
            return "0"
        if node[0] == "A":
            return node[1]
        if node[0] == "N":
            inner = self._render(node[1])
            text = "!(%s)" % inner
        else:
            op = "&&" if node[0] == "&" else "||"
            text = "(%s) %s (%s)" % (self._render(node[1]), op, self._render(node[2]))
        if len(text) > 96:
            self.fresh += 1
            name = "p_%d" % self.fresh
            self._temps.append("%s = %s;" % (name, text))
            self._spill[id(node)] = name
            return name
        self._spill[id(node)] = text
        return text


def _loop_bodies(entry, succs):
    on = set()
    seen = set()
    back = []

    def walk(node):
        seen.add(node)
        on.add(node)
        for target in succs.get(node, []):
            if target not in succs and target != entry:
                continue
            if target in on:
                back.append((node, target))
            elif target not in seen:
                walk(target)
        on.discard(node)

    if entry is not None:
        walk(entry)
    bodies = {}
    reverse = _preds(succs)
    for _src, header in back:
        if header in bodies:
            continue
        forward = _reachable(header, succs)
        backward = _reachable(header, reverse)
        bodies[header] = (forward & backward) | {header}
    return bodies


def _components(bodies):
    headers = list(bodies)
    parent = {header: header for header in headers}

    def find(header):
        while parent[header] != header:
            parent[header] = parent[parent[header]]
            header = parent[header]
        return header

    for left in headers:
        for right in headers:
            if left == right:
                continue
            one, two = bodies[left], bodies[right]
            # Equal bodies are one loop with two headers. A proper subset is nesting.
            if one & two and not (one < two or two < one):
                parent[find(left)] = find(right)
    groups = {}
    for header in headers:
        groups.setdefault(find(header), set()).add(header)
    found = []
    for grouped in groups.values():
        body = set()
        for header in grouped:
            body |= bodies[header]
        found.append((grouped, body))
    return found


def _innermost(comps):
    found = []
    for headers, body in comps:
        if any(header in body and header not in headers
               for other, _other_body in comps if other != headers
               for header in other):
            continue
        found.append((headers, body))
    return found


def _topo(entries, succs, nodes):
    """Ready nodes in sort-key order. A heap, not a list popped from the front."""
    nodes = set(nodes)
    entry_set = set(entries)
    indeg = {node: 0 for node in nodes}
    for node in nodes:
        for target in succs.get(node, []):
            if target in nodes:
                indeg[target] += 1
    tie = 0
    heap = []

    def push(node):
        nonlocal tie
        tie += 1
        rank = 0 if node in entry_set else 1
        heapq.heappush(heap, ((rank,) + _sort_key(node), tie, node))

    for node in nodes:
        if indeg[node] == 0:
            push(node)
    order = []
    while heap:
        _key, _tie, node = heapq.heappop(heap)
        order.append(node)
        for target in succs.get(node, []):
            if target not in nodes:
                continue
            indeg[target] -= 1
            if indeg[target] == 0:
                push(target)
    if len(order) != len(nodes):
        raise _Budget("cycle")
    return order


def _reachable_any(entries, succs):
    found = set()
    for entry in entries:
        found |= _reachable(entry, succs)
    return found


def _unique(items):
    found = []
    for item in items:
        if item not in found:
            found.append(item)
    return found


def _label(node):
    if isinstance(node, tuple):
        return str(node[1])
    if isinstance(node, dict):
        return str(node.get("id", (0, 0))[1])
    return "%x" % node


def _sort_key(node):
    if isinstance(node, tuple):
        return (1, node[1])
    if isinstance(node, dict):
        return (1, node.get("id", (0, 0))[1])
    return (0, node if isinstance(node, int) else 0)


def _indent(lines, spaces):
    pad = " " * spaces
    return [pad + line if line else line for line in lines]


def _unwrap(expr):
    """Drop one pair of parentheses that wraps the whole expression."""
    if len(expr) < 2 or expr[0] != "(" or expr[-1] != ")":
        return expr
    depth = 0
    for index, char in enumerate(expr):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(expr) - 1:
                return expr
    return expr[1:-1]


def _goto_count(lines):
    return sum(len(re.findall(r"\bgoto\b", line)) for line in lines or [])
