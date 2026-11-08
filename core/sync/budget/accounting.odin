package budget

@(private)
phase_valid :: proc(cost: Cost, phase: Job_Phase) -> bool {
	if cost.jobs == 0 do return phase == .None
	return phase == .Queued || phase == .Running || phase == .Held
}

@(private)
admit :: proc(node: ^Node, remove, add: Cost) -> Error {
	assert(
		node.used.bytes >= remove.bytes &&
		node.used.streams >= remove.streams &&
		node.used.jobs >= remove.jobs,
	)
	bytes := node.used.bytes - remove.bytes
	streams := node.used.streams - remove.streams
	jobs := node.used.jobs - remove.jobs
	if add.bytes > max(u64) - bytes ||
	   add.streams > max(u64) - streams ||
	   add.jobs > max(u64) - jobs {
		return .Overflow
	}
	if add.bytes > node.limits.bytes - bytes ||
	   add.streams > node.limits.streams - streams ||
	   add.jobs > node.limits.jobs - jobs {
		return .Limit_Exceeded
	}
	return .None
}

@(private)
change_usage :: proc(node: ^Node, remove, add: Cost, before, after: Job_Phase) {
	node.used.bytes = node.used.bytes - remove.bytes + add.bytes
	node.used.streams = node.used.streams - remove.streams + add.streams
	node.used.jobs = node.used.jobs - remove.jobs + add.jobs
	switch before {
	case .None:
	case .Queued:
		node.used.queued -= remove.jobs
	case .Running:
		node.used.running -= remove.jobs
	case .Held:
		node.used.held -= remove.jobs
	}
	switch after {
	case .None:
	case .Queued:
		node.used.queued += add.jobs
	case .Running:
		node.used.running += add.jobs
	case .Held:
		node.used.held += add.jobs
	}
	node.peak.bytes = max(node.peak.bytes, node.used.bytes)
	node.peak.streams = max(node.peak.streams, node.used.streams)
	node.peak.jobs = max(node.peak.jobs, node.used.jobs)
	node.peak.queued = max(node.peak.queued, node.used.queued)
	node.peak.running = max(node.peak.running, node.used.running)
	node.peak.held = max(node.peak.held, node.used.held)
}

@(private)
reject :: proc(start: ^Node) {
	node := start
	for node != nil {
		if node.rejected != max(u64) do node.rejected += 1
		node = node.parent
	}
}
