package endpoint

import "sort"

// MergeEndpointLinks returns the stable base links plus the current endpoint
// links, replacing identities that share the same namespace and ifindex.
func MergeEndpointLinks(base []LinkIdentity, endpoints map[string]Endpoint) []LinkIdentity {
	result := append([]LinkIdentity(nil), base...)
	positions := make(map[[2]uint64]int, len(result))
	for index, link := range result {
		key := [2]uint64{link.NetNSInode, uint64(link.IfIndex)}
		if _, ok := positions[key]; !ok {
			positions[key] = index
		}
	}
	uids := make([]string, 0, len(endpoints))
	for uid := range endpoints {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		endpoint := endpoints[uid]
		for _, link := range []LinkIdentity{endpoint.PeerLink, endpoint.HostLink} {
			key := [2]uint64{link.NetNSInode, uint64(link.IfIndex)}
			if index, ok := positions[key]; ok {
				result[index] = link
				continue
			}
			positions[key] = len(result)
			result = append(result, link)
		}
	}
	return result
}
