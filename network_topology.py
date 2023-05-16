import heapq

def dijkstra(graph, start, end):
    heap = [(0, start)]
    visited = set()
    while heap:
        (dist, node) = heapq.heappop(heap)
        if node not in visited:
            visited.add(node)
            if node == end:
                return dist
            for neighbor, cost in graph[node].items():
                if neighbor not in visited:
                    heapq.heappush(heap, (dist + cost, neighbor))
    return float('inf')

def find_path(src, dst):
    graph = {}
    switches = ['s1', 's2', 's3', 's4']
    edges = [('s1', 's2'), ('s1', 's3'), ('s2', 's4'), ('s3', 's4')]
    for switch in switches:
        graph[switch] = {}
        for edge in edges:
            if switch == edge[0]:
                graph[switch][edge[1]] = 1
            elif switch == edge[1]:
                graph[switch][edge[0]] = 1
    hosts = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9', 'h10', 'h11', 'h12', 'h13', 'h14', 'h15', 'h16']
    paths = []
    for i in range(len(switches)):
        for j in range(i+1, len(switches)):
            for h1 in hosts:
                for h2 in hosts:
                    if h1 != h2 and h1.startswith('h') and h2.startswith('h'):
                        cost = dijkstra(graph, switches[i], h1) + dijkstra(graph, h1, h2) + dijkstra(graph, h2, switches[j])
                        paths.append({
                            'src': h1,
                            'dst': h2,
                            'cost': cost,
                            'route': [
                                switches[i],
                                h1,
                                h2,
                                switches[j]
                            ]
                        })
    paths = sorted(paths, key=lambda x: x['cost'])
    for path in paths:
        if src == path['src'] and dst == path['dst']:
            return path['route'][1:-1]