import json
from collections import deque

def solve():
    try:
        M = json.load(open("maze-solve.json"))
    except FileNotFoundError:
        print("Error: maze-solve.json not found in the current directory.")
        return

    W, H = M["width"], M["height"]
    mask = M["openMask"]
    sx, sy = M["start"]
    ex, ey = M["end"]

    DIRS = [("U", 0, -1, 1), ("R", 1, 0, 2), ("D", 0, 1, 4), ("L", -1, 0, 8)]  # letter, dx, dy, bit

    start, end = (sx, sy), (ex, ey)
    prev = {start: None}
    q = deque([start])
    
    while q:
        x, y = q.popleft()
        if (x, y) == end:
            break
        for letter, dx, dy, bit in DIRS:
            if mask[y][x] & bit:                 # this direction is open
                nx, ny = x+dx, y+dy
                # Bound checks
                if 0 <= nx < W and 0 <= ny < H:
                    if (nx, ny) not in prev:
                        prev[(nx, ny)] = (x, y, letter)
                        q.append((nx, ny))

    if end not in prev:
        print("Error: No path found!")
        return

    path = []
    cur = end
    while prev[cur] is not None:
        px, py, letter = prev[cur]
        path.append(letter)
        cur = (px, py)
    
    move_string = "".join(reversed(path))
    print(f"Path length: {len(move_string)}")
    print(move_string)

if __name__ == "__main__":
    solve()
