# PVE - Pirate Race #2

### Category

Prog

### Difficulty

Medium

### Tags

- PVE

### Author

Log_s

### Description

This is the second Pirate Race PVE challenge. Once again, you are playing against a predefined bot. This time, the bot is more advanced.

To access the platform, you need will need to create a CTFd access token:
- Head to [https://ctf.heroctf.fr/settings#tokens](https://ctf.heroctf.fr/settings#tokens)
- Set the date to the day after the CTF ends (1st December 2025)
- Generate a token (copy and save the value somewhere, you won't be able to display it again)
- Use this token to authenticate to the platform

More details about how to play can be found in the documentation page on the challenge's platform below.

HTTP: [http://pirate.heroctf.fr](http://pirate.heroctf.fr)

### Write Up

This time the bot is more advanced. It find the nearest unvalidated island, move towards it, and circle around it until it is validated.

The following code is, as you can see, much shorter and simpler than the previous one, but also more efficient. The idea is not to blindly circle around an island, but to target the specific point next to it to validate it. Most people will have thought of this kind of solution right away. This solution however, still doesn't take into account the rhum barrels.

```python
import math

def distance(a, b):
    return math.dist(a, b)

def nearest_neighbor_path(points, start):
    unvisited = set(points)
    if start in unvisited:
        unvisited.remove(start)

    path = [start]
    current = start

    while unvisited:
        next_point = min(unvisited, key=lambda p: distance(current, p))
        unvisited.remove(next_point)
        path.append(next_point)
        current = next_point

    return path[1:]

def angle_from_A_to_B(x1, y1, x2, y2):
    dx = x2 - x1
    dy = y2 - y1
    angle_rad = math.atan2(dy, dx)
    angle_deg = math.degrees(angle_rad)
    angle_deg = angle_deg + 90
    return angle_deg % 360

def island_to_target(x, y, t):
    match t:
        case 1: return (x+30, y)
        case 2: return (x, y+30)
        case 3: return (x-30, y)
        case 4: return (x, y-30)
        
def make_move(game_state):
    islands = game_state['islands']
    ship = game_state['your_ship']
    px, py = ship['position']['x'], ship['position']['y']
    data = game_state['data']
    
    # Parse data
    start, target_index = None, None
    if data:
        start, target_index = data.split("|")
        start = tuple(map(int,start.split(",")))
        target_index = int(target_index)
    else:
        start = (px, py)

    # Check if island is validated and move to next island
    if target_index is not None:
        nb_validated = len([island for island in islands if island["validated"]])
        if nb_validated > target_index:
            target_index += 1
    else:
        target_index = 0

    # Compute path
    target_pos = [island_to_target(island["position"]["x"], island["position"]["y"], island["type"]) for island in islands]
    path = nearest_neighbor_path(target_pos, start)

    # Define direction
    tx, ty = path[target_index]         
    angle = angle_from_A_to_B(px, py, tx, ty)
    
    # Assign data
    data = f"{int(start[0])},{int(start[1])}|{target_index}"

    #Return result
    return {
        'acceleration': 100,
        'angle': angle,
        'data': data
    }
```

### Flag

Hero{61d477d29f70b607d1128a5da511d96c}