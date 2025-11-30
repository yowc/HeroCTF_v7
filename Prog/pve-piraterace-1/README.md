# PVE - Pirate Race #1

### Category

Prog

### Difficulty

Easy

### Tags

- PVE

### Author

Log_s

### Description

This is the first Pirate Race PVE challenge. In this challenge, you will need to code your own bot in order to race against a predefined bot.

To access the platform, you need will need to create a CTFd access token:
- Head to [https://ctf.heroctf.fr/settings#tokens](https://ctf.heroctf.fr/settings#tokens)
- Set the date to the day after the CTF ends (1st December 2025)
- Generate a token (copy and save the value somewhere, you won't be able to display it again)
- Use this token to authenticate to the platform

More details about how to play can be found in the documentation page on the challenge's platform below.

HTTP: [http://pirate.heroctf.fr](http://pirate.heroctf.fr)

### Write Up

The first bot you are playing against is a simple bot, which is only moving in a spiral pattern, randomly validating islands. Below is the code for the second bot, which beats the first one. There are many ways to improve upon the following code. The idea is to find the nearest unvalidated island, move towards it, and circle around it until it is validated.

The first two bots to not take into consideration the rhum barrels, which are an addition to make the PVP more interesting.

```python
import math
        
def make_move(game_state):
    islands = game_state['islands']
    ship = game_state['your_ship']
    x, y = ship['position']['x'], ship['position']['y']
    data = game_state['data']

    # Determine at what stage we are
    if not data:
        data = "0-0000,0000,00"

    stage = int(data.split('-')[0])
    tx, ty, tr = map(int, data.split('-')[1].split(','))
    acceleration = 100
    angle = 0

    # The looped state variable is used to reach stage 0 code if we switched from stage 2 from stage 0
    looped_state = True
    while looped_state:
        looped_state = False

        # Find closest unconquered island
        if stage == 0:
            # Get unconquered islands
            unconquered = [i for i in islands if not i['validated']]

            # Find the closest to our current position
            closest_dist = -1
            tx, ty, tr = None, None, None
            for island in unconquered:
                i_x, i_y = island['position']['x'], island['position']['y']
                dx, dy = x - i_x, y - i_y
                dist = math.hypot(dx, dy)
                if closest_dist < 0 or dist < closest_dist:
                    closest_dist = dist
                    tx, ty = i_x, i_y
                    tr = island['radius']

            # Switch to next stage
            stage = 1

        # Move towards it
        if stage == 1:
            # Check if we're very close to target island
            target_dist = math.hypot(x - tx, y - ty)
            if target_dist <= tr + 20:  # Very close to target
                stage = 2
            else:
                # Move directly towards target, only avoid if absolutely necessary
                angle = _angle_from_A_to_B(x, y, tx, ty)
                
                # Check for critical obstacles only (very close ones)
                for island in islands:
                    i_x, i_y = island['position']['x'], island['position']['y']
                    r = island['radius']
                    if (tx, ty) == (i_x, i_y):  # Skip target island
                        continue
                        
                    # Only avoid if we're heading directly into it
                    dist_to_obstacle = math.hypot(x - i_x, y - i_y)
                    if dist_to_obstacle < r + 30:
                        # Calculate minimal avoidance
                        avoidance_angle = _calculate_minimal_avoidance(
                            (x, y), (tx, ty), (i_x, i_y), r
                        )
                        if avoidance_angle is not None:
                            angle = avoidance_angle

        # Circle around it until it's validated
        if stage == 2:
            for island in islands:
                i_x, i_y = island['position']['x'], island['position']['y']
                validated = island['validated']
                if i_x == tx and i_y == ty and validated:
                    stage = 0
                    looped_state = True
            
            # Circle very close to the island
            circle_angle = _calculate_close_circle_angle((x, y), (tx, ty), tr)
            angle = circle_angle
            
            # Slow down when very close
            dist_to_target = math.hypot(x - tx, y - ty)
            if dist_to_target < tr + 15:
                acceleration = 20

    data = f'{stage}-{tx:04},{ty:04},{tr:02}'

    return {
        'acceleration': acceleration,
        'angle': angle,
        'data': data
        }

def _normalize_angle(angle):
    """Ensure angle is between 0 and 360 degrees."""
    return angle % 360

def _calculate_minimal_avoidance(start, goal, obstacle, radius):
    """Calculate minimal avoidance angle to just barely avoid an obstacle."""
    sx, sy = start
    gx, gy = goal
    ox, oy = obstacle
    
    # Calculate direct path angle
    direct_angle = _angle_from_A_to_B(sx, sy, gx, gy)
    
    # Calculate angle to obstacle
    obstacle_angle = _angle_from_A_to_B(sx, sy, ox, oy)
    
    # Calculate the difference
    angle_diff = obstacle_angle - direct_angle
    
    # Normalize angle difference to [-180, 180]
    while angle_diff > 180:
        angle_diff -= 360
    while angle_diff < -180:
        angle_diff += 360
        
    # If obstacle is to the right of direct path, go left
    if angle_diff > 0:
        avoidance_angle = direct_angle - 15  # Small left turn
    else:
        avoidance_angle = direct_angle + 15  # Small right turn
    
    # Normalize to 0-360 range
    return _normalize_angle(avoidance_angle)

def _calculate_close_circle_angle(position, target, target_radius):
    """Calculate angle to circle very close to target island."""
    px, py = position
    tx, ty = target
    
    # Calculate current distance to target
    dist_to_target = math.hypot(px - tx, py - ty)
    
    # If we're too far, move towards it
    if dist_to_target > target_radius + 10:
        return _angle_from_A_to_B(px, py, tx, ty)
    
    # If we're close enough, circle around it
    # Calculate perpendicular angle for circling
    dx, dy = px - tx, py - ty
    if dx == 0 and dy == 0:
        # We're exactly at the center, pick a random direction
        import random
        return random.uniform(0, 360)
    
    # Calculate perpendicular direction for circling
    # Use the same angle calculation as _angle_from_A_to_B for consistency
    perp_angle_rad = math.atan2(-dx, dy)  # Perpendicular to radius
    perp_angle_deg = math.degrees(perp_angle_rad)
    perp_angle_deg = (perp_angle_deg + 90)  # Same transformation as _angle_from_A_to_B
    return _normalize_angle(perp_angle_deg)

def _angle_from_A_to_B(x1, y1, x2, y2):
    """Calculate angle from point A to point B."""
    dx = x2 - x1
    dy = y2 - y1
    angle_rad = math.atan2(dy, dx)
    angle_deg = math.degrees(angle_rad)
    angle_deg = angle_deg + 90  # Adjust for coordinate system
    return _normalize_angle(angle_deg)
```

### Flag

Hero{b4a1f2b4dd380f4f1a0298eb4efe98bb}