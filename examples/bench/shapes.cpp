// Stripped C++ sample for the decompiler scoreboard.
// Virtual calls, a loop, a switch, and structure fields. The values depend on
// argc, and the helpers are noinline, so -O2 cannot fold the body away.
// Compile: g++ -O2 -s -fno-exceptions -fno-devirtualize
struct Point {
    int x;
    int y;
};

struct Shape {
    virtual int area() const = 0;
    virtual ~Shape() {}
};

struct Rect : Shape {
    int w;
    int h;
    Rect(int width, int height) : w(width), h(height) {}
    int area() const override { return w * h; }
};

struct Circle : Shape {
    int r;
    explicit Circle(int radius) : r(radius) {}
    int area() const override { return 3 * r * r; }
};

__attribute__((noinline))
static int span(Point *left, Point *right) {
    int dx = left->x - right->x;
    int dy = left->y - right->y;
    if (dx < 0) {
        dx = -dx;
    }
    if (dy < 0) {
        dy = -dy;
    }
    return dx + dy;
}

__attribute__((noinline))
static Shape *pick(Rect *box, Circle *round, int kind) {
    if (kind & 1) {
        return box;
    }
    return round;
}

__attribute__((noinline))
static int total(Shape **items, int count) {
    int sum = 0;
    for (int index = 0; index < count; index++) {
        if (items[index] != 0) {
            sum += items[index]->area();
        }
    }
    return sum;
}

__attribute__((noinline))
static int classify(int value) {
    switch (value & 7) {
    case 0:
        return 1;
    case 1:
        return 2;
    case 2:
        return 3;
    case 3:
        return 5;
    default:
        return value;
    }
}

int main(int argc, char **argv) {
    Rect box(argc, argc + 3);
    Circle round(argc + 1);
    Shape *items[4];
    items[0] = pick(&box, &round, argc);
    items[1] = pick(&box, &round, argc + 1);
    items[2] = 0;
    items[3] = &box;
    Point a;
    Point b;
    a.x = argc;
    a.y = argv != 0 ? argc + 2 : 0;
    b.x = 4;
    b.y = argc;
    return total(items, argc & 3) + span(&a, &b) + classify(argc);
}
