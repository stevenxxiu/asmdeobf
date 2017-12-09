
class MemValues:
    def __init__(self):
        self.values = {}  # {(offset, size): value}

    def has(self, offset, size):
        return (offset, size) in self.values

    def read(self, offset, size):
        return self.values.get((offset, size), None)

    def delete(self, offset, size):
        for cache_offset, cache_size in list(self.values):
            if offset < cache_offset + cache_size and cache_offset < offset + size:
                self.values.pop((cache_offset, cache_size))

    def write(self, offset, size, value, can_overlap=True):
        if can_overlap:
            self.delete(offset, size)
        self.values[(offset, size)] = value

    def invalidate(self):
        self.values.clear()


def is_var(name):
    return isinstance(name, str) and str.isidentifier(name)
