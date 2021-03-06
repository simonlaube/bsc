# -------------------------------------------------
# Implementation by Simon laube
# -------------------------------------------------

class PriorityQueue:
    """Implementation for the TinySSB ressource manager queue.
    Highest Priority: 0. Priorities get lower the higher the priority number is.
    This queue gives entries of all priority classes a chance to get popped,
    however higher priority entries have more assigned slots.
    Number of slots: sum_{i = 0..nr_priorities-1} int(i^1.5)"""
    def __init__(self, nr_priorities):

        # defines the number of different priority classes
        self.nr_priorities = nr_priorities
        self.queue = []
        self._init_priority_queues()
        self.slot_ranges = self._calculate_slots()
        self.nr_pos = self.slot_ranges[-1]
        self.current_pos = 0 # iterates over all slots
        self.size = 0

    def _init_priority_queues(self):
        """Initializes the queues for each priority."""
        for i in range(0, self.nr_priorities):
            self.queue.append([])

    def _calculate_slots(self):
        """Calculates which priority gets how many slots."""
        slots = []
        for i in range(0, self.nr_priorities):
            # exponential slot assignments.
            slots.insert(0, int(pow(i + 1, 1.5)))
        for i in range(1, self.nr_priorities):
            slots[i] = slots[i] + slots[i - 1]
        return slots

    def _next_pos(self):
        self.current_pos = (self.current_pos + 1) % self.nr_pos

    def append(self, priority, pkt):
        """Adds a packet to the given priority queue."""
        if pkt in self.queue[priority]:
            return
        if priority < 0 or priority > self.nr_priorities - 1:
            print('the given priority is out of range: it is now adjusted to the closest valid priority.')
        if priority <= 0:
            self.queue[0].append(pkt)
        elif priority >= self.nr_priorities - 1:
            self.queue[self.nr_priorities - 1].append(pkt)
        else:
            self.queue[priority].append(pkt)
        self.size += 1

    def _next_with_priority(self, priority):
        """Gets first packet in priority class. If class is empty, go to next class until pkt found.
        If no packet in priority queue, return None."""
        if self.size == 0:
            # reset position
            self.current_pos = 0
            return None
        i = 0
        # TODO: if queue is empty, first go to higher priorities
        while not self.queue[priority] and i < self.nr_priorities:
            priority = (self.nr_priorities + (priority - 1)) % self.nr_priorities
            i += 1
        self._next_pos()
        # return copy of element (without deleting entry in priority queue)
        return (priority, self.queue[priority][0])

    def next(self):
        """Returns the next packet without removing it."""
        for i in range(0, self.nr_priorities):
            if self.current_pos < self.slot_ranges[i]:
                return self._next_with_priority(i)
    
    def remove(self, priority, pkt):
        """Removes a packet from the priority list."""
        self.size -= 1
        self.queue[priority].remove(pkt)

    def pop_next(self):
        """Returns the next packet and removes it."""
        next = self.next()
        if not next:
            return None
        priority, pkt = next
        self.remove(priority, pkt)
        return pkt
