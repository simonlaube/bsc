from priority_queue import PriorityQueue

def test_pq_slot_ranges():
    """Tests if the priority classes get the right amount of slots assigned.
    slots[x] = slots[x - 1] + nr of assigned slots to category x."""
    pq = PriorityQueue(3)
    assert(pq.slot_ranges[2] == 8), 'test_pq_slots failed'
    assert(pq.slot_ranges[1] == 7), 'test_pq_slots failed'
    assert(pq.slot_ranges[0] == 5), 'test_pq_slots failed'
    print('test_pq_slot_ranges successful')

def test_pq_next():
    pq = PriorityQueue(3)
    for i in range(0, 10):
        pq.append(0, '0')
        pq.append(1, '1')
        pq.append(2, '2')
    assert(pq.next() == '0')
    assert(pq.next() == '0')
    assert(pq.next() == '0')
    assert(pq.next() == '0')
    assert(pq.next() == '0')
    assert(pq.next() == '1')
    assert(pq.next() == '1')
    assert(pq.next() == '2')
    assert(pq.next() == '0')
    print('test_pq_next successful')

def test_pq_next_empty():
    pq = PriorityQueue(3)
    assert(pq.next() == None)
    print('test_pq_next_empty successfull')

def main():
    test_pq_slot_ranges()
    test_pq_next()
    test_pq_next_empty()

if __name__ == '__main__':
    main()
