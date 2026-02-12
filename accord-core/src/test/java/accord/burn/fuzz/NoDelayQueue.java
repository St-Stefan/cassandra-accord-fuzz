/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package accord.burn.fuzz;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import accord.impl.basic.Pending;
import accord.impl.basic.PendingQueue;
import accord.utils.RandomSource;

import static accord.impl.basic.RecurringPendingRunnable.isRecurring;

/**
 * A deterministic queue that orders items by their deadline time.
 */
public class NoDelayQueue implements PendingQueue {
    private static class Item implements Comparable<Item> {
        final Pending pending;
        long time;
        long seq;

        Item(Pending pending) {
            this.pending = pending;
        }

        @Override
        public int compareTo(Item other) {
            int c = Long.compare(this.time, other.time);
            if (c == 0)
                c = Long.compare(this.seq, other.seq);
            return c;
        }

        @Override
        public String toString() {
            return "@" + time + "/" + seq + ":" + pending;
        }
    }

    private final PriorityQueue<Item> queue = new PriorityQueue<>();
    private final IdentityHashMap<Pending, Item> preregistered = new IdentityHashMap<>();

    private long now = 0;
    private long seq = 0;
    private int recurring = 0;

    // Fixed time increment per operation to avoid any timeout-based behavior
    private static final long AVERAGE_PROCESSING_TIME_MILLIS = 0;

    @SuppressWarnings("unused")
    public NoDelayQueue() {
    }

    @SuppressWarnings("unused")
    public NoDelayQueue(RandomSource random) {
        // Ignore random?
    }

    @Override
    public void add(Pending item) {
        add(item, 0, TimeUnit.NANOSECONDS);
    }

    @Override
    public void addNoDelay(Pending add) {
        add(add, 0, TimeUnit.NANOSECONDS);
    }

    @Override
    public void add(Pending item, long delay, TimeUnit units) {
        long executionTime = now + units.toMillis(delay);

        Item scheduled = preregistered.get(item);
        if (scheduled == null) {
            scheduled = new Item(item);
            preregistered.put(item, scheduled);
            if (isRecurring(item))
                ++recurring;
        }

        scheduled.time = executionTime;
        scheduled.seq = seq++;

        queue.add(scheduled);
    }

    @Override
    public void preregister(Pending item) {
        if (preregistered.put(item, new Item(item)) != null)
            throw new IllegalStateException("Item already preregistered");
        if (isRecurring(item))
            ++recurring;
    }

    @Override
    public boolean remove(Pending remove) {
        Item item = preregistered.get(remove);
        if (item == null)
            return false;

        preregistered.remove(remove);
        queue.remove(item);

        if (isRecurring(remove))
            --recurring;

        return true;
    }

    @Override
    public Pending poll() {
        if (queue.isEmpty())
            return null;
        Item item = queue.poll();
        now = Math.max(now + AVERAGE_PROCESSING_TIME_MILLIS, item.time);

        preregistered.remove(item.pending);
        if (isRecurring(item.pending))
            --recurring;
        return item.pending;
    }

    @Override
    public List<Pending> drain(Predicate<Pending> toDrain) {
        List<Pending> result = new ArrayList<>();
        Iterator<Item> it = queue.iterator();
        while (it.hasNext()) {
            Item item = it.next();
            if (toDrain.test(item.pending)) {
                it.remove();
                preregistered.remove(item.pending);
                if (isRecurring(item.pending))
                    --recurring;
                result.add(item.pending);
            }
        }
        return result;
    }

    @Override
    public int size() {
        return queue.size();
    }

    @Override
    public long nowInMillis() {
        return now;
    }

    @Override
    public boolean hasNonRecurring() {
        return recurring != preregistered.size();
    }

    @Override
    public Iterator<Pending> iterator() {
        return queue.stream().map(item -> item.pending).iterator();
    }

    @Override
    public String toString() {
        return "FifoDelayQueue{size=" + queue.size() + ", now=" + now + "}";
    }
}