#include "pipeline/WorkQueue.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <numeric>
#include <thread>
#include <vector>

namespace bseal::pipeline::test {
    namespace {

        TEST(WorkQueue, PushThenPopSingleThread) {
            WorkQueue<int> queue(2);

            EXPECT_TRUE(queue.push(10));
            EXPECT_TRUE(queue.push(20));

            auto first = queue.pop();
            ASSERT_TRUE(first.has_value());
            EXPECT_EQ(*first, 10);

            auto second = queue.pop();
            ASSERT_TRUE(second.has_value());
            EXPECT_EQ(*second, 20);
        }

        TEST(WorkQueue, PushAfterCloseReturnsFalse) {
            WorkQueue<int> queue(1);

            queue.close();

            EXPECT_TRUE(queue.closed());
            EXPECT_FALSE(queue.push(42));

            auto value = queue.pop();
            EXPECT_FALSE(value.has_value());
        }

        TEST(WorkQueue, CloseDrainsAlreadyQueuedItems) {
            WorkQueue<int> queue(4);

            ASSERT_TRUE(queue.push(1));
            ASSERT_TRUE(queue.push(2));
            ASSERT_TRUE(queue.push(3));

            queue.close();

            auto a = queue.pop();
            auto b = queue.pop();
            auto c = queue.pop();
            auto d = queue.pop();

            ASSERT_TRUE(a.has_value());
            ASSERT_TRUE(b.has_value());
            ASSERT_TRUE(c.has_value());
            EXPECT_FALSE(d.has_value());

            EXPECT_EQ(*a, 1);
            EXPECT_EQ(*b, 2);
            EXPECT_EQ(*c, 3);
        }

        TEST(WorkQueue, CloseWakesBlockedConsumer) {
            WorkQueue<int> queue(1);

            std::atomic_bool consumer_returned{false};

            std::thread consumer([&] {
                auto value = queue.pop();
                EXPECT_FALSE(value.has_value());
                consumer_returned.store(true, std::memory_order_release);
            });

            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            EXPECT_FALSE(consumer_returned.load(std::memory_order_acquire));

            queue.close();
            consumer.join();

            EXPECT_TRUE(consumer_returned.load(std::memory_order_acquire));
        }

        TEST(WorkQueue, TransfersAllItemsBetweenMultipleThreads) {
            constexpr int producer_count = 4;
            constexpr int items_per_producer = 250;
            constexpr int total_items = producer_count * items_per_producer;

            WorkQueue<int> queue(16);

            std::atomic_int producer_done_count{0};

            std::vector<std::thread> producers;
            producers.reserve(producer_count);

            for (int producer = 0; producer < producer_count; ++producer) {
                producers.emplace_back([&, producer] {
                    const int base = producer * items_per_producer;

                    for (int i = 0; i < items_per_producer; ++i) {
                        ASSERT_TRUE(queue.push(base + i));
                    }

                    producer_done_count.fetch_add(1, std::memory_order_acq_rel);
                });
            }

            std::vector<int> consumed;
            consumed.reserve(total_items);

            std::thread consumer([&] {
                while (true) {
                    auto item = queue.pop();
                    if (!item) {
                        break;
                    }

                    consumed.push_back(*item);
                }
            });

            for (auto &producer : producers) {
                producer.join();
            }

            ASSERT_EQ(producer_done_count.load(std::memory_order_acquire), producer_count);

            queue.close();
            consumer.join();

            ASSERT_EQ(consumed.size(), static_cast<std::size_t>(total_items));

            std::sort(consumed.begin(), consumed.end());

            std::vector<int> expected(total_items);
            std::iota(expected.begin(), expected.end(), 0);

            EXPECT_EQ(consumed, expected);
        }

        TEST(WorkQueue, ZeroCapacityIsNormalizedToOne) {
            WorkQueue<int> queue(0);

            EXPECT_TRUE(queue.push(123));

            auto value = queue.pop();
            ASSERT_TRUE(value.has_value());
            EXPECT_EQ(*value, 123);
        }

    } // namespace
} // namespace bseal::pipeline::test