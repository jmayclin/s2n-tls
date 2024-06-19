/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include "s2n_test.h"
#include "tls/s2n_resume.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_set.h"

#define NUM_TEST_KEYS    3
#define NUM_TEST_THREADS 2
#define DELETION_INDEX   1
#define TEST_ITERATIONS  10000000

/* copy pasted */
static int s2n_config_store_ticket_key_comparator(const void *a, const void *b)
{
    if (((const struct s2n_ticket_key *) a)->intro_timestamp >= ((const struct s2n_ticket_key *) b)->intro_timestamp) {
        return S2N_GREATER_OR_EQUAL;
    } else {
        return S2N_LESS_THAN;
    }
}

void *s2n_thread_test_cb(void *thread_comms)
{
    struct s2n_set *set = (struct s2n_set *) thread_comms;

    //struct random_communication *thread_comms_ptr = (struct random_communication *) thread_comms;
    EXPECT_OK(s2n_set_remove(set, DELETION_INDEX));

    return NULL;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    printf("starting the test\n");

    uint32_t count[NUM_TEST_KEYS] = { 0 };

    for (int iter = 0; iter < TEST_ITERATIONS; iter++) {
        const int element_size = sizeof(struct s2n_ticket_key);
        EXPECT_NULL(s2n_set_new(element_size, NULL));

        struct s2n_set *set = NULL;
        EXPECT_NOT_NULL(set = s2n_set_new(element_size, s2n_config_store_ticket_key_comparator));
        // uint32_t set_len = 0;
        // EXPECT_OK(s2n_set_len(set, &set_len));
        // EXPECT_EQUAL(set_len, 0);

        // we don't want any key that is all zeros, so start with i = 0
        for (int i = 1; i <= NUM_TEST_KEYS; i++) {
            struct s2n_ticket_key key = { 0 };
            uint8_t *bytes = &key;
            for (int j = 0; j < sizeof(struct s2n_ticket_key); j++) {
                bytes[j] = i;
            }

            EXPECT_OK(s2n_set_add(set, &key));
        }

        {
            uint32_t set_len = 0;
            EXPECT_OK(s2n_set_len(set, &set_len));
            EXPECT_EQUAL(set_len, NUM_TEST_KEYS);
        }

        pthread_t threads[NUM_TEST_THREADS];
        EXPECT_EQUAL(pthread_create(&threads[0], NULL, s2n_thread_test_cb, set), 0);
        EXPECT_EQUAL(pthread_create(&threads[1], NULL, s2n_thread_test_cb, set), 0);

        // sleep for 1 ms
        // set atomic to true
        EXPECT_EQUAL(pthread_join(threads[0], NULL), 0);
        EXPECT_EQUAL(pthread_join(threads[1], NULL), 0);

        {
            uint32_t set_len = 0;
            EXPECT_OK(s2n_set_len(set, &set_len));
            count[set_len - 1]++;

            struct s2n_ticket_key *key = NULL;
            for (int k = 0; k < set_len; k++) {
                EXPECT_OK(s2n_set_get(set, k, &key));
                uint8_t *bytes = key;
                bool found_zero = false;
                bool all_zero = true;
                for (int l = 0; l < sizeof(struct s2n_ticket_key); l++) {
                    if (bytes[l] == 0) {
                        found_zero = true;
                    } else {
                        all_zero = false;
                    }
                };

                if (found_zero) {
                    printf("oh no, something was zerod\n");
                }

                if (found_zero && !all_zero) {
                    printf(".... This is a problem\n");
                }
            }
            //EXPECT_EQUAL(set_len, NUM_TEST_KEYS - 1);
        }

        // struct s2n_ticket_key *key = NULL;
        // for (int i = 0; i < NUM_TEST_KEYS; i++) {
        //     EXPECT_OK(s2n_set_get(set, i, &key));
        //     EXPECT_EQUAL(key->intro_timestamp, i + 1);
        // }
        EXPECT_OK(s2n_set_free(set));
    }

    for (int i = 0; i < NUM_TEST_KEYS; i++) {
        printf("len: %d: %d\n", i + 1, count[i]);
    }

    EXPECT_EQUAL(1, 2);

    // struct array_element e1 = { .first = 1, .second = 'a' };
    // EXPECT_OK(s2n_set_add(set, &e1));
    // EXPECT_OK(s2n_set_len(set, &set_len));
    // EXPECT_EQUAL(set_len, 1);
    // EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    // EXPECT_NOT_NULL(ep);
    // EXPECT_EQUAL(ep->first, 1);
    // EXPECT_EQUAL(ep->second, 'a');
    // EXPECT_ERROR(s2n_set_get(set, 1, (void **) &ep));

    END_TEST();
}
