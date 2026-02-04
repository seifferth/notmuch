#!/usr/bin/env bash

test_description='Message decryption with protected/spoofed Message-ID headers'
. $(dirname "$0")/test-lib.sh || exit 1

##################################################

test_require_external_prereq gpgsm

add_gnupg_home
add_gpgsm_home

add_email_corpus encrypted-message-ids

test_begin_subtest "spoofed id is used without crypto indexing"
output=$(notmuch show --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="spoofed-message-id@crypto.notmuchmail.org"'

test_begin_subtest "spoofed id is used without crypto indexing even when decrypting"
output=$(notmuch show --decrypt=true --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="spoofed-message-id@crypto.notmuchmail.org"'

test_begin_subtest "reindex messages with decrypted indexing enabled"
test_expect_success 'notmuch reindex --decrypt=true tag:inbox'

test_begin_subtest "real id is used with crypto indexing, even when not decrypting"
test_subtest_known_broken
output=$(notmuch show --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="real-message-id@crypto.notmuchmail.org"'

test_begin_subtest "real id is used with crypto indexing, also when decrypting"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="real-message-id@crypto.notmuchmail.org"'

test_begin_subtest "reindex messages with decrypted indexing disabled again"
test_expect_success 'notmuch reindex tag:inbox'

test_begin_subtest "spoofed id is used after second reindexing"
output=$(notmuch show --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="spoofed-message-id@crypto.notmuchmail.org"'

test_begin_subtest "spoofed id is used after second reindexing even when decrypting"
output=$(notmuch show --decrypt=true --format=json subject:Message_001)
test_json_nodes <<<"$output" \
                'message_id:[0][0][0]["id"]="spoofed-message-id@crypto.notmuchmail.org"'

test_done
