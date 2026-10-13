#!/usr/bin/env bash

test_description='Message decryption with RFC 9788 header protection'
. $(dirname "$0")/test-lib.sh || exit 1

##################################################

test_require_external_prereq gpgsm

add_gnupg_home

add_email_corpus rfc9788

test_begin_subtest "verify spoofed headers are shown without decryption"
output=$(notmuch show --format=json id:rfc9788_msg001@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["headers"]["From"]="<test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["headers"]["To"]="hidden-recipients: ;"' \
                'subject:[0][0][0]["headers"]["Subject"]="[...]"' \
                'date:[0][0][0]["headers"]["Date"]="Wed, 20 Aug 2025 09:00:00 +0000"'

test_begin_subtest "verify protected headers are shown with decryption"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_msg001@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["headers"]["From"]="Charlie <test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["headers"]["To"]="Alice <alice@example.com>, Bob <bob@example.com>"' \
                'subject:[0][0][0]["headers"]["Subject"]="Secret subject goes here"' \
                'date:[0][0][0]["headers"]["Date"]="Tue, 23 Sep 2025 09:23:00 +0200"'

test_begin_subtest "verify protected headers are shown with decryption and --body=false"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --body=false --format=json id:rfc9788_msg001@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["headers"]["From"]="Charlie <test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["headers"]["To"]="Alice <alice@example.com>, Bob <bob@example.com>"' \
                'subject:[0][0][0]["headers"]["Subject"]="Secret subject goes here"' \
                'date:[0][0][0]["headers"]["Date"]="Tue, 23 Sep 2025 09:23:00 +0200"'

test_begin_subtest "verify indexing works as expected (1/3) -- hidden from"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org from:Charlie)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (1/3) -- hidden to:Alice"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Alice)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (1/3) -- hidden to:Bob"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Bob)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (1/3) -- hidden subject"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org subject:Secret)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (1/3) -- hidden date"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org date:2025-09-23)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (1/3) -- hidden thread structure (msg001)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg001@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (1/3) -- hidden thread structure (msg002)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg002@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg002@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (1/3) -- hidden thread structure (msg003)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg003@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg003@crypto.notmuchmail.org'

test_begin_subtest "verify indexing works as expected (2/3) -- reindex"
test_expect_success 'notmuch reindex --decrypt=true id:rfc9788_msg001@crypto.notmuchmail.org or id:rfc9788_msg002@crypto.notmuchmail.org or id:rfc9788_msg003@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted from"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org from:Charlie)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted to:Alice"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Alice)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted to:Bob"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Bob)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted subject"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org subject:Secret)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted date"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org date:2025-09-23)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted thread structure (msg001)"
test_subtest_known_broken
output=$(notmuch show --entire-thread=true id:rfc9788_msg001@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org
id:rfc9788_msg002@crypto.notmuchmail.org
id:rfc9788_msg003@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted thread structure (msg002)"
test_subtest_known_broken
output=$(notmuch show --entire-thread=true id:rfc9788_msg002@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org
id:rfc9788_msg002@crypto.notmuchmail.org
id:rfc9788_msg003@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted thread structure (msg003)"
test_subtest_known_broken
output=$(notmuch show --entire-thread=true id:rfc9788_msg003@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org
id:rfc9788_msg002@crypto.notmuchmail.org
id:rfc9788_msg003@crypto.notmuchmail.org'

test_begin_subtest "verify indexing works as expected (3/3) -- reindex"
test_expect_success 'notmuch reindex --decrypt=false id:rfc9788_msg001@crypto.notmuchmail.org or id:rfc9788_msg002@crypto.notmuchmail.org or id:rfc9788_msg003@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (3/3) -- hidden from"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org from:Charlie)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (3/3) -- hidden to:Alice"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Alice)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (3/3) -- hidden to:Bob"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Bob)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (3/3) -- hidden subject"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org subject:Secret)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (3/3) -- hidden date"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org date:2025-09-23)
test_expect_equal "$output" ''
test_begin_subtest "verify indexing works as expected (3/3) -- hidden thread structure (msg001)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg001@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (3/3) -- hidden thread structure (msg002)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg002@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg002@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (3/3) -- hidden thread structure (msg003)"
output=$(notmuch show --entire-thread=true id:rfc9788_msg003@crypto.notmuchmail.org | grep $'\fmessage{ id:' | sed 's/^.message{ //;s/ .*//')
test_expect_equal "$output" 'id:rfc9788_msg003@crypto.notmuchmail.org'

test_done
