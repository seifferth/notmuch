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
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org from:Charlie)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted to:Alice"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Alice)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted to:Bob"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org to:Bob)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted subject"
output=$(notmuch search --output=messages id:rfc9788_msg001@crypto.notmuchmail.org subject:Secret)
test_expect_equal "$output" 'id:rfc9788_msg001@crypto.notmuchmail.org'
test_begin_subtest "verify indexing works as expected (2/3) -- decrypted date"
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

test_begin_subtest "verify that legacy display elements are removed (1/2)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_legacy_display_01@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'message_content:[0][0][0]["body"][0]["content"][1]["content"]="Greetings, Alice and Bob! This message has a legacy display element.\n"'

test_begin_subtest "verify that legacy display elements are removed (2/2)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_legacy_display_02@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'message_content:[0][0][0]["body"][0]["content"][1]["content"]="Greetings, Alice and Bob! This message has a legacy display element.\n"'

# RFC 9788 suggests that a MUA should handle mismatched From headers as
# follows:
#
# 1. When displaying the message, render the outer From header.
# 2. When replying to the message, use the inner From header.
#
# Following this guidance in notmuch is not straightforward, though, since
# notmuch performs neither of these two functions. (I.e. notmuch just outputs
# the message which is then rendered by the frontend; and while there is
# 'notmuch reply', there is no guarantee that the frontend will use it.)
# This leaves us with two choices:
#
# 1. Use the outer From header -- which we can't do because it could easily
#    lead the frontend to treat the outer From header as authentic in spite
#    of our knowledge that it has been tampered with.
# 2. Use the inner From header -- which we can't do because it would introduce
#    an attack vector for spoofing the From header.
#
# Since neither of these options seems acceptable, I decided to clear a
# mismatched From header instead. This should at least ensure that the user
# does not use the wrong header accidentally. It might also lead them to
# investigate the issue in more depth (e.g. by looking at the message's source
# code) and understand what has happened.
#
# Also note that this decision could be discussed further. If such discussion
# leads to finding a better solution for this problem, the test cases described
# below should be updated to align with the new expectations.
#
test_begin_subtest "guard against From header spoofing (1/2)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_spoofed_from_01@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["headers"]["From"]=""'
test_begin_subtest "guard against From header spoofing (2/2)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_spoofed_from_02@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["headers"]["From"]=""'

test_begin_subtest "guard against MITM'ed outer headers"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_mitm_redirect@crypto.notmuchmail.org)
expected=$(notmuch show --decrypt=true --format=json id:rfc9788_mitm_redirect@crypto.notmuchmail.org | sed 's/, *"Reply-To": *"Bob <mallory@example\.com>"//')
test_expect_equal_json "$output" "$expected"

test_begin_subtest "verify header mask (1/3)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_msg001@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["crypto"]["decrypted"]["header-mask"]["From"]="<test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["To"]="hidden-recipients: ;"' \
                'subject:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Subject"]="[...]"' \
                'date:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Date"]="Wed, 20 Aug 2025 09:00:00 +0000"'
test_begin_subtest "verify header mask (2/3)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_msg002@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["crypto"]["decrypted"]["header-mask"]["From"]="<test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["To"]="hidden-recipients: ;"' \
                'subject:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Subject"]="[...]"' \
                'date:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Date"]="Wed, 20 Aug 2025 08:00:00 +0000"' \
                'in-reply-to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["In-Reply-To"]=null' \
                'references:[0][0][0]["crypto"]["decrypted"]["header-mask"]["References"]=null'
test_begin_subtest "verify header mask (3/3)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_msg003@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'from:[0][0][0]["crypto"]["decrypted"]["header-mask"]["From"]="<test_suite@notmuchmail.org>"' \
                'to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["To"]="hidden-recipients: ;"' \
                'subject:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Subject"]="[...]"' \
                'date:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Date"]="Wed, 20 Aug 2025 20:00:00 +0000"' \
                'in-reply-to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["In-Reply-To"]=null' \
                'references:[0][0][0]["crypto"]["decrypted"]["header-mask"]["References"]=null'
test_begin_subtest "guard against header guessing attacks"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_guessing_attack@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'subject:[0][0][0]["crypto"]["decrypted"]["header-mask"]["Subject"]="[...]"' \
                'in-reply-to:[0][0][0]["crypto"]["decrypted"]["header-mask"]["In-Reply-To"]=null' \
                'references:[0][0][0]["crypto"]["decrypted"]["header-mask"]["References"]=null'

test_begin_subtest "verify protected Message-IDs are handled correctly (1/7)"
output=$(notmuch show --decrypt=false --format=json id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'id:[0][0][0]["id"]="rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org"'
test_begin_subtest "verify protected Message-IDs are handled correctly (2/7)"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'id:[0][0][0]["id"]="rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org"'
test_begin_subtest "verify protected Message-IDs are handled correctly (3/7)"
output=$(notmuch search --output=messages id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org)
test_expect_equal "$output" "id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org"
test_begin_subtest "verify protected Message-IDs are handled correctly (4/7) -- reindex with decryption"
test_expect_success "notmuch reindex --decrypt=true id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org"
test_begin_subtest "verify protected Message-IDs are handled correctly (5/7)"
test_subtest_known_broken
output=$(notmuch search --output=messages id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org)
test_expect_equal "$output" "id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org"
test_begin_subtest "verify protected Message-IDs are handled correctly (6/7) -- reindex without decryption"
test_expect_success "notmuch reindex --decrypt=false id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org"
test_begin_subtest "verify protected Message-IDs are handled correctly (7/7)"
output=$(notmuch search --output=messages id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org or id:rfc9788_protected_message_id_inner_value@crypto.notmuchmail.org)
test_expect_equal "$output" "id:rfc9788_protected_message_id_outer_value@crypto.notmuchmail.org"

notmuch config set show.extra_headers X-Custom-Header
test_begin_subtest "verify that accessing a non-masked custom header without decryption works as expected"
output=$(notmuch show --decrypt=false --format=json id:rfc9788_non_masked_user_defined_header@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'custom_header_value:[0][0][0]["headers"]["X-Custom-Header"]="custom_value_goes_here"'
test_begin_subtest "verify that accessing a non-masked custom header with decryption works as expected"
output=$(notmuch show --decrypt=true --format=json id:rfc9788_non_masked_user_defined_header@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'custom_header_value:[0][0][0]["headers"]["X-Custom-Header"]="custom_value_goes_here"'
test_begin_subtest "verify that accessing a hidden custom header with decryption works as expected"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_hidden_user_defined_header@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'custom_header_value:[0][0][0]["headers"]["X-Custom-Header"]="custom_value_goes_here"' \
                'header_mask:[0][0][0]["crypto"]["decrypted"]["header-mask"]["X-Custom-Header"]=null'
test_begin_subtest "verify that accessing an intentionally spoofed custom header without decryption works as expected"
output=$(notmuch show --decrypt=false --format=json id:rfc9788_intentionally_spoofed_user_defined_header@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'custom_header_value:[0][0][0]["headers"]["X-Custom-Header"]="this_value_is_phony"'
test_begin_subtest "verify that accessing an intentionally spoofed custom header with decryption works as expected"
test_subtest_known_broken
output=$(notmuch show --decrypt=true --format=json id:rfc9788_intentionally_spoofed_user_defined_header@crypto.notmuchmail.org)
test_json_nodes <<<"$output" \
                'custom_header_value:[0][0][0]["headers"]["X-Custom-Header"]="this_value_is_real"' \
                'header_mask:[0][0][0]["crypto"]["decrypted"]["header-mask"]["X-Custom-Header"]="this_value_is_phony"'
notmuch config set show.extra_headers

test_done
