# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# reference seed taken from libsodium's
# libsodium/test/default/box_seed.c
test_seed = (
    b"77076d0a7318a57d3c16c17251b26645"
    b"df4c2f87ebc0992ab177fba51db92c2a"
)

# reference public and secret keys taken
# splitting the expected test output from
# libsodium/test/default/box_seed.exp
test_pk = (
    b"ed7749b4d989f6957f3bfde6c56767e9"
    b"88e21c9f8784d91d610011cd553f9b06"
)

test_sk = (
    b"accd44eb8e93319c0570bc11005c0e01"
    b"89d34ff02f6c17773411ad191293c98f"
)
