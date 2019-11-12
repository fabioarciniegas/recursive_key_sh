#!/usr/bin/env bash
# A proof of concept and illustration of using N HMACs instead of ONE
# hard-coded plain app key.
#
echo -e "\x1B[91m"
# Essential idea: Instead of provisioning a single CLIENT_KEY to all
#                 devices provision to each device a KEY such that
#                 KEY = RANDOM_PART_1+HMAC(RANDOM_PART_1,CLIENT_KEY)

echo -e "\x1B[0m"

# --------------------------------------
#               PROVISIONING
# --------------------------------------

echo -e "\x1B[91mReminder: HMACS verify integrity and authenticity (therefore all results below are different)\x1B[0m "
echo -n "any message"  | openssl dgst -sha256
echo -n 'any message' | openssl dgst -sha256 -hmac 'specific key'
echo -n 'any message' | openssl dgst -sha256 -hmac 'do not have key'
echo -n 'another message' | openssl dgst -sha256 -hmac 'specific key'


echo -e "\x1B[91mHow to build an app key to be provisioned:\x1B[0m"

provisioned_key_part_1='xxxx___n_random_characters'
client_master_key='yyyy_n_random_characters'

echo -e "\x1B[91mGenerate an HMAC for part_1:\x1B[0m "
provisioned_key_part_2=`echo -n $provisioned_key_part_1 | openssl dgst -sha256 -hmac $client_master_key`

echo -e "\x1B[91mProvisioned key is union of two parts (random and hmac): \x1B[0m "

echo -e "\x1B[32mPROVISIONED KEY = \x1B[34m$provisioned_key_part_1\x1B[33m$provisioned_key_part_2\x1B[0m "
provisioned_key=$provisioned_key_part_1$provisioned_key_part_2

echo -e "\x1B[91mNote: provisioned_key is just copied as a string into the device, which doesn't need to calculate HMACs\x1B[0m "


# --------------------------------------
#               VERIFICATION
#
# Party A send a message and its HMAC.
# Party B verifies by calculating the HMAC of the message and verifying it is the same as the one received.
# --------------------------------------

echo -e "\x1B[91mNow suppose the provisioned key is sent through the API. We Split in its componentes and verify:\x1B[0m "
received_key=$provisioned_key
echo -n $received_key | cut -c1-26 | tr -d $'\n'

echo -n $received_key | cut -c27- | tr -d $'\n'

message=`echo -n $received_key | cut -c1-26 | tr -d $'\n'`

claimed_hmac=`echo -n $received_key | cut -c27- | tr -d $'\n'`

calculated_hmac=`echo -n $message | openssl dgst -sha256 -hmac $client_master_key`

echo -e "\x1B[91m$claimed_hmac == \n$calculated_hmac\x1B[0m"

# Note that at no point was the client master key in any device.

# The verification relies not on the uniqueness of the app_key
# provisioned to the device but in its authenticity. In other words,
# we rely on the fact that the HMAC part of the provisioned key can
# only be valid if it was generated with the secret client master key


# --------------------------------------
#                RECURSION
# --------------------------------------

# The above is enough to provide n keys to m devices instead of
# relying on a single app key. That is the main point.

# However, the concept can be applied  recursively so the keys shared
# with clients are not master keys but mere secondary keys. Only Trend
# would ever know a master key (M) . The keys shared with partners (S_i) are
# always derived. The device keys provisioned to partners's devices
# (D_i) are in turn always derived from the secondary.
#
# HMAC(random,Master) = Secondary Key
# HMAC(random,Secondary) = Tertiary Key
# ...
# HMAC(random,Tertiary) = Key provisioned to Device
#
#
# In internal conversations we have sometimes referred to this scheme as
# "KMS-like" only to imply intuitively that we can apply it recursively and have
# hierarchies of keys, not to say we are using AWS KMS or that the concept
# of envelope encryption is directly used.
#
# This would be helpful to allow subkeys to be shared with clients
# without fear of compromising one unique per-client master key.
# The following code illustrates the idea:

partner_master_key_completely_internal='0000:n_random_characters'
master=$partner_master_key_completely_internal

secondary_key_part_1='0000:0000:n_random_characters'

secondary_key_part_2=`echo -n $secondary_key_part_1 | openssl dgst -sha256 -hmac $master`
secondary_key=$secondary_key_part_1$secondary_key_part_2

tertiary_key_1_part_1='0000:0000:0000:n_random_characters'
tertiary_key_1_part_2=`echo -n $tertiary_key_part_1 | openssl dgst -sha256 -hmac $secondary_key`
tertiary_key_1=$tertiary_key_1_part_1$tertiary_key_1_part_2


tertiary_key_2_part_1='0000:0000:0001:n_random_characters'
tertiary_key_2_part_2=`echo -n $tertiary_key_2_part_1 | openssl dgst -sha256 -hmac $secondary_key`
tertiary_key_2=$tertiary_key_2_part_1$tertiary_key_2_part_2

# CLIENT 1 (0000)                  CLIENT 2 (0001)
#   |                                   | 
#   \___ Secondary  (0000:0000)          \___ Secondary (0001:0000)
#         |
#         \____ Tertiary 1 (0000:0000:0000)
#         \____ Tertiary 2 (0000:0000:0001)
#


echo -e "\x1B[91mOnly tertiary key 2 is shared with partner: \n$tertiary_key_1\x1B[0m"
key_used_by_client=$tertiary_key_2
echo -e "\x1B[91mPartner uses it to create a provisioned key: \x1B[0m"
provisioned_key_part_1='n_random_characters'
provisioned_key_part_2=`echo -n $provisioned_key_part_1 | openssl dgst -sha256 -hmac $key_used_by_client`

echo -e "\x1B[32mPROVISIONED KEY = \x1B[34m$provisioned_key_part_1\x1B[33m$provisioned_key_part_2\x1B[0m "
provisioned_key=$provisioned_key_part_1$provisioned_key_part_2


echo -e "\x1B[91mNow suppose a key is sent through API. Split its componentes and verify:\x1B[0m "
received_key=$provisioned_key
echo -n $received_key | cut -c1-19 | tr -d $'\n'

echo -n $received_key | cut -c20- | tr -d $'\n'

echo -n $received_key | cut -c1-19 | tr -d $'\n' | openssl dgst -sha256 -hmac $tertiary_key_1

received_part_2=`echo -n $received_key | cut -c20- | tr -d $'\n'`

# We don't know which LEAF key was used (could be tertiary_key_1 or
# tertiary_key_2). So we test each.
# Of course you could use envelope encryption to include the name of
# the key directly, but even this simplest implementation is feasible
# given that the number of leaf keys in the tree is small for any
# given client 

try_key_0_0_0=`echo -n $received_key | cut -c1-19 | tr -d $'\n' | openssl dgst -sha256 -hmac $tertiary_key_1`

echo -e "\x1B[91m$received_part_2 != \n$try_key_0_0_0\x1B[0m"


try_key_0_0_1=`echo -n $received_key | cut -c1-19 | tr -d $'\n' | openssl dgst -sha256 -hmac $tertiary_key_2`

leaf_used=$tertiary_key_2
echo -e "\x1B[91m$received_part_2 == \n$try_key_0_0_1. It was encrypted with 0000:0000:0001\x1B[0m"


echo $leaf_used

# Note we could rotate/revoke not only leaf keys but whole
# branches of the tree and decline a transaction if any parent is
# revoked

# Suppose we found out a careless developer on our partner side
# exposed key 0000:0000 in github so we revoked it (note that you have to
# provide a way to remember a blacklist of keys -not shown here)

echo -e "\x1B[91mWe want to recursively verify that parent keys are valid too.\x1B[0m"

# Note we don't even need to put 0000:0000:0001 in the key. We wrote it that
# way only to make the explanation more intuitive. We could figure
# out the parent of tertiary_key_2 recursively by checking the
# possible parents for a match:

leaf_part_1=`echo -n $leaf_used | cut -c1-34 | tr -d $'\n'`
leaf_part_2=`echo -n $leaf_used | cut -c35- | tr -d $'\n'`

echo $leaf_part_1
echo $secondary_key

try_key_0_0=`echo -n $leaf_part_1 | openssl dgst -sha256 -hmac $secondary_key`
#try_key_0_i=`echo -n $leaf_part_1 | openssl dgst -sha256 -hmac $secondary_key_i`

echo -e "\x1B[91m$leaf_part_2 == \n$try_key_0_0. It was encrypted with key 0000:0000\x1B[0m"

echo -e "\x1B[91mEncrypted with real key 0000:0000:0001 BUT parent key 0000:0000 previously revoked. \x1B[5mDECLINED\x1B[0m"

# Notice the revokation of whole branches of keys does not necessarily mean
# a breach. One case could be penetration testing where all the keys associated
# with the testing belong to a branch that is revoked after the pen testing ends.




