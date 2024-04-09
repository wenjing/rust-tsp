#!/bin/bash

# install using
cargo install --path .

echo "---- cleanup the database"
rm -f database.json

echo "---- create a new sender identity"
tsp create marlon

echo "---- create a new receiver identity"
tsp create marc

echo "---- verify the address of the sender"
tsp verify did:web:tsp-test.org:user:marlon

echo "---- verify the address of the receiver"
tsp verify did:web:tsp-test.org:user:marc

echo "---- wait 2 seconds and then send a message to the receiver"
sleep 2 && echo "Oh hello Marc" | tsp send -s did:web:tsp-test.org:user:marlon -r did:web:tsp-test.org:user:marc &

echo "---- receive the message"
tsp receive --one did:web:tsp-test.org:user:marc
