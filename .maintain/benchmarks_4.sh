#!/bin/sh
export RAYON_NUM_THREADS=8
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_confidential_asset -e=* --heap-pages 4096 --db-cache 512 --execution wasm --wasm-execution compiled --output  ./pallets/confidential-asset/src/weights.rs --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
