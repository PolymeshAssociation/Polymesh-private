#!/bin/sh
export RAYON_NUM_THREADS=8
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_session -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_multisig -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_corporate_ballot -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
# Babe's weights are not auto-generated.
#./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_babe -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_timestamp -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_scheduler -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_preimage -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_indices -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_corporate_actions -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_asset -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
./target/release/polymesh-private benchmark pallet -s 100 -r 5 -p=pallet_test_utils -e=* --heap-pages 4096 --db-cache 512 --execution native --output  ./pallets/weights/src/ --template ./.maintain/frame-weight-template.hbs  >> data.txt 2>> log.txt
