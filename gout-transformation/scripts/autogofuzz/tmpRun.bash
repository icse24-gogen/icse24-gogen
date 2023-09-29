./autogofuzz -mode=1 -rootdir=topproj -workers=60 -projs=beego -bins=/home/gogen/workspace/gowork/src/topproj/beego/otherDepFuzz.txt -fuzztime=3 #9h
./autogofuzz -mode=1 -rootdir=topproj -workers=27 -projs=caddy -bins=/home/gogen/workspace/gowork/src/topproj/caddy/otherDepFuzz.txt -fuzztime=3 #3h
./autogofuzz -mode=1 -rootdir=topproj -workers=60 -projs=cobra -bins=/home/gogen/workspace/gowork/src/topproj/cobra/otherDepFuzz.txt -fuzztime=3 #6h


./autogofuzz -mode=1 -rootdir=topproj -workers=37 -projs=minio -bins=/home/gogen/workspace/gowork/src/topproj/minio/otherDepFuzz.txt -fuzztime=3 &
./autogofuzz -mode=1 -rootdir=topproj -workers=22 -projs=fzf -bins=/home/gogen/workspace/gowork/src/topproj/fzf/otherDepFuzz.txt -fuzztime=3 &
./autogofuzz -mode=1 -rootdir=topproj -workers=3 -projs=gogs -bins=/home/gogen/workspace/gowork/src/topproj/gogs/otherDepFuzz.txt -fuzztime=3 #3h

./autogofuzz -mode=1 -rootdir=topproj -workers=5 -projs=frp -bins=/home/gogen/workspace/gowork/src/topproj/frp/otherDepFuzz.txt -fuzztime=3 &
./autogofuzz -mode=1 -rootdir=topproj -workers=3 -projs=gorm -bins=/home/gogen/workspace/gowork/src/topproj/gorm/otherDepFuzz.txt -fuzztime=3 &
./autogofuzz -mode=1 -rootdir=topproj -workers=54 -projs=rclone -bins=/home/gogen/workspace/gowork/src/topproj/rclone/otherDepFuzz.txt -fuzztime=3 #9h
