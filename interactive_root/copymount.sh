SUROOT=/dev/su-root

mkdir -p "$SUROOT"

mount -t tmpfs -o mode=0755,suid,exec,size=4M tmpfs "$SUROOT"

cp /data/local/tmp/su "$SUROOT/su"
chown 0:0 "$SUROOT/su"
chmod 4755 "$SUROOT/su"

ls -lZ "$SUROOT/su"
