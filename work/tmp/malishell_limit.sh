# Conservative cap: 2048 pages (~8MB @ 4K pages)
export MALI_MAX_LIVE_PAGES=2048
#
# # Ensure you can pull it after reboot
export MALI_LOG_PATH=/data/local/tmp/mali_fuzz.log
#
# # fsync every 25 lines (more durable, slightly slower)
export MALI_LOG_FSYNC_EVERY=25

./mali_fuzz_live_limited 0 0xdeadbeef
