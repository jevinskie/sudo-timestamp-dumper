# sudo-timestamp-dumper
Utility to dump the contents of sudo >= 1.8.10 multi-record timestamp file

## Example Output
```
ts_entry[  0].version    => 2
ts_entry[  0].size       => 0x38
ts_entry[  0].type       => TS_LOCKEXCL (0x4)
ts_entry[  0].flags      => (0x0)
ts_entry[  0].auth_uid   => 0
ts_entry[  0].sid        => 0
ts_entry[  0].start_time => Wed Dec 31 19:00:00 1969
ts_entry[  0].ts         => Wed Dec 31 19:00:00 1969

ts_entry[  1].version    => 2
ts_entry[  1].size       => 0x38
ts_entry[  1].type       => TS_PPID (0x3)
ts_entry[  1].flags      => (0x0)
ts_entry[  1].auth_uid   => 501
ts_entry[  1].sid        => 1
ts_entry[  1].start_time => Wed Jul  3 22:59:12 2024
ts_entry[  1].ts         => Wed Jul  3 23:00:38 2024
ts_entry[  1].ppid       => 17987

ts_entry[  2].version    => 2
ts_entry[  2].size       => 0x38
ts_entry[  2].type       => TS_TTY (0x2)
ts_entry[  2].flags      => (0x0)
ts_entry[  2].auth_uid   => 501
ts_entry[  2].sid        => 91483
ts_entry[  2].start_time => Thu Jul  4 13:35:32 2024
ts_entry[  2].ts         => Thu Jul  4 13:40:37 2024
ts_entry[  2].ttydev     => 0x0810000005

ts_entry[  3].version    => 2
ts_entry[  3].size       => 0x38
ts_entry[  3].type       => TS_PPID (0x3)
ts_entry[  3].flags      => (0x0)
ts_entry[  3].auth_uid   => 501
ts_entry[  3].sid        => 1
ts_entry[  3].start_time => Fri Jul  5 11:16:07 2024
ts_entry[  3].ts         => Fri Jul  5 11:16:54 2024
ts_entry[  3].ppid       => 42615

ts_entry[  4].version    => 2
ts_entry[  4].size       => 0x38
ts_entry[  4].type       => TS_PPID (0x3)
ts_entry[  4].flags      => TS_DISABLED (0x1)
ts_entry[  4].auth_uid   => 501
ts_entry[  4].sid        => 1
ts_entry[  4].start_time => Fri Jul  5 23:19:17 2024
ts_entry[  4].ts         => Wed Dec 31 19:00:00 1969
ts_entry[  4].ppid       => 6454

ts_entry[  5].version    => 2
ts_entry[  5].size       => 0x38
ts_entry[  5].type       => TS_TTY (0x2)
ts_entry[  5].flags      => (0x0)
ts_entry[  5].auth_uid   => 501
ts_entry[  5].sid        => 13433
ts_entry[  5].start_time => Fri Jul  5 23:47:11 2024
ts_entry[  5].ts         => Sat Jul  6 03:20:51 2024
ts_entry[  5].ttydev     => 0x0810000007

ts_entry[  6].version    => 2
ts_entry[  6].size       => 0x38
ts_entry[  6].type       => TS_TTY (0x2)
ts_entry[  6].flags      => (0x0)
ts_entry[  6].auth_uid   => 501
ts_entry[  6].sid        => 45672
ts_entry[  6].start_time => Mon Jul  8 18:12:55 2024
ts_entry[  6].ts         => Mon Jul  8 18:19:40 2024
ts_entry[  6].ttydev     => 0x0810000003

ts_entry[  7].version    => 2
ts_entry[  7].size       => 0x38
ts_entry[  7].type       => TS_PPID (0x3)
ts_entry[  7].flags      => TS_DISABLED (0x1)
ts_entry[  7].auth_uid   => 501
ts_entry[  7].sid        => 1
ts_entry[  7].start_time => Tue Jul  9 23:54:24 2024
ts_entry[  7].ts         => Wed Dec 31 19:00:00 1969
ts_entry[  7].ppid       => 10396

ts_entry[  8].version    => 2
ts_entry[  8].size       => 0x38
ts_entry[  8].type       => TS_PPID (0x3)
ts_entry[  8].flags      => (0x0)
ts_entry[  8].auth_uid   => 501
ts_entry[  8].sid        => 1
ts_entry[  8].start_time => Wed Jul 10 12:02:12 2024
ts_entry[  8].ts         => Wed Jul 10 12:03:51 2024
ts_entry[  8].ppid       => 12854

ts_entry[  9].version    => 2
ts_entry[  9].size       => 0x38
ts_entry[  9].type       => TS_TTY (0x2)
ts_entry[  9].flags      => (0x0)
ts_entry[  9].auth_uid   => 501
ts_entry[  9].sid        => 20273
ts_entry[  9].start_time => Sun Jul 14 15:03:31 2024
ts_entry[  9].ts         => Sun Jul 14 15:17:29 2024
ts_entry[  9].ttydev     => 0x081000000d

ts_entry[ 10].version    => 2
ts_entry[ 10].size       => 0x38
ts_entry[ 10].type       => TS_TTY (0x2)
ts_entry[ 10].flags      => (0x0)
ts_entry[ 10].auth_uid   => 501
ts_entry[ 10].sid        => 67133
ts_entry[ 10].start_time => Sun Jul 14 16:20:59 2024
ts_entry[ 10].ts         => Sun Jul 14 17:14:02 2024
ts_entry[ 10].ttydev     => 0x0810000009

ts_entry[ 11].version    => 2
ts_entry[ 11].size       => 0x38
ts_entry[ 11].type       => TS_TTY (0x2)
ts_entry[ 11].flags      => TS_DISABLED (0x1)
ts_entry[ 11].auth_uid   => 501
ts_entry[ 11].sid        => 26263
ts_entry[ 11].start_time => Sun Jul 14 16:30:26 2024
ts_entry[ 11].ts         => Sun Jul 14 17:08:38 2024
ts_entry[ 11].ttydev     => 0x081000000a

ts_entry[ 12].version    => 2
ts_entry[ 12].size       => 0x38
ts_entry[ 12].type       => TS_TTY (0x2)
ts_entry[ 12].flags      => (0x0)
ts_entry[ 12].auth_uid   => 501
ts_entry[ 12].sid        => 85036
ts_entry[ 12].start_time => Sun Jul 14 18:24:35 2024
ts_entry[ 12].ts         => Mon Jul 15 18:46:58 2024
ts_entry[ 12].ttydev     => 0x0810000016

ts_entry[ 13].version    => 2
ts_entry[ 13].size       => 0x38
ts_entry[ 13].type       => TS_TTY (0x2)
ts_entry[ 13].flags      => (0x0)
ts_entry[ 13].auth_uid   => 501
ts_entry[ 13].sid        => 92764
ts_entry[ 13].start_time => Mon Jul 15 04:13:16 2024
ts_entry[ 13].ts         => Mon Jul 15 11:26:51 2024
ts_entry[ 13].ttydev     => 0x0810000008

ts_entry[ 14].version    => 2
ts_entry[ 14].size       => 0x38
ts_entry[ 14].type       => TS_TTY (0x2)
ts_entry[ 14].flags      => (0x0)
ts_entry[ 14].auth_uid   => 501
ts_entry[ 14].sid        => 45021
ts_entry[ 14].start_time => Mon Jul 15 18:44:07 2024
ts_entry[ 14].ts         => Mon Jul 15 18:46:51 2024
ts_entry[ 14].ttydev     => 0x0810000003
```
