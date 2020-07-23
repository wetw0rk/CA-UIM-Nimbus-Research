# Nimpack

This program was made for me to better understand the nimbus protocol, it works by generating a nimbus packet for the nimcontroller. Once coded, within the same day I found an additional 4 bugs. That being said use this with caution when sending weird / unexpected data (non-standard probes). Usage is simple enough as shown below.

```
root@scr1ptKiddie:~# ./nimpack
usage: ./nimpack [-h] [-t TARGET] [-p PORT] [ARG=VAL]

Nimpack - Nimbus packet generator

optional arguments:
  -h, --help                  show this help message and exit
  -t TARGET, --target TARGET  target host to probe
  -p PORT, --port PORT        nimcontroller port

positional arguments:
  probe
  arg=val

examples:
  ./nimpack -t 192.168.88.130 -p 48000 directory_list directory=C:\\
  ./nimpack -t 192.168.88.130 -p 48000 os_info
```

Below is a list of common permission settings. Although, I've observed these do not always matter so it doesn't hurt to sent a probe ;)


| permission | meaning |
|---|---|
| 0 |  open |
|1 |read |
|2| write |
|3| admin |
|4| super|

Below is a list of some probes you can send, keep in mind that these permissions may be more or less strict depending on the target host. Another thing to note is this IS NOT AT ALL official documentation so I am not responsible if you DoS a system.

| PROBE | ARGS | PERMISSION |
|---|---|---|
| _status  | `detail%d` | `0` |
| _command | `detail%d` | `0` |
| _debug | `level%d,trunc_size%d,trunc_time%d,now%d` | `1` |
| _stop | `` | `3` |
| _restart | `` | `3` |
| checkin | `hubaddr,hubip` | `0` |
| probe_checkin |`type%d` | `0` |
| iptoname | `ip,port%d` | `0` |
| nametoip | `name` | `0` |
| login | `type%d` | `0` |
| verify_login | `` | `0` |
| change_password | `` | `0` |
| probe_list | `name,robot` | `1` |
| probe_register | `name,active,type,timespec,command,arguments,workdir,config,datafile,logfile,description,group,fail_window,realip` | `3` |
| probe_unregister |  `name,noforce%d` | `3` |
| probe_activate | `name` | `3` |
| probe_deactivate | `name,noforce%d,waitforstop%d` | `3` |
| probe_store | `filename` | `3` |
| probe_config_lock | `name,locktype%d,lockid%d,robot` | `3` |
| probe_config_lock_list | `name` | `3` |
| probe_config_get | `name,robot,var` | `1` |
| probe_config_set | `name,section,key,value,lockid%d,robot` | `3` |
| probe_set_port | `name,port%d,pid%d` | `0` |
| probe_start | `name` | `3` |
| probe_stop | `name` | `3` |
| probe_change_par | `name,par,value` | `3` |
| probe_tail_logfile | `name,size%d,prev_record%d` | `1` |
| probe_tail_logfile_session | `name,max_buffer%d,from_start%d`| `1` |
| probe_verify | `name` | `3` |
| probe_set_priority_level | `name,priority_level%d` | `2` |
| restart_all_probes |  `marketplace_only%d`  | `3` |
| port_register | `name,port%d,pid%d` | `0` |
| port_unregister | `name,pid%d` | `0` |
| port_reserve | `name` | `0` |
| port_reserve_starting_from | `name,start_port%d` | `0` |
| port_list | `` | `1` |
| get_info | `interfaces%d,robot` | `0` |
| get_ordered_ip_list | `` | `1` |
| gethub | `` | `0` |
| sethub PDS_PCH | `hubdomain,hubname,hubip,hub_dns_name,hubport%d,robotip_alias` | `3` |
| log_level | `level%d` | `3` |
| check_hub | `` | `0` |
| inst_pkg | `package` | `3` |
| inst_file_start | `package,file,type,mode,crc` | `3` |
| inst_file_next | `id` | `3` |
| inst_file_end | `id` | `3` |
| inst_execute | `package,section,expire%d,robot_name` | `3` |
| inst_ready | `` | `3` |
| inst_list | `package` | `1` |
| inst_list_summary | `` | `1` |
| inst_pkg_remove | `package,probe,noforce%d` | `3` |
| inst_request | `package,distsrv` | `3` |
| os_info | `` | `0` |
| directory_list | `directory,type%d,detail%d` | `1` |
| file_stat | `directory,file` | `1` |
| text_file_get | `directory,file,buffer_size%d` | `1` |
| text_file_put | `directory,file,mode,file_contents` | `3` |
| file_get_start | `directory,file,type,buffer_size%d,start_pos%d` | `1` |
| file_get_next | `id` | `1` |
| file_get_end | `id` | `1` |
| file_put_start | `directory,file,type,mode` | `3` |
| file_put_next | `id` |`3` |
| file_put_end | `id` | `3` |
| remote_config_get |  `name` | `0` |
| remote_config_set |  `name,section,key,value,lockid%d` |`0` |
| spooler_flush | ``| `0` |
| validate_license | `license,mode%d` | `0` |
| test_alarm | `level` | `0` |
| get_environment | `variable` | `1` |
| check_product_guid | `guid` | `3` |
| remote_list | `detail%d` | `0` |
| maint_until | `until%d,for%d,comment,from%d` | `2` |
| _shutdown | `id` | `0` |
| _audit_type | `type%d` | `4` |
| _audit_restore | `probe,checkpoint%d,lockid%d,robot` | `4` |
| _audit_send | `description,status%d` | `3` |
| _nis_cache | `age%d,bulk_size%d,robot` | `0` |
| _nis_cache_advanced |  `age%d,bulk_size%d,robot,min_age%d` | `0` |
| _nis_cache_clean | `robot,min_age%d` | `0` |
| _reset_device_id_and_restart | `robot` | `0` |
| hubcall_robotup | `license%d,hubdomain,hubname,hubrobotname,hubpost_port%d,origin,ssl_cipher,ssl_mode` | `0` |
| hubcall_alive | `` | `0` |
| hubcall_probelist | `` | `0` |
| hubcall_update_hub_info | `origin` | `0` |
| validate_ip_suggestions | `input_ips` | `0` |
| check_marketplace_user | `encrypted_username,encrypted_password` | `3` |
| run_controller_plugins_now | `plugin_name` | `1` |
| plugins_get_info |  `plugin_name` | `1` |
| protected_files | `` | `3` |
| protect_file | `owner,path` | `3` |
| unprotect_file | `owner,path` | `3` |
| verify_file | `owner,path` | `1` |
| verify_files | `owner` | `1` |
