# Vuln-research attack surface — bdservicehost_exe @ v27_x

**Status:** `partial`

**Total named functions:** 1002  
**Classified:** 65  
**Unclassified:** 937


## Summary by category

| Category | Count | What to do with these |
|---|---:|---|
| **trust_boundary** | 6 | Trust/auth/verify checks — bypass these and the rest doesn't matter. Top priority for vuln research. |
| **ipc_source** | 20 | External-input entry points. Track every byte of caller-controlled data from here. |
| **privilege_sink** | 11 | Privileged operations — service/cert/driver install. Hit these via IPC and you have an LPE. |
| **process_sink** | 4 | Process creation. Path-injection or token-confusion here = code exec as the service principal. |
| **dll_load_sink** | 4 | DLL load surface. Classic LPE vector if any load path is attacker-controllable. |
| **path_handling** | 2 | Path resolution / env var manipulation — junction-LPE candidates. |
| **defense** | 8 | Sanitization / canonicalization — bypass these and the sinks become reachable. |
| **file_source** | 7 | File-content sources. Look for parser bugs (JSON/XML) and unbounded copies. |
| **file_write_sink** | 3 | File-write sinks. Look at path control + content control independently. |
| **crypto** | 2 | Crypto surface — replay, signature bypass, downgrade. |

---


## trust_boundary (6)

_Trust/auth/verify checks — bypass these and the rest doesn't matter. Top priority for vuln research._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `1400045c0` | `verify_authenticode_signature` | 10 | llm_rename | high | Calls CryptMsgGetParam, CryptMsgClose, CertFindCertificateInStore, CertCloseStore, CertFreeCertif... |
| `1400355a4` | `__except_validate_context_record` | 6 | ghidra_original | n/a |  |
| `140037eb0` | `validate_stream_is_ansi_if_required` | 6 | ghidra_original | n/a |  |
| `140005250` | `verify_file_trust` | 6 | llm_rename | high | Calls WinVerifyTrust directly and delegates to verify_file_via_catalog (FUN_140004ee0); top-level... |
| `140004ee0` | `verify_file_via_catalog` | 6 | llm_rename | high | Calls CryptCATAdminAcquireContext/CalcHashFromFileHandle/EnumCatalogFromHash/CatalogInfoFromConte... |
| `1400042c0` | `verify_signer_cert_chain` | 6 | llm_rename | medium | Invokes cert_get_subject_name (140003ba0) and FUN_140003ef0/0039f0; orchestrates signer cert vali... |

## ipc_source (20)

_External-input entry points. Track every byte of caller-controlled data from here._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `140015ca0` | `service__on_control_handler` | 10 | llm_rename | high | Strings 'service::on_control_handler','service_manager::unprotect_service'. SCM control-handler c... |
| `1400349d0` | `DecompHandler` | 6 | ghidra_original | n/a |  |
| `1400320ac` | `__C_specific_handler` | 6 | ghidra_original | n/a |  |
| `1400386c0` | `__acrt_get_sigabrt_handler` | 6 | ghidra_original | n/a |  |
| `140057050` | `_guard_dispatch_icall` | 6 | ghidra_original | n/a |  |
| `140042b80` | `_query_new_handler` | 6 | ghidra_original | n/a |  |
| `140047994` | `fp_format_dispatch_fe` | 6 | llm_rename | medium | Calls __acrt_fltout, fp_format_f_internal, fp_format_e_internal; subroutine of FUN_140047bf4 that... |
| `140047bf4` | `fp_format_dispatch_full` | 6 | llm_rename | high | Caller is type_case_a; calls fp_format_a/fp_format_e/fp_format_f_internal/__acrt_fltout/strcpy_s ... |
| `14000ff70` | `guarded_recursive_dispatch_14000ff70` | 6 | llm_rename | low | Self-recursive, calls _guard_dispatch_icall and __uncaught_exception. CFG-guarded virtual dispatc... |
| `140008fd0` | `init_internal_crash_handler` | 6 | llm_rename | high | Reads 'Software\Bitdefender\InternalCrashEnabled' via RegOpenKeyExW, spawns CreateThread with 'cr... |
| `140008370` | `thread_init_dispatch_wrapper` | 6 | llm_rename | low | Calls init_thread_local_once then _guard_dispatch_icall; thin wrapper around a thread-safe-once c... |
| `1400144b0` | `vb_dispatch_icall_with_seh_a` | 6 | llm_rename | low | 225 insns, callers in init/setup region, callees include _guard_dispatch_icall + __uncaught_excep... |
| `1400147e0` | `vb_dispatch_icall_with_seh_b` | 6 | llm_rename | low | 164 insns, single caller FUN_14000ac10, same _guard_dispatch_icall+__uncaught_exception pattern a... |
| `140014c60` | `vb_dispatch_icall_with_seh_c` | 6 | llm_rename | low | 103 insns, 5 callers, same _guard_dispatch_icall+FUN_140012ef0+__uncaught_exception template; ano... |
| `1400308cc` | `vb_eh_catch_dispatch_helper` | 6 | llm_rename | low | Called from FUN_14003328c (EH dispatcher cluster); chains into FUN_140030c58. Shape matches an MS... |
| `140030c58` | `vb_eh_catch_dispatch_inner` | 6 | llm_rename | low | Sole callee of FUN_1400308cc (catch-dispatch helper); leaf with no callees. Likely the inner stat... |
| `140001b70` | `vb_indirect_dispatch_thunk` | 6 | llm_rename | medium | Sole callee is _guard_dispatch_icall; CFG-guarded indirect call thunk pattern. |
| `1400220b0` | `vb_json_parse_dispatch_a` | 6 | llm_rename | high | 1353 insns, 35 callees, error strings 'object separator', 'object key', 'number overflow parsing'... |
| `140023770` | `vb_json_parse_dispatch_b` | 6 | llm_rename | high | 1340 insns mirroring 1400220b0 with same JSON parser error strings but disjoint callee set; sibli... |
| `14000a900` | `vb_load_bdch_crash_handler` | 6 | llm_rename | high | Strings 'bdch.dll', 'enable_crash_handler', 'load crash handler failed'; calls GetModuleHandleExW... |

## privilege_sink (11)

_Privileged operations — service/cert/driver install. Hit these via IPC and you have an LPE._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `140016380` | `service__register_service_events` | 9 | llm_rename | high | String 'service::register_service_events','events map is empty'; iterates an events map registeri... |
| `140016620` | `service__unregister_service_events` | 9 | llm_rename | high | String 'service::unregister_service_events'; mirror of register_service_events using same FUN_140... |
| `14002c690` | `service_manager_install_service` | 9 | llm_rename | high | Calls OpenSCManagerW/OpenServiceW/CreateServiceW/ChangeServiceConfig2W; error strings open_sc_man... |
| `14002bba0` | `change_service_config2_inner` | 8 | llm_rename | high | Wraps ChangeServiceConfig2W with err logging 'ChangeServiceConfig2W failed'. |
| `14002b740` | `change_service_config_inner` | 8 | llm_rename | high | Wraps ChangeServiceConfigW; logs 'ChangeServiceConfigW failed'. |
| `140043d04` | `_register_onexit_function` | 4 | ghidra_original | n/a |  |
| `140042fd8` | `_register_thread_local_exe_atexit_callback` | 4 | ghidra_original | n/a |  |
| `14002c3f0` | `install_bdelam_certificate` | 4 | llm_rename | high | Reads \drivers\bdelam.sys via SHGetKnownFolderPath, GetProcAddress(InstallELAMCertificateInfo) fr... |
| `140043c90` | `onexit_register_thunk` | 4 | llm_rename | high | Called from _onexit, tail-calls _register_onexit_function; standard CRT onexit shim. |
| `140012ef0` | `std_facet_register_locked` | 4 | llm_rename | medium | Calls _Facet_Register, _Lockit/~_Lockit pair: STL facet registration under the global locale lock. |
| `140013c80` | `std_facet_register_via_FUN1400025d0` | 4 | llm_rename | medium | Same shape as 134e0/12ef0 (_Facet_Register + _Lockit/~_Lockit + _guard_dispatch_icall) but routes... |

## process_sink (4)

_Process creation. Path-injection or token-confusion here = code exec as the service principal._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `14002bca0` | `set_service_launch_type` | 9 | llm_rename | high | String tag 'set_service_launch_type'; opens SCM/service then ChangeServiceConfig2W via 14002bba0. |
| `14002aeb0` | `start_service` | 7 | llm_rename | high | Top-level 'start_service' orchestrator: open_sc_manager, open_service, wait_to_stop/start, calls ... |
| `14002ac10` | `start_service_inner` | 7 | llm_rename | high | Inner helper: StartServiceW + wait_service_to_stop + logs 'StartServiceW failed' under 'start_ser... |
| `14000b2a0` | `vb_start_service_dispatcher` | 7 | llm_rename | high | Strings 'start_service_dispatcher', 'StartServiceCtrlDispatcherW failed with error'; calls StartS... |

## dll_load_sink (4)

_DLL load surface. Classic LPE vector if any load path is attacker-controllable._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `140003820` | `LoadLibraryByName` | 9 | llm_rename | high | Calls LoadLibraryW then GetLastError; small wrapper used by FUN_140005f40 and FUN_140012190 to lo... |
| `1400038c0` | `load_library_or_throw` | 9 | llm_rename | high | Calls LoadLibraryW + GetLastError; on failure references 'LoadLibrary failed' string and invokes ... |
| `140007040` | `vb_load_bdch_dll_resolve_exports` | 7 | llm_rename | high | Loads bdch.dll via GetModuleHandleExW, resolves ~17 exports (GetAPIVersion, EnableBdch, SubmitDum... |
| `14000d5f0` | `vb_unload_module_wrapper` | 6 | llm_rename | medium | Small 18-instr leaf calls FreeLibrary plus FUN_14002f180 helper; classic module unload/cleanup sh... |

## path_handling (2)

_Path resolution / env var manipulation — junction-LPE candidates._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `140009c70` | `sanitize_path_env_var` | 8 | llm_rename | high | Strings 'san_path_env-{7D9669CE-...}', 'PATH' (x2); calls GetSystemDirectoryW, SetEnvironmentVari... |
| `140056d28` | `set_env_var_nolock_helper` | 8 | llm_rename | medium | Sole caller is common_set_variable_in_environment_nolock<char>; helper for environment variable m... |

## defense (8)

_Sanitization / canonicalization — bypass these and the sinks become reachable._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `140009c70` | `sanitize_path_env_var` | 10 | llm_rename | high | Strings 'san_path_env-{7D9669CE-...}', 'PATH' (x2); calls GetSystemDirectoryW, SetEnvironmentVari... |
| `14001f280` | `json_escape_unicode_u4hex` | 7 | llm_rename | high | Format string '<U+%.4X>' is nlohmann/json's unicode-escape rendering for token strings. |
| `140042bb4` | `_seh_filter_exe` | 5 | ghidra_original | n/a |  |
| `140059e96` | `vb_eh_filter_rethrow_fh4_thunk` | 5 | llm_rename | medium | Sole callee ExFilterRethrowFH4: FH4-format C++ EH rethrow filter (newer MSVC funclet variant of E... |
| `140059df9` | `vb_eh_filter_rethrow_thunk` | 5 | llm_rename | medium | Sole callee ExFilterRethrow: MSVC C++ EH rethrow filter funclet emitted around rethrow inside a c... |
| `140059f48` | `vb_frame_unwind_filter_thunk` | 5 | llm_rename | medium | 8-insn funclet whose only callee is __FrameUnwindFilter: stack-frame unwind exception filter for ... |
| `140059bf7` | `vb_seh_filter_exe_thunk` | 5 | llm_rename | medium | Sole callee _seh_filter_exe: CRT SEH top-level exception filter wrapper used by /EHa to translate... |
| `140035570` | `vcrt_seh_filter_stub` | 5 | llm_rename | low | Tiny (6 insn) leaf invoked from _CallSettingFrame, _CallSettingFrameEncoded, and __C_specific_han... |

## file_source (7)

_File-content sources. Look for parser bugs (JSON/XML) and unbounded copies._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `14001a250` | `parse_config_accepted_controls` | 9 | llm_rename | high | Strings 'acceptedControls', 'The accepted control is not recognized', 'type must be string'; call... |
| `14001a7f0` | `parse_config_registered_events` | 9 | llm_rename | high | Strings 'registeredEvents', 'The registered event is not recognized', 'type must be string'; call... |
| `14001a110` | `parse_config_string_field` | 9 | llm_rename | medium | Only string 'type must be string, but is '; small helper called from config parser FUN_14001b450;... |
| `140019eb0` | `parse_config_version` | 9 | llm_rename | high | Strings 'version', 'The JSON version is not accepted', 'type must be number' + called from main c... |
| `14003eef8` | `_fread_nolock_s` | 5 | ghidra_original | n/a |  |
| `14003f158` | `fread` | 5 | ghidra_original | n/a |  |
| `14003f178` | `fread_s` | 5 | ghidra_original | n/a |  |

## file_write_sink (3)

_File-write sinks. Look at path control + content control independently._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `14002e910` | `fs_set_file_attributes_by_path` | 8 | llm_rename | high | Calls __std_fs_open_handle, SetFileInformationByHandle, CloseHandle, GetLastError, terminate — ST... |
| `14003ecc8` | `_fwrite_nolock` | 4 | ghidra_original | n/a |  |
| `14003ee74` | `fwrite` | 4 | ghidra_original | n/a |  |

## crypto (2)

_Crypto surface — replay, signature bypass, downgrade._

| Addr | Name | W | Source | Confidence | Rationale |
|---|---|---:|---|---|---|
| `1400045c0` | `verify_authenticode_signature` | 8 | llm_rename | high | Calls CryptMsgGetParam, CryptMsgClose, CertFindCertificateInStore, CertCloseStore, CertFreeCertif... |
| `140028bc0` | `vb_hash_bucket_init` | 6 | llm_rename | medium | String 'invalid hash bucket count' anchors this as a hash-table constructor/initializer validatin... |

---

## How to use this report

1. Start with `trust_boundary` — these are functions whose JOB is to enforce a policy. Any bypass becomes a bug regardless of what's downstream.
2. Map `ipc_source` -> (intermediate calls) -> `privilege_sink` / `process_sink` / `dll_load_sink` to find privilege-elevation chains. Each chain is a source→sink candidate.
3. Read the rationale strings — they cite the concrete signal the LLM rename worker found. That signal is your starting point for ACID analysis.
4. Pair this report with the engagement's decomp .c files for body-level review of any function that looks promising.
5. Functions surfaced here whose names start with `vb_` came from LLM passes — confidence levels matter; treat `low` as 'still worth checking but suspect the name'.

