# Reconstruction detail — bdservicehost_exe @ v27_x

**Status:** `partial`

**Catalog path:** `catalog/reconstructed/bdservicehost_exe_v27_x`


## Coverage

- Hard gate (reachable_named_100pct): **fail**
- Soft gate (tail_named_80pct): **fail**
- User-defined functions: 1368
- Named: 1002 (73.2%)
- Named via Pass 0: 1
- Skipped: 0 externals, 28 thunks

## Carryforward

- No prior version found; this is the first reconstruction of this binary.

## Pass log

| Pass | Started | Duration | Tools | Renames proposed | Tokens |
|---|---|---|---|---|---|
| `pass0` | 2026-05-11T17:42:15Z | 0s | project_discovery, iat_wrapper_detection | 1 | 0 |
| `pass1` | 2026-05-11T17:47:09Z | 2164s | llm_rename | 395 | 0 |

## Project discovery

- Binary: `bdservicehost.exe` (x86, Portable Executable (PE))
- Function counts: total=1396, user-defined=1368, external=0, thunk=28
- Entrypoints: 1 (14002f9f0)
- Exports: 1 (entry)
- Reachable user-defined functions: 662

## Proposed renames

| Addr | From | To | Confidence | Source | Rationale |
|---|---|---|---|---|---|
| `140001020` | `FUN_140001020` | `RegisterServiceControlEventHandlers` | high | llm_rename | Strings list every SERVICE_CONTROL_* notification token (NETBINDCHANGE, PRESHUTDOWN, SESSIONCHANGE, POWEREVENT, TRIGGEREVENT); uses operator_new + vector-destructor, looks like construction of a service-control event handler registry. |
| `140001390` | `FUN_140001390` | `RegisterPowerEventHandlers` | high | llm_rename | Only strings are ACDC_POWER_SOURCE and BATTERY_PERCENTAGE (PBT_POWERSETTINGCHANGE GUID names); same construction pattern as 140001020 (operator_new + vector destructor) — registers power-event sub-handlers. |
| `1400014e0` | `FUN_1400014e0` | `CrtInitLocksTu1` | medium | llm_rename | Tiny CRT init thunk calling _Init_locks then atexit — classic per-TU C++ runtime locale/locks initializer. |
| `140001520` | `FUN_140001520` | `CrtInitLocksTu2` | medium | llm_rename | Identical shape to 1400014e0 (calls _Init_locks then atexit); second-TU duplicate CRT lock initializer. |
| `140001550` | `FUN_140001550` | `AtlBaseModuleInit` | high | llm_rename | Constructs a CAtlBaseModule and registers atexit; canonical ATL global-module per-TU initializer. |
| `1400015d0` | `FUN_1400015d0` | `StdExceptionDestructor` | high | llm_rename | Single callee is __std_exception_destroy; this is the standard C++ exception-object destructor stub for a derived exception class. |
| `140001640` | `FUN_140001640` | `ThrowBadArrayNewLength_Inner` | high | llm_rename | Contains the literal 'bad array new length' twice and is called only by 140001670 which itself calls _CxxThrowException — inner helper that builds the std::bad_array_new_length object. |
| `140001670` | `FUN_140001670` | `ThrowBadArrayNewLength` | high | llm_rename | Calls 140001640 (bad-array-new-length constructor) then _CxxThrowException; called from dozens of allocation sites — the canonical __scrt_throw_std_bad_array_new_length helper. |
| `140001690` | `FUN_140001690` | `StdExceptionCopyCtorA` | medium | llm_rename | Sole callee is __std_exception_copy; 17-instruction copy constructor for a std::exception-derived type. |
| `1400016d0` | `FUN_1400016d0` | `StdExceptionCopyCtorB` | medium | llm_rename | Same shape as 140001690 (single __std_exception_copy call, 17 insns) — copy constructor for a sibling exception class. |
| `140001710` | `FUN_140001710` | `LoadLogDllAndResolveExports` | high | llm_rename | Strings 'log.dll', '\log.dll' plus the full LogInit/LogApplySettings/LogSetSettingsFile/LogEnable/LogWrite/LogTrackEvent export list; callees LoadLibraryW + GetProcAddress + GetModuleFileNameW — dynamically loads log.dll and binds its function pointers. |
| `1400019c0` | `FUN_1400019c0` | `InvokeVTableMethodGuarded` | medium | llm_rename | Tiny (20 insns) wrapper whose only callee is _guard_dispatch_icall; called from 20+ different functions — looks like a small CFG-guarded indirect-call thunk for a virtual-method dispatch. |
| `140001a20` | `FUN_140001a20` | `ThrowLengthErrorStringTooLong` | high | llm_rename | Only string is 'string too long' and the function tail-calls FUN_14002d6f4 — canonical std::_Xlength_error('string too long') throw helper called from string/container length checks. |
| `140001a40` | `FUN_140001a40` | `vb_exception_ctor_variant_a` | medium | llm_rename | Calls __std_exception_copy with many varied callers; classic C++ std::exception-derived constructor copying message string. |
| `140001ab0` | `FUN_140001ab0` | `vb_exception_ctor_variant_b` | medium | llm_rename | Second std::exception-style constructor (calls __std_exception_copy + FUN_14002f160) with distinct caller set from 140001a40, likely different derived class. |
| `140001b20` | `FUN_140001b20` | `vb_exception_copy_ctor` | medium | llm_rename | Small leaf calling only __std_exception_copy; shape of an exception copy constructor. |
| `140001b60` | `FUN_140001b60` | `vb_trivial_inline_stub` | low | llm_rename | 4-instruction leaf, no callers/callees, no strings; likely a tiny inline accessor or stub. |
| `140001b70` | `FUN_140001b70` | `vb_indirect_dispatch_thunk` | medium | llm_rename | Sole callee is _guard_dispatch_icall; CFG-guarded indirect call thunk pattern. |
| `140001be0` | `FUN_140001be0` | `vb_helper_called_by_throw_site` | low | llm_rename | Tiny 5-instruction leaf invoked by FUN_140001fc0 (a _CxxThrowException site); likely a small param-setup helper for the throw. |
| `140001c00` | `FUN_140001c00` | `vb_small_accessor_140001c00` | low | llm_rename | 5-instruction leaf with single caller FUN_140002cd0; no strings; insufficient signal for semantic name. |
| `140001c20` | `FUN_140001c20` | `vb_core_object_method_109i` | low | llm_rename | Large 109-instruction method called via vtable (guard_dispatch_icall) by several wrappers (140001ee0/140001e20); likely a virtual method but no string anchor. |
| `140001dd0` | `FUN_140001dd0` | `vb_exception_dtor` | medium | llm_rename | Calls __std_exception_destroy; canonical std::exception-derived destructor. |
| `140001e20` | `FUN_140001e20` | `vb_invoke_core_method_140001c20_a` | medium | llm_rename | Forwards into FUN_140001c20 with setup via FUN_14002f180/FUN_1400106a0; thin invocation wrapper used at throw site FUN_140001fc0. |
| `140001ee0` | `FUN_140001ee0` | `vb_invoke_core_method_140001c20_b` | medium | llm_rename | Second wrapper around FUN_140001c20 with identical callee set as 140001e20 but different caller pair, sibling invocation path. |
| `140001fc0` | `FUN_140001fc0` | `vb_throw_exception_via_140001e20` | high | llm_rename | Builds object via FUN_140001e20 and FUN_140001be0 then calls _CxxThrowException; canonical C++ throw helper. |
| `140002000` | `FUN_140002000` | `vb_exception_ctor_variant_c` | medium | llm_rename | Standalone routine whose only library call is __std_exception_copy; another std::exception-derived constructor. |
| `140002060` | `FUN_140002060` | `vb_exception_ctor_variant_d` | medium | llm_rename | Same shape as 140002000 (calls only __std_exception_copy), distinct address/size suggests another derived-exception constructor. |
| `1400020c0` | `FUN_1400020c0` | `vb_get_category_name_generic` | high | llm_rename | Two-instruction leaf returning literal string "generic"; MSVC std::generic_category::name() override. |
| `1400020d0` | `FUN_1400020d0` | `vb_format_message_helper_140002` | low | llm_rename | Calls FUN_14002d7d0 and FUN_1400106a0 (same pair used by iostream-error builder 140002160); likely a sibling message-formatting helper. |
| `140002120` | `FUN_140002120` | `vb_thunk_to_14002f180` | low | llm_rename | Small 11-instruction routine whose only callee is FUN_14002f180; likely a thin forwarder/initializer. |
| `140002150` | `FUN_140002150` | `vb_get_category_name_iostream` | high | llm_rename | Two-instruction leaf returning literal string "iostream"; MSVC std::iostream_category::name() override. |
| `140002160` | `FUN_140002160` | `vb_iostream_category_message` | high | llm_rename | References string "iostream stream error" and calls the same helpers as 1400020d0; std::iostream_category::message() implementation. |
| `1400021f0` | `FUN_1400021f0` | `FormatSystemErrorMessage` | high | llm_rename | Calls __std_system_error_allocate_message and LocalFree with 'unknown error' fallback string; classic system_category::message() implementation |
| `1400022f0` | `FUN_1400022f0` | `ThrowBadCast` | high | llm_rename | Sole caller is FUN_140002320 (CxxThrowException wrapper) and references 'bad cast' string twice; constructs std::bad_cast exception object |
| `140002320` | `FUN_140002320` | `ThrowBadCastException` | high | llm_rename | Calls FUN_1400022f0 (ThrowBadCast ctor) then _CxxThrowException; invoked from 5 sites doing dynamic_cast-style checks |
| `140002340` | `FUN_140002340` | `CopyStdException` | high | llm_rename | Only callee is __std_exception_copy; matches std::exception copy-constructor thunk pattern |
| `140002380` | `FUN_140002380` | `DestroyStdException` | medium | llm_rename | Calls FUN_14002f180 (likely __std_exception_destroy); 13-instruction exception-object dtor shape |
| `1400023b0` | `FUN_1400023b0` | `LocaleFacetCtorScalar` | medium | llm_rename | Calls _Locinfo_dtor and ~_Lockit; matches MSVC std::locale facet constructor scaffolding using _Lockit guard |
| `140002480` | `FUN_140002480` | `InvokeGuardedIcall` | low | llm_rename | Only callee is _guard_dispatch_icall; small CFG-guarded indirect call thunk |
| `1400024c0` | `FUN_1400024c0` | `WidenMbStringWithFacet` | medium | llm_rename | Calls _calloc_base and _Mbrtowc in a loop; converts a multibyte buffer to wide chars using a locale facet |
| `1400025d0` | `FUN_1400025d0` | `CtypeFacetCtorFromLocale` | high | llm_rename | Calls _Locinfo_ctor, _Lockit, _Getcvt, operator_new with 'bad locale name' xref; std::ctype facet constructor from locale name |
| `1400027c0` | `FUN_1400027c0` | `GetCtypeTable_wrapper` | high | llm_rename | 8-instruction forwarder whose only callee is _Getwctypes; thin wrapper exposing the ctype<wchar_t> table fetch |
| `1400027e0` | `FUN_1400027e0` | `CtypeWideDoIs` | medium | llm_rename | 30-insn function with sole callee _guard_dispatch_icall; size and shape match ctype<wchar_t>::do_is virtual dispatch |
| `140002840` | `FUN_140002840` | `CtypeWideDoScanIs` | low | llm_rename | Twin of 1400027e0 (same size/insns/callee _guard_dispatch_icall); likely sibling ctype<wchar_t> virtual (do_scan_is/do_scan_not) |
| `1400028b0` | `FUN_1400028b0` | `CtypeWideDoToLower` | high | llm_rename | Sole callee _Towlower; std::ctype<wchar_t>::do_tolower implementation |
| `140002910` | `FUN_140002910` | `CtypeWideDoToUpper` | high | llm_rename | Sole callee _Towupper; std::ctype<wchar_t>::do_toupper implementation |
| `140002960` | `FUN_140002960` | `CtypeWideDoNarrow` | medium | llm_rename | Calls _Mbrtowc; 23-insn ctype<wchar_t>::do_narrow-style routine converting a wide char via locale facet |
| `1400029d0` | `FUN_1400029d0` | `CtypeWideDoNarrowRange` | medium | llm_rename | Calls _Mbrtowc in a 48-insn loop; matches std::ctype<wchar_t>::do_narrow range-overload narrowing a wide buffer |
| `140002aa0` | `FUN_140002aa0` | `WideToMultibyteConvert` | low | llm_rename | Small helper calling _Wcrtomb; likely a single-codepoint wchar->mb conversion routine. |
| `140002b00` | `FUN_140002b00` | `WideToMultibyteConvertLoop` | low | llm_rename | Larger sibling of 140002aa0 calling _Wcrtomb; likely loops over a wide string converting to multibyte. |
| `140002c10` | `FUN_140002c10` | `IosBaseFailureBuild` | medium | llm_rename | Sole caller is FUN_140002cd0 which xrefs ios_base::failbit/badbit/eofbit strings; builds the exception object before throw. |
| `140002cd0` | `FUN_140002cd0` | `ThrowIosBaseFailure` | high | llm_rename | Xrefs 'ios_base::badbit/eofbit/failbit set' strings and calls _CxxThrowException via helper FUN_140002c10; classic MSVC _Xfailure. |
| `140002d50` | `FUN_140002d50` | `StdExceptionCopy_wrapper` | medium | llm_rename | Single forwarder to __std_exception_copy; matches std::exception copy-ctor shape. |
| `140002e10` | `FUN_140002e10` | `StreamObjectCtor` | medium | llm_rename | Calls operator_new, _Init, _guard_dispatch_icall; many callers; constructs a stream/ios-like object with vtable dispatch. |
| `140003050` | `FUN_140003050` | `StreamObjectCtor_thunk` | low | llm_rename | Thin wrapper that forwards to FUN_140003090 (likely the real ctor) with shared callers; sole caller FUN_1400151c0. |
| `140003090` | `FUN_140003090` | `StreamObjectDtor` | medium | llm_rename | Calls _Ios_base_dtor; shares many callers with StreamObjectCtor (140002e10), suggesting paired ctor/dtor. |
| `140003230` | `FUN_140003230` | `StreamObjectCtor_thunk2` | low | llm_rename | 8-instruction forwarder to FUN_140002e10 (StreamObjectCtor); likely a default-args trampoline. |
| `140003250` | `FUN_140003250` | `WinErrorCategoryName` | medium | llm_rename | 2-instruction stub returning constant 'win_error' string; classic std::error_category::name() override. |
| `140003260` | `FUN_140003260` | `FormatWin32ErrorMessage` | high | llm_rename | Calls FormatMessageA plus operator_new and string helpers; large (288 insns) string-building routine for Win32 error codes. |
| `1400036f0` | `FUN_1400036f0` | `CaptureLastError` | medium | llm_rename | Calls GetLastError and forwards to FUN_140001ee0; multiple Win32-API-using callers (FUN_140006670 etc.) consume its result. |
| `140003730` | `FUN_140003730` | `LogGetModuleFileNameFailure` | high | llm_rename | Xrefs 'GetModuleFileName failed' string and forwards to FUN_140001ee0 (likely the logger); pure failure-path reporter. |
| `140003760` | `FUN_140003760` | `BuildErrorRecord` | low | llm_rename | Shares callee shape with FUN_140002c10 (FUN_140001c20 + FUN_140035d28 + FUN_1400106a0); many error-path callers including FUN_140003730 area. |
| `140003820` | `FUN_140003820` | `LoadLibraryByName` | high | llm_rename | Calls LoadLibraryW then GetLastError; small wrapper used by FUN_140005f40 and FUN_140012190 to load a DLL with error capture. |
| `140003890` | `FUN_140003890` | `FreeLibrary_wrapper` | high | llm_rename | 11-instruction single forwarder to FreeLibrary; only one caller FUN_140057200. |
| `1400038c0` | `FUN_1400038c0` | `load_library_or_throw` | high | llm_rename | Calls LoadLibraryW + GetLastError; on failure references 'LoadLibrary failed' string and invokes _CxxThrowException. |
| `1400039c0` | `FUN_1400039c0` | `close_handle_wrapper` | medium | llm_rename | Tiny 11-instr leaf that only calls CloseHandle; classic RAII handle closer. |
| `140003b00` | `FUN_140003b00` | `throw_bad_optional_access` | high | llm_rename | 2-instruction stub holding the 'Bad optional access' string; matches std::bad_optional_access throw helper. |
| `140003b60` | `FUN_140003b60` | `std_exception_copy_ctor` | medium | llm_rename | Sole callee is __std_exception_copy; 17-instr exception-object copy constructor wrapper. |
| `140003ba0` | `FUN_140003ba0` | `cert_get_subject_name_string` | high | llm_rename | Calls CertGetNameStringW + GetLastError; sole caller is the cert-verify pipeline at FUN_1400042c0. |
| `140004110` | `FUN_140004110` | `crypt_query_signed_object` | high | llm_rename | Calls CryptQueryObject + GetLastError; called by the signature-verify driver FUN_1400045c0. |
| `1400042c0` | `FUN_1400042c0` | `verify_signer_cert_chain` | medium | llm_rename | Invokes cert_get_subject_name (140003ba0) and FUN_140003ef0/0039f0; orchestrates signer cert validation within signature pipeline. |
| `1400045c0` | `FUN_1400045c0` | `verify_authenticode_signature` | high | llm_rename | Calls CryptMsgGetParam, CryptMsgClose, CertFindCertificateInStore, CertCloseStore, CertFreeCertificateContext; classic Authenticode/CMS verify driver. |
| `140004ee0` | `FUN_140004ee0` | `verify_file_via_catalog` | high | llm_rename | Calls CryptCATAdminAcquireContext/CalcHashFromFileHandle/EnumCatalogFromHash/CatalogInfoFromContext + WinVerifyTrust; catalog-based file trust verification. |
| `140005250` | `FUN_140005250` | `verify_file_trust` | high | llm_rename | Calls WinVerifyTrust directly and delegates to verify_file_via_catalog (FUN_140004ee0); top-level trust verifier. |
| `140005390` | `FUN_140005390` | `throw_bad_expected_access` | high | llm_rename | 2-instr stub anchored on 'bad expected access' string; std::expected access throw helper. |
| `1400053c0` | `FUN_1400053c0` | `throw_if_null_or_invalid` | low | llm_rename | Calls _CxxThrowException after invoking FUN_140001e20; tiny validate-or-throw helper. Naming heuristic. |
| `1400060a0` | `FUN_1400060a0` | `vb_get_module_filename_or_throw` | high | llm_rename | Calls GetModuleFileNameW, on failure calls GetLastError and _CxxThrowException with string 'GetModuleFileName failed'. |
| `140006180` | `FUN_140006180` | `vb_get_module_path_silent` | medium | llm_rename | GetModuleFileNameW + GetLastError but no throw string; sibling of 1400060a0 that returns error code instead of throwing (called by 140006460/140006b60/140009410). |
| `140006460` | `FUN_140006460` | `vb_init_once_module_path` | medium | llm_rename | Uses _Init_thread_header/_Init_thread_footer + atexit around FUN_140006180 (module path getter); classic one-shot init of cached module path. |
| `140006670` | `FUN_140006670` | `vb_get_module_path_validated` | high | llm_rename | GetModuleFileNameW wrapper that also throws on 'GetModuleFileName returned an unexpected path' (path-shape validation) and 'GetModuleFileName failed'. |
| `1400067c0` | `FUN_1400067c0` | `vb_get_exe_path_cached` | medium | llm_rename | Large GetModuleFileNameW wrapper (194 insns) called from 5 sites including service init paths; likely cached/normalised exe-path getter. |
| `140006b60` | `FUN_140006b60` | `vb_init_log_dll_for_session` | high | llm_rename | References 'log.dll' string; calls GetCurrentProcessId, ProcessIdToSessionId, FreeLibrary — session-aware log.dll loader/init. |
| `140006e00` | `FUN_140006e00` | `vb_module_handle_dtor` | medium | llm_rename | Tiny (16 insns) wrapper calling FreeLibrary then FUN_140011e70; shape of an HMODULE-holding object destructor. |
| `140006e40` | `FUN_140006e40` | `vb_alloc_thunk_malloc` | medium | llm_rename | Two-instruction tailcall to _malloc_base; allocator thunk passed to FUN_140014f60 (caller is likely allocator-table consumer). |
| `140006e50` | `FUN_140006e50` | `vb_alloc_thunk_realloc` | medium | llm_rename | Three-instruction tailcall to _realloc_base; sibling of 140006e40, same allocator-table pattern. |
| `140006ea0` | `FUN_140006ea0` | `vb_guarded_icall_thunk` | low | llm_rename | Calls _guard_dispatch_icall (CFG-guarded indirect call dispatcher); 30-insn thunk that forwards through a function pointer. |
| `140006f20` | `FUN_140006f20` | `vb_dll_holder_release` | medium | llm_rename | Calls FreeLibrary plus allocator helpers (FUN_14002f180/FUN_140035d28); release/cleanup of a dynamically loaded DLL wrapper. |
| `140006fc0` | `FUN_140006fc0` | `vb_bdch_loader_new` | high | llm_rename | operator_new then calls FUN_140007040 (bdch loader); classic ctor that heap-allocates the bdch wrapper object then initializes it. |
| `140007040` | `FUN_140007040` | `vb_load_bdch_dll_resolve_exports` | high | llm_rename | Loads bdch.dll via GetModuleHandleExW, resolves ~17 exports (GetAPIVersion, EnableBdch, SubmitDump, ListDumps, SignalHandler, etc.) via GetProcAddress with error logging. |
| `140007d80` | `FUN_140007d80` | `load_iservconfig_dll` | medium | llm_rename | String 'iservconfig.dll' present; called by config-loading parent FUN_140007f90 ('common'); 120 insns suggest LoadLibrary+resolve flow. |
| `140007f90` | `FUN_140007f90` | `load_common_config_module` | medium | llm_rename | String 'common'; calls load_iservconfig_dll and shared helpers; dispatched via _guard_dispatch_icall; sits between bdch.template.json reader and iservconfig loader. |
| `140008220` | `FUN_140008220` | `load_bdch_template_json` | high | llm_rename | Sole string 'bdch.template.json' and short size (53 insns) consistent with a template-file open/load wrapper; called by FUN_1400083c0 (bdch handler). |
| `140008300` | `FUN_140008300` | `init_thread_local_once` | high | llm_rename | Calls _Init_thread_header, atexit, _Init_thread_footer — canonical MSVC thread-safe static init pattern; 21 insns. |
| `140008370` | `FUN_140008370` | `thread_init_dispatch_wrapper` | low | llm_rename | Calls init_thread_local_once then _guard_dispatch_icall; thin wrapper around a thread-safe-once callback dispatch. |
| `1400083c0` | `FUN_1400083c0` | `load_or_create_bdch_json` | high | llm_rename | Strings 'bdch-{35312C50-...}', 'bdch.json', 'dch.json.bkp'; 1522 bytes; calls FreeLibrary, signal, template loader — bdch config load with backup fallback. |
| `1400089c0` | `FUN_1400089c0` | `bdch_config_init_wrapper` | medium | llm_rename | Thin wrapper (88 insns) calling load_or_create_bdch_json via guard_dispatch_icall; single caller from higher init chain. |
| `140008d20` | `FUN_140008d20` | `sleep_stub` | low | llm_rename | 11 insns, only callee is Sleep; isolated leaf. |
| `140008d50` | `FUN_140008d50` | `sleep_then_abort` | high | llm_rename | 6 insns; calls Sleep then abort — canonical delayed-abort termination handler. |
| `140008d70` | `FUN_140008d70` | `sleep_then_terminate` | high | llm_rename | 7 insns; calls Sleep then terminate — delayed std::terminate handler companion to sleep_then_abort. |
| `140008d90` | `FUN_140008d90` | `handle_terminate_marker` | medium | llm_rename | Strings '#terminate#' (x2); 166 insns; called from FUN_14000ac10 (crash/abort dispatcher); appears to be terminate-token processor. |
| `140008fd0` | `FUN_140008fd0` | `init_internal_crash_handler` | high | llm_rename | Reads 'Software\Bitdefender\InternalCrashEnabled' via RegOpenKeyExW, spawns CreateThread with 'crash#'/'abort#' tokens; classic crash-handler bootstrap. |
| `140009410` | `FUN_140009410` | `load_log_and_iservconfig_dlls` | high | llm_rename | Strings 'log.dll' + 'iservconfig.dll'; calls LoadLibraryW, GetLastError, FreeLibrary; 443 insns — module loader for logging + iservconfig. |
| `140009b30` | `FUN_140009b30` | `module_unload_wrapper` | medium | llm_rename | 30 insns; calls FreeLibrary via guard_dispatch_icall; counterpart unloader to load_log_and_iservconfig_dlls (same parent FUN_14000bfe0). |
| `140009ba0` | `FUN_140009ba0` | `san_path_env_helper` | low | llm_rename | Called by san_path_env builder; 50 insns of generic accessor helpers (FUN_14002f180/35d28/2f160) — likely string/buffer helper for PATH sanitiser. |
| `140009c70` | `FUN_140009c70` | `sanitize_path_env_var` | high | llm_rename | Strings 'san_path_env-{7D9669CE-...}', 'PATH' (x2); calls GetSystemDirectoryW, SetEnvironmentVariableW, _wdupenv_s — rewrites PATH env to a sanitised value. |
| `14000a2b0` | `FUN_14000a2b0` | `san_path_env_once_init` | medium | llm_rename | Calls san_path_env_helper plus _Init_thread_header/atexit/_Init_thread_footer — thread-safe one-time initializer for PATH sanitiser state. |
| `14000a330` | `FUN_14000a330` | `vb_resolve_desktop_path` | medium | llm_rename | Sole string 'Desktop' and call to __std_fs_get_file_id; likely resolves/validates a Desktop directory path. |
| `14000a4d0` | `FUN_14000a4d0` | `vb_close_service_handle_wrapper` | high | llm_rename | 11-insn thin wrapper whose only callee is CloseServiceHandle. |
| `14000a500` | `FUN_14000a500` | `vb_open_scm_or_throw` | high | llm_rename | String 'OpenSCManager failed' + calls OpenSCManagerW, GetLastError, _CxxThrowException. |
| `14000a600` | `FUN_14000a600` | `vb_query_updatesrv_service_state` | high | llm_rename | Strings UPDATESRV, NoRestrictBDAppsOnUpdate, '.DEFAULT\Software\SetID\bd.update.configure'; calls OpenServiceW, QueryServiceStatus, RegGetValueW via SCM-open helper. |
| `14000a900` | `FUN_14000a900` | `vb_load_bdch_crash_handler` | high | llm_rename | Strings 'bdch.dll', 'enable_crash_handler', 'load crash handler failed'; calls GetModuleHandleExW, FreeLibrary. |
| `14000ac10` | `FUN_14000ac10` | `vb_service_start_and_check_intentional_crash` | high | llm_rename | Strings 'start', 'check_intentional_crash', 'crash interval: '; calls load_bdch_crash_handler (14000a900). |
| `14000afb0` | `FUN_14000afb0` | `vb_service_run_as_executable` | high | llm_rename | Strings 'service::run_as_executable', 'Run as executable: Press x to exit'; calls AllocConsole/FreeConsole/_kbhit/_getwch. |
| `14000b2a0` | `FUN_14000b2a0` | `vb_start_service_dispatcher` | high | llm_rename | Strings 'start_service_dispatcher', 'StartServiceCtrlDispatcherW failed with error'; calls StartServiceCtrlDispatcherW. |
| `14000b390` | `FUN_14000b390` | `vb_set_current_dir_or_log` | high | llm_rename | Strings 'set_current_dir', 'Failed to set current directory, err: '; calls SetCurrentDirectoryW, GetLastError. |
| `14000b620` | `FUN_14000b620` | `vb_ensure_directory_exists` | high | llm_rename | Strings 'remove', 'symlink_status', 'create_directory'; calls __std_fs_get_stats and __std_fs_create_directory. |
| `14000b750` | `FUN_14000b750` | `vb_init_bdservicehost_log_dir` | high | llm_rename | Strings 'bdservicehost', 'BDLogging'; calls SHGetKnownFolderPath then ensure_directory_exists (14000b620). |
| `14000baf0` | `FUN_14000baf0` | `vb_build_bdlogging_path` | high | llm_rename | Strings '\BDLogging\', '\bdservicehost'; calls SHGetKnownFolderPath + ensure_directory_exists; path-composition helper. |
| `14000bfe0` | `FUN_14000bfe0` | `vb_init_update_environment` | medium | llm_rename | Called only by wWinMain; fans out to query_updatesrv_service_state (14000a600) and resolve_desktop_path (14000a330); coordinator before service start. |
| `14000c090` | `FUN_14000c090` | `vb_wWinMain` | high | llm_rename | Massive 890-insn entry: strings 'wWinMain', 'cmd line arguments:', 'install'/'uninstall'/'enable'/'disable'/'start'/'stop'/'debug', SetDefaultDllDirectories, CommandLineToArgvW. |
| `14000d240` | `FUN_14000d240` | `vb_get_module_dir_with_backslash` | high | llm_rename | Calls GetModuleFileNameW, PathRemoveFileSpecW, PathAddBackslashW; throws on failure. |
| `14000d5f0` | `FUN_14000d5f0` | `vb_unload_module_wrapper` | medium | llm_rename | Small 18-instr leaf calls FreeLibrary plus FUN_14002f180 helper; classic module unload/cleanup shape with no other side effects. |
| `14000e180` | `FUN_14000e180` | `vb_invoke_de30_thunk` | medium | llm_rename | 24-instr thunk whose sole non-trivial callee is FUN_14000de30; called from two distinct sites (FUN_14000ef10, FUN_140003090) indicating shared adapter. |
| `14000e3c0` | `FUN_14000e3c0` | `vb_ios_base_dtor_thunk` | high | llm_rename | 7-instr leaf whose only callee is _Ios_base_dtor; invoked from 4 sites — canonical MSVC std::ios_base destructor trampoline. |
| `14000ea70` | `FUN_14000ea70` | `logging_CLogDLL_dtor_thunk_a` | medium | llm_rename | Tiny 17-insn thunk whose only callee is FUN_14000eb20 (logging::CLogDLL::~CLogDLL); caller is FUN_140017910. Likely vtable/dtor thunk wrapping the log-DLL destructor. |
| `14000eae0` | `FUN_14000eae0` | `logging_CLogDLL_dtor_thunk_b` | medium | llm_rename | 11-insn thunk; sole callee FUN_14000eb20 (logging::CLogDLL::~CLogDLL); called from FUN_140017910. Second dtor adjustor thunk variant for the logging singleton. |
| `14000eb20` | `FUN_14000eb20` | `logging_CLogDLL_dtor` | high | llm_rename | Strings 'LogDeinit' + 'logging::CLogDLL::~CLogDLL' embedded; calls FreeLibrary/GetProcAddress/atexit consistent with logging DLL teardown destructor. |
| `14000eca0` | `FUN_14000eca0` | `std_exception_copy_wrapper` | medium | llm_rename | 17-insn leaf whose only callee is __std_exception_copy; no callers in batch — pattern matches MSVC std::exception copy ctor/assign helper. |
| `14000ef10` | `FUN_14000ef10` | `ios_stream_wrapper_dtor_14000ef10` | low | llm_rename | Small (24 insns) function calling _Ios_base_dtor then FUN_14000e180; shape of an iostream-derived object destructor wrapper. Single caller FUN_140015180. |
| `14000efe0` | `FUN_14000efe0` | `ios_base_dtor_thunk_14000efe0` | low | llm_rename | 19-insn leaf calling _Ios_base_dtor and FUN_14002f180 (likely __security_check_cookie/cleanup). Classic ios_base destructor thunk shape. |
| `14000ff70` | `FUN_14000ff70` | `guarded_recursive_dispatch_14000ff70` | low | llm_rename | Self-recursive, calls _guard_dispatch_icall and __uncaught_exception. CFG-guarded virtual dispatch with EH; shared by 5 unrelated callers. Likely tree/visitor recursion. |
| `1400101a0` | `FUN_1400101a0` | `alloc_construct_object_small_1400101a0` | medium | llm_rename | 5 callers, same operator_new + FUN_140001a20 + FUN_140001670 callee shape (without FUN_1400316b0). Smaller-arity allocator helper in same family as 140010340/1400106a0. |
| `140010340` | `FUN_140010340` | `alloc_construct_object_140010340` | medium | llm_rename | Called by 21 sites; calls operator_new plus two constructor-helpers (FUN_140001a20, FUN_140001670) and FUN_1400316b0 (likely registry/list insert). Object-allocator factory. |
| `140010530` | `FUN_140010530` | `alloc_construct_with_init_140010530` | medium | llm_rename | Same ctor-helper family but additionally calls FUN_140031e00 (likely string/buffer init or copy). Variant with initialised content; 2 callers. |
| `1400106a0` | `FUN_1400106a0` | `alloc_construct_object_variant_1400106a0` | medium | llm_rename | Called by 40 sites with identical callee signature to FUN_140010340 (operator_new + ctor helpers + FUN_1400316b0). Sibling allocator factory, possibly different type/size. |
| `140011df0` | `FUN_140011df0` | `vb_throw_invalid_string_position` | high | llm_rename | 4-instruction thunk holding the literal 'invalid string position' and calling FUN_14002d718 (std::_Xout_of_range/std::_Xran). Classic STL out-of-range helper inlined per TU. |
| `140011e70` | `FUN_140011e70` | `vb_clogdll_deinit_freelibrary` | high | llm_rename | Holds strings 'LogDeinit' and 'logging::CLogDLL::~CLogDLL'; calls GetProcAddress, FreeLibrary, Sleep. Logging-DLL destructor that resolves and calls LogDeinit before unloading. |
| `140012190` | `FUN_140012190` | `bd_open_file_with_cleanup` | medium | llm_rename | Calls CreateFileW, CloseHandle, FreeLibrary, GetLastError: opens a file handle with module-load lifecycle; cleanup branch on failure. |
| `140012520` | `FUN_140012520` | `bd_load_productinfo_module` | high | llm_rename | Strings 'BdCreateObject'/'BdDestroyObject'/'productinfo' x4, calls LoadLibraryExW+LoadLibraryW+GetProcAddress+FreeLibrary: dynamic-loads productinfo plugin and resolves Bd object factory exports. |
| `140012a30` | `FUN_140012a30` | `shared_exception_thrower` | low | llm_rename | 11 callers from disparate dispatchers; calls __uncaught_exception and _guard_dispatch_icall: shared throw/rethrow or error-propagation helper invoked from many sites. |
| `140012ef0` | `FUN_140012ef0` | `std_facet_register_locked` | medium | llm_rename | Calls _Facet_Register, _Lockit/~_Lockit pair: STL facet registration under the global locale lock. |
| `1400134e0` | `FUN_1400134e0` | `std_locale_init_via_FUN140013fd0` | medium | llm_rename | Calls _Facet_Register, _Lockit pair, and FUN_140013fd0 (std_locale_ctor_from_name): wrapper that initialises a named locale facet under lock. |
| `140013c80` | `FUN_140013c80` | `std_facet_register_via_FUN1400025d0` | medium | llm_rename | Same shape as 134e0/12ef0 (_Facet_Register + _Lockit/~_Lockit + _guard_dispatch_icall) but routes through FUN_1400025d0; per-facet registration wrapper. |
| `140013fd0` | `FUN_140013fd0` | `std_locale_ctor_from_name` | high | llm_rename | Strings 'false','bad locale name'; calls _Locinfo_ctor/_Locinfo_dtor/_Lockit/_Mbrtowc/_Getcvt: STL std::locale constructor from a named locale string. |
| `140014290` | `FUN_140014290` | `std_locale_name_validate` | high | llm_rename | String 'bad locale name'; calls _Locinfo_ctor/_Locinfo_dtor/_Lockit: helper that validates a locale name and constructs Locinfo, throwing on failure. |
| `140014450` | `FUN_140014450` | `throw_vector_too_long` | high | llm_rename | Single string 'vector too long' + 4 instructions + 12 callers across container ops = std::vector::_Xlength throw helper. |
| `1400144b0` | `FUN_1400144b0` | `vb_dispatch_icall_with_seh_a` | low | llm_rename | 225 insns, callers in init/setup region, callees include _guard_dispatch_icall + __uncaught_exception; SEH-wrapped indirect dispatcher. Distinct from 1400147e0/140014c60 variants. |
| `1400147e0` | `FUN_1400147e0` | `vb_dispatch_icall_with_seh_b` | low | llm_rename | 164 insns, single caller FUN_14000ac10, same _guard_dispatch_icall+__uncaught_exception pattern as 1400144b0; SEH-protected indirect call wrapper variant. |
| `140014ae0` | `FUN_140014ae0` | `vb_alloc_and_construct` | medium | llm_rename | 104 insns, callees include operator_new + FUN_140001670 (likely ctor) + FUN_1400316b0 (release/exit handler); allocates and constructs an object. |
| `140014c60` | `FUN_140014c60` | `vb_dispatch_icall_with_seh_c` | low | llm_rename | 103 insns, 5 callers, same _guard_dispatch_icall+FUN_140012ef0+__uncaught_exception template; another SEH indirect-dispatch wrapper sibling. |
| `140015120` | `FUN_140015120` | `ret_zero_stub` | medium | llm_rename | 2 insns / 5 bytes, no callers/callees: minimal stub, almost certainly `xor eax,eax; ret` returning 0/false. |
| `140015130` | `FUN_140015130` | `ret_const_stub_8b` | low | llm_rename | 2 insns / 8 bytes, no edges: tiny constant-return stub (likely mov eax,imm; ret). |
| `140015140` | `FUN_140015140` | `ret_const_stub_11b` | low | llm_rename | 2 insns / 11 bytes, no edges: tiny constant-return stub (likely mov rax,imm64; ret or lea + ret). |
| `140015170` | `FUN_140015170` | `thunk_to_FUN_14000ece0` | medium | llm_rename | 3 insns / 12 bytes, no callers, single callee FUN_14000ece0: classic jmp-thunk forwarder. |
| `140015180` | `FUN_140015180` | `thunk_to_FUN_14000ef10` | medium | llm_rename | 3 insns / 12 bytes, no callers, single callee FUN_14000ef10: classic jmp-thunk forwarder. |
| `140015190` | `FUN_140015190` | `thunk_to_FUN_14000ed20` | medium | llm_rename | 3 insns / 12 bytes, no callers, single callee FUN_14000ed20: classic jmp-thunk forwarder. |
| `1400151a0` | `FUN_1400151a0` | `scalar_deleting_dtor_thunk_a` | medium | llm_rename | 3 insns / 12 bytes, callee FID_conflict:`scalar_deleting_destructor': MSVC vftable scalar-deleting-destructor thunk. |
| `1400151b0` | `FUN_1400151b0` | `scalar_deleting_dtor_thunk_b` | medium | llm_rename | 3 insns / 12 bytes, callee FID_conflict:`scalar_deleting_destructor': sibling scalar-deleting-destructor thunk for another class vftable slot. |
| `1400151d0` | `FUN_1400151d0` | `log_format_vsprintf` | medium | llm_rename | Wraps __stdio_common_vsprintf_s; called by many logging stubs (FUN_14000f0d0/f8f0/f7c0/fa20/f690/f020/f3b0) to format log message buffers. |
| `140015270` | `FUN_140015270` | `log_trace_exit` | high | llm_rename | Format strings '<- %s [%d]' indicate function-exit trace logging. Called by every service:: method as the exit logger; uses timeGetTime for timestamp. |
| `140015360` | `FUN_140015360` | `service__ctor` | high | llm_rename | Strings 'service::service','CreateServiceImplementation','DestroyServiceImplementation','Can't load service dll.' Loads service DLL via LoadLibraryW + GetProcAddress; service constructor. |
| `140015710` | `FUN_140015710` | `service__dtor_thunk` | medium | llm_rename | Tiny 16-instr wrapper that calls FUN_14002f180 then service__dtor; matches destructor thunk pattern for service object. |
| `140015750` | `FUN_140015750` | `service__dtor` | medium | llm_rename | Called only by FUN_140015710 (likely dtor thunk); invokes guard_dispatch_icall + CloseHandle + FreeLibrary, mirror of service__ctor cleanup path. |
| `140015820` | `FUN_140015820` | `service__StopService` | high | llm_rename | String 'service::StopService' + SetEvent call to signal service stop; entry trace via log_trace_exit pair pattern. |
| `1400159d0` | `FUN_1400159d0` | `service__run_as_service` | high | llm_rename | String 'service::run_as_service','Failed to register control handler.' Calls RegisterServiceCtrlHandlerExW + GetMessageW/DispatchMessageW + MsgWaitForMultipleObjectsEx; SCM main loop. |
| `140015ca0` | `FUN_140015ca0` | `service__on_control_handler` | high | llm_rename | Strings 'service::on_control_handler','service_manager::unprotect_service'. SCM control-handler callback dispatching control codes; called by FUN_140016eb0 (control handler thunk). |
| `140015fc0` | `FUN_140015fc0` | `service__uninit` | high | llm_rename | String 'service::uninit'; CloseHandle of service handles and final report_status call. Service teardown. |
| `140016190` | `FUN_140016190` | `service__report_status` | high | llm_rename | String 'service::report_status' + SetServiceStatus call; SCM status reporter used by run_as_service and uninit. |
| `140016380` | `FUN_140016380` | `service__register_service_events` | high | llm_rename | String 'service::register_service_events','events map is empty'; iterates an events map registering service event sinks. |
| `140016620` | `FUN_140016620` | `service__unregister_service_events` | high | llm_rename | String 'service::unregister_service_events'; mirror of register_service_events using same FUN_140016ed0 helper. Called by run_as_service on shutdown. |
| `140016820` | `FUN_140016820` | `service__is_command_trusted` | high | llm_rename | Strings 'service::is_command_trusted','bdservicehost.'; uses __std_fs_get_stats — checks command file/path against trust policy for SCM control. |
| `140016b80` | `FUN_140016b80` | `service__remove_trust_command_file` | high | llm_rename | Strings 'service::remove_trust_command_file','bdservicehost.','Failed to remove file: '; deletes trust-command file used by IPC. Called from run_as_service. |
| `140016eb0` | `FUN_140016eb0` | `service__control_handler_thunk` | medium | llm_rename | 10-instr stub whose sole callee is on_control_handler; matches the trampoline registered via RegisterServiceCtrlHandlerExW. |
| `140016ed0` | `FUN_140016ed0` | `service_events_map_iter_helper` | low | llm_rename | Called by both register_service_events and unregister_service_events; uses operator_new + FUN_140017180/16fb0 — likely event-map element constructor/iterator. |
| `140016f80` | `FUN_140016f80` | `log_error_prefix` | low | llm_rename | Tiny 11-insn fn with sole string 'Error: ' calling a formatter/logger helper; likely emits the 'Error: ' prefix into a log line. |
| `140017180` | `FUN_140017180` | `unordered_map_reserve_or_rehash` | medium | llm_rename | Throws 'unordered_map/set too long', calls bucket-init helper (FUN_140017450) and ceilf for load-factor math; STL-style rehash/reserve. |
| `140017450` | `FUN_140017450` | `unordered_map_init_buckets` | medium | llm_rename | Throws 'invalid hash bucket count' and allocates via operator_new; called by the rehash fn — classic STL unordered_map bucket allocator. |
| `1400178b0` | `FUN_1400178b0` | `fprintf_to_stdio_stream` | medium | llm_rename | 22-insn wrapper around __stdio_common_vfwprintf with __acrt_iob_func resolving the target FILE*; small fwprintf-style helper. |
| `140017900` | `FUN_140017900` | `get_iservice_additional_config_iid_str` | high | llm_rename | 2-insn leaf returning the literal 'IServiceAdditionalConfiguration.1'; an interface-id string getter used by the install dispatcher. |
| `140017910` | `FUN_140017910` | `service_additional_configuration_install` | high | llm_rename | Strings name 'service_additional_configuration::install'; LoadLibraryW+GetProcAddress('SvcGetObject') then calls IServiceAdditionalConfiguration::Install and logs result. |
| `1400180b0` | `FUN_1400180b0` | `multibyte_to_widechar_convert` | high | llm_rename | Calls MultiByteToWideChar twice (size probe then convert), throws on 'MultiByteToWideChar failed'/'for size failed'; canonical MB->W converter. |
| `140018340` | `FUN_140018340` | `throw_map_set_too_long` | medium | llm_rename | 4-insn helper containing 'map/set too long' string and calling FUN_14002d6f4 (exception thrower); STL length_error trampoline. |
| `140018380` | `FUN_140018380` | `json_exception_ctor` | medium | llm_rename | Holds '[json.exception.' literal, called by parse_error/type_error/etc builders; nlohmann::json exception base constructor. |
| `1400186d0` | `FUN_1400186d0` | `json_throw_parse_error` | high | llm_rename | Strings 'parse_error'/'parse error', calls json_exception_ctor (FUN_140018380) and exception copy; nlohmann::json parse_error builder. |
| `140018aa0` | `FUN_140018aa0` | `json_format_position_at_line_column` | high | llm_rename | Strings ' at line ' and ', column '; called only from json_throw_parse_error to format position suffix on the parse-error message. |
| `140018ed0` | `FUN_140018ed0` | `json_throw_invalid_iterator` | high | llm_rename | Builds and throws nlohmann::json invalid_iterator exception; string 'invalid_iterator' + std::exception copy ctor pattern shared with sibling throw helpers. |
| `1400190c0` | `FUN_1400190c0` | `json_throw_type_error` | high | llm_rename | nlohmann::json type_error throw helper; identical shape (487 bytes, exception_copy callee, 128 insns) to invalid_iterator/out_of_range throwers. |
| `1400192b0` | `FUN_1400192b0` | `json_throw_out_of_range` | high | llm_rename | nlohmann::json out_of_range throw helper; string literal + std::exception_copy + identical sibling shape. |
| `1400194a0` | `FUN_1400194a0` | `json_throw_other_error` | high | llm_rename | nlohmann::json other_error throw helper; string 'other_error' + __std_exception_copy callee. |
| `1400196b0` | `FUN_1400196b0` | `locale_ctor_from_name` | high | llm_rename | Constructs std::locale from name; calls _Locinfo_ctor/_Lockit/operator_new and throws runtime_error with 'bad locale name' on failure. |
| `140019850` | `FUN_140019850` | `ctype_tolower_thunk` | medium | llm_rename | Thin 23-insn wrapper around CRT _Tolower; classic std::ctype<char>::tolower virtual implementation shape. |
| `1400198b0` | `FUN_1400198b0` | `ctype_toupper_thunk` | medium | llm_rename | Thin 23-insn wrapper around CRT _Toupper; std::ctype<char>::toupper virtual implementation. |
| `140019ac0` | `FUN_140019ac0` | `CBdServicePowerSourceEvent_Register` | high | llm_rename | Strings name CBdServicePowerSourceEvent::Register and log RegisterPowerSettingNotification GUID_ACDC_POWER_SOURCE failure with GetLastError. |
| `140019c40` | `FUN_140019c40` | `CBdServiceBatteryPercentageEvent_Register` | high | llm_rename | Strings name CBdServiceBatteryPercentageEvent::Register; registers GUID_BATTERY_PERCENTAGE_REMAINING power-setting notification, logs failure. |
| `140019eb0` | `FUN_140019eb0` | `parse_config_version` | high | llm_rename | Strings 'version', 'The JSON version is not accepted', 'type must be number' + called from main config parser FUN_14001b450; validates the 'version' JSON field as numeric. |
| `14001a110` | `FUN_14001a110` | `parse_config_string_field` | medium | llm_rename | Only string 'type must be string, but is '; small helper called from config parser FUN_14001b450; throws on non-string JSON values. Generic string-field extractor. |
| `14001a250` | `FUN_14001a250` | `parse_config_accepted_controls` | high | llm_rename | Strings 'acceptedControls', 'The accepted control is not recognized', 'type must be string'; called from FUN_14001b450; validates a list of accepted service control names. |
| `14001a7f0` | `FUN_14001a7f0` | `parse_config_registered_events` | high | llm_rename | Strings 'registeredEvents', 'The registered event is not recognized', 'type must be string'; called from FUN_14001b450; parses registered-event list, allocates entries via operator_new. |
| `14001b1c0` | `FUN_14001b1c0` | `load_service_config_file` | high | llm_rename | String 'Could not open the configuration file.'; uses _Ios_base_dtor (fstream); calls FUN_14001b450 (config parser) after open. Top-level config loader. |
| `14001b450` | `FUN_14001b450` | `parse_service_config_json` | high | llm_rename | Strings 'serviceName','serviceDisplayName','serviceGroup','serviceDescription','relativeDllPath','runProtected'; dispatches to version/controls/events sub-parsers; Windows version check via VerifyVersionInfoW. |
| `14001bc20` | `FUN_14001bc20` | `stdio_flush_thunk` | medium | llm_rename | Tiny wrapper calling fflush via _guard_dispatch_icall; CFG-guarded vtable thunk over fflush. |
| `14001bc70` | `FUN_14001bc70` | `stdio_setvbuf_wrapper` | medium | llm_rename | Wraps setvbuf with FUN_14001d8d0 helper; small stdio buffer-mode adapter. |
| `14001bcd0` | `FUN_14001bcd0` | `stdio_fsetpos_wrapper` | medium | llm_rename | Calls fsetpos via thunk; stream seek wrapper used by stream abstraction layer. |
| `14001bdb0` | `FUN_14001bdb0` | `stdio_seek_wrapper` | medium | llm_rename | Calls common_fseek + fgetpos; combined seek/tell adapter over CRT FILE*. |
| `14001bec0` | `FUN_14001bec0` | `stream_write_buffer` | medium | llm_rename | Calls fwrite via _guard_dispatch_icall; size validation via FUN_1400316b0; output write adapter. |
| `14001bff0` | `FUN_14001bff0` | `stream_read_buffer` | medium | llm_rename | Calls fread via _guard_dispatch_icall with size validation; counterpart to stream_write_buffer. |
| `14001c1b0` | `FUN_14001c1b0` | `stream_getc_unget` | medium | llm_rename | Calls fgetc + ungetc via guard dispatch; character-level stream read with pushback support. |
| `14001c4e0` | `FUN_14001c4e0` | `stream_ungetc_wrapper` | medium | llm_rename | Calls ungetc; pushback adapter for the stream abstraction layer. |
| `14001c5c0` | `FUN_14001c5c0` | `stream_putc_write` | medium | llm_rename | Calls fputc and fwrite via guard dispatch; character/buffer write adapter. |
| `14001cdf0` | `FUN_14001cdf0` | `vb_map_at_lookup_or_throw` | high | llm_rename | Strings 'invalid map<K, T> key' and 'cannot use at() with ' plus memcmp + _CxxThrowException match std::map::at()-style keyed lookup that throws on missing key. |
| `14001d320` | `FUN_14001d320` | `vb_throw_helper_a` | medium | llm_rename | Tiny 33-byte wrapper whose sole callee is the std::exception copy ctor (vb_std_exception_init_copy); paired with 14001d490 and called from 14001e410/14001e2a0 throw sites. |
| `14001d350` | `FUN_14001d350` | `vb_std_exception_init_copy` | high | llm_rename | Only callee is __std_exception_copy and it has 5 callers that look like throw helpers (14001d320/490/4c0, 14001e0d0, 14001f3f0); classic exception-object ctor copying message. |
| `14001d3d0` | `FUN_14001d3d0` | `vb_invoke_14001c7b0_via_guard` | low | llm_rename | 16-instr trampoline calling FUN_14001c7b0 and FUN_14002f180 (likely __security_check_cookie); no strings, no callers — pass1 placeholder marking the bridge to 14001c7b0. |
| `14001d490` | `FUN_14001d490` | `vb_throw_helper_b` | medium | llm_rename | Mirror of 14001d320: 33-byte wrapper, sole callee is std::exception copy ctor, same two callers (14001e410, 14001e2a0); second of paired throw helpers for distinct exception types. |
| `14001d7d0` | `FUN_14001d7d0` | `vb_fstream_write_helper` | medium | llm_rename | Calls fwrite via guard_dispatch_icall; wrapped by callers that subsequently call fclose (FUN_14001d9d0). File-stream write helper. |
| `14001d8d0` | `FUN_14001d8d0` | `vb_fstream_buffer_access` | medium | llm_rename | Calls _get_stream_buffer_pointers (MSVC CRT internal for stream buffer state); file-stream buffer peek/access helper. |
| `14001d9d0` | `FUN_14001d9d0` | `vb_fstream_close_flush` | medium | llm_rename | Calls FUN_14001d7d0 (fwrite helper) then fclose; matches close-and-flush pattern for buffered output stream wrapper. |
| `14001ddd0` | `FUN_14001ddd0` | `vb_json_type_name` | high | llm_rename | Returns one of {object,array,string,boolean,discarded,number} string literals; matches nlohmann::json::type_name() signature. Called from many JSON helpers in this module. |
| `14001de50` | `FUN_14001de50` | `vb_json_throw_exception` | high | llm_rename | Embeds nlohmann/json 3.7.0 commit hash '961c151d...3.7.0' and calls _CxxThrowException; classic json::exception::create/parse_error builder. |
| `14001e680` | `FUN_14001e680` | `json_parser_parse` | high | llm_rename | Strings 'syntax error', 'while parsing', 'last read', 'unexpected', 'expected' are nlohmann/json parser error messages; 572 insn parse driver. |
| `14001ef90` | `FUN_14001ef90` | `json_parse_value_dispatch` | high | llm_rename | Strings 'invalid BOM; must be 0xEF 0xBB 0xBF', 'false', 'invalid literal' match nlohmann/json scanner literal/BOM dispatch. |
| `14001f280` | `FUN_14001f280` | `json_escape_unicode_u4hex` | high | llm_rename | Format string '<U+%.4X>' is nlohmann/json's unicode-escape rendering for token strings. |
| `14001f6d0` | `FUN_14001f6d0` | `json_token_type_to_string` | high | llm_rename | Returns literal names ('true literal','false literal','null literal','string literal','number literal','<parse error>','end of input','unknown token'): nlohmann::detail::lexer::token_type_name. |
| `14001f960` | `FUN_14001f960` | `json_scan_literal_true` | medium | llm_rename | Called from json_parse_value_dispatch alongside scan_number/string; no strings but sibling of scan_false (fb20) which has 'invalid literal'. |
| `14001fb20` | `FUN_14001fb20` | `json_scan_literal_false_null` | high | llm_rename | 'invalid literal' x2 + called from json_parse_value_dispatch; matches nlohmann lexer scan_literal for false/null tokens. |
| `14001fc00` | `FUN_14001fc00` | `json_scan_number` | high | llm_rename | Strings 'invalid number; expected digit after -/+/./exponent' and callees _strtoi64/strtoull match nlohmann::detail::lexer::scan_number. |
| `140020640` | `FUN_140020640` | `json_scan_string_utf8_check` | high | llm_rename | 'invalid string: ill-formed UTF-8 byte' is nlohmann lexer's UTF-8 validator inside scan_string. |
| `140021240` | `FUN_140021240` | `json_scan_string_utf8_check_variant` | medium | llm_rename | Same 'invalid string: ill-formed UTF-8 byte' strings; no callers in batch but mirrors 140020640 sibling lexer routine. |
| `140021870` | `FUN_140021870` | `throw_vector_bool_too_long` | high | llm_rename | Single string 'vector<bool> too long', tiny stub (4 insn) that calls a throw helper: MSVC STL _Xlength for vector<bool>. |
| `140021b50` | `FUN_140021b50` | `vb_json_value_get_bool` | high | llm_rename | Strings 'cannot get value', 'cannot use value() with ', 'type must be boolean, but is ' + _CxxThrowException; classic nlohmann::json get<bool>() accessor that throws type_error when stored type != boolean. |
| `1400220b0` | `FUN_1400220b0` | `vb_json_parse_dispatch_a` | high | llm_rename | 1353 insns, 35 callees, error strings 'object separator', 'object key', 'number overflow parsing', 'value', 'array', 'object'; JSON parser state machine (likely nlohmann::detail::parser::parse variant A). |
| `140023770` | `FUN_140023770` | `vb_json_parse_dispatch_b` | high | llm_rename | 1340 insns mirroring 1400220b0 with same JSON parser error strings but disjoint callee set; sibling parse() instantiation (different value-type template arg) from nlohmann::json detail::parser. |
| `140024fb0` | `FUN_140024fb0` | `vb_json_parser_short_helper_b` | low | llm_rename | Sole caller JSON parser 140023770; 16-insn shim into FUN_140028680; thin parser dispatch helper specific to the b-variant parse loop. |
| `140024ff0` | `FUN_140024ff0` | `vb_json_parser_helper_a` | medium | llm_rename | Only called from JSON parser 1400220b0; calls _guard_dispatch_icall + small helpers (FUN_140025870, FUN_140025c20); likely token/iterator step helper used during parse. |
| `1400250e0` | `FUN_1400250e0` | `vb_json_iter_compare_or_get` | high | llm_rename | Strings 'cannot get value' and 'cannot compare iterators of different containers' + _CxxThrowException; nlohmann::json iterator compare / value() accessor throwing invalid_iterator/type_error. |
| `140025440` | `FUN_140025440` | `vb_json_parser_emit_value` | medium | llm_rename | Sole caller is JSON parser 1400220b0; uses operator_new + many parser helpers (FUN_1400214b0, FUN_140025800, FUN_140025c20); constructs/emits a json value node during parse. |
| `140025680` | `FUN_140025680` | `vb_locale_ctor_from_name` | high | llm_rename | String 'bad locale name' + _Locinfo_ctor / _Locinfo_dtor / _Lockit calls; MSVC std::locale constructor from name (_Locinfo bootstrap throwing runtime_error on invalid). |
| `140025b90` | `FUN_140025b90` | `shared_state_lookup_helper` | low | llm_rename | Tiny (42 ins) hot leaf called by 10 sibling functions (FUN_140026af0..140028190 family); each is a dispatch handler. Likely a shared lookup/get-state helper for that handler family. |
| `140025c20` | `FUN_140025c20` | `recursive_tree_node_builder` | low | llm_rename | Self-recursive (calls FUN_140025c20), allocates via operator_new, mutually recursive with FUN_14002a4c0. Pattern of recursive tree/graph node construction. |
| `1400261e0` | `FUN_1400261e0` | `unordered_map_reserve_or_rehash` | medium | llm_rename | Single caller, allocates via operator_new, uses ceilf (load-factor math), throws 'unordered_map/set too long' length_error. Classic MSVC unordered container rehash/reserve helper. |
| `140026490` | `FUN_140026490` | `unordered_map_emplace_or_insert` | medium | llm_rename | Two callers, calls memcmp+ceilf+operator_new and emits 'unordered_map/set too long'. MSVC unordered_map emplace/insert with hash-bucket growth (ceilf for max_load_factor). |
| `140026df0` | `FUN_140026df0` | `container_erase_with_iterator_check` | medium | llm_rename | Throws 'cannot use erase() with', 'iterator does not fit current value', 'iterator out of range' via _CxxThrowException. MSVC checked erase(iterator) implementation. |
| `140028bc0` | `FUN_140028bc0` | `vb_hash_bucket_init` | medium | llm_rename | String 'invalid hash bucket count' anchors this as a hash-table constructor/initializer validating bucket count param. |
| `140029be0` | `FUN_140029be0` | `vb_intrusive_list_node_recurse` | low | llm_rename | Self-recursive 30-instr leaf calling sibling FUN_140029e10; classic intrusive-list/tree node walk releasing nodes. |
| `140029e80` | `FUN_140029e80` | `vb_shared_object_helper` | low | llm_rename | Hot leaf called by 8 sibling FUN_14002xxx constructors after operator_new+FUN_140014450+FUN_140001670+FUN_140035d28; likely shared-state/refcount init helper. |
| `14002a6a0` | `FUN_14002a6a0` | `format_exception_description` | medium | llm_rename | Builds 'Description: ...; ec: ...' diagnostic string; widely called by error paths in service/install code. |
| `14002a810` | `FUN_14002a810` | `delete_service` | high | llm_rename | String tag 'delete_service'; opens SCM, OpenServiceW, DeleteService, CloseServiceHandle with err logging. |
| `14002aaa0` | `FUN_14002aaa0` | `control_service_send` | high | llm_rename | Calls ControlService; logs 'ControlService failed'; helper for stop/pause via SCM control codes. |
| `14002ac10` | `FUN_14002ac10` | `start_service_inner` | high | llm_rename | Inner helper: StartServiceW + wait_service_to_stop + logs 'StartServiceW failed' under 'start_service' tag. |
| `14002aeb0` | `FUN_14002aeb0` | `start_service` | high | llm_rename | Top-level 'start_service' orchestrator: open_sc_manager, open_service, wait_to_stop/start, calls start_service_inner. |
| `14002b350` | `FUN_14002b350` | `stop_service_inner` | high | llm_rename | QueryServiceStatus + ControlService (via 14002aaa0) + wait_service_to_stop; logs 'query_service_status failed'. |
| `14002b4e0` | `FUN_14002b4e0` | `stop_service` | high | llm_rename | Top-level stop_service: open_sc_manager/open_service then calls stop_service_inner; matching error log strings. |
| `14002b740` | `FUN_14002b740` | `change_service_config_inner` | high | llm_rename | Wraps ChangeServiceConfigW; logs 'ChangeServiceConfigW failed'. |
| `14002b840` | `FUN_14002b840` | `enable_service_autostart` | high | llm_rename | String tag 'enable_service_autostart'; opens SCM/service then ChangeServiceConfigW via 14002b740. |
| `14002bba0` | `FUN_14002bba0` | `change_service_config2_inner` | high | llm_rename | Wraps ChangeServiceConfig2W with err logging 'ChangeServiceConfig2W failed'. |
| `14002bca0` | `FUN_14002bca0` | `set_service_launch_type` | high | llm_rename | String tag 'set_service_launch_type'; opens SCM/service then ChangeServiceConfig2W via 14002bba0. |
| `14002c000` | `FUN_14002c000` | `wait_service_to_start` | high | llm_rename | String tag 'wait_service_to_start'; QueryServiceStatus polling loop with Sleep/GetTickCount. |
| `14002c1f0` | `FUN_14002c1f0` | `wait_service_to_stop` | high | llm_rename | String tag 'wait_service_to_stop'; QueryServiceStatus polling loop with Sleep/GetTickCount. |
| `14002c3f0` | `FUN_14002c3f0` | `install_bdelam_certificate` | high | llm_rename | Reads \drivers\bdelam.sys via SHGetKnownFolderPath, GetProcAddress(InstallELAMCertificateInfo) from kernel32.dll. |
| `14002c690` | `FUN_14002c690` | `service_manager_install_service` | high | llm_rename | Calls OpenSCManagerW/OpenServiceW/CreateServiceW/ChangeServiceConfig2W; error strings open_sc_manager failed, open_service failed; large install/configure routine. |
| `14002cd20` | `FUN_14002cd20` | `service_manager_disable_service` | high | llm_rename | Strings literally name service_manager::disable_service; uses OpenSCManagerW/OpenServiceW + CloseServiceHandle; logs Failed to send custom control / open service / open service manager. |
| `14002d48c` | `FUN_14002d48c` | `critical_section_dtor_wrapper` | medium | llm_rename | Small wrapper calling DeleteCriticalSection; called from two siblings (FUN_14005a5c0, FUN_14005a4d0); destructor for object owning a CRITICAL_SECTION. |
| `14002d4fc` | `FUN_14002d4fc` | `throw_bad_alloc` | high | llm_rename | Tiny 7-instruction stub, only string is bad allocation (duplicated); called from operator_new helper FUN_14002d6b4; matches std::bad_alloc throw thunk. |
| `14002d51c` | `FUN_14002d51c` | `std_exception_ctor_copy_a` | medium | llm_rename | 17-instruction constructor calling __std_exception_copy; no callers in batch; matches MSVC std::exception/runtime_error copy-ctor pattern. |
| `14002d570` | `FUN_14002d570` | `std_exception_ctor_copy_b` | medium | llm_rename | Same shape as 14002d51c: 17-instr __std_exception_copy wrapper, no in-batch callers; MSVC stdexception-derived ctor. |
| `14002d5ac` | `FUN_14002d5ac` | `std_exception_ctor_copy_c` | medium | llm_rename | 19-instr __std_exception_copy wrapper called from FUN_14002d6f4; MSVC stdexception-derived class ctor (likely runtime_error/logic_error subtype). |
| `14002d5f4` | `FUN_14002d5f4` | `std_exception_ctor_copy_d` | medium | llm_rename | 17-instr __std_exception_copy wrapper; matches MSVC stdexception-derived copy ctor pattern. |
| `14002d66c` | `FUN_14002d66c` | `std_exception_ctor_copy_e` | medium | llm_rename | 19-instr __std_exception_copy wrapper called from FUN_14002d718; MSVC stdexception-derived class ctor. |
| `14002d6b4` | `FUN_14002d6b4` | `operator_new_or_throw` | medium | llm_rename | 6-instruction wrapper called from operator_new and other allocators; on failure calls throw_bad_alloc (FUN_14002d4fc) via _CxxThrowException; classic operator_new fallback path. |
| `14002d760` | `FUN_14002d760` | `throw_bad_function_call` | high | llm_rename | Tiny 2-instruction stub containing only the literal string 'bad function call' — matches std::bad_function_call throw helper emitted by std::function call operator. |
| `14002d7d0` | `FUN_14002d7d0` | `addr_family_error_message` | medium | llm_rename | Small leaf returning one of {'address family not supported','unknown error'}; classic std::system_category socket error-message lookup. Two callers in net init region. |
| `14002dc94` | `FUN_14002dc94` | `locale_ctype_table_init` | high | llm_rename | 51 insns, calls __lc_locale_name_func, __lc_codepage_func, __pctype_func, _wcsdup, _calloc_base — CRT _Getctype-style locale ctype table builder. |
| `14002e3c0` | `FUN_14002e3c0` | `wide_to_multibyte_convert` | high | llm_rename | 53 insns, callees are WideCharToMultiByte + GetLastError; single caller wrapper that converts a UTF-16 buffer to a narrow string with error reporting. |
| `14002e910` | `FUN_14002e910` | `fs_set_file_attributes_by_path` | high | llm_rename | Calls __std_fs_open_handle, SetFileInformationByHandle, CloseHandle, GetLastError, terminate — STL <filesystem> permission/attribute mutator (e.g. fs::permissions or last_write_time backend). |
| `14002eb60` | `FUN_14002eb60` | `fs_open_wide_file_stream` | medium | llm_rename | Calls common_fsopen<wchar_t> and fclose; mid-size routine likely the wide-char file-open wrapper used by STL filesystem helpers. |
| `14002f200` | `FUN_14002f200` | `init_condvar_fallback_table` | high | llm_rename | Strings 'api-ms-win-core-synch-l1-2-0.dll','kernel32.dll','SleepConditionVariableCS','WakeAllConditionVariable'; GetModuleHandleW+GetProcAddress+CreateEventW+InitializeCriticalSectionAndSpinCount — CRT condvar emulation init on pre-Vista. |
| `14002f2d0` | `FUN_14002f2d0` | `vb_cleanup_critsect_and_handle` | medium | llm_rename | Tiny leaf calling CloseHandle then DeleteCriticalSection — typical paired teardown of a synchronized handle owner. |
| `14002f790` | `FUN_14002f790` | `vb_scrt_common_main_seh_wide` | high | llm_rename | MSVC scrt_common_main_seh variant: _configthreadlocale, _configure_wide_argv, common_initialize_environment_nolock<wchar_t>, __scrt_initialize_onexit_tables, _set_fmode, atexit. |
| `14002f850` | `FUN_14002f850` | `vb_scrt_initialize_default_local_stdio_options` | medium | llm_rename | Tiny thunk into FUN_1400302f8 which itself initialises stdio table; matches MSVC scrt_initialize_default_local_stdio_options shape. |
| `14002f860` | `FUN_14002f860` | `vb_scrt_dllmain_crt_thunk` | low | llm_rename | Small wrapper invoking the same atexit-registration helper (FUN_14000df40) plus FUN_140030008; resembles a CRT init/dllmain shim. |
| `14002f87c` | `FUN_14002f87c` | `vb_scrt_common_main_seh` | high | llm_rename | Called by entry; uses __scrt_initialize_crt, _initterm/_initterm_e, _get_wide_winmain_command_line, __scrt_acquire/release_startup_lock, _cexit — MSVC wWinMainCRTStartup body. |
| `14002fba0` | `FUN_14002fba0` | `vb_seh_failfast_buffer_overrun` | high | llm_rename | Calls capture_previous_context, IsProcessorFeaturePresent, __raise_securityfailure — matches __report_gsfailure / __report_securityfailure pattern. |
| `14002fc88` | `FUN_14002fc88` | `vb_report_rangecheckfailure_impl` | high | llm_rename | Caller is __report_rangecheckfailure; uses capture_current_context, IsProcessorFeaturePresent, __raise_securityfailure — body of range-check failfast. |
| `14002fe08` | `FUN_14002fe08` | `vb_operator_new_thunk` | medium | llm_rename | 5-instruction leaf whose sole callee is operator_new — minimal new() forwarder/thunk. |
| `14002fe1c` | `FUN_14002fe1c` | `vb_acrt_reportfault_tail` | low | llm_rename | 2-instr stub called from __acrt_call_reportfault and FUN_14002fe24 (UEF); likely the tail/terminate stub after fault reporting. |
| `14002fe24` | `FUN_14002fe24` | `vb_unhandled_exception_filter` | high | llm_rename | RtlCaptureContext + RtlLookupFunctionEntry + RtlVirtualUnwind + UnhandledExceptionFilter + IsDebuggerPresent + SetUnhandledExceptionFilter — canonical MSVC __scrt_unhandled_exception_filter. |
| `1400302f8` | `FUN_1400302f8` | `vb_initialize_default_stdio_options` | medium | llm_rename | Called only by FUN_14002f850; invokes FUN_140015230 (likely _setmode/stdio helper) plus a tiny init thunk — stdio defaults initializer. |
| `140030330` | `FUN_140030330` | `vb_invoke_guarded_callback` | low | llm_rename | 17-instr helper whose only callee is _guard_dispatch_icall — Control-Flow-Guarded indirect-call trampoline. |
| `140030370` | `FUN_140030370` | `vb_invoke_guarded_callback_b` | low | llm_rename | Identical shape to FUN_140030330 (17 instr, only _guard_dispatch_icall); a second CFG indirect-call trampoline with no resolved callers. |
| `14003078c` | `FUN_14003078c` | `vb_eh_frame_unwind_helper` | medium | llm_rename | Mid-size EH helper; calls abort + StateFromIp wrapper (FUN_140032534); siblings of FrameUnwindToEmptyState/GetEstablisherFrame. Likely an internal unwind step in __FrameHandler3. |
| `1400308cc` | `FUN_1400308cc` | `vb_eh_catch_dispatch_helper` | low | llm_rename | Called from FUN_14003328c (EH dispatcher cluster); chains into FUN_140030c58. Shape matches an MSVC catch-block dispatch/transition helper. |
| `140030a34` | `FUN_140030a34` | `vb_catchit_fh3_unwind` | high | llm_rename | Called by CatchIt<class___FrameHandler3>; invokes RtlUnwindEx via FUN_14002f160 wrapper. Classic __FrameHandler3 CatchIt unwind invoker. |
| `140030b38` | `FUN_140030b38` | `vb_catchit_fh4_unwind` | high | llm_rename | Called exclusively by CatchIt<class___FrameHandler4>; invokes RtlUnwindEx via FUN_14002f160. __FrameHandler4 sibling of 140030a34. |
| `140030c58` | `FUN_140030c58` | `vb_eh_catch_dispatch_inner` | low | llm_rename | Sole callee of FUN_1400308cc (catch-dispatch helper); leaf with no callees. Likely the inner state-transition step of the catch dispatcher. |
| `140030ed0` | `FUN_140030ed0` | `vb_vcrt_getptd_thunk_a` | medium | llm_rename | Tiny 8-instr thunk over __vcrt_getptd; called from CRT helpers FUN_140034c10/FUN_140034d9c. Per-thread data accessor wrapper. |
| `140030ee8` | `FUN_140030ee8` | `vb_vcrt_getptd_thunk_b` | medium | llm_rename | Sibling of 140030ed0: tiny __vcrt_getptd thunk used by EH dispatcher cluster (FUN_14003328c, FUN_140032dc4). |
| `14003126c` | `FUN_14003126c` | `vb_crt_initterm_helper` | low | llm_rename | Mid-size leaf called from very early init functions FUN_140001710/FUN_1400067c0/FUN_140006670 (matches MSVC CRT bootstrap region). Resembles _initterm-style table walker. |
| `14003131c` | `FUN_14003131c` | `vb_environ_table_helper` | high | llm_rename | Callers: common_set_variable_in_environment_nolock<wchar_t>, create_environment_string<wchar_t>, __acrt_get_qualified_locale, FUN_140008d90. UCRT environment-table maintenance helper. |
| `140031398` | `FUN_140031398` | `vb_locale_string_parse_helper` | low | llm_rename | Mid-size (155 ins) leaf called from FUN_14000c090 + FUN_140008d90, which sit in the locale/environ neighbourhood. Best guess: locale or env-string parser. |
| `1400316b0` | `FUN_1400316b0` | `vb_acrt_locale_update` | medium | llm_rename | Large hub (312 ins, 60+ callers spanning fp_format_*, write_string, _fread_nolock_s, __dcrt_get_wide_environment_from_os, _Locimp, _Init, signal, write_double_translated_ansi_nolock). Looks like the ACRT per-thread/per-call locale/state update routine. |
| `140031e00` | `FUN_140031e00` | `vb_acrt_mbcp_table_init` | medium | llm_rename | Hub (108 ins) reached from setSBCS, _setmbcp_nolock, parse_bcp47, __lc_wcstolc, __acrt_GetStringTypeA, _wctomb_s_l, fp_format_a, __acrt_fltout. Locale/code-page table initialiser. |
| `1400322e0` | `FUN_1400322e0` | `vb_unreached_tls_or_init_thunk` | low | llm_rename | Tiny orphan (no callers in this batch) that tail-calls FUN_140035ac0; resembles a TLS callback or module-init thunk. |
| `140032534` | `FUN_140032534` | `vb_eh_state_from_ip_fh3` | high | llm_rename | Single-line wrapper over StateFromIp; callers are FrameUnwindToEmptyState, GetEstablisherFrame, GetHandlerSearchState, ExecutionInCatch — the __FrameHandler3 family. |
| `14003253c` | `FUN_14003253c` | `vb_eh_state_from_ip_fh4` | high | llm_rename | Twin of 140032534: tiny StateFromIp wrapper used by FUN_14003328c + FUN_140034d9c (the FrameHandler4 dispatch cluster). |
| `140032694` | `FUN_140032694` | `vb_build_catch_object_fh3_inner` | high | llm_rename | Sole caller BuildCatchObjectInternal<class___FrameHandler3>; calls __AdjustPointer, _guard_dispatch_icall, _GetThrowImageBase, _GetImageBase. Inner copy-ctor invoker for FrameHandler3 catch object. |
| `140032894` | `FUN_140032894` | `vb_build_catch_object_fh4_inner` | high | llm_rename | Twin of 140032694 under BuildCatchObjectInternal<class___FrameHandler4>; same callees (__AdjustPointer, _guard_dispatch_icall, _GetThrowImageBase, _GetImageBase). FH4 catch-object copy-ctor invoker. |
| `140032dc4` | `FUN_140032dc4` | `vcrt_FrameHandler3_internal` | high | llm_rename | Called by FrameHandler3 wrapper; uses TypeMatchHelper<__FrameHandler3>, CatchIt, GetEstablisherFrame, GetHandlerSearchState, ExecutionInCatch — core __CxxFrameHandler3 dispatch routine. |
| `14003328c` | `FUN_14003328c` | `vcrt_FrameHandler4_internal` | high | llm_rename | Mirror of 140032dc4 but for FrameHandler4 (TryBlockMap4, HandlerMap4, DecompHandler, TypeMatchHelper<__FrameHandler4>) — core __CxxFrameHandler4 dispatcher. |
| `140033788` | `FUN_140033788` | `vcrt_FH3_CallSETranslator` | medium | llm_rename | Helper of FrameHandler3 path; calls _CallSETranslator<>, EncodePointer, CatchIt<__FrameHandler3> — likely SEH-to-C++ translator bridge for FH3. |
| `1400339a0` | `FUN_1400339a0` | `vcrt_FH4_CallSETranslator` | medium | llm_rename | FH4 counterpart to 140033788; uses _CallSETranslator<>, TryBlockMap4, HandlerMap4, DecompHandler, CatchIt<__FrameHandler4>. |
| `140033f14` | `FUN_140033f14` | `vcrt_CxxFrameHandler3_dispatch` | high | llm_rename | Called directly from __CxxFrameHandler3; uses _guard_dispatch_icall, FrameUnwindToEmptyState, StateFromIp, __except_validate_context_record — top-level FH3 dispatcher. |
| `14003414c` | `FUN_14003414c` | `vcrt_CxxFrameHandler4_dispatch` | high | llm_rename | Called from __CxxFrameHandler4; uses TryBlockMap4, StateFromIp, _guard_dispatch_icall, FrameUnwindToEmptyState — top-level FH4 dispatcher. |
| `140034570` | `FUN_140034570` | `vcrt_throw_bad_exception` | high | llm_rename | Tiny (7 insn) leaf with literal 'bad exception' strings; called from both FH3 and FH4 dispatchers — emits std::bad_exception. |
| `140034780` | `FUN_140034780` | `vcrt_unwind_destroy_frame` | medium | llm_rename | Calls _FindAndUnlinkFrame, _CreateFrameInfo, __DestructExceptionObject, _IsExceptionObjectToBeDestroyed — frame unwind + exception object teardown. |
| `140034c10` | `FUN_140034c10` | `vcrt_FH3_unwind_to_state` | medium | llm_rename | Reached via FrameUnwindToEmptyState and FH3 dispatcher; calls _CallSettingFrame, GetCurrentState, SetState — FH3 frame-unwind state iterator. |
| `140034d9c` | `FUN_140034d9c` | `vcrt_FH4_unwind_to_state` | medium | llm_rename | FH4 counterpart of 140034c10; calls ReadEntry, _CallSettingFrame(Encoded), getStateFromIterators, SetState — FH4 unwind state iterator. |
| `14003511c` | `FUN_14003511c` | `vcrt_TypeMatch_FH3_wrapper` | medium | llm_rename | Called from both FH3 and FH4 internal dispatchers; uses TypeMatchHelper<__FrameHandler3>, _GetThrowImageBase, _GetImageBase — type-match thunk. |
| `140035350` | `FUN_140035350` | `vcrt_FH4_ReadEntry_helper` | low | llm_rename | Only callee is ReadEntry; sole caller is FH4 unwind iterator — small helper resolving FH4 unwind/handler table entries. |
| `140035570` | `FUN_140035570` | `vcrt_seh_filter_stub` | low | llm_rename | Tiny (6 insn) leaf invoked from _CallSettingFrame, _CallSettingFrameEncoded, and __C_specific_handler — SEH filter trampoline stub. |
| `1400355dc` | `FUN_1400355dc` | `vcrt_load_apims_proc` | high | llm_rename | Uses LoadLibraryExW + GetProcAddress + FreeLibrary + wcsncmp on 'api-ms-' string; called from __vcrt_FlsAlloc/Free/Get/Set and InitializeCriticalSectionEx — apiset resolver. |
| `140035920` | `FUN_140035920` | `vcrt_unwind_helper_a` | low | llm_rename | Small thunk in 140034780 unwind chain; calls two SEH filter stubs (FUN_1400355a0/FUN_140035570) — frame teardown helper. |
| `140035950` | `FUN_140035950` | `vcrt_unwind_helper_b` | low | llm_rename | Sibling of FUN_140035920 under FUN_140034780; calls SEH filter stub FUN_140035570 — secondary frame teardown helper. |
| `1400359c8` | `FUN_1400359c8` | `crt_fp_init_state` | medium | llm_rename | Calls _ctrlfp, _sptype, __doserrno from CRT startup callers FUN_14000f0d0/FUN_14000f3b0 — FPU/control-word and errno initialization during CRT init. |
| `140035ac0` | `FUN_140035ac0` | `vb_free_wrapper` | high | llm_rename | 3-instruction thunk whose only callee is _free_base; >20 diverse callers across CRT/CAtl destructors confirm generic deallocation thunk. |
| `140035d08` | `FUN_140035d08` | `vb_crt_invalid_parameter_thunk` | high | llm_rename | Tiny function called from nearly every CRT stdio/locale/strtox routine, sole callee is _invalid_parameter. Classic CRT invalid-parameter forwarder. |
| `140035d28` | `FUN_140035d28` | `vb_crt_invalid_parameter_watson_thunk` | high | llm_rename | Tiny function with callees _invalid_parameter + _invoke_watson and a huge fan-in across STL containers/_Tidy_deallocate/deallocate. Standard MSVC invalid-parameter/watson forwarder. |
| `140035e08` | `FUN_140035e08` | `vb_acrt_getptd_helper` | medium | llm_rename | Small helper invoking __acrt_getptd then FUN_140046d84; pattern matches CRT per-thread-data fetch + downstream init/check helper. |
| `1400378b0` | `FUN_1400378b0` | `vb_printf_type_n_or_integer_helper` | medium | llm_rename | Only callers are type_case_n and type_case_integer (printf %n and integer-conversion handlers); 17-insn helper shared by both code paths. |
| `140038420` | `FUN_140038420` | `vb_locale_wcsicmp_helper` | medium | llm_rename | Callees _LocaleUpdate, __ascii_wcsicmp, _towlower_l, __doserrno; callers include ProcessCodePage and TranslateName. Locale-aware wide case-insensitive comparison helper. |
| `1400385f0` | `FUN_1400385f0` | `vb_acrt_locked_dispatch` | medium | llm_rename | 40-insn routine that acquires __acrt_lock, invokes _guard_dispatch_icall (indirect CFG-guarded call), then __acrt_unlock. Standard CRT locked indirect-call dispatcher. |
| `1400398e4` | `FUN_1400398e4` | `vb_stdio_stream_lock_helper` | medium | llm_rename | 2-insn helper called by every stdio op (fseek/fgetc/fputc/fclose/fread_s/ftell/ungetc/find_or_allocate_unused_stream_nolock); pattern matches FILE* lock acquire helper. |
| `1400398f0` | `FUN_1400398f0` | `vb_stdio_stream_unlock_helper` | medium | llm_rename | 2-insn sibling of 1400398e4; same stdio callers plus unwind funclets FUN_14005a*. Matches FILE* lock-release helper. |
| `14003e064` | `FUN_14003e064` | `vb_strtod_l_thunk` | high | llm_rename | 2-insn 8-byte tail-call thunk; sole callee is common_strtod_l<>. Standard locale-aware strtod forwarder. |
| `14003ebd0` | `FUN_14003ebd0` | `common_fseek_wrapper` | medium | iat_wrapper_detection | 2-instruction function with single import-like callee common_fseek at 14003ebc8 |
| `14003f950` | `FUN_14003f950` | `vb_acrt_mbstowcs_via_lcmapstring` | medium | llm_rename | Large CRT routine calling __acrt_GetLocaleInfoA, GetCPInfo, __acrt_LCMapStringA, __acrt_GetStringTypeA with calloc/free. Matches MSVC narrow->wide conversion via LCMapString. |
| `140042610` | `FUN_140042610` | `vb_printf_type_s_narrow_helper` | medium | llm_rename | Only caller is printf-formatter type_case_s; 108-insn helper handling %s formatting (likely narrow/MBCS branch). |
| `140042760` | `FUN_140042760` | `vb_locale_name_helper` | medium | llm_rename | Callers are __acrt_LCMapStringW, __acrt_CompareStringW, __crtLCMapStringW, __acrt_copy_locale_name, __acrt_DownlevelLCIDToLocaleName, create_environment_string<wchar_t>, type_case_s. Shared locale-name normalisation helper. |
| `140042fcc` | `FUN_140042fcc` | `abort_via_common_exit` | high | llm_rename | Called from abort/raise, tail-calls common_exit; classic MSVC abort terminator thunk. |
| `140043014` | `FUN_140043014` | `exit_common_thunk` | medium | llm_rename | 3-insn thunk into common_exit; CRT exit wrapper sibling of abort_via_common_exit. |
| `140043c90` | `FUN_140043c90` | `onexit_register_thunk` | high | llm_rename | Called from _onexit, tail-calls _register_onexit_function; standard CRT onexit shim. |
| `140043d70` | `FUN_140043d70` | `initialize_onexit_table_wrapper` | high | llm_rename | Single callee _initialize_onexit_table; CRT onexit table init wrapper. |
| `140043da0` | `FUN_140043da0` | `dcrt_uninitialize_environments_wrapper` | high | llm_rename | Wraps __dcrt_uninitialize_environments_nolock; CRT env teardown shim. |
| `140043df0` | `FUN_140043df0` | `vcrt_uninitialize_thunk` | high | llm_rename | 2-insn tail-call to __vcrt_uninitialize; vcruntime teardown thunk. |
| `140043e9c` | `FUN_140043e9c` | `execute_crt_initializers` | high | llm_rename | Caller __scrt_initialize_crt, callee __acrt_execute_initializers; CRT init-table executor wrapper. |
| `1400447d8` | `FUN_1400447d8` | `acrt_locale_ref_add_helper` | medium | llm_rename | Called from a 3-lambda operator() composition, callee is __acrt_add_locale_ref; thin wrapper that bumps a locale ref count inside a CRT locale-update helper. |
| `140045ad8` | `FUN_140045ad8` | `crt_errno_from_doserrno_set` | medium | llm_rename | Calls __doserrno then FUN_140035d08 (errno mapper); classic CRT _dosmaperr-style helper that translates a DOS error code into errno. |
| `140045cd4` | `FUN_140045cd4` | `crt_fp_raise_or_set_errno` | medium | llm_rename | Branches to _raise_exc_ex / _set_errno_from_matherr / _ctrlfp / _errcode; FP exception dispatch wrapper deciding between raising SIGFPE or setting errno. |
| `140045dc8` | `FUN_140045dc8` | `crt_fp_statfp_apply` | medium | llm_rename | 158-instr helper called only from FUN_140045cd4, calls _set_statfp via FUN_140046498; applies the FP status word for the FP exception path. |
| `1400463c4` | `FUN_1400463c4` | `crt_fp_matherr_set_errno` | medium | llm_rename | Calls _set_errno_from_matherr and _ctrlfp from the FP exception dispatcher; sets errno from a matherr-style code. |
| `140046498` | `FUN_140046498` | `crt_fp_statfp_writeback` | low | llm_rename | Shared helper of the _set_statfp path called by the FP exception apply routine and a higher-level math wrapper. |
| `140046950` | `FUN_140046950` | `crt_ptd_array_release` | high | llm_rename | Calls destroy_ptd_array then _free_base; per-thread-data array destructor releasing the PTD slot table. |
| `140046d84` | `FUN_140046d84` | `crt_ctype_lookup_helper` | medium | llm_rename | Called from islower/isupper/__pctype_func/___mb_cur_max_func/___lc_codepage_func/___lc_locale_name_func; the shared per-thread ctype/locale lookup. |
| `140047044` | `FUN_140047044` | `ansi_translate_mbtowc_thunk` | medium | llm_rename | Two-instruction tail-call to _mbtowc_l from write_double_translated_ansi_nolock; thin wrapper invoking the locale-aware mbtowc on a translated ANSI char. |
| `140047994` | `FUN_140047994` | `fp_format_dispatch_fe` | medium | llm_rename | Calls __acrt_fltout, fp_format_f_internal, fp_format_e_internal; subroutine of FUN_140047bf4 that dispatches between %f and %e formatting. |
| `140047bf4` | `FUN_140047bf4` | `fp_format_dispatch_full` | high | llm_rename | Caller is type_case_a; calls fp_format_a/fp_format_e/fp_format_f_internal/__acrt_fltout/strcpy_s — top-level %a/%e/%f/%g printf FP formatter. |
| `140048478` | `FUN_140048478` | `env_find_wchar_entry` | high | llm_rename | Called from common_getenv_nolock<wchar_t> and common_set_variable_in_environment_nolock<wchar_t>; uses __ascii_wcsnicmp + __acrt_CompareStringW to locate a wide env var. |
| `1400485b8` | `FUN_1400485b8` | `env_find_ansi_entry` | high | llm_rename | Called from common_set_variable_in_environment_nolock<char>; uses _strnicmp_l + __acrt_CompareStringA — ANSI-side env var lookup counterpart of env_find_wchar_entry. |
| `140049ec0` | `FUN_140049ec0` | `close_handle_thunk` | low | llm_rename | Seven-instruction wrapper that calls CloseHandle; orphan tiny thunk with no captured callers in this slice. |
| `14004dac0` | `FUN_14004dac0` | `fp_double_handle_special` | medium | llm_rename | Calls _handle_nan plus FUN_1400553ec; double-precision FP special-case dispatcher (NaN / infinity handling). |
| `14004dbf0` | `FUN_14004dbf0` | `fp_float_handle_special` | medium | llm_rename | Calls _handle_nanf and FUN_140055514; single-precision counterpart of fp_double_handle_special for float NaN/inf handling. |
| `14004e414` | `FUN_14004e414` | `vb_mbctype_init_thread_data` | medium | llm_rename | Locked CRT helper called from __acrt_initialize_multibyte path (via 14004e8c4); allocates/frees thread mbc data, sets doserrno; classic _setmbcp helper. |
| `14004e8c4` | `FUN_14004e8c4` | `vb_acrt_initialize_multibyte_impl` | high | llm_rename | Sole callee of __acrt_initialize_multibyte; calls _setmbcp_nolock, getSystemCP, _malloc_base; the multibyte init body. |
| `14004ea84` | `FUN_14004ea84` | `vb_acrt_update_multibyte_thread_data` | high | llm_rename | Called by __acrt_update_thread_multibyte_data and the init body; lock/free/abort pattern matches per-thread mbc data refresh. |
| `14004ee80` | `FUN_14004ee80` | `vb_get_command_line_tchar` | high | llm_rename | Tiny wrapper that calls GetCommandLineW and GetCommandLineA; classic CRT _acmdln/_wcmdln initializer. |
| `14004f050` | `FUN_14004f050` | `vb_get_process_heap_wrapper` | high | llm_rename | 7-instruction wrapper around GetProcessHeap; CRT heap-handle accessor. |
| `14004f790` | `FUN_14004f790` | `vb_acrt_get_locale_monetary` | high | llm_rename | Calls __acrt_GetLocaleInfoA, _calloc_base, __acrt_locale_free_monetary; builds monetary lconv block (CRT lconv init). |
| `14004fd30` | `FUN_14004fd30` | `vb_acrt_get_locale_numeric` | high | llm_rename | Calls __acrt_GetLocaleInfoA and __acrt_locale_free_numeric; numeric counterpart to 14004f790, builds numeric lconv block. |
| `140050a04` | `FUN_140050a04` | `vb_update_thread_locale_info` | high | llm_rename | Called by _wsetlocale; uses __acrt_getptd/_updatetlocinfoEx_nolock under lock — per-thread locale update helper. |
| `140050cf0` | `FUN_140050cf0` | `vb_init_locale_country` | high | llm_rename | Calls __acrt_GetLocaleInfoEx, TestDefaultCountry, wcsncpy_s; populates locale country string with fallback test. |
| `140050fe0` | `FUN_140050fe0` | `vb_init_locale_codepage` | medium | llm_rename | Same shape as country init (GetLocaleInfoEx + wcsncpy_s) but smaller and no TestDefaultCountry; likely codepage/locale-name field init. |
| `140051500` | `FUN_140051500` | `vb_resolve_lcid_from_locale` | high | llm_rename | Calls LcidFromHexString + GetLocaleInfoW + __acrt_getptd; converts locale string to LCID. |
| `140051750` | `FUN_140051750` | `vb_init_locale_language` | high | llm_rename | LcidFromHexString + TestDefaultLanguage + GetLocaleInfoW; CRT language-field initialization with default-language fallback. |
| `1400519a0` | `FUN_1400519a0` | `vb_init_locale_country_from_lcid` | medium | llm_rename | LcidFromHexString + GetLocaleInfoW + TestDefaultLanguage (smaller variant); secondary locale-field initializer. |
| `140051fe0` | `FUN_140051fe0` | `vb_fpu_control_stub` | medium | llm_rename | Tiny 3-instruction helper called by _set_statfp, _control87, _ctrlfp; FPU control-word read/return stub. |
| `140052290` | `FUN_140052290` | `vb_fp_format_helper` | high | llm_rename | Called by fp_format_e (and two siblings); uses fegetround + __doserrno; floating-point formatting rounding helper. |
| `140053824` | `FUN_140053824` | `vb_locale_wcsnicmp_helper` | high | llm_rename | Used by __acrt_stdio_parse_mode<wchar_t> and locale-init paths; calls __ascii_wcsnicmp + _towlower_l + _LocaleUpdate. |
| `140054290` | `FUN_140054290` | `close_handle_thunk` | medium | llm_rename | Tiny 7-instr leaf wrapping CloseHandle; classic thunk/forwarder shape with no other callees. |
| `140054eac` | `FUN_140054eac` | `lowio_open_file` | high | llm_rename | Called from common_sopen_dispatch<>; uses CreateFileW + __acrt_lowio_set_os_handle + _alloc_osfhnd + configure_text_mode + truncate_ctrl_z_if_present. CRT lowio open implementation. |
| `1400552c8` | `FUN_1400552c8` | `fpe_set_errno_helper` | medium | llm_rename | Shared helper of fp exception handlers; calls _ctrlfp and _set_errno_from_matherr. Used by both float and double exception raisers. |
| `1400553ec` | `FUN_1400553ec` | `raise_fp_exception_double` | high | llm_rename | Calls _exception_enabled, _raise_exc (double variant), _set_errno_from_matherr, _ctrlfp; mirror of float variant at 140055514. CRT _fdtest/_except1-style double FPE raiser. |
| `140055514` | `FUN_140055514` | `raise_fp_exception_float` | high | llm_rename | Same shape as 1400553ec but calls _raise_excf (float). CRT float FPE raiser. |
| `140055a20` | `FUN_140055a20` | `initialize_multibyte_thunk` | medium | llm_rename | Tiny wrapper around __acrt_initialize_multibyte; CRT mbcs init forwarder. |
| `140055f90` | `FUN_140055f90` | `fltout_format_core` | high | llm_rename | Called from __acrt_fltout; 1386-byte float-to-string conversion core that drives log10-based digit formatter at 140056a90. |
| `140056a90` | `FUN_140056a90` | `compute_log10_for_fltout` | high | llm_rename | Strings 'log10' x2 indicate libm log10 call site; called by fltout core and forwards to fp helper. Computes exponent via log10. |
| `140056ab0` | `FUN_140056ab0` | `log10_with_fpe_handling` | medium | llm_rename | Bridges log10 call site to raise_fp_exception_double; handles domain/range errors for log10. |
| `140056d28` | `FUN_140056d28` | `set_env_var_nolock_helper` | medium | llm_rename | Sole caller is common_set_variable_in_environment_nolock<char>; helper for environment variable mutation. |
| `140056dd4` | `FUN_140056dd4` | `fp_format_a_helper` | medium | llm_rename | Sole caller fp_format_a; assistive routine for %a hex-float formatting. |
| `140058080` | `FUN_140058080` | `vb_container_tidy_dealloc_thunk_140058080` | low | llm_rename | 13-insn thunk calling MSVC STL _Tidy_deallocate; likely container destructor/cleanup wrapper. No strings, no callers visible. |
| `140058ff0` | `FUN_140058ff0` | `vb_map_lookup_key_not_found_throw` | high | llm_rename | Strings 'key ' and "' not found" plus _CxxThrowException callee match the canonical std::map/unordered_map at()-style 'key not found' throw helper. |
| `1400597e0` | `FUN_1400597e0` | `vb_allocator_overflow_throw_dealloc_thunk` | low | llm_rename | Calls _CxxThrowException + deallocate; shape matches MSVC allocator length_error/bad_alloc throw helper that frees buffer before throwing. |
| `140059b6c` | `FUN_140059b6c` | `vb_array_unwind_cleanup_thunk` | medium | llm_rename | Sole callee __ArrayUnwind: SEH/EH cleanup funclet that destroys partially-constructed array on exception. Pure unwind helper. |
| `140059bf7` | `FUN_140059bf7` | `vb_seh_filter_exe_thunk` | medium | llm_rename | Sole callee _seh_filter_exe: CRT SEH top-level exception filter wrapper used by /EHa to translate SEH into C++. |
| `140059df9` | `FUN_140059df9` | `vb_eh_filter_rethrow_thunk` | medium | llm_rename | Sole callee ExFilterRethrow: MSVC C++ EH rethrow filter funclet emitted around rethrow inside a catch block. |
| `140059e96` | `FUN_140059e96` | `vb_eh_filter_rethrow_fh4_thunk` | medium | llm_rename | Sole callee ExFilterRethrowFH4: FH4-format C++ EH rethrow filter (newer MSVC funclet variant of ExFilterRethrow). |
| `140059f48` | `FUN_140059f48` | `vb_frame_unwind_filter_thunk` | medium | llm_rename | 8-insn funclet whose only callee is __FrameUnwindFilter: stack-frame unwind exception filter for C++ EH. |
| `14005a5d0` | `FUN_14005a5d0` | `atl_base_module_dtor_thunk` | medium | llm_rename | 12-byte function with single callee ~CAtlBaseModule; likely a thunk/wrapper invoking the ATL base module destructor (compiler-generated cleanup stub). |

## Renames by source

- `iat_wrapper_detection`: 1
- `llm_rename`: 395
