HMODULE * __fastcall FUN_10002ff0(HMODULE *param_1)

{
  undefined1 (*lpFilename) [16];
  DWORD DVar1;
  undefined1 (*_Dst) [16];
  HMODULE pHVar2;
  FARPROC pFVar3;
  
  *param_1 = (HMODULE)0x0;
  param_1[1] = (HMODULE)0x0;
  param_1[2] = (HMODULE)0x0;
  param_1[3] = (HMODULE)0x0;
  param_1[4] = (HMODULE)0x0;
  param_1[5] = (HMODULE)0x0;
  param_1[6] = (HMODULE)0x0;
  param_1[7] = (HMODULE)0x0;
  param_1[8] = (HMODULE)0x0;
  param_1[9] = (HMODULE)0x0;
  param_1[10] = (HMODULE)0x0;
  param_1[0xc] = (HMODULE)0x0;
  param_1[0xd] = (HMODULE)0x0;
  param_1[0xe] = (HMODULE)0x0;
  param_1[0xf] = (HMODULE)0x0;
  param_1[0x10] = (HMODULE)0x0;
  param_1[0x11] = (HMODULE)0x0;
  GetModuleHandleExW(0,L"log.dll",param_1);
  pHVar2 = *param_1;
  if (pHVar2 == (HMODULE)0x0) {
    lpFilename = (undefined1 (*) [16])FUN_1002e6a3(0xfffe);
    _memset(lpFilename,0,0xfffe);
    DVar1 = GetModuleFileNameW((HMODULE)&IMAGE_DOS_HEADER_10000000,(LPWSTR)lpFilename,0x7fff);
    if ((DVar1 != 0) && (_Dst = FUN_1002fe24(lpFilename,0x5c), _Dst != (undefined1 (*) [16])0x0)) {
      _wcscpy_s((wchar_t *)_Dst,0x7fff - ((int)_Dst - (int)lpFilename >> 1),L"\\log.dll");
      pHVar2 = LoadLibraryW((LPCWSTR)lpFilename);
      *param_1 = pHVar2;
    }
    thunk_FUN_100330ca(lpFilename);
    pHVar2 = *param_1;
    if (pHVar2 == (HMODULE)0x0) goto LAB_100031e8;
  }
  pFVar3 = GetProcAddress(pHVar2,"LogInit");
  if (pFVar3 != (FARPROC)0x0) {
    (*pFVar3)();
  }
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogApplySettings");
  param_1[1] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetSettingsFile");
  param_1[2] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogEnable");
  param_1[3] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetLevel");
  param_1[4] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetPath");
  param_1[5] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetType");
  param_1[6] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetMode");
  param_1[7] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetMaxSize");
  param_1[8] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogSetDepth");
  param_1[9] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogWrite");
  param_1[10] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogIsEnabled");
  param_1[0xb] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogMonitorSettings");
  param_1[0xc] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogGetLevel");
  param_1[0x11] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogUninitDeskMetrics");
  param_1[0xd] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogTrackEvent");
  param_1[0xe] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogTrackEventData");
  param_1[0xf] = pHVar2;
  pHVar2 = (HMODULE)GetProcAddress(*param_1,"LogRemoveModule");
  param_1[0x10] = pHVar2;
  if (param_1[10] != (HMODULE)0x0) {
    return param_1;
  }
LAB_100031e8:
  param_1[10] = (HMODULE)&LAB_10003230;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10003200 @ 10003200