void FUN_140015360(undefined8 *param_1)

{
  int iVar1;
  int iVar2;
  DWORD DVar3;
  HMODULE *ppHVar4;
  HANDLE pvVar5;
  HMODULE hModule;
  FARPROC pFVar6;
  longlong lVar7;
  LPCWSTR lpLibFileName;
  undefined1 auStackY_648 [32];
  HMODULE *local_608;
  int local_600;
  undefined4 local_5f8 [4];
  undefined8 *local_5e8;
  undefined8 local_5d8;
  undefined8 local_5d0;
  undefined8 local_5c0 [3];
  undefined8 local_5a8 [3];
  undefined8 local_590 [3];
  undefined8 local_578 [3];
  undefined8 local_560 [35];
  DWORD local_448;
  undefined **ppuStack_440;
  DWORD local_438;
  wchar_t local_434 [260];
  wchar_t local_22c [266];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_648;
  *param_1 = service::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  DVar3 = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  local_5e8 = param_1;
  ppHVar4 = FUN_14000eb20();
  param_1[6] = ppHVar4;
  LOCK();
  *(int *)(param_1 + 7) = *(int *)(param_1 + 7) + 1;
  UNLOCK();
  local_438 = timeGetTime();
  wcsncpy_s(local_434,0x102,L"service::service",0xffffffffffffffff);
  wcscat_s(local_434,0x104,L"()");
  wcsncpy_s(local_22c,0x104,L"service::service",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_608 = FUN_14000eb20();
    LOCK();
    local_600 = 1;
    UNLOCK();
    if (local_608 == (HMODULE *)0x0) {
      local_608 = FUN_14000eb20();
      LOCK();
      local_600 = 2;
      UNLOCK();
    }
    local_5f8[0] = 0x20;
    FUN_1400019c0((longlong)local_608,1,local_5f8,&IMAGE_DOS_HEADER_140000000,local_22c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_600 + -1;
    iVar2 = local_600;
    while (-1 < iVar1) {
      local_600 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_600;
    }
    LOCK();
    UNLOCK();
  }
  pvVar5 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCWSTR)0x0);
  param_1[1] = pvVar5;
  lpLibFileName = (LPCWSTR)(DAT_14007acf0 + 0x80);
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0x98)) {
    lpLibFileName = *(LPCWSTR *)lpLibFileName;
  }
  hModule = LoadLibraryW(lpLibFileName);
  if (hModule == (HMODULE)0x0) {
    DVar3 = GetLastError();
    ppuStack_440 = &PTR_vftable_14007ad08;
    local_448 = DVar3;
  }
  if ((HMODULE)param_1[3] != (HMODULE)0x0) {
    FreeLibrary((HMODULE)param_1[3]);
    param_1[3] = 0;
  }
  param_1[3] = hModule;
  if (DVar3 != 0) {
    FUN_140001ab0(local_5c0,0x14006b950);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_5c0,(ThrowInfo *)&DAT_140077818);
  }
  pFVar6 = GetProcAddress(hModule,"CreateServiceImplementation");
  if (pFVar6 == (FARPROC)0x0) {
    FUN_140001ab0(local_5a8,0x14006b988);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_5a8,(ThrowInfo *)&DAT_140077818);
  }
  pFVar6 = GetProcAddress((HMODULE)param_1[3],"DestroyServiceImplementation");
  param_1[5] = pFVar6;
  if (pFVar6 != (FARPROC)0x0) {
    lVar7 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    if (lVar7 == 0) {
      FUN_140001ab0(local_578,0x14006ba18);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_578,(ThrowInfo *)&DAT_140077818);
    }
    local_5d8 = 0x9b7121ed18dcd4a3;
    local_5d0 = 0xbbd74b04c72d4ba6;
    lVar7 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,&local_5d8);
    param_1[4] = lVar7;
    if (lVar7 != 0) {
      FUN_140015270((longlong)&local_438);
      FUN_14002f160(local_18 ^ (ulonglong)auStackY_648);
      return;
    }
    FUN_140001ab0(local_560,0x14006ba38);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_560,(ThrowInfo *)&DAT_140077818);
  }
  FUN_140001ab0(local_590,0x14006b9e0);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_590,(ThrowInfo *)&DAT_140077818);
}


// FUNCTION_END

// FUNCTION_START: FUN_140015710 @ 140015710