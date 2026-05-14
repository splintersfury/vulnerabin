void FUN_140016b80(longlong *param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  LPCWSTR ***ppppWVar6;
  undefined8 ****ppppuVar7;
  ulonglong uVar8;
  undefined1 auStackY_5c8 [32];
  HMODULE *local_588;
  int local_580;
  undefined4 local_578 [2];
  LPCWSTR **local_570 [2];
  undefined8 local_560;
  ulonglong local_558;
  longlong local_550 [16];
  char local_4d0;
  undefined8 ***local_458 [2];
  ulonglong local_448;
  ulonglong local_440;
  DWORD local_438;
  wchar_t local_434 [260];
  wchar_t local_22c [266];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_5c8;
  local_438 = timeGetTime();
  uVar8 = 0xffffffffffffffff;
  wcsncpy_s(local_434,0x102,L"service::remove_trust_command_file",0xffffffffffffffff);
  wcscat_s(local_434,0x104,L"()");
  wcsncpy_s(local_22c,0x104,L"service::remove_trust_command_file",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_588 = FUN_14000eb20();
    LOCK();
    local_580 = 1;
    UNLOCK();
    if (local_588 == (HMODULE *)0x0) {
      local_588 = FUN_14000eb20();
      LOCK();
      local_580 = 2;
      UNLOCK();
    }
    local_578[0] = 0x20;
    FUN_1400019c0((longlong)local_588,1,local_578,&IMAGE_DOS_HEADER_140000000,local_22c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_580 + -1;
    iVar3 = local_580;
    while (-1 < iVar1) {
      local_580 = iVar3 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar3 + -2;
      iVar3 = local_580;
    }
    LOCK();
    UNLOCK();
  }
  local_448 = 0;
  local_440 = 7;
  local_458[0] = (undefined8 ****)0x0;
  FUN_140010340((longlong *)local_458,(undefined8 *)L"bdservicehost.",0xe);
  puVar4 = (undefined8 *)(*(code *)PTR__guard_dispatch_icall_14005b538)(param_1);
  do {
    uVar8 = uVar8 + 1;
  } while (*(short *)((longlong)puVar4 + uVar8 * 2) != 0);
  FUN_14000e630(local_458,puVar4,uVar8);
  ppppuVar7 = local_458;
  if (7 < local_440) {
    ppppuVar7 = (undefined8 ****)local_458[0];
  }
  local_570[0] = (LPCWSTR **)0x0;
  local_560 = 0;
  local_558 = 7;
  FUN_140010340((longlong *)local_570,ppppuVar7,local_448);
  ppppWVar6 = local_570;
  if (7 < local_558) {
    ppppWVar6 = (LPCWSTR ***)local_570[0];
  }
  uVar5 = FUN_14002e910((LPCWSTR)ppppWVar6);
  if (7 < local_558) {
    if ((0xfff < local_558 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_570[0] + (-8 - (longlong)local_570[0][-1]))))
    goto LAB_140016ea3;
    FUN_14002f180();
  }
  if ((char)uVar5 == '\0') {
    FUN_140002e10(local_550,8,0x14006bce0);
    if ((local_4d0 != '\0') && (FUN_140012a30(local_550,0x14006bd28), local_4d0 != '\0')) {
      FUN_14000e200(local_550,(int)((ulonglong)uVar5 >> 0x20));
    }
    FUN_140003090(local_550);
  }
  if (7 < local_440) {
    if ((0xfff < local_440 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_458[0] + (-8 - (longlong)local_458[0][-1])))) {
      FUN_140035d28();
LAB_140016ea3:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  local_448 = 0;
  local_440 = 7;
  local_458[0] = (undefined8 ***)((ulonglong)local_458[0] & 0xffffffffffff0000);
  FUN_140015270((longlong)&local_438);
  FUN_14002f160(local_18 ^ (ulonglong)auStackY_5c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016eb0 @ 140016eb0