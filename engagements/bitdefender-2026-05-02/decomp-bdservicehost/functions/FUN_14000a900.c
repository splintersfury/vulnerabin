void FUN_14000a900(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  code *pcVar1;
  BOOL BVar2;
  undefined1 *puVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  LPCWSTR ***ppppWVar6;
  undefined1 auStack_208 [32];
  undefined4 local_1e8;
  longlong local_1e0 [2];
  undefined8 local_1d0;
  ulonglong local_1c8;
  undefined8 *local_1c0;
  longlong local_1b8 [16];
  char local_138;
  HMODULE local_c0;
  undefined1 local_b8 [8];
  undefined8 *local_b0;
  undefined8 local_a8;
  undefined8 *local_a0;
  undefined8 local_98;
  undefined **local_90;
  code *local_88;
  undefined ***local_58;
  char local_50;
  HMODULE local_48;
  LPCWSTR **local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  ulonglong uStack_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_208;
  local_1e8 = 0;
  local_b8[0] = 1;
  if (7 < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  local_a8 = 0;
  local_98 = 0;
  local_a0 = param_3;
  if (7 < (ulonglong)param_3[3]) {
    local_a0 = (undefined8 *)*param_3;
  }
  local_90 = std::_Func_impl_no_alloc<void_(__cdecl*)(void),void>::vftable;
  local_88 = FUN_14000a8d0;
  local_58 = &local_90;
  local_50 = '\x01';
  *param_1 = 0;
  local_1c0 = param_1;
  local_b0 = param_2;
  local_c0 = (HMODULE)operator_new(0x78);
  puVar3 = FUN_1400089c0((undefined1 *)local_c0,local_b8,param_3);
  *param_1 = puVar3;
  local_1e8 = 3;
  if (*(int *)(puVar3 + 0x70) < 0) {
    FUN_140001ab0(local_1e0,0x14006afb0);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_1e0,(ThrowInfo *)&DAT_140077818);
  }
  plVar4 = FUN_14000a810(local_1e0);
  puVar5 = FUN_14000e630(plVar4,(undefined8 *)L"bdch.dll",8);
  local_40 = (LPCWSTR **)*puVar5;
  uStack_38 = puVar5[1];
  local_30 = puVar5[2];
  uStack_28 = puVar5[3];
  puVar5[2] = 0;
  puVar5[3] = 7;
  *(undefined2 *)puVar5 = 0;
  local_1e8 = 7;
  if (7 < local_1c8) {
    if ((0xfff < local_1c8 * 2 + 2) &&
       (0x1f < (CONCAT62(local_1e0[0]._2_6_,(undefined2)local_1e0[0]) -
               *(longlong *)(CONCAT62(local_1e0[0]._2_6_,(undefined2)local_1e0[0]) + -8)) - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  local_1d0 = 0;
  local_1c8 = 7;
  local_1e0[0]._0_2_ = 0;
  local_48 = (HMODULE)0x0;
  ppppWVar6 = &local_40;
  if (7 < uStack_28) {
    ppppWVar6 = (LPCWSTR ***)local_40;
  }
  FUN_1400038c0(&local_48,(LPCWSTR)ppppWVar6);
  local_c0 = (HMODULE)0x0;
  ppppWVar6 = &local_40;
  if (7 < uStack_28) {
    ppppWVar6 = (LPCWSTR ***)local_40;
  }
  BVar2 = GetModuleHandleExW(1,(LPCWSTR)ppppWVar6,&local_c0);
  if (BVar2 == 0) {
    FUN_140002e10(local_1b8,4,0x14006b008);
    local_1e8 = 0xf;
    if (local_138 != '\0') {
      FUN_140012a30(local_1b8,0x14006afd0);
    }
    FUN_140003090(local_1b8);
  }
  else {
    FreeLibrary(local_c0);
  }
  if (local_48 != (HMODULE)0x0) {
    FreeLibrary(local_48);
    local_48 = (HMODULE)0x0;
  }
  if (7 < uStack_28) {
    if ((0xfff < uStack_28 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_40 + (-8 - (longlong)local_40[-1])))) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  local_30 = 0;
  uStack_28 = 7;
  local_40 = (LPCWSTR **)((ulonglong)local_40 & 0xffffffffffff0000);
  if ((local_50 != '\0') && (local_58 != (undefined ***)0x0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)
              (local_58,CONCAT71((int7)((ulonglong)&local_90 >> 8),local_58 != &local_90));
  }
  FUN_14002f160(local_20 ^ (ulonglong)auStack_208);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ac10 @ 14000ac10