void FUN_14002d0a0(DWORD param_1,LPCWSTR *param_2,undefined8 param_3)

{
  uint *puVar1;
  undefined8 *puVar2;
  LPCWSTR pWVar3;
  undefined1 auStackY_b8 [32];
  undefined8 local_88 [3];
  longlong local_70 [4];
  undefined8 local_50 [6];
  char local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_b8;
  pWVar3 = DAT_14007acf0;
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
    pWVar3 = *(LPCWSTR *)DAT_14007acf0;
  }
  FUN_14002aeb0(local_50,pWVar3,param_3,param_1,param_2);
  if (local_20 == '\0') {
    FUN_14002d150((longlong)local_50);
    FUN_14002f160(local_18 ^ (ulonglong)auStackY_b8);
    return;
  }
  puVar1 = (uint *)FUN_14002d1c0((longlong)local_50);
  puVar2 = (undefined8 *)FUN_14002a6a0(local_70,puVar1);
  FUN_140001a40(local_88,puVar2);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_88,(ThrowInfo *)&DAT_140077818);
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d150 @ 14002d150