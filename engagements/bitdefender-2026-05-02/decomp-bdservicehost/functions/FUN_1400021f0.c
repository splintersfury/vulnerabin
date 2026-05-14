void FUN_1400021f0(undefined8 param_1,longlong *param_2,DWORD param_3)

{
  char *pcVar1;
  ulonglong uVar2;
  undefined1 auStack_48 [32];
  char *local_28;
  ulonglong local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_48;
  local_28 = (char *)0x0;
  local_20 = __std_system_error_allocate_message(param_3,(longlong *)&local_28);
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0xf;
  *(undefined1 *)param_2 = 0;
  pcVar1 = local_28;
  uVar2 = local_20;
  if (local_20 == 0) {
    pcVar1 = "unknown error";
    uVar2 = 0xd;
  }
  FUN_1400106a0(param_2,(undefined8 *)pcVar1,uVar2);
  LocalFree(local_28);
  FUN_14002f160(local_18 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002290 @ 140002290